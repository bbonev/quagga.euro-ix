/* Quagga Work Queue Support.
 *
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include "misc.h"

#include "workqueue.h"
#include "memory.h"
#include "linklist.h"

/*==============================================================================
 * Work Queue Item Function
 * ========================
 *
 * When a work queue is "run", the items on the queue are dispatched, in turn
 * until the allotted time is used up.
 *
 * Each work queue item has a data pointer and a function associated with it.
 * When the item is dispatched the function is called and is passed the
 * data pointer and the current "yield time".  If the function finds that
 * there is no work to be done, it must return wqrc_nothing.  If the function
 * finds that there is something to be done it may do some amount of work,
 * and return wqrc_something.  The amount of work may depend on the
 * "yield time" if the function wishes.
 *
 * When a work queue item is dispatched it may return with:
 *
 *   * wqrc_nothing   -- there was nothing to do.
 *
 *     The next item (if any) is dispatched -- unconditionally.
 *
 *     NB: wqrc_nothing <=> no (actual) work was done, and no (material) time
 *         was spent doing it.
 *
 *   * wqrc_something -- something has been done.
 *
 *     If time has not run out, the next item (if any) is dispatched.
 *
 * Running a given work queue will run items on the ring until:
 *
 *   * the time-slot has expired when an item returns wqrc_something.
 *
 *   * the queue becomes empty.
 *
 *   * all items have returned wqrc_nothing.
 *
 *     Returning wqrc_nothing with wqrc_retain must be done with a little
 *     caution.  Generally, when an item runs out of work it should remove
 *     itself from the queue, to be put back on again when more work rolls up.
 *     But it is possible to run a work queue where items are "polled" and
 *     return wqrc_nothing with wqrc_retain if they have nothing to do.  The
 *     thing to watch out for is that the queue runner will keep going around
 *     the ring until all items report wqrc_nothing.
 *
 * What the next item is depends on the "action" which is:
 *
 *   wqrc_retain     -- leave item as is, but step to the next on the ring
 *
 *                      The item will be dispatched again when the ring comes
 *                      round to it again.
 *
 *   wqrc_rerun      -- leave item as is, and rerun if time allows
 *
 *                      This is probably not useful for wqrc_nothing.
 *
 *   wqrc_remove     -- remove item from work queue
 *   wqrc_release    -- remove item from work queue and free it
 *
 *                      The next item is the one which followed the current
 *                      one before it was removed.
 */

/*------------------------------------------------------------------------------
 * Initialise (creating as required) a work queue item
 *
 * If wqi == NULL, create a new work queue item
 *
 * Sets the given work queue item function and data pointer.
 *
 * Returns:  address of the given or created item
 */
extern wq_item
wq_item_init_new(wq_item wqi, wq_function func, void* data)
{
  if (wqi == NULL)
    wqi = XCALLOC(MTYPE_WORK_QUEUE_ITEM, sizeof(wq_item_t)) ;
  else
    memset(wqi, 0, sizeof(wq_item_t)) ;

  wqi->func = func ;
  wqi->data = data ;

  return wqi ;
} ;

/*------------------------------------------------------------------------------
 * Free work queue item created by wq_item_init_new() -- if any
 *
 * NB: it is the caller's responsibility to ensure that the item is not on any
 *     work queue.
 *
 * NB: it is the caller's responsibility to ensure that any data referred to by
 *     the work queue item has been released as required.
 *
 * Returns:  NULL
 */
extern wq_item
wq_item_free(wq_item wqi)
{
  if (wqi != NULL)
    XFREE(MTYPE_WORK_QUEUE_ITEM, wqi) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Append given work queue item to the given work queue.
 *
 * NB: it is the caller's responsibility to ensure that the item is not on any
 *     work queue, and that it is properly initialised.
 *
 * Returns:  address of the given work queue item.
 */
extern wq_item
wq_item_add(wq_base wq, wq_item wqi)
{
  rdl_append(*wq, wqi, queue) ;

  return wqi ;
} ;

/*------------------------------------------------------------------------------
 * Remove given work queue item from the given work queue.
 *
 * NB: it is the caller's responsibility to ensure that the item is on the
 *     work queue !
 *
 * Returns:  address of the given work queue item.
 */
extern wq_item
wq_item_del(wq_base wq, wq_item wqi)
{
  rdl_del(*wq, wqi, queue) ;

  return wqi ;
} ;

/*------------------------------------------------------------------------------
 * Remove given work queue item from the given work queue and free it.
 *
 * NB: it is the caller's responsibility to ensure that the item is on the
 *     work queue !
 *
 * Returns:  NULL
 */
extern wq_item
wq_item_del_free(wq_base wq, wq_item wqi)
{
  if (wqi != NULL)
    rdl_del(*wq, wqi, queue) ;

  return wq_item_free(wqi) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise the given work queue
 */
extern void
wq_init(wq_base wq)
{
  rdl_init(*wq) ;
} ;

/*------------------------------------------------------------------------------
 * Run the given work queue
 *
 * NB: only when an item returns wqrc_something does this check for time
 *     expired.  Which means:
 *
 *       * no matter what the time now and the yield time, will dispatch
 *         items until hits end of queue or an item does something.
 *
 *       * ie: no matter what the time now and the yield time, one item will
 *             get a chance to do something.
 *
 * Returns:  true <=> at least one item reported wqrc_something at some time.
 *                 => *p_now set to time after last item that reported
 *                    wqrc_something
 *
 *          false <=> no item reported wqrc_something and have reached the end
 *                    of the queue.
 *                 => *p_now *untouched*
 */
extern bool
wq_run(wq_base wq, qtime_mono_t yield_time, qtime_mono_t* p_now)
{
  bool          something ;
  wq_item       wqi, nothing ;
  qtime_mono_t  now ;

  something = false ;
  now       = 0 ;               /* calm down compiler   */
  nothing   = NULL ;

  wqi       = rdl_head(*wq) ;
  while (wqi != nothing)
    {
      wq_ret_code_t ret ;
      wq_item       next ;

      /* Do something and collect the result
       */
      ret = wqi->func(wqi->data, yield_time) ;

      switch (ret & wqrc_action_mask)
        {
          /* wqrc_retain: keep the item, and step past it.
           */
          case wqrc_retain:
            next = rdl_next(wqi, queue) ;
            break ;

          /* wqrc_rerun:  if time allows, rerun now, otherwise leave as head.
           */
          case wqrc_rerun:
            next = wqi ;
            break ;

          /* Treat nonsence response as remove with nothing.
           */
          default:
            qassert(false) ;
            fall_through ;

          /* wqrc_remove: remove item from queue
           */
          case wqrc_remove:
            next = rdl_del(*wq, wqi, queue) ;
            wqi  = NULL ;
            break ;

          /* wqrc_release: remove item from queue and free it
           */
          case wqrc_release:
            next = rdl_del(*wq, wqi, queue) ;
            wq_item_free(wqi) ;
            wqi  = NULL ;
            break ;
        } ;

      /* If we did something, see if we should yield.
       */
      confirm((wqrc_something != 0) && ((wqrc_nothing & wqrc_something) == 0)) ;

      if (ret & wqrc_something)
        {
          something = true ;

          now = qt_get_monotonic() ;

          if (now >= yield_time)
            break ;

          /* We did something for the current item, so clear the nothing
           * trap.
           */
          nothing = NULL ;
        }
      else
        {
          /* We did nothing for the current item, so if we don't have a
           * nothing trap set, set it.
           */
          if (nothing == NULL)
            nothing = wqi ;
        } ;

      wqi = next ;
    } ;

  if (something)
    *p_now = now ;

  return something ;
} ;

/*==============================================================================
 * Previous workqueue implementation.
 *
 * Copyright (C) 2005 Sun Microsystems, Inc.
 */
#include <lib/zebra.h>
#include "thread.h"
#include "command.h"
#include "log.h"

/* master list of work_queues */
static struct list work_queues;

enum {
  WQ_MIN_GRANULARITY   = 1,
  WQ_HYSTERESIS_FACTOR = 4,
} ;

/*------------------------------------------------------------------------------
 * Free given work queue item -- running any work queue 'del_item_data'
 */
static void
work_queue_item_free (struct work_queue *wq, struct work_queue_item *item)
{
  /* call private data deletion callback if needed
   */
  if (wq->spec.del_item_data != NULL)
    wq->spec.del_item_data (wq, item) ;

  XFREE (MTYPE_WORK_QUEUE_ITEM, item) ;
  return;
}

/*------------------------------------------------------------------------------
 * create a new work queue, of given name.
 *
 * user must fill in the 'spec' of the returned work queue before adding
 * anything to it
 */
extern struct work_queue *
work_queue_new (struct thread_master *m, const char *queue_name)
{
  struct work_queue *new;

  new = XCALLOC (MTYPE_WORK_QUEUE, sizeof(work_queue_t));

  new->name   = XSTRDUP (MTYPE_WORK_QUEUE_NAME, queue_name);
  new->master = m;
  SET_FLAG (new->flags, WQ_UNPLUGGED);

  listnode_add (&work_queues, new);

  new->cycles.granularity = WQ_MIN_GRANULARITY;

  /* Default values, can be overridden by caller
   */
  new->spec.hold = WORK_QUEUE_DEFAULT_HOLD;

  return new;
}

/*------------------------------------------------------------------------------
 * destroy work queue
 *
 * Runs work_queue_item_free() across entire queue.
 */
extern void
work_queue_free (struct work_queue *wq)
{
  work_queue_item item ;

  if (wq->thread != NULL)
    thread_cancel(wq->thread);

  while ((item = wq->head) != NULL)
    {
      wq->head = item->next ;
      work_queue_item_free(wq, item) ;
    } ;

  XFREE (MTYPE_WORK_QUEUE_NAME, wq->name);
  XFREE (MTYPE_WORK_QUEUE, wq);
  return;
}

/*------------------------------------------------------------------------------
 * if appropriate, schedule work queue thread
 */
static int
work_queue_schedule (struct work_queue *wq, unsigned int delay)
{
  if ( CHECK_FLAG (wq->flags, WQ_UNPLUGGED)
       && (wq->thread == NULL)
       && (wq->head != NULL) )
    {
      wq->thread = thread_add_background (wq->master, work_queue_run,
                                          wq, delay);
      return 1;
    }
  else
    return 0;
}

/*------------------------------------------------------------------------------
 * Create new work queue item and place on the end of the given work queue.
 *
 * Schedules the work queue if there were no items (unless already scheduled
 * or plugged).
 *
 * Returns:  the address of the new item
 */
extern work_queue_item
work_queue_item_add (struct work_queue *wq)
{
  work_queue_item item ;

  assert (wq);

  item = XCALLOC (MTYPE_WORK_QUEUE_ITEM, sizeof (struct work_queue_item));

  item->next = NULL ;
  if (wq->head == NULL)
    {
      assert(wq->list_count == 0) ;
      wq->head = item ;
      item->prev = NULL ;
    }
  else
    {
      assert((wq->tail != NULL) && (wq->list_count > 0)) ;
      wq->tail->next = item ;
      item->prev = wq->tail ;
    } ;
  wq->tail = item ;

  wq->list_count += 1 ;
  work_queue_schedule (wq, wq->spec.hold);

  return item ;
}

/*------------------------------------------------------------------------------
 * Remove given work queue item from the given work queue, and free the item.
 *
 * Returns:  the address of item after the removed one (if any)
 */
static work_queue_item
work_queue_item_remove (work_queue wq, work_queue_item item)
{
  work_queue_item next ;

  assert ((wq != NULL) && (item != NULL)) ;

  next = item->next ;

  if (wq->head == item)
    {
      /* Removing the first item
       */
      assert(item->prev == NULL) ;

      wq->head = next ;

      if (wq->tail == item)
        {
          /* Removing the only item
           */
          assert((next == NULL) && (wq->list_count == 1)) ;
          wq->tail = NULL ;
        }
      else
        {
          /* First, but not the only item
           */
          assert((next != NULL) && (wq->list_count > 1)) ;
          wq->head->prev = NULL ;
        } ;
    }
  else if (wq->tail == item)
    {
      /* Removing last, but not only item
       */
      assert(next == NULL) ;
      assert((item->prev != NULL) && (wq->list_count > 1)) ;

      wq->tail = item->prev ;
      wq->tail->next = NULL ;
    }
  else
    {
      /* Removing from somewhere in middle
       */
      assert(next != NULL) ;
      assert((item->prev != NULL) && (wq->list_count > 2)) ;

      item->prev->next = next ;
      item->next->prev = item->prev ;
    } ;

  wq->list_count -= 1 ;
  work_queue_item_free (wq, item);

  return next ;
}

/*------------------------------------------------------------------------------
 * Requeue given work queue item at the end of the given work queue
 *
 * Returns:  the address of the next item to process
 *
 * Note that the next item to process will be the given item, if it is the last
 * on the queue.
 */
static work_queue_item
work_queue_item_requeue (work_queue wq, work_queue_item item)
{
  work_queue_item next ;
  work_queue_item last ;

  next = item->next ;
  last = wq->tail ;

  assert(last != NULL) ;

  if (last == item)
    {
      /* Requeuing last item -- easy !
       */
      assert(next == NULL) ;
      return item ;
    } ;

  assert(next != NULL) ;

  if (wq->head == item)
    {
      /* Requeuing first, but not only item
       */
      assert(item->prev == NULL) ;

      wq->head    = next ;
      next->prev  = NULL ;
    }
  else
    {
      /* Requeuing something in middle
       */
      work_queue_item prev ;

      prev = item->prev ;

      assert(prev != NULL) ;

      prev->next  = next ;
      next->prev  = prev ;
    } ;

  item->next   = NULL ;
  item->prev   = last ;

  last->next   = item ;
  wq->tail     = item ;

  return next ;
} ;

/*------------------------------------------------------------------------------
 * 'plug' a queue: Stop it from being scheduled,
 * ie: prevent the queue from draining.
 */
extern void
work_queue_plug (work_queue wq)
{
  if (wq->thread)
    thread_cancel (wq->thread);

  wq->thread = NULL;

  UNSET_FLAG (wq->flags, WQ_UNPLUGGED);
}

/*------------------------------------------------------------------------------
 * unplug queue, schedule it again, if appropriate
 * Ie: Allow the queue to be drained again
 */
extern void
work_queue_unplug (work_queue wq)
{
  SET_FLAG (wq->flags, WQ_UNPLUGGED);

  /* if thread isnt already waiting, add one
   */
  work_queue_schedule (wq, wq->spec.hold);
}

/*------------------------------------------------------------------------------
 * Thread function: process the work queue and reschedule if required.
 *
 * Runs the first item in the work queue,
 *
 *
 * Returns: 0
 */
extern int
work_queue_run (struct thread *thread)
{
  work_queue      wq;
  work_queue_item item ;
  wq_item_status  ret;
  uint cycles ;
  bool yielded ;

  wq = THREAD_ARG (thread);
  wq->thread = NULL;

  assert (wq != NULL) ;

  /* calculate cycle granularity:
   * list iteration == 1 cycle
   * granularity == # cycles between checks whether we should yield.
   *
   * granularity should be > 0, and can increase slowly after each run to
   * provide some hysteris, but not past cycles.best or 2*cycles.
   *
   * Best: starts low, can only increase
   *
   * Granularity: starts at WQ_MIN_GRANULARITY, can be decreased
   *              if we run to end of time slot, can increase otherwise
   *              by a small factor.
   *
   * We could use just the average and save some work, however we want to be
   * able to adjust quickly to CPU pressure. Average wont shift much if
   * daemon has been running a long time.
   */
  if (wq->cycles.granularity == 0)
    wq->cycles.granularity = WQ_MIN_GRANULARITY;

  cycles  = 0 ;
  yielded = false ;

  item = wq->head ;
  while (item != NULL)
  {
    /* run and take care of items that want to be retried immediately
     *
     * Note that we check for maximum retry exceeded at the top of the loop,
     * which picks up WQ_RETRY_LATER which
     */
    while (1)
      {
        if (item->ran > wq->spec.max_retries)
          {
            ret = WQ_ERROR ;
            break ;
          } ;

        ret = wq->spec.workfunc (wq, item) ;

        if (ret != WQ_RETRY_NOW)
          break ;

        item->ran += 1 ;
      } ;

    switch (ret)
      {
        case WQ_QUEUE_BLOCKED:
          goto stats ;

        case WQ_RETRY_LATER:
          item->ran += 1 ;
          goto stats;

        case WQ_REQUEUE:
          item = work_queue_item_requeue (wq, item);
          cycles += 1 ;
          break;

        case WQ_RETRY_NOW:
          /* a RETRY_NOW that gets here has exceeded max_tries, same as ERROR
           */
        case WQ_ERROR:
          if (wq->spec.errorfunc != NULL)
            wq->spec.errorfunc (wq, item);

          fall_through ;

        case WQ_SUCCESS:
        default:
          item = work_queue_item_remove (wq, item);
          cycles += 1 ;
          break;
      } ;

    /* test if we should yield
     */
    if ( ((cycles % wq->cycles.granularity) == 0)
                                                && thread_should_yield (thread))
      {
        yielded = true;
        break ;
      }
  } ;

stats:

  if (yielded && (cycles < wq->cycles.granularity))
    {
      /* we yielded, check whether granularity should be reduced
       */
      wq->cycles.granularity = ((cycles > 0) ? cycles
                                             : WQ_MIN_GRANULARITY);
    }
  else if (cycles >= (wq->cycles.granularity))
    {
      /* otherwise, should granularity increase?
       */
      if (cycles > wq->cycles.best)
        wq->cycles.best = cycles;

      /* along with yielded check, provides hysteresis for granularity
       */
      if (cycles > (wq->cycles.granularity * WQ_HYSTERESIS_FACTOR
                                           * WQ_HYSTERESIS_FACTOR))
        wq->cycles.granularity *= WQ_HYSTERESIS_FACTOR; /* quick ramp-up */
      else if (cycles > (wq->cycles.granularity * WQ_HYSTERESIS_FACTOR))
        wq->cycles.granularity += WQ_HYSTERESIS_FACTOR;
    }

  wq->runs++;
  wq->cycles.total += cycles;

#if 0
  printf ("%s: cycles %d, new: best %d, worst %d\n",
            __func__, cycles, wq->cycles.best, wq->cycles.granularity);
#endif

  /* Is the queue done yet?   If it is, call the completion callback.
   */
  if (wq->head != NULL)
    work_queue_schedule (wq, 0);
  else if (wq->spec.completion_func)
    wq->spec.completion_func (wq);

  return 0;
}

/*------------------------------------------------------------------------------
 * Reporting command(s)
 */
DEFUN(show_work_queues,
      show_work_queues_cmd,
      "show work-queues",
      SHOW_STR
      "Work Queue information\n")
{
  struct listnode *node;
  struct work_queue *wq;

  vty_out (vty,
           "%c %8s %5s %8s %21s%s",
           ' ', "List","(ms) ","Q. Runs","Cycle Counts   ",
           VTY_NEWLINE);
  vty_out (vty,
           "%c %8s %5s %8s %7s %6s %6s %s%s",
           'P',
           "Items",
           "Hold",
           "Total",
           "Best","Gran.","Avg.",
           "Name",
           VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS_RO ((&work_queues), node, wq))
    {
      vty_out (vty,"%c %8d %5d %8ld %7d %6d %6u %s%s",
               (CHECK_FLAG (wq->flags, WQ_UNPLUGGED) ? ' ' : 'P'),
               wq->list_count,
               wq->spec.hold,
               wq->runs,
               wq->cycles.best, wq->cycles.granularity,
                 (wq->runs) ?
                   (unsigned int) (wq->cycles.total / wq->runs) : 0,
               wq->name,
               VTY_NEWLINE);
    }

  return CMD_SUCCESS;
} ;

CMD_INSTALL_TABLE(extern, workqueue_cmd_table, ALL_RDS) =
{
  { RESTRICTED_NODE, &show_work_queues_cmd                              },
  { VIEW_NODE,       &show_work_queues_cmd                              },
  { ENABLE_NODE,     &show_work_queues_cmd                              },

  CMD_INSTALL_END
} ;
