/* Quagga Pthreads support -- header
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include <stdbool.h>

#include "qpnexus.h"
#include "memory.h"
#include "thread.h"
#include "sigevent.h"

/* prototypes */
static void* qpn_start(void* arg);
static void qpn_in_thread_init(qpn_nexus qpn);

/*==============================================================================
 * Quagga Nexus Interface -- qpn_xxxx
 *

 */

/*==============================================================================
 * Initialisation, add hook, free etc.
 *
 */

/*------------------------------------------------------------------------------
 * Initialise a nexus -- allocating it if required.
 *
 * If main_thread is set then no new thread will be created
 * when qpn_exec() is called, instead the finite state machine will be
 * run in the calling thread.  The main thread will only block the
 * message queue's signal.  Non-main threads will block most signals.
 *
 * Returns the qpn_nexus.
 */
extern qpn_nexus
qpn_init_new(qpn_nexus qpn, bool main_thread, const char* name)
{
  if (qpn == NULL)
    qpn = XCALLOC(MTYPE_QPN_NEXUS, sizeof(struct qpn_nexus)) ;
  else
    memset(qpn, 0,  sizeof(struct qpn_nexus)) ;

  qpn->name        = name ;

  qpn->selection   = qps_selection_init_new(qpn->selection);
  qpn->pile        = qtimer_pile_init_new(qpn->pile);
  qpn->queue       = mqueue_init_new(qpn->queue, mqt_signal_unicast);
  qpn->main_thread = main_thread;
  qpn->start       = qpn_start;

  qpt_spin_init(qpn->stats_slk) ;

  if (main_thread)
    qpn->thread_id = qpt_thread_self();

  return qpn;
}

/*------------------------------------------------------------------------------
 * Add a hook function to the given nexus.
 */
extern void
qpn_add_hook_function(qpn_hook_list list, void* hook)
{
  passert(list->count < qpn_hooks_max) ;
  list->hooks[list->count++] = hook ;
} ;

/*------------------------------------------------------------------------------
 * Reset given nexus and, if required, free the nexus structure.
 *
 * Free timers, selection, message queue and its thread signal.
 *
 * Leaves all pointers to these things NULL -- which generally means that the
 * object is empty or otherwise out of action.
 */
extern qpn_nexus
qpn_reset(qpn_nexus qpn, bool free_structure)
{
  qps_file qf;
  qtimer qtr;

  if (qpn == NULL)
    return NULL;

  /* timers and the pile */
  if (qpn->pile != NULL)
    {
      while ((qtr = qtimer_pile_ream(qpn->pile, 1)))
          qtimer_free(qtr);
      qpn->pile = NULL ;
    }

  /* files and selection */
  if (qpn->selection != NULL)
    {
      while ((qf = qps_selection_ream(qpn->selection, 1)))
          qps_file_free(qf);
      qpn->selection = NULL ;
    }

  if (qpn->queue != NULL)
    qpn->queue = mqueue_reset(qpn->queue, 1);

  if (qpn->mts != NULL)
    qpn->mts = mqueue_thread_signal_reset(qpn->mts, 1);

  if (free_structure)
    XFREE(MTYPE_QPN_NEXUS, qpn) ;       /* sets qpn = NULL      */

  return qpn ;
} ;

/*==============================================================================
 * Execution of a nexus
 */

/*------------------------------------------------------------------------------
 * If not main qpthread create new qpthread.
 *
 * For all qpthreads: start the thread !
 */
extern void
qpn_exec(qpn_nexus qpn)
{
  if (qpn->main_thread)
    qpn->start(qpn);
  else
    qpt_thread_create(qpn->start, qpn, NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Pthread routine
 *
 * Processes:
 *
 *   1) Main thread only -- signals.
 *
 *   2) High priority pending work -- event hooks.
 *
 *   3) Messages coming from other pthreads -- mqueue_queue.
 *
 *   4) All priority pending work -- event hooks.
 *
 *   5) I/O -- qpselect
 *
 *      This deals with all active sockets for read/write/connect/accept.
 *
 *      Each time a socket is readable, one message is read and dispatched.
 *      The pselect timeout is set to be when the next timer is due.
 *
 *   6) Timers -- qtimers
 *
 *   7) Low priority pending work
 */
static void*
qpn_start(void* arg)
{
  qpn_nexus qpn = arg;
  mqueue_block mqb;
  int actions;
  qtime_mono_t now ;
  qtime_t      max_wait ;
  unsigned i;
  unsigned done ;
  unsigned prev ;
  bool     wait ;

  /* now in our thread, complete initialisation                         */
  qpn_in_thread_init(qpn);

  /* custom in-thread initialization                                    */
  for (i = 0; i < qpn->in_thread_init.count ;)
    ((qpn_init_function*)(qpn->in_thread_init.hooks[i++]))() ;

  /* Until required to terminate, loop                                  */
  prev = 1 ;
  done = 1 ;
  while (!qpn->terminate)
    {
      ++qpn->raw.cycles ;

      /* Signals are highest priority -- only execute for main thread   */
      if (qpn->main_thread)
        {
          int ret = quagga_sigevent_process() ;
          if (ret != 0)
            {
              ++done ;                  /* count each signal            */
              ++qpn->raw.signals ;
            } ;
        } ;

      /* Foreground hooks, if any.                                      */
      for (i = 0; i < qpn->foreground.count ; ++i)
        {
          int ret = ((qpn_hook_function*)(qpn->foreground.hooks[i]))() ;
          if (ret != 0)
            {
              ++done ;                  /* count each foreground action */
              ++qpn->raw.foreg ;
            } ;
        } ;

      /* take stuff from the message queue
       *
       * If nothing done this time and last time around the loop then will
       * arrange to wait iff the queue is empty first time through.
       */
      wait = ((prev == 0) && (done == 0)) ;
      do
        {
          mqb = mqueue_dequeue(qpn->queue, wait, qpn->mts) ;
          if (mqb == NULL)
            break;

          mqb_dispatch(mqb, mqb_action);

          wait = false ;
          ++done ;
        } while (done < 200) ;

      qpn->raw.dispatch += done ;

      /* block for some input, output, signal or timeout
       *
       * wait will be true iff found nothing to do this and last time round the
       * loop.
       */
      now = qt_get_monotonic() ;

      if (wait)
        max_wait = qtimer_pile_top_wait(qpn->pile, QTIME(MAX_PSELECT_WAIT),
                                                                          now) ;
      else
        max_wait = 0 ;

      /* We are about to do a pselect, which may wait.  Now is the time to
       * set the "raw" current time, and publish the stats.
       */
      qpn->raw.last_time = now ;

      qpt_spin_lock(qpn->stats_slk) ;
      qpn->stats = qpn->raw ;
      qpt_spin_unlock(qpn->stats_slk) ;

      /* Do pselect, which may now wait
       *
       * After pselect, if is "wait", then will have set the message queue
       * waiting, which can now be cleared.  Also, any time since
       * "raw.last_time" must be counted as idle time.
       *
       * Remember current "done" as "prev", and set done 0 or 1, depending on
       * I/O action count -- processing I/O actions and/or timers is counted as
       * a single activity.
       */
      do
        actions = qps_pselect(qpn->selection, max_wait) ;
      while (actions < 0) ;

      now = qt_get_monotonic() ;

      if (wait)
        {
          qpn->raw.idle += now - qpn->raw.last_time ;

          mqueue_done_waiting(qpn->queue, qpn->mts) ;
        } ;

      prev = done ;
      done = (actions != 0) ? 1 : 0 ;
      qpn->raw.io_acts += actions ;

      while (actions)
        actions = qps_dispatch_next(qpn->selection) ;

      /* process timers -- also counts as one activity
       */
      while (qtimer_pile_dispatch_next(qpn->pile, now))
        {
          ++qpn->raw.timers ;
          done = 1 ;                    /* Done something in this pass  */
        } ;

      /* If nothing done so far in this pass, and nothing in the previous,
       * see if anything in the background
       */
      if ((prev == 0) && (done == 0))
        {
          for (i = 0; i < qpn->background.count ; ++i)
            {
              int ret = ((qpn_hook_function*)(qpn->background.hooks[i]))() ;
              if (ret != 0)
                {
                  ++done ;
                  ++qpn->raw.backg ;
                } ;
            } ;
        } ;
    } ;

  /* custom in-thread finalization                                      */
  for (i = qpn->in_thread_final.count; i > 0 ;)
    ((qpn_init_function*)(qpn->in_thread_final.hooks[--i]))() ;

  return NULL;
}

/*------------------------------------------------------------------------------
 * Now running in our thread, do common initialisation
 */
static void
qpn_in_thread_init(qpn_nexus qpn)
{
  sigset_t newmask;

  memset(&qpn->raw, 0, sizeof(qpn_stats_t)) ;
  qpn->raw.start_time = qt_get_monotonic() ;
  qpn->raw.last_time  = qpn->raw.start_time ;

  qpt_spin_lock(qpn->stats_slk) ;
  qpn->prev_stats = qpn->stats = qpn->raw ;
  qpt_spin_unlock(qpn->stats_slk) ;

  qpn->thread_id = qpt_thread_self();

  if (qpn->main_thread)
    {
      /* Main thread, block the message queue's signal */
      sigemptyset (&newmask);
      sigaddset (&newmask, SIGMQUEUE);
    }
  else
    {
      /*
       * Not main thread.  Block most signals, but be careful not to
       * defer SIGTRAP because doing so breaks gdb, at least on
       * NetBSD 2.0.  Avoid asking to block SIGKILL, just because
       * we shouldn't be able to do so.  Avoid blocking SIGFPE,
       * SIGILL, SIGSEGV, SIGBUS as this is undefined by POSIX.
       * Don't block SIGPIPE so that is gets ignored on this thread.
       */
      sigfillset (&newmask);
      sigdelset (&newmask, SIGTRAP);
      sigdelset (&newmask, SIGKILL);
      sigdelset (&newmask, SIGPIPE);
      sigdelset (&newmask, SIGFPE);
      sigdelset (&newmask, SIGILL);
      sigdelset (&newmask, SIGSEGV);
      sigdelset (&newmask, SIGBUS);
    }

  if (qpthreads_enabled)
    qpt_thread_sigmask(SIG_BLOCK, &newmask, NULL);
  else
    {
      if (sigprocmask(SIG_BLOCK, &newmask, NULL) != 0)
        zabort_errno("sigprocmask failed") ;
    }

  /* Now we have thread_id and mask, prep for using message queue. */
  if (qpn->queue != NULL)
    qpn->mts = mqueue_thread_signal_init(qpn->mts, qpn->thread_id, SIGMQUEUE);
  if (qpn->selection != NULL)
    qps_set_signal(qpn->selection, SIGMQUEUE, newmask);
}

/*------------------------------------------------------------------------------
 * Ask the thread to terminate itself quickly and cleanly.
 *
 * Does nothing if terminate already set.
 */
void
qpn_terminate(qpn_nexus qpn)
{
  if (!qpn->terminate)
    {
      qpn->terminate = true ;

      /* wake up any pselect */
      if (qpthreads_enabled)
        qpt_thread_signal(qpn->thread_id, SIGMQUEUE);
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get a copy of the current stats for the given nexus.
 *
 * This copies the stats to the "prev_stats" area in the nexus.
 */
extern void
qpn_get_stats(qpn_nexus qpn, qpn_stats curr, qpn_stats prev)
{
  qpt_spin_lock(qpn->stats_slk) ;

  *prev = qpn->prev_stats ;
  *curr = qpn->stats ;

  qpn->prev_stats = qpn->stats ;

  qpt_spin_unlock(qpn->stats_slk) ;
} ;
