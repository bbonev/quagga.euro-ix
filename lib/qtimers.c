/* Quagga timers support -- functions
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
#include "misc.h"

#include "qtimers.h"
#include "memory.h"
#include "heap.h"
#include "log.h"

/*==============================================================================
 * Quagga Timers -- qtimer_xxxx
 *
 * Here and in qtimers.h is a data structure for managing multiple timers
 * each with an action to be executed when the timer expires.
 *
 * The qtime_pile structure manages a "pile" of qtimer structures which are
 * waiting for the right time to go off.
 *
 * NB: it is ASSUMED that a qtime_pile will be private to the thread in which
 *     it is created and used.
 *
 *     There is NO mutex handling here.
 *
 * Timers are triggered by calling qtimer_dispatch_next().  This is given the
 * current qtimer time (see below), and it dispatches the first timer whose
 * time has come (or been passed).  Dispatching a timer means calling its
 * action function (see below).  Each call of qtimer_dispatch_next() triggers
 * at most one timer.
 *
 * Time Base
 * ---------
 *
 * The time base for qtimers is the monotonic time provided in qtime.c/.h.
 *
 * Interval
 * --------
 *
 * There is an optional interval associated with each timer.
 *
 * The timer may be set to "now + interval", and the interval is stored with
 * the timer.
 *
 * The timer may be set to its current time + stored interval (to provide a
 * "steady" clock).
 *
 * Action Functions
 * ----------------
 *
 * There is a separate action function for each timer.
 *
 * When the action function is called it is passed the qtimer structure, the
 * timer_info pointer from that structure and the time which triggered the
 * timer (which may, or may not, be the current qtimer time).
 *
 * During an action function timers may be set/unset, actions changed, and so
 * on... there are no restrictions EXCEPT that may NOT recurse into the
 * dispatch function.
 *
 * If nothing is done with the time during the action function, the timer is
 * implicitly unset when the action function returns.
 */

static int
qtimer_cmp(qtimer* a, qtimer* b)        /* the heap discipline  */
{
  if ((**a).time < (**b).time)
    return -1 ;
  if ((**a).time > (**b).time)
    return +1 ;
  return 0 ;
} ;

/*==============================================================================
 * qtimer_pile handling
 */

/*------------------------------------------------------------------------------
 * Initialise a timer pile -- allocating it if required.
 *
 * Returns the qtimer_pile.
 */
qtimer_pile
qtimer_pile_init_new(qtimer_pile qtp)
{
  if (qtp == NULL)
    qtp = XCALLOC(MTYPE_QTIMER_PILE, sizeof(struct qtimer_pile)) ;
  else
    memset(qtp, 0, sizeof(struct qtimer_pile)) ;

  /* Zeroising has initialised:
   *
   *   timers        -- invalid heap -- need to properly initialise
   *
   *   name          -- empty '\0' terminated name
   */

  /* (The typedef is required to stop Eclipse (3.4.2 with CDT 5.0) whining
   *  about first argument of offsetof().)
   */
  typedef struct qtimer qtimer_t ;

  heap_init_new_backlinked(&qtp->timers, 0, (heap_cmp*)qtimer_cmp,
                                                 offsetof(qtimer_t, backlink)) ;
  return qtp ;
} ;

/*------------------------------------------------------------------------------
 * Set name of given qtimer pile -- name field is fixed length
 */
extern void
qtimer_pile_set_name(qtimer_pile qtp, const char* name)
{
  uint l ;

  l = strlen(name) ;
  if (l >= sizeof(qtp->name))
    l = sizeof(qtp->name) - 1 ;

  strncpy(qtp->name, name, l) ;
} ;

/*------------------------------------------------------------------------------
 * Get the timer time for the first timer due to go off in the given pile.
 *
 * The caller must provide a maximum acceptable time.  If the qtimer pile is
 * empty, or the top entry times out after the maximum time, then the maximum
 * is returned.
 *
 * NB: returns a time *interval*, which may be -ve !
 */
extern qtime_t
qtimer_pile_top_wait(qtimer_pile qtp, qtime_t max_wait, qtime_t now)
{
  qtimer  qtr ;

  qtr = heap_top_item(&qtp->timers) ;

  if (qtr == NULL)
    {
      if ((qtimers_debug > 1) && (qtp->name[0] != '\0'))
        {
          qtime_mono_t actual = qt_get_monotonic() ;

          zlog_debug("%s(%s) @ %ld: pile empty, now=%+ld, max_wait=%ld",
                       __func__, qtp->name, (long)actual, (long)(now - actual),
                                                                     max_wait) ;
        } ;
    }
  else
    {
      qtime_t top_wait ;

      top_wait = qtr->time - now ;

      if ((qtimers_debug > 1) && (qtp->name[0] != '\0'))
        {
          qtime_mono_t actual = qt_get_monotonic() ;

          zlog_debug("%s(%s) @ %ld: now=%+ld, '%s'=%+ld, max_wait=%+ld",
                       __func__, qtp->name, (long)actual, (long)(now - actual),
                                                qtr->name, top_wait, max_wait) ;
        } ;

      if (top_wait < max_wait)
        max_wait = top_wait ;
    } ;

  return max_wait ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch the next timer whose time is <= the given "upto" time.
 *
 * The upto time must be a qtimer time (!) -- see qtimer_time_now().
 *
 * The upto argument allows the caller to get a qtimer_time_now() value, and
 * then process all timers upto that time.
 *
 * Returns true  <=> dispatched a timer, and there may be more to do.
 *         false <=> nothing to do (and nothing done).
 *
 * NB: it is a sad, very sad, mistake to recurse into this !
 */
extern bool
qtimer_pile_dispatch_next(qtimer_pile qtp, qtime_mono_t upto)
{
  qtimer   qtr ;
  qtr_state_t state ;

  if (qtimers_debug)
    qtimer_pile_verify(qtp) ;

  qtr = heap_top_item(&qtp->timers) ;

  if (qtr == NULL)
    return false ;

  passert((qtp == qtr->pile) && (qtr->state == qtrs_active)) ;

  if (qtr->time > upto)
    {
      if ((qtimers_debug > 1) && (qtr->name[0] != '\0'))
        {
          qtime_mono_t actual = qt_get_monotonic() ;

          zlog_debug("%s(%s) @ %ld: '%s' time %+ld > upto=%+ld -- Stop",
                                      __func__, qtr->pile->name, (long)actual,
                                        qtr->name, (long)(qtr->time - actual),
                                                        (long)(upto - actual)) ;
        } ;

      return false ;
    } ;

  if ((qtimers_debug > 1) && (qtr->name[0] != '\0'))
    {
      qtime_mono_t actual = qt_get_monotonic() ;

      zlog_debug("%s(%s) @ %ld: '%s' time %+ld <= upto=%+ld -- Dispatched",
                                     __func__, qtr->pile->name, (long)actual,
                                        qtr->name, (long)(qtr->time - actual),
                                                        (long)(upto - actual)) ;
    } ;

  qtr->state = qtrs_dispatch | qtrs_unset_pending | qtrs_active ;
                                /* Timer must be unset if is still here
                                   when the action function returns     */
  qtr->action(qtr, qtr->timer_info, upto) ;

  state = qtr->state ;
  qtr->state &= qtrs_active ;   /* No longer in dispatch                */

  confirm((qtrs_active != 0) && (qtrs_inactive == 0)) ;

  if      ((state & qtrs_free_pending) != 0)
    qtimer_free(qtr) ;
  else if ((state & qtrs_unset_pending) != 0)
    qtimer_unset(qtr) ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Ream out (another) item from qtimer_pile.
 *
 * If pile is empty, release the qtimer_pile structure, if required.
 *
 * Useful for emptying out and discarding a pile of timers:
 *
 *     while ((p_qtr = qtimer_pile_ream_free(qtp)))
 *       ... do what's required to release the item p_qtr
 *
 * Each qtr is set "inactive", so no longer in the pile.  The if the caller
 * is able to release the qtr, then it should do so, otherwise it can be left
 * for the owner to release (which they can do without reference to the pile,
 * which may by then have been released).
 *
 * Returns NULL when timer pile is empty (and has been released, if required).
 *
 * If the timer pile is not released, it may be reused without reinitialisation,
 * and any qtr not freed may also be reused.
 *
 * NB: once reaming has started, the timer pile MUST NOT be used for anything,
 *     and the process MUST be run to completion.
 */
extern qtimer
qtimer_pile_ream(qtimer_pile qtp, free_keep_b free_structure)
{
  qtimer qtr ;
  confirm(free_it == true) ;

  qtr = heap_ream(&qtp->timers, keep_it) ; /* ream, keeping the heap    */

  if (qtr != NULL)
    {
      qtr->state = qtrs_inactive ;      /* has been removed from pile   */
      if (free_structure)
        qtr->pile = NULL ;              /* no longer usable             */
    }
  else
    {
      if (free_structure)               /* pile is empty, may now free it */
        XFREE(MTYPE_QTIMER_PILE, qtp) ;
    } ;

  return qtr ;
} ;

/*==============================================================================
 * qtimer handling
 */

/*------------------------------------------------------------------------------
 * Initialise qtimer structure -- allocating one if required.
 *
 * Associates qtimer with the given pile of timers, and sets up the action and
 * the timer_info.
 *
 * Once initialised, the timer may be set.
 *
 * Returns the qtimer.
 */
extern qtimer
qtimer_init_new(qtimer qtr, qtimer_pile qtp,
                                        qtimer_action* action, void* timer_info)
{
  if (qtr == NULL)
    qtr = XCALLOC(MTYPE_QTIMER, sizeof(struct qtimer)) ;
  else
    memset(qtr, 0, sizeof(struct qtimer)) ;

  /* Zeroising has initialised:
   *
   *   pile        -- NULL -- not in any pile (yet)
   *   backlink    -- unset
   *
   *   state       -- qtrs_inactive
   *
   *   time        -- unset
   *   action      -- NULL -- no action set (yet)
   *   timer_info  -- NULL -- no timer info set (yet)
   *
   *   interval    -- unset
   *
   *   name        -- empty '\0' terminated string
   */
  confirm(qtrs_inactive == 0) ;

  qtr->pile       = qtp ;
  qtr->action     = action ;
  qtr->timer_info = timer_info ;

  return qtr ;
} ;

/*------------------------------------------------------------------------------
 * Set name of given qtimer -- name field is fixed length
 */
extern void
qtimer_set_name(qtimer qtr, const char* name)
{
  uint l ;

  l = strlen(name) ;
  if (l >= sizeof(qtr->name))
    l = sizeof(qtr->name) - 1 ;

  strncpy(qtr->name, name, l) ;
} ;

/*------------------------------------------------------------------------------
 * Free given timer -- if any.
 *
 * Unsets it first if it is active.
 *
 * Returns: NULL
 *
 * Note: if this is currently a dispatched timer, then does not actually free,
 *       but leaves that for the dispatch loop to tidy up.  The caller is
 *       expected to assume that the timer has gone, gone.
 */
extern qtimer
qtimer_free(qtimer qtr)
{
  /* Note that if is the current dispatched timer and an unset is still
   * pending, then it must still be active.
   */
  if (qtr != NULL)
    {
      if ((qtr->state & qtrs_active) != 0)
        qtimer_unset(qtr) ;

      if ((qtr->state & qtrs_dispatch) == 0)
        XFREE(MTYPE_QTIMER, qtr) ;
      else
        qtr->state = qtrs_dispatch | qtrs_free_pending ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set pile in which given timer belongs.
 *
 * Does nothing if timer already belongs to the given pile.
 *
 * Unsets the timer if active in another pile, before reassigning it.
 */
extern void
qtimer_set_pile(qtimer qtr, qtimer_pile qtp)
{
  if (qtr->pile == qtp)
    return ;

  /* Note that if is the current dispatched timer and an unset is still
   * pending, then it must still be active.
   */
  if ((qtr->state & qtrs_active) != 0)
    qtimer_unset(qtr) ;

  qtr->pile = qtp ;
}

/*------------------------------------------------------------------------------
 * Set given timer.
 *
 * Setting a -ve time => qtimer_unset.
 *
 * Sets any given action -- if the action given is NULL, retains previously set
 * action.
 *
 * If the timer is already active, sets the new time & updates pile.  If is the
 * dispatched timer, and was pending being unset, then no longer needs to be
 * unset.
 *
 * Otherwise, sets the time and adds to pile -- making timer active.
 *
 * It is an error to set a timer which has a NULL action.
 */
extern void
qtimer_set(qtimer qtr, qtime_mono_t when, qtimer_action* action)
{
  qtimer_pile qtp ;

  qtp = qtr->pile ;
  assert(qtp != NULL) ;

  if ((qtimers_debug > 1) && (qtr->name[0] != '\0'))
    {
      qtime_mono_t actual = qt_get_monotonic() ;

      zlog_debug("%s(%s) @ %ld: '%s' for %+ld",
                                  __func__, qtp->name, (long)actual,
                                            qtr->name, (long)(when - actual)) ;
    }
  confirm(sizeof(long) > 4) ;

  if (when < 0)
    return qtimer_unset(qtr) ;

  if (qtimers_debug)
    qtimer_pile_verify(qtp) ;

  qtr->time = when ;

  if ((qtr->state & qtrs_active) != 0)
    {
      /* Is active, so update the timer in the pile.
       */
      heap_update_item(&qtp->timers, qtr) ;

      qtr->state &= ~qtrs_unset_pending ;   /* no unset required, now   */
    }
  else
    {
      /* Is not active, so insert the timer into the pile.
       */
      heap_push_item(&qtp->timers, qtr) ;

      qtr->state |= qtrs_active ;
    } ;

  if (action != NULL)
    qtr->action = action ;
  else
    assert(qtr->action != NULL) ;

  if (qtimers_debug)
    qtimer_pile_verify(qtp) ;

  if (qdebug)
    assert( (qtr->state ==  qtrs_active) ||
            (qtr->state == (qtrs_active | qtrs_dispatch)) ) ;
} ;

/*------------------------------------------------------------------------------
 * Unset given timer
 *
 * If the timer is active, removes from pile and sets inactive.
 *
 * If timer is pending being unset (because is the dispatched timer), then this
 * does the unset (early) and the unset pending state is cleared.
 */
extern void
qtimer_unset(qtimer qtr)
{
  if ((qtimers_debug > 1) && (qtr->name[0] != '\0'))
    {
      const char*  unset ;
      qtime_mono_t when ;
      qtime_mono_t actual = qt_get_monotonic() ;

      if (qtr->state & qtrs_active)
        {
          when  = qtr->time - actual ;
          unset = "" ;
        }
      else
        {
          when  = 0 ;
          unset = "unset=" ;
        } ;

      zlog_debug("%s(%s) @ %ld: '%s' for %s%+ld",
                            __func__, qtr->pile->name, (long)actual,
                                                 qtr->name, unset, (long)when) ;
      confirm(sizeof(long) > 4) ;
    } ;

  if ((qtr->state & qtrs_active) != 0)
    {
      qtimer_pile qtp = qtr->pile ;

      assert(qtp != NULL) ;

      if (qtimers_debug)
        qtimer_pile_verify(qtp) ;

      heap_delete_item(&qtp->timers, qtr) ;

      qtr->state &= ~(qtrs_unset_pending | qtrs_active);
                                  /* not active, no unset required, now   */
      if (qtimers_debug)
        qtimer_pile_verify(qtp) ;
    } ;

  qassert( (qtr->state ==  qtrs_inactive) ||
           (qtr->state == (qtrs_inactive | qtrs_dispatch)) ) ;
} ;

/*==============================================================================
 * Verification code for debug purposes.
 */
static void qtimer_pile_assert_fail(qtimer_pile qtp, qtimer qtr,
                                        vector_index_t iq, const char* failed) ;
extern void
qtimer_pile_verify(qtimer_pile qtp)
{
  heap   th = &qtp->timers ;
  vector v ;
  vector_index_t  i ;
  vector_length_t e ;
  qtimer qtr ;
  bool seen_dispatch ;

  assert(qtp != NULL) ;

#define qtimer_assert(assertion) \
  if (!(assertion)) qtimer_pile_assert_fail(qtp, qtr, i, #assertion)

  qtp->ok = true ;

  /* (The typedef is required to stop Eclipse (3.4.2 with CDT 5.0) whining
   *  about first argument of offsetof().)
   */
  typedef struct qtimer qtimer_t ;

  assert(th->cmp             == (heap_cmp*)qtimer_cmp) ;
  assert(th->state           == Heap_Has_Backlink) ;
  assert(th->backlink_offset == offsetof(qtimer_t, backlink)) ;

  v = th->v ;
  e = vector_end(v) ;
  seen_dispatch = false ;
  for (i = 0 ; i < e ; ++i)
    {
      qtr = vector_get_item(v, i) ;

      if (qtr == NULL)
        {
          qtimer_assert(qtr != NULL) ;
          continue ;
        }

      if (qtr->state != qtrs_active)
        {
          uint valid_state ;

          valid_state = qtr->state & (qtrs_active | qtrs_dispatch
                                                  | qtrs_unset_pending) ;

          if (qtr->state & qtrs_dispatch)
            {
              qtimer_assert(!seen_dispatch) ;
              seen_dispatch = true ;
           } ;

          qtimer_assert(qtr->state == valid_state) ;
        } ;

      qtimer_assert(qtr->pile     == qtp) ;
      qtimer_assert(qtr->backlink == i) ;
      qtimer_assert(qtr->action   != NULL) ;

      if (i != 0)
        {
          qtimer qtr_p ;

          qtr_p = vector_get_item(v, (i - 1) / 2) ;

          qtimer_assert(qtr_p->time <= qtr->time) ;
        } ;
    } ;

  assert(qtp->ok) ;
} ;

/*------------------------------------------------------------------------------
 * Report a qtimer_pile verification error.
 *
 * On the first failure, dump the entire pile.
 *
 * For all failures, output the assertion failure message.
 */
static void
qtimer_pile_assert_fail(qtimer_pile qtp, qtimer qtr, vector_index_t iq,
                                                             const char* failed)
{
  if (qtp->ok)
    {
      vector v ;
      vector_index_t  i ;
      vector_length_t e ;

      qtp->ok = false ;

      v = qtp->timers.v ;
      e = vector_end(v) ;

      zlog_err("*** qtimer_pile failure in pile '%s' @ %p with %d entries",
                                                            qtp->name, qtp, e) ;
      for (i = 0 ; i < e ; ++i)
        {
          qtimer qtr ;

          qtr = vector_get_item(v, i) ;

          if (qtr == NULL)
            {
              zlog_err("***%5u: NULL entry", (uint)i) ;
              continue ;
            } ;

          zlog_err("***%5u: %p(%u) '%s' st=%0X t=%ld i=%ld (p=%p)",
              (uint)i, qtr, (uint)(qtr->backlink), qtr->name, (uint)qtr->state,
              (long)(qtr->time), (long)(qtr->interval), qtr->pile) ;
        } ;
    } ;

  zlog_err("*** (%s) is not true for entry %u", failed, iq) ;
} ;
