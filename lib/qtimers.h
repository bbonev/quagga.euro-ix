/* Quagga timers support -- header
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

#ifndef _ZEBRA_QTIMERS_H
#define _ZEBRA_QTIMERS_H

#include "misc.h"

#include "zassert.h"
#include "qtime.h"
#include "heap.h"

/*==============================================================================
 * Quagga Timers -- qtimer_xxxx
 *
 * Here and in qtimers.c is a data structure for managing multiple timers
 * each with an action to be executed when the timer expires.
 */

/*------------------------------------------------------------------------------
 * Sort out QTIMERS_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if QTIMERS_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set QTIMERS_DEBUG    == 0 to turn off debug
 *       *  or set QTIMERS_DEBUG    != 0 to turn on debug
 *       *  or set QTIMERS_NO_DEBUG != 0 to force debug off
 */

#ifdef QTIMERS_DEBUG            /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(QTIMERS_DEBUG)
#  undef  QTIMERS_DEBUG
#  define QTIMERS_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define QTIMERS_DEBUG QDEBUG
#endif

#ifdef QTIMERS_NO_DEBUG         /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(QTIMERS_NO_DEBUG)
#  undef  QTIMERS_DEBUG
#  define QTIMERS_DEBUG 0
# endif
#endif

enum { qtimers_debug  = QTIMERS_DEBUG } ;

/*==============================================================================
 * Data Structures.
 */

typedef struct qtimer        qtimer_t ;
typedef struct qtimer*       qtimer ;

typedef struct qtimer_pile   qtimer_pile_t ;
typedef struct qtimer_pile*  qtimer_pile ;

typedef void (qtimer_action)(qtimer qtr, void* timer_info, qtime_mono_t when) ;

typedef enum
{
  qtrs_inactive      = 0,
  qtrs_active        = 1,

  qtrs_unset_pending = 2,
  qtrs_free_pending  = 4,

  qtrs_dispatch      = 8,
} qtr_state_t ;

struct qtimer
{
  qtimer_pile     pile ;        /* pile currently allocated to          */
  heap_backlink_t backlink ;

  qtr_state_t     state ;

  qtime_mono_t    time ;        /* current time to trigger action       */
  qtimer_action*  action ;
  void*           timer_info ;

  qtime_t         interval ;    /* optional timer interval              */

  char            name[32] ;    /* optional timer name                  */
} ;

struct qtimer_pile
{
  heap_t      timers ;

  bool        ok ;              /* for pile verification                */

  char        name[31] ;        /* optional time pile name              */
} ;

/*==============================================================================
 * Functions
 */

extern qtimer_pile qtimer_pile_init_new(qtimer_pile qtp) ;
extern void qtimer_pile_set_name(qtimer_pile qtp, const char* name) ;
extern bool qtimer_pile_dispatch_next(qtimer_pile qtp, qtime_mono_t upto) ;
extern qtime_t qtimer_pile_top_wait(qtimer_pile qtp, qtime_t max_wait,
                                                                  qtime_t now) ;
extern qtimer qtimer_pile_ream(qtimer_pile qtp, free_keep_b free_structure) ;

extern qtimer qtimer_init_new(qtimer qtr, qtimer_pile qtp,
                                      qtimer_action* action, void* timer_info) ;
extern void qtimer_set_name(qtimer qtr, const char* name) ;
extern void qtimer_set_pile(qtimer qtr, qtimer_pile qtp) ;
Inline void qtimer_set_action(qtimer qtr, qtimer_action* action) ;
Inline void qtimer_set_info(qtimer qtr, void* timer_info) ;

extern void qtimer_set(qtimer qtr, qtime_mono_t when, qtimer_action* action) ;
extern qtime_t qtimer_has_left(qtimer qtr) ;
extern void qtimer_unset(qtimer qtr) ;
extern qtimer qtimer_free(qtimer qtr) ;

Inline bool qtimer_is_active(qtimer qtr) ;

Inline void qtimer_add(qtimer qtr, qtime_t interval, qtimer_action* action) ;
Inline qtime_mono_t qtimer_get(qtimer qtr) ;
Inline void qtimer_set_interval(qtimer qtr, qtime_t interval,
                                                     qtimer_action* action) ;
Inline void qtimer_add_interval(qtimer qtr, qtimer_action* action) ;

Inline qtime_t qtimer_get_interval(qtimer qtr) ;
extern void qtimer_pile_verify(qtimer_pile qtp) ;

/*==============================================================================
 * Inline functions
 */

/*------------------------------------------------------------------------------
 * Set given timer to given time later than *its* current time.
 *
 * NB: if the timer is not active, new time is wrt the last time set.
 */
Inline void
qtimer_add(qtimer qtr, qtime_t interval, qtimer_action* action)
{
  qtimer_set(qtr, qtimer_get(qtr) + interval, action);
} ;

/*------------------------------------------------------------------------------
 * Get the given timer's time
 *
 * NB: if the timer is not active, returns the last time set.
 */
Inline qtime_mono_t
qtimer_get(qtimer qtr)
{
  return qtr->time ;
} ;

/*------------------------------------------------------------------------------
 * Set action for given timer -- setting a NULL action unsets the timer.
 */
Inline void
qtimer_set_action(qtimer qtr, qtimer_action* action)
{
  if (action == NULL)
    qtimer_unset(qtr) ;
  qtr->action = action ;
} ;

/*------------------------------------------------------------------------------
 * Set timer_info for given timer.
 */
Inline void
qtimer_set_info(qtimer qtr, void* timer_info)
{
  qtr->timer_info = timer_info ;
} ;

/*------------------------------------------------------------------------------
 * Set interval for the given timer, and set the timer.
 *
 * It is assumed that the interval is +ve !
 *
 * Sets the timer to go off at the current time + given interval.  So, a
 * zero interval will set a timer to go off RSN.
 */
Inline void
qtimer_set_interval(qtimer qtr, qtime_t interval, qtimer_action* action)
{
  qtr->interval = interval ;
  qtimer_set(qtr, qt_add_monotonic(interval), action) ;
} ;

/*------------------------------------------------------------------------------
 * Set timer to go off at the last time it was set to go off plus the current
 * interval.
 */
Inline void
qtimer_add_interval(qtimer qtr, qtimer_action* action)
{
  qtimer_add(qtr, qtr->interval, action) ;
} ;

/*------------------------------------------------------------------------------
 * Get the current value of the interval field
 */
Inline qtime_t
qtimer_get_interval(qtimer qtr)
{
  return qtr->interval ;
} ;

/*------------------------------------------------------------------------------
 * See if given qtimer (if any) is active
 */
Inline bool
qtimer_is_active(qtimer qtr)
{
  return (qtr != NULL) && ((qtr->state & qtrs_active) != 0) ;
}

#endif /* _ZEBRA_QTIMERS_H */
