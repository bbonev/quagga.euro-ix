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

#ifndef _ZEBRA_QPNEXUS_H
#define _ZEBRA_QPNEXUS_H

#include "misc.h"
#include <time.h>
#include <errno.h>
#include <signal.h>

#include "qpthreads.h"
#include "qtimers.h"
#include "mqueue.h"
#include "qpselect.h"
#include "list_util.h"

/*==============================================================================
 * Quagga Nexus Interface -- qpn_xxxx
 *
 * Object to hold, a qpthread, a qps_selection, a qtimer_pile, a mqueue_queue
 * together with the thread routine to poll and dispatch their respective
 * action routines.
 *
 */
enum
{
  /* maximum time in seconds to sit in a pselect  */
  MAX_PSELECT_WAIT = 10,

  /* signal for message queues                    */
  SIG_INTERRUPT    = SIGUSR2,

  /* number of hooks per hook list                */
  qpn_hooks_max    = 4,
} ;

/*==============================================================================
 * Data Structures.
 */
typedef int qpn_hook_function(void) ;   /* dispatch of tasks    */
typedef int qpn_init_function(void) ;   /* loop/stop work      */

typedef struct qpn_hook_list* qpn_hook_list ;
struct qpn_hook_list
{
  void*     hooks[qpn_hooks_max] ;
  unsigned  count ;
} ;

typedef struct qpn_stats
{
  qtime_mono_t  start_time ;
  qtime_mono_t  last_time ;
  qtime_mono_t  idle ;

  urlong   cycles ;
  urlong   signals ;
  urlong   foreg ;
  urlong   dispatch ;
  urlong   io_acts ;
  urlong   timers ;
  urlong   backg ;

} qpn_stats_t ;

typedef qpn_stats_t* qpn_stats ;

typedef struct qpn_nexus* qpn_nexus ;

struct qpn_nexus
{
  /* name of thread
   */
  const char* name ;

#if 0
  /* list of known nexuses in creation order.
   */
  struct dl_list_pair(qpn_nexus) list ;


  /* set true when the pthread has started, which means that it:
   *
   *   * is on the list of known nexuses (the flag is set once everything
   *     else is set, and under the same mutex as adding to the list).
   *
   *   * has a valid thread_id
   *
   *   * has a valid cpu_clock_id
   */
  bool started ;
#endif

  /* set true to terminate the thread (eventually)
   */
  volatile bool terminate;

  /* true if this is the main thread
   */
  bool main_thread;

  /* Underlying qpt_thread
   */
  qpt_thread    qpth ;

  /* Signal mask for pselect and the signal used to interrupt pselect.
   */
  sigset_t      pselect_mask[1] ;
  int           pselect_signal ;

  /* pselect handler
   */
  qps_selection selection;

  /* timer pile
   */
  qtimer_pile pile;

  /* message queue
   */
  mqueue_queue queue;

  /* qpthread routine, can override
   */
  void* (*loop)(qpt_thread);

  /* in-thread initialise, can override.  Called within the thread after all
   * other initialisation just before thread loop
   *
   * These are typedef int qpn_init_function(void).
   *
   * These are executed in the order given.
   */
  struct qpn_hook_list in_thread_init ;

  /* in-thread finalise, can override.  Called within thread just before
   * thread dies.  Nexus components all exist but thread loop is no longer
   * executed
   *
   * These are typedef int qpn_init_function(void).
   *
   * These are executed in the reverse of the order given.
   */
  struct qpn_hook_list in_thread_final ;

  /* in-thread queue(s) of events or other work.
   *
   * The hook function(s) are called in the qpnexus loop, at the top of the
   * loop.  So in addition to the mqueue, I/O, timers and any background stuff,
   * the thread may have other queue(s) of things to be done.
   *
   * These are typedef int qpn_hook_function(void).
   *
   * Hook function can process some queue(s) of things to be done.  It does not
   * have to empty its queues, but it MUST only return 0 if all queues are now
   * empty.
   */
  struct qpn_hook_list foreground ;

  /* in-thread background queue(s) of events or other work.
   *
   * The hook functions are called at the bottom of the qpnexus loop, but only
   * when there is absolutely nothing else to do.
   *
   * These are typedef int qpn_hook_function(void).
   *
   * The hook function should do some unit of background work (if there is any)
   * and return.  MUST return 0 iff there is no more work to do.
   */
  struct qpn_hook_list background ;

  /* statistics gathering
   *
   * NB: not valid until "started"
   */
  qpt_spin_t    slk ;

  qpn_stats_t   raw ;           /* belongs to thread                    */
  qpn_stats_t   stats ;         /* set, under spin lock, once per cycle */
  qpn_stats_t   prev_stats ;    /* set, under spin lock, each time stats
                                 * are fetched.                         */

  /* For signal and for watch-dog -- read/written under slk
   *
   * NB: not valid until "started"
   */
  bool          signal ;        /* a signal is pending                  */
  uint8_t       idleness ;      /* 0 => active,
                                 * 1 => idle, waiting for timer
                                 * 2 => idle, and seen by watch-dog
                                 * 3 => idle, and seen a second time !
                                 */
  qpt_thread_stats_t qpth_stats ;
};

/*------------------------------------------------------------------------------
 * Each qpnexus has a qpt_thread, and its "data" is set to refer to the
 * parent qpnexus -- so this is how a running pthread can find its nexus.
 */
Inline qpn_nexus
qpn_find_self(void)
{
  return qpt_thread_self_data() ;
} ;

/*==============================================================================
 * Functions
 */
extern void qpn_init(void) ;
extern qpn_nexus qpn_init_new(qpn_nexus qpn, bool main_thread,
                                                             const char* name) ;
extern void qpn_add_hook_function(qpn_hook_list list, void* hook) ;
extern void qpn_main_start(qpn_nexus qpn) ;
extern void qpn_exec(qpn_nexus qpn);
extern void qpn_terminate(qpn_nexus qpn);
extern void qpn_signal(qpn_nexus qpn) ;
extern qpn_nexus qpn_reset(qpn_nexus qpn, free_keep_b free_structure);

extern void qpn_get_stats(qpn_nexus qpn, qpn_stats curr, qpn_stats prev) ;

extern void qpn_wd_start_up(void) ;
extern bool qpn_wd_prepare(const char* arg) ;
extern void qpn_wd_start(void) ;
extern void qpn_wd_finish(void) ;

#endif /* _ZEBRA_QPNEXUS_H */
