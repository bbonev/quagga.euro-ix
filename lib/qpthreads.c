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

/* This MUST come first...  otherwise we don't get __USE_UNIX98, which is     */
/* essential if glibc is to allow pthread_mutexattr_settype() to be used.     */
#include "config.h"

#include <signal.h>
#include <string.h>

#include "qpthreads.h"
#include "memory.h"

/* If this is not set, will get errors later.   */
//#ifndef __USE_UNIX98
//#error "_USE_UNIX98 not defined"
//#endif

/*==============================================================================
 * Quagga Pthread Interface -- qpt_xxxx
 *
 * Here (and in qpthreads.h) are captured all the pthreads features used in
 * Quagga.
 *
 * This provides:
 *
 *   * "wrappers" around functions which should not fail, but whose return
 *     code it is best to check... at least in a debug environment.
 *
 *   * the possibility of a separate no pthreads build where pthread facilities
 *     are either dummied out or otherwise dealt with.
 *
 *   * the ability to add any work-arounds which may be required if poorly
 *     conforming pthreads implementations are encountered
 *
 * Continued Working Without Pthreads
 * ==================================
 *
 * A big Global Switch -- qpthreads_enabled -- is used to control whether the
 * system is pthreaded or not.
 *
 * The initial state is qpthreads_enabled == false (0).
 *
 * The function qpt_set_qpthreads_enabled() should be called when the
 * application has decided whether to use qpthreads or not.  (But does not have
 * to call this if it is happy to proceed in the default -- disabled -- state.)
 *
 * If this is never set, then the system runs without pthreads, and all the
 * mutex and condition variable functions are NOPs.  This allows, for example,
 * mutex operations to be placed where they are needed for thread-safety,
 * without affecting the code when running without pthreads.
 *
 * There are a very few operations which require qpthreads_enabled:
 *
 *   * qpt_thread_attr_init
 *   * qpt_thread_create
 *
 * A few operations "freeze" the state of qpthreads_enabled.  Any call of these
 * before qpthreads are enabled, causes the state to be frozen, disabled.  This
 * means that any later attempt to enable qpthreads will be refused.  These
 * operations are:
 *
 *   * qpt_mutex_init_new
 *   * qpt_cond_init_new
 *   * qpt_splin_init_new
 *
 * This allows the application to decide as late as possible (but no later)
 * whether to enable pthreads.  If a mutex, condition variable or spin lock has
 * been initialised before the application gets around to enabling qpthreads,
 * that will be trapped when qpthreads is finally enabled.
 *
 * Pthread Requirements
 * ====================
 *
 * This is assuming support for 1003.1-2004 -- XOPEN Issue 6, with [THR], [SPI]
 * and [XSI] options.
 *
 * In 1003.1-2008, XOPEN issue 7, [THR], [SPI] and pthread_mutexattr_settype()
 * have been moved to Base.
 *
 * The [XSI] is required for pthread_mutexattr_settype(), only.
 *
 * If qpt_thread_attr_init() uses:
 *
 *   pthread_attr_getinheritsched()/_setinheritshed()    [TPS]
 *   pthread_attr_getscope()/_setscope()                 [TPS]
 *   pthread_attr_getschedpolicy()/_setschedpolicy()     [TPS]
 *   pthread_attr_getschedparam()/_setschedparam()       [THR]
 *
 * but they are only required if explicit scheduling attributes are being set.
 * (So, could be dropped where not supported.)
 *
 * Amongst the things which are NOT required:
 *
 *   pthread_attr_getguardsize()/_setguardsize()          [XSI]
 *   pthread_attr_getstack()/_setstack()                  [TSA TSS]
 *   pthread_attr_getstackaddr()/_setstackaddr()          [TSA OB]
 *   pthread_attr_getstacksize()/_setstacksize()          [TSA TSS]
 *
 *   pthread_barrier_xxx()                                [BAR]
 *
 *   pthread_condattr_getpshared()/_setpshared()          [TSH]
 *
 *   pthread_mutex_getprioceiling()/_setprioceiling()     [TPP]
 *   pthread_mutex_timedlock()                            [TMO]      pro tem
 *   pthread_mutexattr_getprioceiling()/_setprioceiling() [TPP]
 *   pthread_mutexattr_getprotocol()/_setprotocol()       [TPP TPI]
 *   pthread_mutexattr_getpshared()/_setpshared()         [TSH]
 *
 *   pthread_rwlock_xxx()                                 [THR]      pro tem
 *   pthread_rwlockattr_init()/_destroy()                 [THR]      pro tem
 *   pthread_rwlockattr_getpshared()/_setpshared()        [TSH]
 *
 * [CS] (Clock Select) is assumed if HAVE_CLOCK_MONOTONIC.
 *
 * NB: it is essential that pthread_kill() delivers the signal to the target
 *     thread only -- ie, it must be POSIX compliant.  That rules out the old
 *     (2.4) LinuxThreads.  For Linux, 2.6 (or greater) is required, with
 *     NPTL (these days generally included in glibc).
 *
 * NB: for glibc to give all the required features, either _GNU_SOURCE or
 *     _XOPEN_SOURCE must be set *before* the first #include <features.h>.
 *     _XOPEN_SOURCE=600 is sufficient.
 *
 * Pthread Thread Attributes -- Scheduling
 * =======================================
 *
 * Pthreads defines some useful looking real-time scheduling features.
 *
 * One would like to be able to give I/O intensive threads an advantage over
 * CPU bound threads.
 *
 * Unfortunately, conformance allows a system to have its own scheduling
 * system -- so long as the standard ones are implemented.  Further, there is
 * no way of telling what priority values are reasonable, even in the standard
 * scheduling policies.
 *
 * The approach taken here is that by default a thread will be created with
 * the system default attributes -- which may mean inheriting the creating
 * thread's scheduling attributes.
 *
 * It is also possible to construct a set of attributes, using the most
 * obviously useful properties.  It is envisaged that this may be used when a
 * configuration file is used to set locally sensible values.   The attributes
 * supported are:
 *
 *    * attr_detached       -- whether to start detached or not
 *    * attr_inherit_sched  -- whether to inherit scheduling attributes
 *    * attr_sched_scope    -- scheduling scope
 *    * attr_sched_policy   -- scheduling policy
 *    * attr_sched_priority -- scheduling priority
 *
 * See qpt_thread_attr_init, below.
 *
 * Not supported here are:
 *
 *    * attr_guardsize
 *    * attr_stack
 *    * attr_stacksize
 *
 * Pthread Mutex Attributes -- Error Checking
 * ==========================================
 *
 * Mutexes are kept simple, only attr_type is used, and that by default.
 *
 * POSIX defines four types of mutex:
 *
 *   _NORMAL      no ownership check   -- owner will deadlock if locks mutex !
 *                                     -- undefined what happens if unlock
 *                                        mutex not owned by self !
 *                no recursive locking
 *
 *   _ERRORCHECK  checks for ownership on lock and unlock
 *                no recursive locking
 *
 *   _RECURSIVE   checks for ownership on lock and unlock
 *                counts up locks and counts down unlocks
 *
 *                This looks useful, but goes wrong with condition variables !
 *
 *   _DEFAULT     undefined whether checks owner or not, on lock and/or unlock.
 *                no recursive locking
 *
 * See qpthreads.h for discussion of Quagga's standard type (QPT_MUTEX_TYPE).
 *
 * Other attributes are left in their default state:
 *
 *   * attr_prioceiling  -- default undefined
 *   * attr_protocol     -- default undefined
 *   * attr_pshared      -- defaults to _PROCESS_PRIVATE
 *
 * For the time being it is assumed that these are too exotic.
 *
 * Pthread Condition Variable Attributes
 * =====================================
 *
 * Condition variables have only two attributes:
 *
 *   * attr_clock        -- which clock to use
 *   * attr_pshared      -- defaults to _PROCESS_PRIVATE
 *
 * The use a clock other than Quagga's standard (QPT_COND_CLOCK_ID) is possible,
 * but not recommended.  (See qpthreads.h for discussion of this.)
 *
 * Pthread Specific Signal Handling
 * ================================
 *
 * In a threaded application, need to use pthread_sigmask (not sigproc_mask).
 * (Can use pthread_sigmask in a single threaded application.)
 *
 * To direct a signal at a given thread need pthread_kill. *
 */

/*==============================================================================
 * The Global Switch
 *
 * The state of the switch is:  unset        -- implicitly not enabled
 *                              set_frozen   -- implicitly not enabled & frozen
 *                              set_disabled -- explicitly not enabled
 *                              set_enabled  -- explicitly set enabled
 *
 * "set_frozen" means that "qpthreads_freeze_enabled_state()" has been called,
 * and the state was unset at the time.  This means that some initialisation
 * has been done on the basis of !qpthreads_enabled, and it is TOO LATE to
 * enable qpthreads afterwards.
 */

enum qpthreads_enabled_state
{
  qpt_state_unset         = 0,
  qpt_state_set_frozen    = 1,
  qpt_state_set_disabled  = 2,
  qpt_state_set_enabled   = 3,
} ;

static enum qpthreads_enabled_state qpthreads_enabled_state = qpt_state_unset ;

uint8_t qpthreads_enabled_flag          = 0 ;
uint8_t qpthreads_thread_created_flag   = 0 ;

/* Function to set qpthreads_enabled, one way or the other.
 *
 * Returns:  true <=> successful set the required state.
 *          false <=> it is too late to enable qpthreads :-(
 *
 * NB: can repeatedly set to the same state, but not change state once set.
 */
extern int
qpt_set_qpthreads_enabled(int how)
{
  switch (qpthreads_enabled_state)
    {
      case qpt_state_unset:
        break ;

      case qpt_state_set_frozen:
        if (how != 0)
          return 0 ;
        break ;

      case qpt_state_set_disabled:
        if (how != 0)
          zabort("qpthreads_enabled is already set: cannot set enabled") ;
        break ;

      case qpt_state_set_enabled:
        if (how == 0)
          zabort("qpthreads_enabled is already set: cannot set disabled") ;
        break ;

      default:
        break ;
    } ;

  qpthreads_enabled_flag  = (how != 0) ;
  qpthreads_enabled_state = (how != 0) ? qpt_state_set_enabled
                                       : qpt_state_set_disabled ;
  return 1 ;
} ;

/* Get state of qpthreads_enabled, and freeze if not yet explictly set.
 *
 * Where some initialisation depends on the state of qpthreads_enabled(), this
 * returns the state and freezes it if it is implicitly not enabled.
 */
extern int
qpt_freeze_qpthreads_enabled(void)
{
  if (qpthreads_enabled_state == qpt_state_unset)
    qpthreads_enabled_state = qpt_state_set_frozen ;

  return qpthreads_enabled_flag ;
} ;

/*==============================================================================
 * Thread creation and attributes.
 *
 * Threads may be created with a given set of attributes if required.
 *
 * qpt_thread_attr_init() will initialise a set of attributes including the
 * current standard scheduling attributes.  It is envisaged that configuration
 * options may be used to specify these.
 *
 * qpt_thread_create() creates a thread using the given attributes.  If those
 * are NULL, then the system defaults are used.
 */

/* Initialise a set of attributes -- setting the scheduling options.
 *
 * Options:
 *
 *   qpt_attr_joinable       -- the default if nothing specified.
 *   qpt_attr_detached       -- overrides qpt_attr_joinable.
 *
 *   qpt_attr_sched_inherit  -- all scheduling attributes are to be inherited.
 *                              No explicit scheduling attributes may be set.
 *
 *   qpt_attr_sched_scope    -- set explicit, given, scope.
 *   qpt_attr_sched_policy   -- set explicit, given, policy
 *   qpt_attr_sched_priority -- set explicit, given, priority
 *
 * If none of the _sched_ options are given, then the scheduling attributes are
 * left to whatever default values the system chooses.
 *
 * If the _sched_inherit option is specified, none of the other _sched_ options
 * may be specified.
 *
 * If any of the explicit scheduling options are given, they are set in this
 * order.  If only some of these options are given, then the caller is
 * assuming that the system will choose sensible defaults.
 *
 * The scope, policy and priority arguments are use only if the corresponding
 * option is specified.
 *
 * NB: FATAL error to attempt this is !qptthreads_enabled.
 *
 * Returns the address of the qpt_thread_attr_t structure.
 */
qpt_thread_attr_t*
qpt_thread_attr_init(qpt_thread_attr_t* attr, enum qpt_attr_options opts,
                                            int scope, int policy, int priority)
{
  int err ;

  assert((opts & ~qpt_attr_known) == 0) ;
  passert(qpthreads_enabled) ;

  /* Initialise thread attributes structure (allocating if required.)   */
  if (attr == NULL)
    attr = XMALLOC(MTYPE_QPT_THREAD_ATTR, sizeof(qpt_thread_attr_t)) ;

  err = pthread_attr_init(attr) ;
  if (err != 0)
    zabort_err("pthread_attr_init failed", err) ;

  /* If not qpt_attr_detached, then set joinable.       */
  err = pthread_attr_setdetachstate(attr,
                         (opts & qpt_attr_detached) ? PTHREAD_CREATE_DETACHED
                                                    : PTHREAD_CREATE_JOINABLE) ;
  if (err != 0)
    zabort_err("pthread_attr_setdetachstate failed", err) ;

  /* If setting anything to do with scheduling...       */
  if (opts & qpt_attr_sched_setting)
    {
      /* Either we inherit or we set explicit parameters.       */

      err = pthread_attr_setinheritsched(attr,
                    (opts & qpt_attr_sched_inherit) ? PTHREAD_INHERIT_SCHED
                                                    : PTHREAD_EXPLICIT_SCHED) ;
      if (err != 0)
        zabort_err("pthread_attr_setinheritsched", err) ;

      if (opts & qpt_attr_sched_inherit)
        assert((opts & qpt_attr_sched_explicit) == 0) ;
      else
        {
          if (opts & qpt_attr_sched_scope)
            {
              err = pthread_attr_setscope(attr, scope) ;
              if (err != 0)
                zabort_err("pthread_attr_setscope failed", err) ;
            } ;
          if (opts & qpt_attr_sched_policy)
            {
              err = pthread_attr_setschedpolicy(attr, scope) ;
              if (err != 0)
                zabort_err("pthread_attr_setschedpolicy failed", err) ;
            } ;
          if (opts & qpt_attr_sched_priority)
            {
              struct sched_param sparm ;
              err = pthread_attr_getschedparam(attr, &sparm) ;
              if (err != 0)
                zabort_err("pthread_attr_getschedparam failed", err) ;
              sparm.sched_priority = priority ;
              err = pthread_attr_setschedparam(attr, &sparm) ;
              if (err != 0)
                zabort_err("pthread_attr_setschedparam failed", err) ;
            } ;
        } ;
    } ;

  /* Done -- return qpt_thread_attr_t*     */
  return attr ;
} ;

/* Create Thread with given attributes (if any).
 *
 * If no attributes are given (attr == NULL) the thread is created with system
 * default attributes -- *except* that it is created joinable.
 *
 * NB: FATAL error to attempt this is !qptthreads_enabled.
 *
 * Returns the qpt_thread_t "thread id".
 */
qpt_thread_t
qpt_thread_create(void* (*start)(void*), void* arg, qpt_thread_attr_t* attr)
{
  qpt_thread_attr_t thread_attr ;
  qpt_thread_t      thread_id ;
  int default_attr ;
  int err ;

  passert(qpthreads_enabled) ;
  qpthreads_thread_created_flag = 1 ;   /* and at least one thread created  */

  default_attr = (attr == NULL) ;
  if (default_attr)
    attr = qpt_thread_attr_init(&thread_attr, qpt_attr_joinable, 0, 0, 0) ;

  err = pthread_create(&thread_id, attr, start, arg) ;
  if (err != 0)
    zabort_err("pthread_create failed", err) ;

  if (default_attr)
    {
      err = pthread_attr_destroy(attr) ;        /* being tidy */
      if (err != 0)
        zabort_err("pthread_attr_destroy failed", err) ;
    } ;

  return thread_id ;
} ;

/* Join given thread -- do nothing if !qpthreads_enabled
 *
 * Tolerates ESRCH (no thread known by given id).
 *
 * Returns whatever the thread returns, NULL otherwise.
 *
 * NB: all other errors are FATAL.
 */
extern void*
qpt_thread_join(qpt_thread_t thread_id)
{
  int   err ;
  void* ret ;

  if (!qpthreads_enabled)
    return NULL ;

  err = pthread_join(thread_id, &ret) ;

  if (err == 0)
    return ret ;

  if (err == ESRCH)
    return NULL ;

  zabort_err("pthread_join failed", err) ;
} ;

/*==============================================================================
 * Mutex initialise and destroy.
 */

/* Initialise Mutex (allocating if required)
 *
 * Does nothing if !qpthreads_enabled -- but freezes the state (attempting to
 * later enable qpthreads will be a FATAL error).
 *
 * Options:
 *
 *   qpt_mutex_quagga      -- see qpthreads.h for discussion of this.
 *   qpt_mutex_normal      -- ie PTHREAD_MUTEX_NORMAL
 *   qpt_mutex_recursive   -- ie PTHREAD_MUTEX_RECURSIVE
 *   qpt_mutex_errorcheck  -- ie PTHREAD_MUTEX_ERRORCHECK
 *   qpt_mutex_default     -- system default
 *
 * Of these _recursive is the most likely alternative to _quagga...  BUT do
 * remember that such mutexes DO NOT play well with condition variables.
 *
 * Returns the mutex -- or original mx if !qpthreads_enabled.
 */
qpt_mutex
qpt_mutex_init_new(qpt_mutex mx, enum qpt_mutex_options opts)
{
  pthread_mutexattr_t mutex_attr ;
  int type ;
  int err ;

  if (!qpthreads_enabled_freeze)
    {
      if (mx != NULL)
        memset(mx, 0x0F, sizeof(qpt_mutex_t)) ;
      return mx ;
    } ;

  if (mx == NULL)
    mx = XMALLOC(MTYPE_QPT_MUTEX, sizeof(qpt_mutex_t)) ;

  /* Set up attributes so we can set the mutex type     */
  err = pthread_mutexattr_init(&mutex_attr);
  if (err != 0)
    zabort_err("pthread_mutexattr_init failed", err) ;

  switch(opts)
  {
    case qpt_mutex_quagga:
      type = QPT_MUTEX_TYPE ;
      break ;
    case qpt_mutex_normal:
      type = PTHREAD_MUTEX_NORMAL ;
      break ;
    case qpt_mutex_recursive:
      type = PTHREAD_MUTEX_RECURSIVE ;
      break ;
    case qpt_mutex_errorcheck:
      type = PTHREAD_MUTEX_ERRORCHECK ;
      break ;
    case qpt_mutex_default:
      type = PTHREAD_MUTEX_DEFAULT ;
      break ;
    default:
      zabort("Invalid qpt_mutex option") ;
  } ;

  err = pthread_mutexattr_settype(&mutex_attr, type);
  if (err != 0)
    zabort_err("pthread_mutexattr_settype failed", err) ;

  /* Now we're ready to initialize the mutex itself     */
  err = pthread_mutex_init(mx, &mutex_attr) ;
  if (err != 0)
    zabort_err("pthread_mutex_init failed", err) ;

  /* Be tidy with the attributes                        */
  err = pthread_mutexattr_destroy(&mutex_attr) ;
  if (err != 0)
    zabort_err("pthread_mutexattr_destroy failed", err) ;

  /* Done: return the mutex                             */
  return mx ;
} ;

/* Destroy given mutex, and (if required) free it.
 *                                       -- or do nothing if !qpthreads_enabled.
 *
 * Returns NULL if freed the mutex, otherwise the address of same.
 *
 * NB: if !qpthreads_enabled qpt_mutex_init_new() will not have allocated
 *     anything, so there can be nothing to release -- so does nothing, but
 *     returns the original mutex address (if any).
 */
qpt_mutex
qpt_mutex_destroy(qpt_mutex mx, int free_mutex)
{
  int err ;

  if (qpthreads_enabled)
    {
      err = pthread_mutex_destroy(mx) ;
      if (err != 0)
        zabort_err("pthread_mutex_destroy failed", err) ;

      if (free_mutex)
        XFREE(MTYPE_QPT_MUTEX, mx) ;    /* sets mx == NULL      */
    } ;

  return mx ;
} ;

/*==============================================================================
 * Condition Variable initialise and destroy.
 */

/* Initialise Condition Variable (allocating if required).
 *
 * Does nothing if !qpthreads_enabled -- but freezes the state (attempting to
 * later enable qpthreads will be a FATAL error).
 *
 * Options:
 *
 *   qpt_cond_quagga     -- use Quagga's default clock
 *   qpt_cond_realtime   -- force CLOCK_REALTIME
 *   qpt_cond_monotonic  -- force CLOCK_MONOTONIC  (if available)
 *
 * NB: FATAL error to attempt this if !qptthreads_enabled.
 *
 * Returns the condition variable -- or original cv if !qpthreads_enabled.
 */
qpt_cond
qpt_cond_init_new(qpt_cond cv, enum qpt_cond_options opts)
{
  pthread_condattr_t cond_attr ;
  int err ;

  if (!qpthreads_enabled_freeze)
    {
      if (cv != NULL)
        memset(cv, 0x0F, sizeof(qpt_cond_t)) ;
      return cv ;
    } ;

  if (cv == NULL)
    cv = XMALLOC(MTYPE_QPT_COND, sizeof(qpt_cond_t)) ;

  /* Set up attributes so we can set the  type     */
  err = pthread_condattr_init(&cond_attr);
  if (err != 0)
    zabort_err("pthread_condattr_init failed", err) ;

  switch(opts)
  {
    case qpt_cond_quagga:
      break ;
    default:
      zabort("Invalid qpt_cond option") ;
  } ;

  err = pthread_condattr_setclock(&cond_attr, QPT_COND_CLOCK_ID);
  if (err != 0)
    zabort_err("pthread_condattr_setclock failed", err) ;

  /* Now we're ready to initialize the condition variable itself        */
  err = pthread_cond_init(cv, &cond_attr) ;
  if (err != 0)
    zabort_err("pthread_cond_init failed", err) ;

  /* Be tidy with the attributes                        */
  err = pthread_condattr_destroy(&cond_attr) ;
  if (err != 0)
    zabort_err("pthread_condattr_destroy failed", err) ;

  /* Done: return the condition variable                */
  return cv ;
} ;

/* Destroy given condition variable, and (if required) free it
 *                                       -- or do nothing if !qpthreads_enabled.
 *
 * NB: if !qpthreads_enabled qpt_cond_init_new() will not have allocated
 *     anything, so there can be nothing to release -- so does nothing, but
 *     returns the original condition variable address (if any).
 *
 * Returns NULL if freed the condition variable, otherwise the address of same.
 */
qpt_cond
qpt_cond_destroy(qpt_cond cv, int free_cond)
{
  int err ;

  if (qpthreads_enabled)
    {
      err = pthread_cond_destroy(cv) ;
      if (err != 0)
        zabort_err("pthread_cond_destroy failed", err) ;

      if (free_cond)
        XFREE(MTYPE_QPT_COND, cv) ;     /* sets cv == NULL      */
    } ;

  return cv ;
} ;

/* Wait for given condition variable or time-out
 *                         -- or return immediate success if !qpthreads_enabled.
 *
 * Returns: wait succeeded (1 => success, 0 => timed-out).
 *
 * NB: timeout time is a qtime_mono_t (monotonic time).
 *
 * Has to check the return value, so zabort_errno if not EBUSY.
 */

int
qpt_cond_timedwait(qpt_cond cv, qpt_mutex mx, qtime_mono_t timeout_time)
{
  struct timespec ts ;
  int err ;

  if (qpthreads_enabled)
    {
      if (QPT_COND_CLOCK_ID != CLOCK_MONOTONIC)
        {
          timeout_time = qt_clock_gettime(QPT_COND_CLOCK_ID)
                                         + (timeout_time - qt_get_monotonic()) ;
        } ;

      err = pthread_cond_timedwait(cv, mx, qtime2timespec(&ts, timeout_time)) ;
      if (err == 0)
        return 1 ;                  /* got condition        */
      if (err == ETIMEDOUT)
        return 0 ;                  /* got time-out         */

      zabort_err("pthread_cond_timedwait failed", err) ;
    }
  else
    return 0 ;
} ;

/*==============================================================================
 * Spinlock initialise and destroy.
 */

/* Initialise Spinlock -- NB: no allocation option
 *
 * Does nothing if !qpthreads_enabled -- but freezes the state.
 */
extern void
qpt_spin_init(qpt_spin slk)
{
  int err ;

  if (!qpthreads_enabled_freeze)
    return ;

  enum {
#ifndef PTHREAD_PROCESS_PRIVATE
    pthread_process_private = 0
#else
    pthread_process_private = PTHREAD_PROCESS_PRIVATE
#endif
  } ;

  err = pthread_spin_init(slk, pthread_process_private) ;
  if (err != 0)
    zabort_err("pthread_spin_init failed", err) ;
} ;

/* Destroy given spin lock -- NB: no free option
 *                                       -- or do nothing if !qpthreads_enabled.
 */
extern void
qpt_spin_destroy(qpt_spin slk)
{
  if (qpthreads_enabled)
    {
      int err = pthread_spin_destroy(slk) ;
      if (err != 0)
        zabort_err("pthread_spin_destroy failed", err) ;
    } ;
} ;

/*==============================================================================
 * Signal Handling.
 */

/* Set thread signal mask   -- requires qpthreads_enabled.
 *
 * Thin wrapper around pthread_sigmask.
 *
 * zaborts if gets any error.
 *
 * NB: it is a FATAL error to do this if !qpthreads_enabled.
 *
 *     This is mostly because wish to avoid all pthreads_xxx calls when not
 *     using pthreads.  There is no reason not to use this in a single threaded
 *     program.
 */
void
qpt_thread_sigmask(int how, const sigset_t* set, sigset_t* oset)
{
  int err ;

  passert(qpthreads_enabled) ;

  if (oset != NULL)
    sigemptyset(oset) ;         /* to make absolutely sure      */

  err = pthread_sigmask(how, set, oset) ;
  if (err != 0)
    zabort_err("pthread_sigmask failed", err) ;
} ;

/* Send given thread the given signal   -- requires qpthreads_enabled (!)
 *
 * Thin wrapper around pthread_kill.
 *
 * zaborts if gets any error.
 */
void
qpt_thread_signal(qpt_thread_t thread, int signum)
{
  int err ;

  passert(qpthreads_enabled) ;

  err = pthread_kill(thread, signum) ;
  if (err != 0)
    zabort_err("pthread_kill failed", err) ;
} ;
