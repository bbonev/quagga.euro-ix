/* Quagga realtime and monotonic clock handling -- functions
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

#include <sys/times.h>
#include <errno.h>

#include "qtime.h"
#include "qpthreads.h"
#include "qfstring.h"
#include "pthread_safe.h"
#include "log.h"

/*==============================================================================
 * This is a collection of functions and (in qtime.h) macros and inline
 * functions which support system time and a monotonic clock.
 */

CONFIRM((sizeof(clock_t) >= 4) && (sizeof(clock_t) <= 8)) ;

/* Variables for qt_craft_monotonic()
 *
 * The spinlock should be redundant... expect to HAVE_CLOCK_MONOTONIC if is
 * able to run qpthreads_enabled !
 *
 * Note that apart from times_monotonic and last_times_sample, these are constant
 * from qt_start_up() onwards.
 */
static qpt_spin_t qt_slock ;

static int64_t times_monotonic ;        /* crafted monotonic clock
                                         *                 in _SC_CLK_TCK's */
static int64_t last_times_sample ;      /* last value returned by times()
                                         *                 in _SC_CLK_TCK's */

static int64_t times_clk_tcks ;         /* sysconf(_SC_CLK_TCK)             */
static qtime_t times_scale_q ;          /* 10**9 / times_clk_tcks           */
static qtime_t times_scale_r ;          /* 10**9 % times_clk_tcks           */

static int64_t step_limit ;             /* for sanity check                 */

/* For qt_random -- some rubbish which depends on state when qt_start_up is
 * called.
 */
static uint32_t qt_random_seed ;

/* For qt_period_origin(), qt_base_fm() & qt_mono_fb()...
 *
 * ...the value to subtract from qtime_mono_t to give qtime_base_t.
 */
qtime_mono_t qt_base_origin ;           /* Declared Private in qtime.h  */

/* For debug we track the CLOCK_MONOTONIC to make sure that it really is !
 *
 * Protected by qt_slock.
 */
static qtime_mono_t track_monotonic ;

/*------------------------------------------------------------------------------
 * Wrapper for times().
 *
 * No errors are defined for times(), but a return of -1 is defined
 * to indicate an error condition, with errno saying what it is !
 *
 * The following deals carefully with this -- cannot afford for the
 * clock either to jump or to get stuck !
 */
static inline clock_t
qt_times(void)
{
#ifdef GNU_LINUX
# define TIMES_ARG  NULL
#else
  struct tms dummy[1] ;
# define TIMES_ARG  dummy
#endif

  clock_t   sample ;

  sample = times(TIMES_ARG) ;
  if (sample == -1)                     /* deal with theoretical error  */
    {
       errno = 0 ;
       sample = times(TIMES_ARG) ;
       if (errno != 0)
         zabort_errno("times() failed") ;
    } ;

  return sample ;
} ;

/*------------------------------------------------------------------------------
 * Early morning start.
 *
 * Prepare for crafted monotonic (just in case !).
 *
 * Set the initial value of the qt_random_seed.
 *
 * Set value of
 *
 * Prepare for debug tracking of monotonic time (if required).
 */
extern void
qt_start_up(void)
{
  lldiv_t  qr ;
  qtime_mono_t now ;

  /* Initial values for crafted monotonic time -- if required.
   */
  times_monotonic   = 0 ;
  last_times_sample = qt_times() ;

  /* Set up times_scale_q & times_scale_q
   */
  confirm(sizeof(qtime_t) <= sizeof(long long int)) ;

  times_clk_tcks = sysconf(_SC_CLK_TCK) ;
  passert((times_clk_tcks > 0) &&
          (times_clk_tcks <= (sizeof(clock_t) > 4) ? 1000000
                                                   :    1000)) ;

  qr = lldiv(QTIME_SECOND, times_clk_tcks) ;
  times_scale_q = qr.quot ;
  times_scale_r = qr.rem ;

  step_limit = (int64_t)24 * 60 * 60 * times_clk_tcks ;

  now = qt_get_monotonic() ;

  /* Local "random" seed.
   */
  qt_random_seed = (uintptr_t)(&qr) ^ now ;
  qt_random_seed = qt_random(3141592653) ;      /* final seed   */

  /* Origin of qtime_base_t as qtime_mono_t.
   *
   * So... subtract this from qtime_mono_t to give qtime_base_t.
   */
  qt_base_origin = now - QT_BASE_ZERO ;

  /* For debug tracking of monotonic time
   */
  track_monotonic = now ;
} ;

/*------------------------------------------------------------------------------
 * For qpthreads_enabled, need a spin lock
 */
extern void
qt_second_stage(void)
{
  qpt_spin_init(qt_slock) ;
}

/*------------------------------------------------------------------------------
 * Final curtain.
 */
extern void
qt_finish(void)
{
  qpt_spin_destroy(qt_slock) ;
} ;

/*==============================================================================
 * Replacement for CLOCK_MONOTONIC.
 *
 * With thanks to Joakim Tjernlund for reminding everyone of the return value
 * from times() !
 *
 * NB: we assume that if this is called, will *NOT* be qpthreads_enabled...
 *     ...we expect will HAVE_CLOCK_MONOTONIC
 *
 * times() is defined to return a value which is the time since some fixed time
 * before the application started (or when the application started).  This time
 * is measured in units of sysconf(_SC_CLK_TCK) ticks per second.
 *
 * The only tricky bit is that the value returned (of type clock_t) is a
 * signed integer, which can overflow.  It is not defined exactly how it
 * does this... This code assumes that the system will wrap around in some
 * obvious way.  The base of the time for this clock may be when the *system*
 * started... so when it overflows may depend on how long the system has been
 * up... which suggests that some sensible wrap around is likely (?).
 *
 * The qtime_t value is in nano-seconds.
 *
 * The result from times() is in units of sysconf(_SC_CLK_TCK) ticks per second.
 *
 * If clock_t is a signed 32-bit integer, which is kept +ve, then the clock
 * overflows/wraps round in 2^31 ticks which is:
 *
 *   at     100 ticks/sec: > 248 days
 *   at   1,000 ticks/sec: >  24 days
 *   at  10,000 ticks/sec: >  59 hours
 *
 * For safety, this asserts that sysconf(_SC_CLK_TCK) <= 1,000,000 for
 * sizeof(clock_t) > 4, but <= 1,000 for sizeof(clock_t) == 4.
 *
 * (It appears that 60, 100, 250 and 1,000 ticks/sec. are popular options.)
 *
 * If sizeof(clock_t) > 4, it is assumed large enough never to wrap around.
 * (But seems unlikely that such a system would not support CLOCK_MONOTONIC !)
 *
 * When clock_t is a 32-bit integer must be at least ready for wrap around.
 * We take the clock_t signed values and widen to 64-bit signed, so we have
 * the current sample (this) and the previous one (last), and two cases to
 * consider:
 *
 *   * +ve wrap around -- so value is 31-bit unsigned, and wraps from large
 *                        +ve value to small +ve value.
 *
 *       step = this - last   will be -ve
 *
 *     'last' will be some value ((INT32_MAX + 1) - x), and 'this' will be some
 *     (relatively) small value y.  The step is x + y, we have:
 *
 *       step = y - ((INT32_MAX + 1) - x) = (x + y) - (INT32_MAX + 1)
 *
 *     so we correct by adding (INT32_MAX + 1).
 *
 *   * -ve wrap around -- so value is 32-bit signed, and wraps from a large
 *                        +ve value to a very -ve value.
 *
 *       step = this - last   will be -ve
 *
 *     'last will' be some value (INT32_MAX + 1) - x, and 'this' will be some
 *     value (y - (INT32_MAX + 1)).  The step is x + y, we have:
 *
 *       step = (y - (INT32_MAX + 1)) - ((INT32_MAX + 1) - x)
 *            = (x + y) - 2 * (INT32_MAX + 1)
 *
 *     so we correct by adding (INT32_MAX + 1).
 *
 * In both cases the wrap around gives an apparently -ve 'step', and that is
 * corrected by adding (INT32_MAX + 1) until it goes +ve.
 *
 * In any event, a step > 24 hours is taken to means that something has gone
 * very, very badly wrong.
 *
 * NB: it is assumed that qt_craft_monotonic will be called often enough to
 *     ensure that the check on the step size will not be triggered !
 *
 * NB: it is assumed that times() does not simply stick if it overflows.
 *
 * TODO: Add a watchdog to monitor the behaviour of this clock ?
 */
Private qtime_mono_t
qt_craft_monotonic(void)
{
  clock_t      this_times_sample ;
  int64_t      result ;
  qtime_mono_t monotonic ;

  /* If clock_t is large enough then we can use it directly, and not keep the
   * times_monotonic up to date.
   *
   * Otherwise calculate the difference between this sample and the
   * previous one -- the step.
   *
   * We do the sum in signed 64 bits, and the samples are signed 64 bits.
   */
  this_times_sample = qt_times() ;

  if (sizeof(clock_t) > 4)
    result = this_times_sample ;
  else
    {
      int64_t step ;

      qpt_spin_lock(qt_slock) ;         /* <-<-<-<-<-<-<-<-<-<-<-<-<-<- */

      step = this_times_sample - last_times_sample ;

      while (step < 0)
        {
          /* If times() wraps unsigned, then result needs INT32_MAX + 1
           * adding to it to get to +ve result.
           *
           * If times() wraps signed, then result needs INT32_MAX + 1 adding
           * to it *twice*.
           */
          step += (uint64_t)INT32_MAX + 1 ;
        } ;

      result = times_monotonic + step ;

      times_monotonic   = result ;
      last_times_sample = this_times_sample ;

      qpt_spin_unlock(qt_slock) ;       /* <-<-<-<-<-<-<-<-<-<-<-<-<-<- */

      if (step > step_limit)
        zabort("Sudden large times_monotonic clock jump") ;
    } ;

  /* Scale to qtime_t units and, if required, make sure is, indeed, monotonic.
   */
  monotonic = result * times_scale_q ;

  if (times_scale_r != 0)
    monotonic += ((result * times_scale_r) / times_clk_tcks) ;

  if (qtime_debug)
    qt_track_monotonic(monotonic) ;

  return monotonic ;
} ;

/*==============================================================================
 * A simple minded random number generator.
 *
 * Uses time and other stuff to produce something which is not particularly
 * predictable... particularly the ms bits !
 */

/*------------------------------------------------------------------------------
 * Take q ^ s, reduce to 32 bits by parts together, then use Knuth recommended
 * linear congruent to "randomise" that, so that most of the original bits
 * affect the result.
 *
 * The result of the linear congruent thingie depends rather more on the low
 * order bits.  The values we are dealing with are times in nano-seconds
 * and addresses and such, the low order bits of which we have a little
 * doubt about.  Hence the "folding" we do on the value.
 *
 * Note that linear congruent tends to be "more random" in the ms bits.
 */
static inline uint32_t
qt_rand(uint64_t q, uint64_t s)
{
  q ^= s ;
  q  = (q ^ ((q >> 16) & 0xFFFF) ^ (q >> 32)) & 0xFFFFFFFF ;

  return ((q * 2650845021) + 5) & 0xFFFFFFFF ;
} ;

/*------------------------------------------------------------------------------
 * Random and largely unpredictable number.
 */
extern uint32_t
qt_random(uint32_t seed)
{
  union
  {
    uint32_t x, y, z ;
  } u ;

  uint64_t t ;

  t = qt_get_realtime() ;       /* in nano-seconds      */

  seed ^= qt_random_seed ;      /* munge a bit          */

  /* Set x by munging the time, the address of x, the current contents of x,
   * and the munged "seed".
   */
  u.x = qt_rand(t ^ (uint64_t)u.x ^ (uintptr_t)&u.x, seed) ;
                  /* munge the address and the contents with the seed   */

  /* Set y by munging the time, the address of y, the current contents of y,
   * and the munged "seed" inverted.
   */
  u.y = qt_rand(t ^ (uint64_t)u.y ^ (uintptr_t)&u.y, ~seed) ;
                  /* munge the current real time with the seed          */

  /* Munge x and y together to create result.
   *
   * Note that we swap the halves of y before munging, in order to spread
   * the "more random" part of y down to the ls end of the result.
   */
  u.z = u.x ^ ((u.y >> 16) & 0xFFFF) ^ ((u.y & 0xFFFF) << 16) ;

  /* Return x and y munged together.
   *
   * Note that we swap the halves of y before munging, in order to spread
   * the "more random" part of y down to the ls end of the result.
   */
  qt_random_seed ^= u.z ;       /* turn over the store of "randomness"  */

  return u.z ;
} ;

/*==============================================================================
 * Error handling
 */

static void qt_clock_failed(clockid_t clock_id, const char* op,
                                                          struct timespec* ts) ;

/*------------------------------------------------------------------------------
 * clock_gettime() for the given clock_id has failed
 *
 * See: qt_clock_gettime()
 *
 * Returns:  0 -- if returns
 */
Private void
qt_clock_gettime_failed(clockid_t clock_id, struct timespec* ts)
{
  return qt_clock_failed(clock_id, "clock_gettime", ts) ;
} ;

/*------------------------------------------------------------------------------
 * clock_getres() for the given clock_id has failed
 *
 * See: qt_clock_getres()
 */
Private void
qt_clock_getres_failed(clockid_t clock_id, struct timespec* ts)
{
  return qt_clock_failed(clock_id, "clock_getres", ts) ;
} ;

/*------------------------------------------------------------------------------
 * Report clock operation failure.
 */
Private void
qt_clock_failed(clockid_t clock_id, const char* op, struct timespec* ts)
{
  int err = errno ;

  if (clock_id == CLOCK_REALTIME)
    zabort(qfs_gen("failed to %s(CLOCK_REALTIME): %s", op,
                                                      errtoa(err, 0).str).str) ;

#ifdef HAVE_CLOCK_MONOTONIC
  if (clock_id == CLOCK_MONOTONIC)
    zabort(qfs_gen("failed to %s(CLOCK_MONOTONIC): %s", op,
                                                      errtoa(err, 0).str).str) ;
#endif

  zlog_err("failed to %s(%d): %s", op, clock_id, errtoa(err, 0).str) ;

  memset(ts, 0, sizeof(*ts)) ;
} ;

/*==============================================================================
 * qtime_period_t support
 */

/*------------------------------------------------------------------------------
 * Construct origin for qt_period_fm() and qt_mono_fp().
 *
 * The origin is the qtime_base_t origin, but with the LS 32 bits randomised.
 *
 * The objective is to allow many periodic timers to be running, at the same
 * rate, but not synchronised to each other !
 */
extern qtime_mono_t qt_period_origin(void)
{
  return qt_base_origin ^ qt_random(123456) ;
} ;

/*==============================================================================
 * For debug
 */

/*------------------------------------------------------------------------------
 * If the monotonic clock jumps around, we will be confused.
 *
 * For debug purposes we check each CLOCK_MONOTONIC result against the previous
 * one.  If it goes backwards by more than 1ms, then we complain.
 *
 * If the clock jumps forwards, then timers will go off early, which is not so
 * bad, and that is not detected here -- but the qpnexus watch-dog will detect
 * the monotonic and realtime clocks diverging.
 */
Private void
qt_track_monotonic(qtime_mono_t this)
{
  qtime_mono_t last ;

  qpt_spin_lock(qt_slock) ;     /* <-<-<-<-<-<-<-<-<-<-<-<-<-<- */

  last = track_monotonic ;
  track_monotonic = this ;

  qpt_spin_unlock(qt_slock) ;   /* <-<-<-<-<-<-<-<-<-<-<-<-<-<- */

  if ((this - last) < -(QTIME(1) / 1000))
    zlog_err("CLOCK_MONOTONIC gone backwards by: %ld", (long)(last - this)) ;
} ;

/*==============================================================================
 * Tracking the local timezone, so can:
 *
 *   a) rapidly convert clock_gettime(CLOCK_REALTIME, ...) times
 *
 *   b) do that thread-safe
 *
 *   c) do that async-signal-safe
 *
 * Assumptions:
 *
 *   a) that timezones are on at most 5 minute boundaries (15 probably!)
 *
 *   b) that DST changes are at least 60 days apart
 *
 *   c) that DST changes occur on times which are on 5 minute boundaries
 *      (60 probably -- but this means that the DST change is on a 5 minute
 *       boundary in local and epoch times !)
 *
 * Sets up and maintains a table containing 8 entries:
 *
 *   [-3] previous - 2
 *   [-2] previous - 1
 *   [-1] previous     -- previous 0-7 days
 *   [ 0] current      -- current  0-7 days
 *   [+1] next         -- next     0-7 days
 *   [+2] next     + 1
 *   [+3] next     + 2
 *   [ X] sentinal
 *
 * These are configured before any threads or anything else very much runs, so
 * they are essentially static.  There is a "current index", which is set to
 * '0' to start with.
 *
 * Each entry comprises:
 *
 *   * start time      -- entry is valid for epoch times >= start
 *   * end time        -- entry is valid for epoch times <  end
 *   * offset          -- add to epoch time to get local
 *
 * When set up the current timezone initially starts on the nearest 5 minute
 * boundary in the past, and covers up to 7 days into the future, unless the
 * timezone changes in that time.  The timezones on either side are set
 * similarly.
 *
 * At most one of these timezones may be a short one -- so this covers at least
 * 14 days into the past and 21 into the future, and as time advances, upto
 * 21 days into the past and down to 14 days into the future.
 *
 * Maximum range is 56 days -- which is within the assumed 60 days between
 * DST changes.
 *
 * When time advances past the current entry the next, next + 1 and + 2 cover
 * at least 14 days (21 if none are short entries).
 *
 * Every now and then (say every 5 minutes) a background process can check the
 * current time.  If that is no longer in the current entry, needs to update
 * the table.  Assuming time is moving forward: sets sentinal to be the next
 * 0-7 days following the current last entry, and updates the "current index".
 *
 * BIG ASSUMPTION: that the "current index" value is written atomically, wrt
 *                 to threads as well as signals.
 *
 *                 It doesn't matter if a thread or signal action code picks
 *                 up an out of date "current index" value, because all the
 *                 entries for the old state are still valid.
 *
 *                 No entry is changed while it is covered by the current
 *                 index -3..+3.
 *
 * This works fine, UNLESS the clock_gettime(CLOCK_REALTIME, ...) changes
 * dramatically -- as might happen if the operator adjusts the system clock a
 * long way !
 *
 * To cope with this, a spare set of 8 entries are kept, and a new table can
 * be built (under mutex).  The worst that happens is that threads may be
 * blocked waiting for the table to be updated.
 *
 * If the table is found to be out of date when a signal is bringing the
 * system down, then the times logged will just have to use either the first
 * or the last entry, and have done with it.
 */

