/* Quagga realtime and monotonic clock handling -- header
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

#ifndef _ZEBRA_QTIME_H
#define _ZEBRA_QTIME_H

#include "misc.h"

#include <time.h>
#include <sys/time.h>
#include <unistd.h>

/*------------------------------------------------------------------------------
 * Sort out QTIME_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if QTIME_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set QTIME_DEBUG    == 0 to turn off debug
 *       *  or set QTIME_DEBUG    != 0 to turn on debug
 *       *  or set QTIME_NO_DEBUG != 0 to force debug off
 */

#ifdef QTIME_DEBUG              /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(QTIME_DEBUG)
#  undef  QTIME_DEBUG
#  define QTIME_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define QTIME_DEBUG QDEBUG
#endif

#ifdef QTIME_NO_DEBUG           /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(QTIME_NO_DEBUG)
#  undef  QTIME_DEBUG
#  define QTIME_DEBUG 0
# endif
#endif

enum { qtime_debug  = QTIME_DEBUG } ;

/*==============================================================================
 * qtime_t -- signed 64-bit integer.
 *
 * The various system/POSIX time functions work in terms of the structures:
 *
 *   timespec   -- tv_secs    seconds
 *                 tv_nsecs   nano-seconds
 *
 *   timeval    -- tv_secs    seconds
 *                 tv_usecs   micro-seconds
 *
 * Given a 64-bit integer it is much easier to do operations on a 64 bit
 * (signed) nano-second value.  That gives > 34 bits for the seconds count,
 * and counts from zero to > 290 years.
 */
typedef int64_t qtime_t ;

typedef qtime_t qtime_real_t ;  /* qtime_t value, realtime time-base      */
typedef qtime_t qtime_mono_t ;  /* qtime_t value, monotonic time-base     */

typedef qtime_t qtime_tod_t ;   /* qtime_t value, timeofday time-base...  */
                                /* ...just in case != CLOCK_REALTIME !    */

/* struct timeval works in micro-seconds
 */
#define TIMEVAL_SECOND   ((int64_t)1000 * 1000)

/* struct timespec and qtime_t work in nano-seconds
 */
#define TIMESPEC_SECOND  ((int64_t)1000 * 1000 * 1000)
#define QTIME_SECOND     ((qtime_t)1000 * 1000 * 1000)
#define QMILLI_SECOND    ((qtime_t)1000 * 1000)
#define QMICRO_SECOND    ((qtime_t)1000)
#define QNANO_SECOND     ((qtime_t)1)

#define QTIME_MAX INT64_MAX

/* Macro to convert time in seconds to a qtime_t
 *
 * Note that the time to convert may be a float -- rounds *down*.
 */
#define QTIME_SECONDS(s)       ((qtime_t)((s) * QTIME_SECOND))
#define QTIME_MILLI_SECONDS(s) ((qtime_t)((s) * QMILLI_SECOND))
#define QTIME_MICRO_SECONDS(s) ((qtime_t)((s) * QMICRO_SECOND))
#define QTIME_NANO_SECONDS(s)  ((qtime_t)((s) * QNANO_SECOND))

#define QTIME(s) QTIME_SECONDS(s)

/* Construct qt_have_clock_monotonic from HAVE_CLOCK_MONOTONIC
 */
enum
{
  qt_have_clock_monotonic
#ifdef HAVE_CLOCK_MONOTONIC
                         = true
#else
                         = false
#endif
};

/* A "base" time -- based on monotonic time -- is supported.
 *
 * The monotonic time is defined by POSIX to start at "an unspecified point in
 * the past (for example, system start-up time or the Epoch)" but also
 * specifies that the "point does not change after system start-up time".
 *
 * For some purposes it is useful to have a version of monotonic time which
 * starts near but not at zero, for the application.  Not at zero, so that
 * zero can signify unset or undefined.  Near zero so that some, reasonable,
 * period into the past can be represented.
 *
 * So a "base" time is a version of monotonic time, whose origin is shifted
 * so that "time zero" (when the application woke up) is a little after day 3
 * -- 2^48 nano-seconds.
 *
 * qt_base_origin is set to be the monotonic time of "base time zero".
 *
 * See qt_mono_fb() and qt_base_fm().
 *
 * One use of "base" times is to construct low resolution time values.  A
 * simple way to do that is to shift off some number of LS bits, leaving some
 * fraction of "binary seconds" -- a binary second is just less than 1.074 sec.
 * Given that the base time is in nano-seconds, with various shifts a 32-bit
 * unsigned value can hold:
 *
 *   qt_base_t >> 24 -- resolution ~0.0168 sec -- range >   2.2 year
 *   qt_base_t >> 25 -- resolution ~0.0336 sec -- range >   4.5 year
 *   qt_base_t >> 26 -- resolution ~0.0671 sec -- range >   9.1 year
 *   qt_base_t >> 27 -- resolution ~0.1342 sec -- range >  18.2 year
 *   qt_base_t >> 28 -- resolution ~0.2684 sec -- range >  36.5 year
 *   qt_base_t >> 29 -- resolution ~0.5370 sec -- range >  73.1 year
 *   qt_base_t >> 30 -- resolution ~1.0737 sec -- range > 146.2 year
 *   qt_base_t >> 31 -- resolution ~2.1475 sec -- range > 292.4 year
 */
typedef uint64_t qtime_base_t ;

#define QT_BASE_ZERO  ((qtime_mono_t)1 << 48)

CONFIRM(QT_BASE_ZERO > QTIME(78 * 60 * 60)) ;
CONFIRM(QT_BASE_ZERO < QTIME(79 * 60 * 60)) ;

Private qtime_mono_t qt_base_origin ;

/* A low resolution time based on a qtime_base_t is a qtime_period_t
 */
typedef uint64_t qtime_period_t ;

enum
{
  QTIME_PERIOD_MIN = 0,                 /* unsigned     */
  QTIME_PERIOD_MAX = UINT64_MAX,
} ;

/*==============================================================================
 * Functions
 */
extern void qt_start_up(void) ;
extern void qt_second_stage(void) ;
extern void qt_finish(void) ;

Inline qtime_t timespec2qtime(struct timespec* p_ts) ;
Inline qtime_t timeval2qtime(struct timeval* p_tv) ;
Inline struct timespec* qtime2timespec(struct timespec* p_ts, qtime_t qt) ;
Inline struct timeval* qtime2timeval(struct timeval* p_tv, qtime_t qt) ;

Inline qtime_real_t qt_get_realtime(void) ;
Inline qtime_mono_t qt_add_realtime(qtime_t interval) ;
Inline qtime_mono_t qt_get_monotonic(void) ;
Inline qtime_mono_t qt_add_monotonic(qtime_t interval) ;
Inline time_t qt_get_mono_secs(void) ;

Inline qtime_base_t qt_base_fm(qtime_mono_t mono) ;
Inline qtime_mono_t qt_mono_fb(qtime_base_t base) ;
Inline qtime_period_t qt_period_fm(qtime_mono_t mono, qtime_mono_t origin,
                                                                   uint shift) ;
Inline qtime_mono_t qt_mono_fp(qtime_period_t period, qtime_mono_t origin,
                                                                   uint shift) ;
Inline qtime_period_t qt_periods(qtime_t ns, uint shift) ;
extern qtime_mono_t qt_period_origin(void) ;

Inline qtime_tod_t qt_get_timeofday(void) ;
Inline qtime_tod_t qt_add_timeofday(qtime_t interval) ;

extern uint32_t qt_random(uint32_t seed) ;

Private qtime_mono_t qt_craft_monotonic(void) ;

Private void qt_clock_gettime_failed(clockid_t clock_id, struct timespec* ts) ;
Private void qt_clock_getres_failed(clockid_t clock_id, struct timespec* ts) ;
Private void qt_track_monotonic(qtime_mono_t this) ;

/*==============================================================================
 * Inline conversion functions
 */

/*------------------------------------------------------------------------------
 * Convert timespec to qtime_t
 *
 * Returns qtime_t value.
 */
Inline qtime_t
timespec2qtime(struct timespec* p_ts)
{
  return QTIME(p_ts->tv_sec) + p_ts->tv_nsec ;
  confirm(QTIME_SECOND == TIMESPEC_SECOND) ;
} ;

/*------------------------------------------------------------------------------
 * Convert timeval to qtime_t
 *
 * Returns qtime_t value.
 */
Inline qtime_t
timeval2qtime(struct timeval* p_tv)
{
  return QTIME(p_tv->tv_sec) + (p_tv->tv_usec * 1000) ;
  confirm(QTIME_SECOND == TIMEVAL_SECOND      * 1000) ;
} ;

/*------------------------------------------------------------------------------
 * Convert qtime_t to timespec
 *
 * Takes address of struct timespec and returns that address.
 */
Inline struct timespec*
qtime2timespec(struct timespec* p_ts, qtime_t qt)
{
  lldiv_t imd = lldiv(qt, QTIME_SECOND) ;
  confirm(sizeof(long long) >= sizeof(qtime_t)) ;

  p_ts->tv_sec  = imd.quot ;
  p_ts->tv_nsec = imd.rem ;
  confirm(TIMESPEC_SECOND == QTIME_SECOND) ;

  return p_ts ;
} ;

/*------------------------------------------------------------------------------
 * Convert timespec to qtime_t
 *
 * Takes address of struct timespec and returns that address.
 */
Inline struct timeval*
qtime2timeval(struct timeval* p_tv, qtime_t qt)
{
  lldiv_t imd = lldiv(qt, QTIME_SECOND) ;
  confirm(sizeof(long long) >= sizeof(qtime_t)) ;

  p_tv->tv_sec  = imd.quot ;
  p_tv->tv_usec = imd.rem / 1000 ;
  confirm(TIMEVAL_SECOND  * 1000 == QTIME_SECOND) ;

  return p_tv ;
} ;

/*==============================================================================
 * Clocks.
 *
 * Here is support for:
 *
 *   * System Clock
 *
 *     This can be read using either clock_gettime(CLOCK_REALTIME, &ts) or
 *     gettimeofday(&tv, NULL) -- which (are believed to) return the same clock,
 *     but in different units.
 *
 *   * Monotonic Clock
 *
 *     Using clock_gettime(CLOCK_MONOTONIC, &ts) if it is available, otherwise
 *     a manufactured equivalent using times() -- see qt_craft_monotonic().
 */

Inline void qt_clock_gettime_ts(clockid_t clock_id, struct timespec* ts) ;
Inline void qt_clock_getres_ts(clockid_t clock_id, struct timespec* ts) ;

/*------------------------------------------------------------------------------
 * Read given clock & return a qtime_t value.
 *
 * For CLOCK_REALTIME and CLOCK_MONOTONIC any failure is (a) exotic, to say
 * the least, and (b) impossible to recover from.
 *
 * For other clocks, it may be possible to continue, so we return zero and
 * leave it up to the caller to worry (should they care) that the clock either
 * occasionally or consistently returns 0 !
 */
Inline qtime_t
qt_clock_gettime(clockid_t clock_id)
{
  struct timespec ts[1] ;

  qt_clock_gettime_ts(clock_id, ts) ;

  return timespec2qtime(ts) ;
} ;

/*------------------------------------------------------------------------------
 * Get resolution of the given clock.
 *
 * For CLOCK_REALTIME and CLOCK_MONOTONIC any failure is (a) exotic, to say
 * the least, and (b) impossible to recover from.
 *
 * For other clocks, it may be possible to continue, so we return a resolution
 * of 0 nanoseconds per clock tick and leave it up to the caller to worry !
 *
 * NB: beware of dividing by this without checking for possible error !!
 */
Inline qtime_t
qt_clock_getres(clockid_t clock_id)
{
  struct timespec ts[1] ;

  qt_clock_getres_ts(clock_id, ts) ;

  return timespec2qtime(ts) ;
} ;

/*------------------------------------------------------------------------------
 * clock_gettime(CLOCK_REALTIME, ...) -- returning qtime_t value
 *
 * While possibility of error is essentially theoretical, must treat it as a
 * FATAL error -- cannot continue with broken time value !
 */
Inline qtime_real_t
qt_get_realtime(void)
{
  return qt_clock_gettime(CLOCK_REALTIME) ;
} ;

/*------------------------------------------------------------------------------
 * qt_get_realtime() + interval
 */
Inline qtime_real_t
qt_add_realtime(qtime_t interval)
{
  return qt_get_realtime() + interval;
} ;

/*------------------------------------------------------------------------------
 * clock_gettime(CLOCK_MONOTONIC, ...) OR qt_craft_monotonic()
 *                                                   -- returning qtime_t value
 *
 * While possibility of error is essentially theoretical, must treat it as a
 * FATAL error -- cannot continue with broken time value !
 */
Inline qtime_mono_t
qt_get_monotonic(void)
{
  if (qt_have_clock_monotonic)
    return qt_clock_gettime(CLOCK_MONOTONIC) ;
  else
    return qt_craft_monotonic() ;
} ;

/*------------------------------------------------------------------------------
 * qt_get_monotonic() + interval
 */
Inline qtime_mono_t
qt_add_monotonic(qtime_t interval)
{
  return qt_get_monotonic() + interval;
} ;

/*------------------------------------------------------------------------------
 * clock_gettime(CLOCK_MONOTONIC, ...) OR qt_craft_monotonic()
 *                                                    -- returning time_t value
 *
 * Value returned is in seconds -- for coarser grain timings.
 *
 * While possibility of error is essentially theoretical, must treat it as a
 * FATAL error -- cannot continue with broken time value !
 */
Inline time_t
qt_get_mono_secs(void)
{
  if (qt_have_clock_monotonic)
    {
      struct timespec ts ;

      qt_clock_gettime_ts(CLOCK_MONOTONIC, &ts) ;
      return ts.tv_sec ;
    }
  else
    return qt_craft_monotonic() / QTIME(1) ;
} ;

/*------------------------------------------------------------------------------
 * gettimeofday(&tv, NULL) -- returning qtime_t value
 */
Inline qtime_tod_t
qt_get_timeofday(void)
{
  struct timeval tv ;
  gettimeofday(&tv, NULL) ;
  return timeval2qtime(&tv) ;
}

/*------------------------------------------------------------------------------
 * qt_get_timeofday() + interval
 */
Inline qtime_tod_t
qt_add_timeofday(qtime_t interval)
{
  return qt_get_timeofday() + interval;
} ;

/*------------------------------------------------------------------------------
 * Read given clock, filling in given struct timespec and dealing with any
 * error.
 */
Inline void
qt_clock_gettime_ts(clockid_t clock_id, struct timespec* ts)
{
  if (clock_gettime(clock_id, ts) != 0)
    qt_clock_gettime_failed(clock_id, ts) ;

  if (qtime_debug && (clock_id == CLOCK_MONOTONIC))
    qt_track_monotonic(timespec2qtime(ts)) ;
} ;

/*------------------------------------------------------------------------------
 * Read given clock's resolution, filling in given struct timespec and dealing
 * with any error.
 */
Inline void
qt_clock_getres_ts(clockid_t clock_id, struct timespec* ts)
{
  if (clock_getres(clock_id, ts) != 0)
    qt_clock_getres_failed(clock_id, ts) ;
} ;

/*==============================================================================
 * Conversion qtime_mono_t <-> qtime_base_t
 */

/*------------------------------------------------------------------------------
 * Get qtime_base_t from qtime_mono_t
 */
Inline qtime_base_t
qt_base_fm(qtime_mono_t mono)
{
  return (qtime_base_t)(mono - qt_base_origin) ;
} ;

/*------------------------------------------------------------------------------
 * Get qtime_mono_t from qtime_base_t
 */
Inline qtime_mono_t
qt_mono_fb(qtime_base_t base)
{
  return (qtime_mono_t)base + qt_base_origin ;
} ;

/*==============================================================================
 * Conversion qtime_mono_t <-> qtime_period_t
 */

/*------------------------------------------------------------------------------
 * Get qtime_period_t from qtime_mono_t
 *
 * Adjusts to period origin and then truncates nano-seconds to period units,
 * by shift.
 */
Inline qtime_period_t
qt_period_fm(qtime_mono_t mono, qtime_mono_t origin, uint shift)
{
  return ((qtime_period_t)(mono - origin)) >> shift ;
} ;

/*------------------------------------------------------------------------------
 * Get qtime_mono_t from qtime_period_t
 *
 * Convert period units to nano-seconds by shift and re-adjust from period
 * origin.
 */
Inline qtime_mono_t
qt_mono_fp(qtime_period_t period, qtime_mono_t origin, uint shift)
{
  return (qtime_mono_t)(period << shift) + origin ;
} ;

/*------------------------------------------------------------------------------
 * Get qtime_period_t from qtime_t -- rounding up
 */
Inline qtime_period_t
qt_periods(qtime_t ns, uint shift)
{
  return ((qtime_period_t)(ns + (1 << shift) - 1)) >> shift ;
} ;



#endif /* _ZEBRA_QTIME_H */
