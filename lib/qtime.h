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

/* A qtime_t second                 123456789 -- nano-seconds             */
#define QTIME_SECOND     ((qtime_t)1000000000)
#define TIMESPEC_SECOND  ((int64_t)1000000000)
#define TIMEVAL_SECOND   ((int64_t)1000000)

/* Macro to convert time in seconds to a qtime_t
 *
 * Note that the time to convert may be a float.
 */
#define QTIME(s) ((qtime_t)((s) * QTIME_SECOND))

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

#endif /* _ZEBRA_QTIME_H */
