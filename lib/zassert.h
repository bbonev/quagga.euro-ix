/*
 * $Id: zassert.h,v 1.2 2004/12/03 18:01:04 ajs Exp $
 */

#ifndef _QUAGGA_ASSERT_H
#define _QUAGGA_ASSERT_H

#include "misc.h"
#include "confirm.h"

extern void _zlog_assert_failed (const char *assertion, const char *file,
                                 unsigned int line, const char *function)
                                                                     No_Return ;
extern void _zlog_abort_mess (const char *mess, const char *file,
                                 unsigned int line, const char *function)
                                                                     No_Return ;

extern void _zlog_abort_errno (const char *mess, const char *file,
                                 unsigned int line, const char *function)
                                                                     No_Return ;

extern void _zlog_abort_err (const char *mess, int err, const char *file,
                                 unsigned int line, const char *function)
                                                                     No_Return ;

extern bool _zlog_critical (const char *mess, const char *file,
                                      unsigned int line, const char *function) ;

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define __ASSERT_FUNCTION    __func__
#elif defined(__GNUC__)
#define __ASSERT_FUNCTION    __FUNCTION__
#else
#define __ASSERT_FUNCTION    NULL
#endif

#define zassert(EX) ((void)((EX) ?  0 : \
                            (_zlog_assert_failed(#EX, __FILE__, __LINE__, \
                                                        __ASSERT_FUNCTION), 0)))

/* Implicitly *permanent* assert() -- irrespective of NDEBUG
 */
#undef assert
#define assert(EX) zassert(EX)

/* Explicitly permanent assert()
 */
#define passert(EX) zassert(EX)

/* NDEBUG time assert()
 */
#ifndef NDEBUG
# define dassert(EX) zassert(EX)
#else
# define dassert(EX)
#endif

/* Assert iff QDEBUG
 */
#define qassert(EX) zassert(!qdebug || (EX))

/* Abort with message
 */
#define zabort(MS) _zlog_abort_mess(MS, __FILE__, __LINE__, __ASSERT_FUNCTION)

/* Abort with message and errno and strerror() thereof
 */
#define zabort_errno(MS) _zlog_abort_errno(MS, __FILE__, __LINE__, \
                                                              __ASSERT_FUNCTION)

/* Abort with message and given error and strerror() thereof
 */
#define zabort_err(MS, ERR) _zlog_abort_err(MS, ERR, __FILE__, __LINE__, \
                                                              __ASSERT_FUNCTION)

/* If QDEBUG, abort with message, otherwise log a critical error.
 */
#define zcritical(MS) (qdebug ? (zabort(MS), true) : \
                      _zlog_critical(MS, __FILE__, __LINE__, __ASSERT_FUNCTION))

/* If QDEBUG, then assert, otherwise, if would assert, log a "critical" error.
 *
 * Returns: true  <=> critical error
 *          false <=> OK
 */
#define qcritical_failed(EX) ((EX) ? false : zcritical(#EX))

#endif /* _QUAGGA_ASSERT_H */
