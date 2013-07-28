/* Miscellaneous basic definitions
 * Copyright (C) 2010 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_MISC_H
#define _ZEBRA_MISC_H

/* "zconfig.h" is included at the start of this "misc.h", and at the start
 * of "zebra.h".  This ensures that we get <features.h> defined early, so
 * that all other #includes get the same set of features.
 */
#include "zconfig.h"

/*------------------------------------------------------------------------------
 * Macros for sexing value of compilation options.
 *
 * In particular allow a blank option to be treated as true, and a zero option
 * to be treated as false.
 *
 * NB: the option MUST be defined, and must be decimal numeric !!
 */
#define STRING_VALUE_INNER(x)  #x
#define STRING_VALUE(x) STRING_VALUE_INNER(x)

#define IS_BLANK_OPTION(x)     IS_BLANK_OPTION_INNER(x)
#define IS_ZERO_OPTION(x)      IS_ZERO_OPTION_INNER(x)
#define IS_NOT_ZERO_OPTION(x)  IS_NOT_OPTION_ZERO_INNER(x)

#define IS_BLANK_OPTION_INNER(x)    (1##x##1 ==  11)
#define IS_ZERO_OPTION_INNER(x)     (1##x##1 == 101)
#define IS_NOT_ZERO_OPTION_INNER(x) (1##x##1 != 101)

/* If QDEBUG is defined, make QDEBUG_NAME and set QDEBUG
 *
 *  Numeric value for QDEBUG: undefined      => 0
 *                            defined, blank => 1
 *                            defined, 0     => 0
 *                            defined, other => other
 *
 * Template for turning compilation option into a value.
 */
#ifdef QDEBUG
# if IS_BLANK_OPTION(QDEBUG)
#  undef  QDEBUG
#  define QDEBUG 1
# endif
#else
# define QDEBUG 0
#endif

enum { qdebug = QDEBUG } ;

#ifndef QDEBUG_NAME
# define QDEBUG_NAME STRING_VALUE(QDEBUG)
#endif

/*------------------------------------------------------------------------------
 * Get compiler specific issues dealt with ASAP
 */

/* __attribute__((always_inline)) -- or equivalent, where available !
 */
#ifdef __GNUC__
#define Always_Inline __attribute__((always_inline))
#else
#define Always_Inline
#warning __attribute__((always_inline)) not available ??
#endif

/* __attribute__((noreturn)) -- or equivalent, where available
 */
#ifdef __GNUC__
#define No_Return __attribute__((noreturn))
#else
#define No_Return
#warning __attribute__((noreturn)) not available ??
#endif

/* __attribute__((unused)) -- or equivalent, where available
 */
#ifdef __GNUC__
#define Unused __attribute__((unused))
#else
#define Unused
#warning __attribute__((unused)) not available ??
#endif

/* __attribute__((aligned(X)))
 */
#ifdef __GNUC__
#define Alignment(unit) __attribute__((aligned(unit))))
#define Must_Align(unit) Alignment(unit)
#else
#define Alignment(unit)
#warning __attribute__((aligned(X))) not available ??
#define Must_Align(unit) __attribute__((aligned(unit))))!!!
#endif

#if 0
/* Extract the largest alignment.
 */
/* __attribute__((aligned(X)))
 */
#ifdef __BIGGEST_ALIGNMENT__

# if (__BIGGEST_ALIGNMENT__ + 0) > 0

#  if   (__BIGGEST_ALIGNMENT__ <= 16) && QDEBUG
#   if (__BIGGEST_ALIGNMENT__ > 8)
#    warning Note: __BIGGEST_ALIGNMENT__ > 8
#   endif
#  elif QDEBUG
#   warning SURPRISE: __BIGGEST_ALIGNMENT__ > 16 !!
#  endif

#  if ((__BIGGEST_ALIGNMENT__ - 1) & __BIGGEST_ALIGNMENT__) != 0
#   warning SURPRISE: __BIGGEST_ALIGNMENT__ is not a power of 2 !!
#  endif

# else
#  error Sorry... really need a sensible value for __BIGGEST_ALIGNMENT__ !!
# endif

#else

# ifdef __GNUC__
# warning Expect GNUC to provide __BIGGEST_ALIGNMENT__
# endif

# error Sorry... really need a value for __BIGGEST_ALIGNMENT__ !!
# define __BIGGEST_ALIGNMENT__ -1

#endif

#define ALIGNOF_BIGGEST __BIGGEST_ALIGNMENT__
#endif

/*------------------------------------------------------------------------------
 * Now a "minimum" set of includes
 */
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>          /* htons etc.           */

#include "confirm.h"
#include "zassert.h"

/*------------------------------------------------------------------------------
 * Odds and sods
 */

/* ROUND_UP to multiple of 'n' -- NB: result may be zero
 */
#define ROUND_UP(v, n) ((((v) + (n) - 1) / (n)) * (n))

/* ROUND_UP_UP to multiple of 'n' -- NB: result will be greater by at least 'n'
 */
#define ROUND_UP_UP(v, n) ((((v) / (n)) + 1) * (n))

/* Bit number to bit mask
 */
#define BIT(b)  (1 << (b))

/* The LS bit of a given value
 */
#define LS_BIT(v) ((v) ^ ((v) & ((v) - 1)))

/* The given value is a power of 2
 */
#define IS_POW_OF_2(v) (((v) & ((v) - 1)) == 0)

/* Just in case there are compiler issues
 */
#define Inline static inline

/* For things which have to be made extern -- typically because they are
 * used by an inline function -- but are not for public consumption.
 */
#define Private extern

/* For use in switch/case
 */
#define fall_through

/*------------------------------------------------------------------------------
 * A bit of a kludge for alignof...
 *
 * If we have an alignof() we can use, we use it.
 *
 * Otherwise, we here make a fake alignof()... but use of that depends on
 * having earlier done: Need_Alignof(blah_t) ;
 *
 * Note: Need_alignof(blah_t) can be done just before the alignof() which
 *       needs it, or at any time after blah_t is fully defined -- the
 *       alignof() just needs the typedef which Need_alignof(blah_t) creates.
 *
 * NB: The blah_t must be a name... not, say, "struct foo" -- which real
 *     alignof() supports!
 */
#ifndef HAVE_ALIGNOF
# if defined(__GNUC__) && false
#  define HAVE_ALIGNOF
#  define alignof(q_t) __alignof__(q_t)
# else
#  define alignof(q_t) offsetof(_alignof_##q_t##_, q)
#  define alignofx(q_t) offsetof(struct { char x ; q_t q ; }, q)
# endif
#endif

#define Need_alignof(q_t) typedef struct { char x ; q_t q ; } _alignof_##q_t##_

/*------------------------------------------------------------------------------
 * Various names for true/false pairs
 *
 * And noting that explicit cast to bool does what you would want.
 */
CONFIRM(((bool)99 == true) && ((bool)0 == false)) ;

enum on_off
{
  on   = true,
  off  = false
} ;
typedef enum on_off on_off_b ;

enum add
{
  add     = true,
  no_add  = false,
  del     = false,
} ;
typedef enum add add_b ;

enum free_keep
{
  free_it = true,
  keep_it = false
} ;
typedef enum free_keep free_keep_b ;

/*------------------------------------------------------------------------------
 * Short hand to help with pointers.
 *
 * Pointer to byte and unsigned equivalent:  ptr_t and uptr_t
 *
 * const void* stuff:
 *
 *         cvp  == const void*          -- ptr to constant void
 *         cvp* == const void**         -- ptr to ptr to constant void
 *   const cvp* == const void* const*   -- ptr to constant ptr to constant void
 *
 * For a constant "object" tend to define:
 *
 *   typedef struct bar  bar_t ;        -- "object" "body"
 *   typedef struct bar* bar ;          -- "object" as passed around
 *   typedef struct bar const* bar_c ;  -- constant object as passed around
 *
 * Occasionally also:
 *
 *   typedef const struct bar  bar_ct ; -- constant "object" "body"
 *
 * ...which may be used for compile-time instantiated objects.  Though can use
 * "const bar_t" just the same.
 *
 * It seems to be straightforward to switch between "bar_c" and "cvp".
 *
 * Less straightforward is mixing "bar_c*" and "cvp*", or "const bar_c*" and
 * "const cvp*".... for reasons which one day one might understand.
 */
typedef uint8_t*        ptr_t ;
typedef const uint8_t*  ptr_c ;

typedef uintptr_t uptr_t ;

typedef const void* cvp ;

/*------------------------------------------------------------------------------
 * Various integer stuff
 *
 * We really want to be able to assume that an 'int' is at least 32 bits
 * and 'short' is at least 16 bits.  Commonly, for 32-bit and 64-bit
 * machines these are exactly 32 and 16 bits, respectively.  In future, if
 * 'int' goes to 64 bits on a 128-bit machine, tant pis !
 *
 * We have a problem with 'long' which, sadly, may or may not be longer than
 * 'int'.  Here what we have is:
 *
 *   * 'long' with typedefs 'ilong' and 'ulong'
 *
 *     mean whatever the compiler gives.  In 64-bit world that tends to
 *     be 64 bits.
 *
 *     This can be used where something longer than 'int' would be preferable,
 *     but is not absolutely essential.
 *
 *   * typedefs 'rlong' and 'urlong'
 *
 *     mean either 'long' or 'long long', to give something which is longer
 *     than 'int'.
 *
 *     Note: will throw errors and fail to define things if neither is longer
 *     than 'int' !
 *
 * We define:
 *
 *   #define RLONG_IS_LONG  ...  -- 0 or 1
 *   #define RLONG_IS_LLONG ...  -- 0 or 1
 *
 *   typedef ... rlong           -- long int or long long int
 *   typedef ... urlong          -- unsigned long int or unsigned long long int
 *
 *   #define RLONG_MAX  ...      -- LONG_MAX or LLONG_MAX
 *   #define RLONG_MIN  ...      -- LONG_MIN or LLONG_MIN
 *   #define URLONG_MAX ...      -- ULONG_MAX or ULLONG_MAX
 *
 * Also:
 *
 *   #define fRL ".."            -- "l" or "ll" for printf etc.
 *
 * And, to complete the picture:
 *
 *   typedef ... rldiv_t  and rldiv()
 */
CONFIRM(USHRT_MAX >= 0xFFFF) ;                  /* 16 bits      */
CONFIRM(UINT_MAX  >= 0xFFFFFFFF) ;              /* 32 bits      */

CONFIRM((ULONG_MAX > UINT_MAX) || (ULLONG_MAX > UINT_MAX)) ;

/* Some useful shorthand
 */
typedef uint8_t        byte ;
typedef unsigned char  uchar ;

typedef unsigned short ushort ;

typedef unsigned int   uint ;
typedef unsigned int   usize ;
typedef unsigned int   ulen ;

enum
{
  BYTE_MAX   = UINT8_MAX,
  USIZE_MAX  = UINT_MAX,
  ULEN_MAX   = UINT_MAX,
} ;

typedef          int   ssize ;
typedef          int   slen ;

typedef          long  ilong ;
typedef unsigned long  ulong ;

typedef          long long llong ;
typedef unsigned long long ullong ;

typedef  intmax_t imax ;
typedef uintmax_t umax ;

#if (LONG_MAX > INT_MAX)
/* 'long' is longer than 'int'
 */
#define RLONG_IS_LONG  1
#define RLONG_IS_LLONG 0

typedef          long rlong ;
typedef unsigned long urlong ;

#define RLONG_MIN  LONG_MIN
#define RLONG_MAX  LONG_MAX
#define URLONG_MAX ULONG_MAX

#define fRL "l"

#else
/* 'long' is not longer than 'int', so 'long long' had better be !
 */
#define RLONG_IS_LONG  0

# if (LLONG_MAX > INT_MAX)
#  define RLONG_IS_LLONG 1
# else
#  error Neither 'long int' nor 'long long int' are longer than 'int'
#  define RLONG_IS_LLONG 0
# endif

typedef          long long rlong ;
typedef unsigned long long urlong ;

#define RLONG_MIN  LLONG_MIN
#define RLONG_MAX  LLONG_MAX
#define URLONG_MAX ULLONG_MAX

#define fRL "ll"

#endif

#if RLONG_IS_LONG
typedef ldiv_t rldiv_t ;
#else
typedef lldiv_t rldiv_t ;
#endif

Inline rldiv_t
rldiv(rlong numer, rlong denom)
{
#if RLONG_IS_LONG
  return ldiv(numer, denom) ;
#else
  return lldiv(numer, denom) ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Rounding
 *
 *   uround_up()    rounds to nearest multiple if 'unit' upwards
                    which may return the original value -- which may be zero.
 *
 *   uround_up_up() rounds up to next multiple of 'unit'
 *                  result is always >= original value + 'unit'
 */
Inline uint
uround_up(uint val, uint unit)
{
  return ((val + unit - 1) / unit) * unit ;
} ;

Inline uint
uround_up_up(uint val, uint unit)
{
  return ((val / unit) + 1) * unit ;
} ;

/*------------------------------------------------------------------------------
 * Reliable abs functions -- returning uint etc.
 *
 * By "reliable" we mean: works with INT_MIN etc.
 */
CONFIRM( ((uint)(-(INT_MIN + 1)) + 1) == -((intmax_t)INT_MIN) ) ;

Inline uint
uabs(int x)
{
  if (x >= 0)
    return x ;
  else
    return (uint)(-(x + 1)) + 1 ;
} ;

Inline ulong
ulabs(ilong x)
{
  if (x >= 0)
    return x ;
  else
    return (ulong)(-(x + 1)) + 1 ;
} ;

Inline ullong
ullabs(llong x)
{
  if (x >= 0)
    return x ;
  else
    return (ullong)(-(x + 1)) + 1 ;
} ;

Inline urlong
urlabs(rlong x)
{
#if RLONG_IS_LONG
  return ulabs(x) ;
#else
  return ullabs(x) ;
#endif
} ;

Inline umax
umaxabs(imax x)
{
  if (x >= 0)
    return x ;
  else
    return (umax)(-(x + 1)) + 1 ;
} ;

/*------------------------------------------------------------------------------
 * Reliable abs functions -- returning uint etc and the sign.
 */
Inline uint
uabs_s(int x, int* sign)
{
  if (x >= 0)
    {
      *sign = (x == 0) ? 0 : + 1 ;
      return x ;
    }
  else
    {
      *sign = -1 ;
      return (uint)(-(x + 1)) + 1 ;
    } ;
} ;

Inline ulong
ulabs_s(long x, int* sign)
{
  if (x >= 0)
    {
      *sign = (x == 0) ? 0 : + 1 ;
      return x ;
    }
  else
    {
      *sign = -1 ;
      return (ulong)(-(x + 1)) + 1 ;
    } ;
} ;

Inline ullong
ullabs_s(llong x, int* sign)
{
  if (x >= 0)
    {
      *sign = (x == 0) ? 0 : + 1 ;
      return x ;
    }
  else
    {
      *sign = -1 ;
      return (ullong)(-(x + 1)) + 1 ;
    } ;
} ;

Inline urlong
urlabs_s(rlong x, int* sign)
{
#if RLONG_IS_LONG
  return ulabs_s(x, sign) ;
#else
  return ullabs_s(x, sign) ;
#endif
} ;

Inline umax
umaxabs_s(imax x, int* sign)
{
  if (x >= 0)
    {
      *sign = (x == 0) ? 0 : + 1 ;
      return x ;
    }
  else
    {
      *sign = -1 ;
      return (umax)(-(x + 1)) + 1 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * htonq/ntohq -- sadly missing elsewhere
 *
 * Also qbswap16/qbswap32/qbswap64 --
 */
Inline uint16_t qbswap16(uint16_t u) Always_Inline ;
Inline uint32_t qbswap32(uint32_t u) Always_Inline ;
Inline uint64_t qbswap64(uint64_t u) Always_Inline ;

Inline uint64_t htonq(uint64_t q) Always_Inline ;
Inline uint64_t ntohq(uint64_t q) Always_Inline ;

#if   defined(HAVE_BYTESWAP_H)
/* The GNU C Library provides this
 */
#include <byteswap.h>

Inline uint16_t
qbswap16(uint16_t u)
{
  return bswap_16(u) ;
} ;

Inline uint32_t
qbswap32(uint32_t u)
{
  return bswap_32(u) ;
} ;

Inline uint64_t
qbswap64(uint64_t u)
{
  return bswap_64(u) ;
} ;

#elif defined(HAVE_SYS_ENDIAN_H)
#include <sys/endian.h>
/* This is the BSD way.
 */

Inline uint16_t
qbswap16(uint16_t u)
{
  return bswap16(u) ;
} ;

Inline uint32_t
qbswap32(uint32_t u)
{
  return bswap32(u) ;
} ;

Inline uint64_t
qbswap64(uint64_t u)
{
  return bswap64(u) ;
} ;

#else
/* This is the fall back
 */

Inline uint16_t
qbswap16(uint16_t u)
{
  return (u << 8) | (u >> 8) ;
} ;

Inline uint32_t
qbswap32(uint32_t u)
{
  return    (u >> 24)           |  (u           << 24)
         | ((u >>  8) & 0xFF00) | ((u & 0xFF00) <<  8) ;
} ;

Inline uint64_t
qbswap64(uint64_t u)
{
  return   (u >> 56)               |  (u               << 56)
        | ((u >> 40) & 0x0000FF00) | ((u & 0x0000FF00) << 40)
        | ((u >> 24) & 0x00FF0000) | ((u & 0x00FF0000) << 24)
        | ((u >>  8) & 0xFF000000) | ((u & 0xFF000000) <<  8) ;
} ;

#endif

Inline uint64_t
htonq(uint64_t hq)
{
#if   BYTE_ORDER == BIG_ENDIAN
  return hq ;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return qbswap64(hq) ;
#endif
} ;

Inline uint64_t
ntohq(uint64_t nq)
{
#if   BYTE_ORDER == BIG_ENDIAN
  return nq ;
#elif BYTE_ORDER == LITTLE_ENDIAN
  return qbswap64(nq) ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Set of functions to load/store Network Order short/long/quad values.
 *
 * These use memcpy to load/store the Network Order values.  Experience is that
 * compilers convert these to single operations, where the processor allows it.
 */
Inline uint8_t  load_b( const void* p) Always_Inline ;
Inline uint16_t load_ns(const void* p) Always_Inline ;
Inline uint32_t load_nl(const void* p) Always_Inline ;
Inline uint64_t load_nq(const void* p) Always_Inline ;

Inline void store_b( void* p, uint8_t  b) Always_Inline ;
Inline void store_ns(void* p, uint16_t s) Always_Inline ;
Inline void store_nl(void* p, uint32_t l) Always_Inline ;
Inline void store_nq(void* p, uint64_t q) Always_Inline ;

Inline uint8_t
load_b(const void* p)
{
  return *((const uint8_t*)p) ;
}

Inline uint16_t
load_ns(const void* p)
{
  uint16_t s ;

  memcpy(&s, p, 2) ;

  return ntohs(s) ;
} ;

Inline uint32_t
load_nl(const void* p)
{
  uint32_t l ;

  memcpy(&l, p, 4) ;

  return ntohl(l) ;
} ;

Inline uint64_t
load_nq(const void* p)
{
  uint64_t q ;

  memcpy(&q, p, 8) ;

  return ntohq(q) ;
} ;

Inline void
store_b(void* p, uint8_t b)
{
  *((uint8_t*)p) = b ;
}

Inline void
store_ns(void* p, uint16_t s)
{
  s = htons(s) ;
  memcpy(p, &s, 2) ;
} ;

Inline void
store_nl(void* p, uint32_t l)
{
  l = htonl(l) ;
  memcpy(p, &l, 4) ;
} ;

Inline void
store_nq(void* p, uint64_t q)
{
  q = htonq(q) ;
  memcpy(p, &q, 8) ;
} ;

/*------------------------------------------------------------------------------
 * Set of functions to load/store short/long/quad values.
 *
 * These do not change the order of the bytes -- so, for example, if was
 * originally Network Order, remains in Network Order.
 *
 * These use memcpy to load/store the values.  Experience is that compilers
 * convert these to single operations, where the processor allows it.
 */
Inline uint16_t load_s(const void* p) Always_Inline ;
Inline uint32_t load_l(const void* p) Always_Inline ;
Inline uint64_t load_q(const void* p) Always_Inline ;
Inline void*    load_p(const void* p) Always_Inline ;

Inline void store_s(void* p, uint16_t s) Always_Inline ;
Inline void store_l(void* p, uint32_t l) Always_Inline ;
Inline void store_q(void* p, uint64_t q) Always_Inline ;
Inline void store_p(void* p, void* v)    Always_Inline ;

Inline uint16_t
load_s(const void* p)
{
  uint16_t s ;

  memcpy(&s, p, 2) ;

  return s ;
} ;

Inline uint32_t
load_l(const void* p)
{
  uint32_t l ;

  memcpy(&l, p, 4) ;

  return l ;
} ;

Inline uint64_t
load_q(const void* p)
{
  uint64_t q ;

  memcpy(&q, p, 8) ;

  return q ;
} ;

Inline void*
load_p(const void* p)
{
  uintptr_t pi ;

  memcpy(&pi, p, sizeof(uintptr_t)) ;

  return (void*)pi ;
} ;

Inline void
store_s(void* p, uint16_t s)
{
  memcpy(p, &s, 2) ;
} ;

Inline void
store_l(void* p, uint32_t l)
{
  memcpy(p, &l, 4) ;
} ;

Inline void
store_q(void* p, uint64_t q)
{
  memcpy(p, &q, 8) ;
} ;

Inline void
store_p(void* p, void* v)
{
  uintptr_t pi ;

  pi = (uintptr_t)v ;
  memcpy(p, &pi, sizeof(uintptr_t)) ;
} ;

/*==============================================================================
 * Extended versions of strtol etc.
 *
 * NB: these use the 'rlong' to ensure that the results are, indeed, long
 *     compared to 'int' !
 */
typedef enum
{
  strtox_signed   = 1,          /* OK and '+' or '-' was present        */
  strtox_ok       = 0,          /* OK                                   */

  strtox_invalid  = -1,         /* badly formed or empty number         */
  strtox_range    = -2,         /* out of range                         */
} strtox_t ;

extern rlong  strtol_x(const char* restrict str, strtox_t* p_tox,
                                                           const char** p_end) ;
extern urlong strtoul_x(const char* restrict str, strtox_t* p_tox,
                                                            const char** p_end);
extern rlong  strtol_xr(const char* restrict str, strtox_t* p_tox,
                                     const char** p_end, rlong min, rlong max) ;
extern urlong strtoul_xr(const char* restrict str, strtox_t* p_tox,
                                   const char** p_end, urlong min, urlong max) ;

/*------------------------------------------------------------------------------
 * Simpler versions of the above -- for when the string is known to be valid,
 * or no extra information is required if it is not.
 */
extern rlong  strtol_s(const char* restrict str) ;
extern urlong strtoul_s(const char* restrict str);
extern rlong  strtol_sr(const char* restrict str, rlong min, rlong max) ;
extern urlong strtoul_sr(const char* restrict str, urlong min, urlong max) ;

/*==============================================================================
 * Where the standard strtol or strtoul will do, BUT want rlong and urlong !
 */
Inline rlong
strtorl(const char* restrict string, char** restrict tailptr, int base)
{
#if RLONG_IS_LONG
  return strtol(string, tailptr, base) ;
#else
  return strtoll(string, tailptr, base) ;
#endif
} ;

Inline urlong
strtourl(const char* restrict string, char** restrict tailptr, int base)
{
#if RLONG_IS_LONG
  return strtoul(string, tailptr, base) ;
#else
  return strtoull(string, tailptr, base) ;
#endif
} ;

/*==============================================================================
 * Generating strings for integer values.
 *
 * The various buffers are large enough for the maximum value, in octal (!)
 * plus sign, leading '0' and trailing '\0'.  Ther are, therefore, plenty big
 * enough for hex plus sign, leading '0x' and trailing '0x'.
 *
 * NB: the functions do NOT insert a trailing '\0'.
 *
 * NB: the functions MUST be given a pointer to the LAST byte of the buffer.
 *
 *     The strings are generated LS digit first.  The LS digit is written
 *     at (ptr - 1).
 *
 *     Nothing is written at or beyond the given pointer, and the value
 *     returned will be < the given pointer.
 */
enum
{
  uint_digits     = ((sizeof(uint)      * 8) + 2) / 3,
  uint_buf_size   = (((1 + 1 + uint_digits   + 1) + 7) / 8) * 8,

  ulong_digits    = ((sizeof(ulong)     * 8) + 2) / 3,
  ulong_buf_size  = (((1 + 1 + ulong_digits  + 1) + 7) / 8) * 8,

  ullong_digits   = ((sizeof(ullong)    * 8) + 2) / 3,
  ullong_buf_size = (((1 + 1 + ullong_digits + 1) + 7) / 8) * 8,

  umax_digits     = ((sizeof(uintmax_t) * 8) + 2) / 3,
  umax_buf_size   = (((1 + 1 + umax_digits   + 1) + 7) / 8) * 8,
} ;

typedef char uint_buf_t[uint_buf_size] ;
typedef char ulong_buf_t[ulong_buf_size] ;
typedef char ullong_buf_t[ullong_buf_size] ;
typedef char umax_buf_t[umax_buf_size] ;

extern char*    itostr(char* ptr,    int v, uint base, bool uc) ;
extern char*    utostr(char* ptr,   uint v, uint base, bool uc) ;
extern char*   iltostr(char* ptr,   long v, uint base, bool uc) ;
extern char*   ultostr(char* ptr,  ulong v, uint base, bool uc) ;
extern char*  illtostr(char* ptr,  llong v, uint base, bool uc) ;
extern char*  ulltostr(char* ptr, ullong v, uint base, bool uc) ;
extern char* imaxtostr(char* ptr,   imax v, uint base, bool uc) ;
extern char* umaxtostr(char* ptr,   umax v, uint base, bool uc) ;

typedef char u32_buf_t[uint_buf_size] ;

Inline char*
irltostr(char* ptr,  rlong v, uint base, bool uc)
{
#if RLONG_IS_LONG
  return iltostr(ptr, v, base, uc) ;
#else
  return illtostr(ptr, v, base, uc) ;
#endif
} ;

Inline char*
urltostr(char* ptr, urlong v, uint base, bool uc)
{
#if RLONG_IS_LONG
  return ultostr(ptr, v, base, uc) ;
#else
  return ulltostr(ptr, v, base, uc) ;
#endif
} ;

Inline char*
u32tostr(char* ptr,    int v, uint base, bool uc)
{
  confirm(sizeof(uint) >= sizeof(uint32_t)) ;

  return utostr(ptr, v, base, uc) ;
} ;

/*==============================================================================
 * String functions
 */
Inline char* strncpy_x(char* restrict dst, const char* restrict src,
                                                                  size_t size) ;
extern char* strtolower(char* str) ;
extern char* strtrim_space(char* str) ;
extern char* strtrim_blank(char* str) ;

extern int strcmp_mixed(const void* restrict a, const void* restrict b) ;
extern int strcmp_lax(const void* restrict a, const void* restrict b) ;

/*------------------------------------------------------------------------------
 * strncpy() except that it ensures the last byte is '\0'.
 *
 * Two cases:
 *
 *  * strlen(src) <  size
 *
 *    strncpy() copies the string and then zeroizes the rest of the dst.
 *
 *    strncpy_x() is the same.
 *
 *  * strlen(src) >= size
 *
 *    strncopy() copies the first size characters, which leaves dst with an
 *    unterminated string !
 *
 *    strncpy_x() copies the first size - 1 characters, and plants a final '\0'.
 */
Inline char*
strncpy_x(char* restrict dst, const char* restrict src, size_t size)
{
  strncpy(dst, src, size) ;
  dst[size - 1] = '\0' ;

  return dst ;
} ;

#endif /* _ZEBRA_MISC_H */
