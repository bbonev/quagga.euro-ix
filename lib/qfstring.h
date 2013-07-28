/* Some fixed size string handling -- header
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

#ifndef _ZEBRA_QFSTRING_H
#define _ZEBRA_QFSTRING_H

#include "misc.h"
#include "vargs.h"

#include "qlump.h"
#include "qtime.h"

/*==============================================================================
 * These "qf_str" address the issues of dealing with *fixed* length
 * strings, particularly where the string handling must be async-signal-safe.
 *
 * Are also used to support snprintf() style printing, but to one or more
 * fixed length buffers.
 *
 * All operations that can possibly be async-signal-safe, are.  Notable
 * exception is anything involving floating point values -- because of the
 * state contain in floating point status/option registers !
 *
 * The qf_str structure is the same as a qstring, which in turn is a qlump.
 *
 * The properties of a qf_str are:
 *
 *    * body        -- pointer to the actual string
 *    * size        -- size of that -- may be zero
 *    * cp          -- current pointer -- this is where new stuff is 'put'
 *    * len         -- length of the string, see below
 *
 *    * state       -- not used by qf_str -- initialised qls_unset
 *    * mytype      -- not used by qf_str -- initialised MTYPE_NULL
 *
 * All the operations which put stuff into qf_str use the qfs->cp.  All the
 * operations treat the actual fixed length body of the qf_str as a window
 * onto a much, much larger string.  The qfs->cp can be -ve and can be greater
 * than the size of the qf_str.  A put operation will advance qfs->cp as if
 * the string were of indefinite length, writing to the actual string when
 * 0 <= qfs->cp < qfs->size.
 *
 * The qfs->len is ignored by the put operations.
 *
 * When putting to a qf_str, will work right up to and including the last
 * byte.  Does not terminate the string -- that must be done explicitly.
 */
typedef qlump_t  qf_str_t[1] ;
typedef qlump_t  qf_str_s ;
typedef qlump_t* qf_str ;

/*------------------------------------------------------------------------------
 * Print format flags for number printing
 */
enum pf_flags
{
  pf_none       = 0,

  /* The following signal how to render the value
   *
   * Note that the encoding for integer, floating point and IP address
   * conversions overlap.
   */
  pf_how_mask   = BIT(3) - 1,           /* 0..7 possible "how"  */
  pf_how_shift  = 0,

  pf_int_dec    = 0 << pf_how_shift,
  pf_int_oct    = 1 << pf_how_shift,
  pf_int_hex    = 2 << pf_how_shift,

  pf_float_g    = 0 << pf_how_shift,
  pf_float_f    = 1 << pf_how_shift,
  pf_float_e    = 2 << pf_how_shift,
  pf_float_a    = 3 << pf_how_shift,

  pf_ipv4       = 0 << pf_how_shift,
  pf_ipv6       = 1 << pf_how_shift,
  pf_ipv6_ipv4  = 2 << pf_how_shift,
  pf_ipv6_raw   = 3 << pf_how_shift,

  pf_uc         = BIT(3),       /* upper-case                   */
  pf_lc         = 0,            /* lower-case                   */

  /* The following correspond to the standard "flags"
   *
   * Note that C standard specifies that ' ' is ignored if '+' seen.
   */
  pf_commas     = BIT( 4),      /* "'": *non-standard*          */
  pf_plus       = BIT( 5),      /* '+': add '+' if >= 0         */
  pf_space      = BIT( 6),      /* ' ': add ' ' if >= 0         */
  pf_zeros      = BIT( 7),      /* '0': add leading 0's         */
  pf_alt        = BIT( 8),      /* '#': "alternative" form      */

  /* Non-standard flags
   */
  pf_plus_nz    = BIT( 9),      /* add '+' if > 0               */

  /* A precision part (empty or otherwise) has been seen
   */
  pf_precision  = BIT(11),      /* '.' seen                     */

  /* For scaled formatting of decimals and byte counts
   */
  pf_scale      = BIT(12),      /* scale and add scale tag      */
  pf_trailing   = BIT(13),      /* add blank scale if required  */

  /* The following signal the type of value
   */
  pf_ptr        = BIT(14),      /* is a pointer         */
  pf_unsigned   = BIT(15),      /* unsigned value       */

  /* Common combination
   */
  pf_hex_x      = pf_unsigned | pf_int_hex,
  pf_hex_X      = pf_unsigned | pf_int_hex | pf_uc,

  pf_void_p     = pf_ptr | pf_hex_x,
} ;

typedef enum pf_flags pf_flags_t ;

CONFIRM(pf_none == pf_int_dec) ;
CONFIRM(pf_none == pf_float_g) ;

/*==============================================================================
 * Fixed Size String Buffers
 *
 * This supports the common case of a function whose task is to construct a
 * (small) string of known maximum length, which will promptly be output
 * or something similar.
 *
 * This scheme removes the need for the caller to construct a small buffer
 * and pass it to the string constructor.  The "magic" is to make the callee
 * return a struct containing the result.  So the callee is, for example:
 *
 *   foo_t make_foo(...) { ... } ;
 *
 * where foo_t is a struct, with a "str" element large enough for all known
 * foo.  So the caller can, for example:
 *
 *   printf("...%s...", ..., make_foo(...).str, ...) ;
 *
 * All the fiddling around with buffers and buffer sizes is hidden from the
 * caller.  And, since the buffer is implicitly on the stack, this is thread
 * safe (and async-signal-safe, provided make_foo() is).
 *
 * The macro: QFB_T(name, len) declares a fixed length buffer type.  So:
 *
 *   QFB_T(79) foo_t ;
 *
 * declares:
 *
 *   typedef struct { char str[79 + 1] ; } foo_t ;
 *
 * NB: the length given *excludes* the terminating '\0' ;
 *
 * NB: the type declared has the "_t" added *automatically*.
 *
 * Having declared a suitable type, function(s) can be declared to return
 * a string in a value of that type.
 *
 * A string generating function can use the buffer directly, for example:
 *
 *   foo_t make_foo(...)
 *   {
 *     foo_t foo_buf ;
 *
 *       ...  foo_buf.str          is the address of the string buffer
 *       ...  sizeof(foo_buf.str)  is its length *including* the '\0'
 *
 *     return foo_buf ;
 *   } ;
 *
 * The qfstring facilities may be used to construct the string, and to
 * facilitate that, the macro QFB_QFS declares the buffer and a qf_str_t and
 * initialises same, thus:
 *
 *   foo_t QFB_QFS(foo_buf, foo_qfs) ;
 *
 * declares:
 *
 *   foo_t    foo_buf ;
 *   qf_str_t foo_qfs = { ...initialised for empty foo... } ;
 *
 * So the string generator can use foo_qfs and qfstring facilities to fill in
 * the string in foo_buf, and then return foo_buf (having terminated it) as
 * above.
 *
 * So... with two macros we reduce the amount of fiddling about required to
 * do something reasonably simple.
 *
 * NB: it is quite possible that the compiler will allocate two buffers, one
 *     in the caller's stack frame and one in the callee's, and returning the
 *     value will involve copying from one to the other.
 */
#define QFB_T(len) \
  typedef struct { char str[((len) | 7) + 1] ; }

#define QFB_QFS(qfb, qfs) \
   qfb ; \
  qf_str_t qfs = { { .body.v   = qfb.str,            \
                     .size     = sizeof(qfb.str),    \
                     .state    = qls_unset,          \
                     .mtype    = 0,                  \
                     .len      = 0,                  \
                     .cp       = 0  } }

/* A "standard" qfb for general use: qfb_gen_t
 */
enum { qfb_gen_len = 200 } ;    /* More than enough for most purposes ! */
QFB_T(qfb_gen_len) qfb_gen_t ;

/* A "standard" qfb for names: qfb_nam_t
 */
enum { qfb_nam_len = 60 } ;     /* More than enough for most purposes ! */
QFB_T(qfb_nam_len) qfb_nam_t ;

/*==============================================================================
 * Simple keyword support
 *
 * A "keyword table" is an array of qfs_keyword_t, the last entry of which
 * has a NULL word, eg:
 *
 *   static qfs_keyword_t deny_permit_table[] =
 *   {
 *     { .word = "deny",    .val = 0 },
 *     { .word = "permit",  .val = 1 },
 *     { .word = NULL }
 *   } ;
 */
typedef struct qfs_keyword
{
  const char* word ;
  uint        val ;             /* NB: <= MAX_INT       */
} qfs_keyword_t ;

/*==============================================================================
 * Functions
 */
extern void qfs_init(qf_str qfs, char* str, uint size) ;
extern void qfs_reset(qf_str qfs) ;
extern void qfs_init_offset(qf_str qfs, char* str, uint size, uint offset) ;
extern void qfs_reset_offset(qf_str qfs, uint offset) ;
extern void qfs_init_as_is(qf_str qfs, char* str, uint size) ;

Inline uint qfs_overflow(qf_str qfs) ;
extern uint qfs_term(qf_str qfs) ;
extern void qfs_term_string(qf_str qfs, const char* src, uint n) ;
Inline const char* qfs_string(qf_str qfs) ;

Inline uint qfs_len(qf_str qfs) ;

extern void qfs_put_ch(qf_str qfs, char ch) ;
extern void qfs_put_str(qf_str qfs, const char* src) ;
extern void qfs_put_n(qf_str qfs, const char* src, uint n) ;
extern void qfs_put_ch_x_n(qf_str qfs, char ch, uint n) ;
extern void qfs_put_n_hex(qf_str qfs, const byte* src, uint n, pf_flags_t pf) ;
extern void qfs_put_justified(qf_str qfs, const char* src, int width) ;
extern void qfs_put_justified_n(qf_str qfs, const char* src,
                                                            uint n, int width) ;

extern void qfs_put_signed(qf_str qfs, intmax_t s_val, pf_flags_t flags,
                                                     int width, int precision) ;
extern void qfs_put_unsigned(qf_str qfs, uintmax_t u_val, pf_flags_t flags,
                                                     int width, int precision) ;
extern void qfs_put_double(qf_str qfs, double val, pf_flags_t flags,
                                                     int width, int precision) ;
extern void qfs_put_long_double(qf_str qfs, long double val, pf_flags_t flags,
                                                     int width, int precision) ;
extern void qfs_put_pointer(qf_str qfs, void* p_val, pf_flags_t flags,
                                                     int width, int precision) ;
extern void qfs_put_ip_address(qf_str qfs, const void* p_ip, pf_flags_t flags,
                                                                    int width) ;
extern void qfs_put_ip_prefix(qf_str qfs, const void* p_ip, byte plen,
                                                  pf_flags_t flags, int width) ;

extern void qfs_printf(qf_str qfs, const char* format, ...)
                                                       PRINTF_ATTRIBUTE(2, 3) ;
extern qfb_gen_t qfs_gen(const char* format, ...)      PRINTF_ATTRIBUTE(1, 2) ;

extern void qfs_vprintf(qf_str qfs, const char *format, va_list args) ;

Inline uint qfs_strlen(const char* str) ;

extern int qfs_keyword_lookup(qfs_keyword_t* table, const char* str,
                                                                  bool strict) ;
extern int qfs_keyword_lookup_nocase(qfs_keyword_t* table, const char* str,
                                                                  bool strict) ;
extern int qfs_keyword_lookup_abstract(void* a_array, const char* str,
                                                                  bool strict,
                           const char* (*a_lookup)(void* a_array, uint index)) ;

/*------------------------------------------------------------------------------
 * Construction of numbers from rlong and other stuff.
 *
 * Need enough space for sign, then groups of 3 decimal digits plus ',' or '\0'.
 * For 64 bits comes out at 29 bytes !
 */
enum { qfs_number_len = 1 + (((64 + 9) / 10) * (3 + 1)) } ;

CONFIRM((sizeof(rlong) * 8) <= 64) ;

QFB_T(qfs_number_len) qfs_num_str_t ;

extern qfs_num_str_t qfs_put_dec_value(rlong val, pf_flags_t flags) ;
extern qfs_num_str_t qfs_put_bin_value(rlong val, pf_flags_t flags) ;

/* Time period expressed as +999,999d99h99m99.999s (22 characters !)
 */
CONFIRM(qfs_number_len > (1+4+4+3+3+3+4)) ;

extern qfs_num_str_t qfs_put_time_period(qtime_t val, pf_flags_t flags) ;

/*==============================================================================
 * The Inline functions.
 */

/*------------------------------------------------------------------------------
 * Current length of qf_str.
 *
 * If the qfs->cp has moved beyond the qfs->len, then will update that.
 *
 * This allows all the "put" operations to proceed without worrying about the
 * qfs->len.  Only when the qfs->len is required does its value crystallize.
 *
 * In all cases, qfs->len is clamped to the qfs->size.
 *
 * When a qf_str is initialised, qfs->len is set to zero.  So, having put
 * stuff to the qf_str, and advanced qfs->cp, calling qfs_len() establishes
 * how much has been put to the fixed length string (zero if qfs->cp <= 0,
 * qfs->size if qfs->cp > qfs->size).
 */
Inline uint
qfs_len(qf_str qfs)
{
  uint cp, len ;

  cp  = qfs->cp ;
  len = qfs->len ;

  if ((cp > len) && (cp < QLUMP_SIZE_NEGATIVE))
    qfs->len = len = cp ;

  if (len > qfs->size)
    qfs->len = len = qfs->size ;

  return len ;
} ;

/*------------------------------------------------------------------------------
 * Did everything we put in the qfs, fit ?.
 *
 * Returns:  number of chars that did *not* fit.
 *
 * NB: an absence of overflow does not guarantee there is space for a '\0'
 *     terminator, if one is required.
 */
Inline uint
qfs_overflow(qf_str qfs)
{
  uint cp, size ;

  size = qfs->size ;
  cp   = qfs->cp ;

  if ((cp <= size) || (cp >= QLUMP_SIZE_NEGATIVE))
    return 0 ;

  return cp - size ;
} ;

/*------------------------------------------------------------------------------
 * Insert '\0' terminator and return address of string.
 *
 * Sets len to the terminated string length -- which excludes the '\0'.
 *
 * If required, overwrites the last character of the string with the '\0'.
 *
 * Does not change cp.
 *
 * NB: this all makes no sense
 */
Inline const char*
qfs_string(qf_str qfs)
{
  qfs_term(qfs) ;
  return qfs->body.c ;
} ;

/*------------------------------------------------------------------------------
 * async-signal-safe strlen
 */
Inline uint
qfs_strlen(const char* str)
{
  const char* s ;

  s = str ;

  if (s != NULL)
    while (*s != '\0')
      ++s ;

  return s - str ;
} ;

#endif /* _ZEBRA_QFSTRING_H */
