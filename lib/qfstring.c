/* Some fixed size string handling
 * Copyright (C) 2010 Chris Hall (GMCH), Highwayman
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

#include <stdio.h>
#include <ctype.h>

#include "qfstring.h"
#include "vargs.h"

/*==============================================================================
 * Initialise, etc.
 *
 * The qf_str is NOT dynamically allocated.
 */

/*------------------------------------------------------------------------------
 * Initialise qf_str -- to given size, zero offset and zero overflow.
 *
 * Note that does not terminate the string -- that must be done separately.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_init(qf_str qfs, char* str, uint size)
{
  memset(qfs, 0, sizeof(qf_str_t)) ;

  confirm(QLUMP_UNSET == 0) ;

  qfs->body.v   = str ;
  qfs->size     = size ;
} ;

/*------------------------------------------------------------------------------
 * Reset qf_str to completely empty, with zero offset.
 *
 * Note that does not terminate the string -- that must be done separately.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_reset(qf_str qfs)
{
  qfs->len = 0 ;
  qfs->cp  = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Initialise qf_str -- to given size, with given offset.
 *
 * Note that does not terminate the string -- that must be done separately.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_init_offset(qf_str qfs, char* str, uint size, uint offset)
{
  assert(offset <= QLUMP_SIZE_MAX) ;

  memset(qfs, 0, sizeof(qf_str_t)) ;

  confirm(QLUMP_UNSET == 0) ;

  qfs->body.v   = str ;
  qfs->size     = size ;
  qfs->cp       = 0 - offset ;
} ;

/*------------------------------------------------------------------------------
 * Reset given qf_str -- with the given offset.
 *
 * Sets ptr back to the start of the string and set the given offset.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_reset_offset(qf_str qfs, uint offset)
{
  assert(offset <= QLUMP_SIZE_MAX) ;

  qfs->len = 0 ;
  qfs->cp  = 0 - offset ;
} ;

/*------------------------------------------------------------------------------
 * Initialise qf_str which already contains string -- to given size.
 *
 * This may be used to prepare for appending to a buffer which already contains
 * a '\0' terminated string.
 *
 * Sets cp = len to point at the existing '\0'.
 *
 * This operation is async-signal-safe.
 *
 * NB: if the size given is less than the length of the string (excluding the
 *     trailing '\0'), then the qfs has already overflowed !
 */
extern void
qfs_init_as_is(qf_str qfs, char* str, uint size)
{
  ulen cp ;

  memset(qfs, 0, sizeof(qf_str_t)) ;

  confirm(QLUMP_UNSET == 0) ;

  qfs->body.v   = str ;
  qfs->size     = size ;

  cp = 0 ;
  while (str[cp] != '\0')
    ++cp ;

  qfs->cp = cp  ;                       /* point at '\0'        */

  if (cp <= size)
    qfs->len = cp ;
  else
    qfs->len = size ;
} ;

/*------------------------------------------------------------------------------
 * Insert '\0' terminator at cp -- overwrites the last byte, if required.
 *
 * If cp is:
 *
 *   * -ve: leaves it alone, but sets len = 0
 *
 *   *  < size: sets len = cp
 *
 *   * >= size: sets len = cp = size - 1
 *
 *              unless size == 0, in which case sets cp = len = 0
 *
 * Result cp == len -- unless cp -ve.
 *
 * Result len does not include the '\0'.
 *
 * Returns:  number of chars that did *not* fit (after using one for '\0').
 *
 * NB: if size == 0 (!) then does not plant '\0', and the number of chars that
 *     did not fit will be >= 1.
 *
 * This operation is async-signal-safe.
 */
extern uint
qfs_term(qf_str qfs)
{
  char*  str ;
  uint   cp ;
  uint   len ;
  uint   size ;
  uint   over ;

  str  = qfs->body.c ;
  size = qfs->size ;
  cp   = qfs->cp ;

  if (cp < size)
    {
      /* Majority case -- cp +ve and within the size and size > 0
       */
      len  = cp ;
      over = 0 ;
    }
  else if (cp >= QLUMP_SIZE_NEGATIVE)
    {
      /* For cp -ve, everything fits -- unless size == 0 !!
       */
      len  = 0 ;
      over = 0 ;

      if (size == 0)
        return 1 ;
    }
  else if (size > 0)
    {
      /* cp +ve: cp > size > 0
       */
      len  = size - 1 ;         /* set to maximum               */
      over = cp - len ;         /* hence overflow               */

      qfs->cp = len ;           /* force cp within qfs          */
    }
  else
    {
      /* cp +ve: cp > size == 0
       *
       * Stupid case... but force 'len' and 'cp' = 0 and overflow includes the
       * '\0'.
       */
      qfs->len = qfs->cp = 0 ;
      return cp + 1 ;
    } ;

  /* Set len to the (new) len, plant terminator and return overflow count.
   */
  qfs->len = len ;
  str[len] = '\0' ;

  return over ;
} ;

/*------------------------------------------------------------------------------
 * Terminate string at cp with the given string of given length (which may
 * include a terminating '\0').
 *
 * If necessary, characters are discarded from the end of the string in order
 * to fit in the terminating stuff.
 *
 * If the terminating stuff won't fit, as much of the end if the terminating
 * stuff as possible is copied to the string -- displacing any existing
 * contents.
 *
 * If cp is -ve, treats it as zero.
 *
 * Result cp == len -- even if cp was -ve.
 *
 * Result len does not include any '\0' on the end of the given string.
 *
 * NB: if size == 0 (!) then plants nothing, and cp = len = 0
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_term_string(qf_str qfs, const char* src, uint n)
{
  uint   cp ;
  uint   size ;

  size = qfs->size ;
  cp   = qfs->cp ;

  if (cp >= QLUMP_SIZE_NEGATIVE)
    cp = 0 ;                    /* treat -ve as zero            */

  if ((cp + n) > size)
    {
      /* Exception cases
       */
      if (size >= n)
        cp = size - n ;
      else
        {
          src += n - size ;     /* step past what won't fit     */
          cp   = 0 ;
          n    = size ;
        } ;
    } ;

  if ((size != 0) && (n != 0))
    {
      char*  str ;
      char   ch ;

      str  = qfs->body.c ;

      do
        str[cp++] = ch = *src++ ;
      while (--n) ;

      if (ch == '\0')
        cp -= 1 ;
    } ;

  qfs->len = qfs->cp = cp ;
} ;

/*==============================================================================
 * Putting stuff into a qfstring
 *
 * All the put operations write to the current 'cp' position in the qfstring,
 * thus:
 *
 *   * advance the 'cp' as if the string was of indefinite size.
 *
 *   * discard stuff until the 'cp' is +ve.
 *
 *   * discard stuff while 'cp' > 'size'
 *
 *   * do NOT change 'len' -- qfs_len() will update the 'len' and return
 *     its value.
 *
 *   * does not maintain a '\0' at the end of the string
 */
static const char lc_hex[] = "0123456789abcdef" ;
static const char uc_hex[] = "0123456789abcdef" ;

/*------------------------------------------------------------------------------
 * Put as much as possible of the source string to the given qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_str(qf_str qfs, const char* src)
{
  uint  size ;
  uint  cp ;
  char* str ;
  char  ch ;

  if (src == NULL)
    return ;

  str  = qfs->body.c ;
  size = qfs->size ;
  cp   = qfs->cp ;

  while ((ch = *src++) != '\0')
    {
      if (cp < size)
        str[cp] = ch ;

      cp += 1 ;
    } ;

  qfs->cp  = cp ;
} ;

/*------------------------------------------------------------------------------
 * Put as much as possible of the first 'n' bytes of the source string to
 * the given qf_str.
 *
 * src may be NULL iff n == 0
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_n(qf_str qfs, const char* src, uint n)
{
  uint  size ;
  uint  cp, ncp ;
  char* str ;

  cp   = qfs->cp ;
  size = qfs->size ;

  ncp     = cp + n ;
  qfs->cp = ncp;                /* update immediately   */

  if (cp >= QLUMP_SIZE_NEGATIVE)
    {
      if ((ncp >= QLUMP_SIZE_NEGATIVE) || (ncp == 0))
        return ;

      src += (n - ncp) ;        /* ncp is number of characters can take */
      n    = ncp ;
      cp   = 0 ;
    } ;

  if (ncp > size)
    {
      if (cp >= size)
        return ;

      n = size - cp ;
    } ;

  str = qfs->body.c ;
  while (n--)
    str[cp++] = *src++ ;
} ;

/*------------------------------------------------------------------------------
 * Put upto 'n' copies of the given character to the qf_str
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_ch_x_n(qf_str qfs, char ch, uint n)
{
  uint  size ;
  uint  cp, ncp ;
  char* str ;

  cp   = qfs->cp ;
  size = qfs->size ;

  ncp     = cp + n ;
  qfs->cp = ncp;                /* update immediately   */

  if (cp >= QLUMP_SIZE_NEGATIVE)
    {
      if ((ncp >= QLUMP_SIZE_NEGATIVE) || (ncp == 0))
        return ;

      n  = ncp ;                /* ncp is number of characters can take */
      cp = 0 ;
    } ;

  if (ncp > size)
    {
      if (cp >= size)
        return ;

      n = size - cp ;
    } ;

  str = qfs->body.c ;
  while (n--)
    str[cp++] = ch ;
} ;

/*------------------------------------------------------------------------------
 * Put as much as possible of the source string to the given qf_str, as
 * hex digit pairs.
 *
 *   pf_uc/pf_lc    -- case to use for the hex
 *
 *   pf_space       -- separate hex pairs by space
 *   pf_alt         -- precede by space -- except if n == 0 !
 */
extern void
qfs_put_n_hex(qf_str qfs, const byte* src, uint n, pf_flags_t pf)
{
  const byte* e ;
  const char* pd ;
  char scratch[3] ;
  uint l ;

  if (n == 0)
    return ;

  if (pf & pf_alt)
    qfs_put_ch(qfs, ' ') ;

  l =  (pf & pf_space) ?      3 :      2 ;
  pd = (pf & pf_uc)    ? uc_hex : lc_hex ;

  confirm(pf_uc != 0) ;

  scratch[2] = ' ' ;

  e = src + n ;
  while (1)
    {
      byte b ;

      b = *src++ ;

      scratch[0] = pd[(b >> 4) & 0xF] ;
      scratch[1] = pd[ b       & 0xF] ;

      if (src == e)
        break ;

      qfs_put_n(qfs, scratch, l) ;
    } ;

  qfs_put_n(qfs, scratch, 2) ;
} ;

/*------------------------------------------------------------------------------
 * Put as much as possible of the source string to the given qf_str, left or
 * right justified to the given width.
 *
 * Ignores the width if the string is longer than it.
 *
 * Negative width => left justify.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_justified(qf_str qfs, const char* src, int width)
{
  qfs_put_justified_n(qfs, src, qfs_strlen(src), width) ;
} ;

/*------------------------------------------------------------------------------
 * Put as much as possible of the first 'n' bytes of the source string to
 * the given qf_str, left or right justified to the given width.
 *
 * Ignores the width if the string is longer than it.
 *
 * Negative width => left justify.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_justified_n(qf_str qfs, const char* src, uint n, int width)
{
  if ((int)n >= abs(width))
    width = 0 ;

  if (width > 0)
    qfs_put_ch_x_n(qfs, ' ', width - n) ;

  qfs_put_n(qfs, src, n) ;

  if (width < 0)
    qfs_put_ch_x_n(qfs, ' ', - width - n) ;
} ;

/*------------------------------------------------------------------------------
 * Put single character.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
inline static void
qfs_put(qf_str qfs, char ch)
{
  uint  size ;
  uint  cp ;
  char* str ;

  str  = qfs->body.c ;
  size = qfs->size ;
  cp   = qfs->cp ;

  if (cp < size)
    str[cp] = ch ;

  qfs->cp = cp + 1 ;
} ;

/*------------------------------------------------------------------------------
 * Put single character.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_ch(qf_str qfs, char ch)
{
  qfs_put(qfs, ch) ;
} ;

/*==============================================================================
 * Number conversion
 *
 * We generate the basic digit string in a buffer, and then copy that to the
 * result.  During the copy we do left/right justification and the padding
 * required for that -- including zero filling.
 *
 * So for the digit string we need to be able to accommodate:
 *
 *   * the digits
 *
 *   * a decimal point
 *
 *   * possibly an exponent = E+999 (or similar)
 *
 *   * commas -- rounding out to a full leading group if zero filling.
 *
 *   * sign  = ' ', '-', '+'
 *
 *   * radix -- '0', '0x' or '0X'
 *
 * For integers, we place a limit on the precision, which limits the number
 * of digits.
 *
 * For floating point we place a limit on the total size of the string, which
 * will give (as a maximum): sign, integer part, '\0' terminator.  So, we
 * calculate the space required for commas on that basis.  The maximum size
 * is substantially bigger than the precision, but in any case, huge.
 */
enum
{
  max_bits       = 256, /* size of number can convert           */
  max_precision  =  99, /* 256 bits in octal is 86 digits       */
  max_float_size = 152, /* including sign, exponent, '\0' term  */
  buf_size       = 208, /* buffer to use for that               */

  /* Assuming max_float_size is all digits, which it isn't, then we
   * calculate the maximum number of commas.
   *
   * This actually calculates the number of groups of digits, which is
   * 1 greater than the number of commas.  So max_commas * 4 is the number
   * of digits + number of commas + 1 -- assuming that the first group is
   * zero filled to 3 digits.
   */
  max_commas    = (max_float_size + 2) / 3,
} ;

/* Make sure we have budgeted for uintmax_t
 */
CONFIRM((sizeof(uintmax_t) * 8) <= max_bits) ;  /* check max_bits     */
CONFIRM((max_precision * 3) >= max_bits) ;      /* check max_digits   */

/* For integers we need space for sign and possibly "0x" radix, in addition to
 * the commas overhead.
 */
CONFIRM(max_float_size >= (1 + 2 + max_precision)) ;

/* Make sure we have budgeted for max_commas plus '\0' terminator.
 *
 * For hex "commas", groups of 4 are used, so the requirement is smaller.
 */
CONFIRM(buf_size >= (max_commas * 4)) ;

/* Make sure we can use umaxtostr()
 */
CONFIRM((uint)buf_size >= (uint)umax_buf_size) ;

/* For floats the precision varies depending on whether double or long double,
 * so need to be able to pass around something which maintains the distinction.
 * (Unlike integer stuff which widens everything to intmax_t/uintmax_t.
 */
typedef struct qfs_float  qfs_float_t ;
typedef struct qfs_float* qfs_float ;

struct qfs_float
{
  union
  {
    double       d ;
    long double ld ;
  } val ;

  bool  is_long ;
} ;

static void qfs_put_integer(qf_str qfs, uintmax_t val, int sign,
                                   pf_flags_t flags, int width, int precision) ;
static void qfs_put_float(qf_str qfs, qfs_float qv, pf_flags_t flags,
                                                     int width, int precision) ;
static void qfs_put_number(qf_str qfs, char* buf, char* digits, int len,
                              int ilen, int sign, pf_flags_t flags, int width) ;

static char* qfs_form_ipv4(char* p, const byte* p_ip, pf_flags_t flags) ;
static char* qfs_form_ipv6(char* p, const byte* p_ip, pf_flags_t flags) ;
static char* qfs_form_ipv6_raw(char* p, const byte* p_ip, pf_flags_t flags) ;

/*------------------------------------------------------------------------------
 * Put signed integer -- converted as per flags, width and precision.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_signed(qf_str qfs, intmax_t s_val, pf_flags_t flags,
                                                       int width, int precision)
{
  uintmax_t u_val ;
  int       sign ;

  if (s_val < 0)
    {
      sign  = -1 ;
      u_val = (uintmax_t)(-(s_val + 1)) + 1 ;
    }
  else
    {
      sign  = (s_val > 0) ? +1 : 0 ;
      u_val = s_val ;
    } ;

  qfs_put_integer(qfs, u_val, sign, flags & ~pf_unsigned, width, precision) ;
} ;

/*------------------------------------------------------------------------------
 * Put unsigned integer -- converted as per flags, width and precision.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_unsigned(qf_str qfs, uintmax_t u_val, pf_flags_t flags,
                                                       int width, int precision)
{
  qfs_put_integer(qfs, u_val, 0, flags | pf_unsigned, width, precision) ;
} ;

/*------------------------------------------------------------------------------
 * Put address -- converted as per flags, width and precision.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 */
extern void
qfs_put_pointer(qf_str qfs, void* p_val, pf_flags_t flags,
                                                       int width, int precision)
{
  confirm(sizeof(uintmax_t) >= sizeof(uintptr_t)) ;
  qfs_put_integer(qfs, (uintptr_t)p_val, 0, flags | pf_unsigned, width, precision) ;
} ;

/*------------------------------------------------------------------------------
 * Put floating point double
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is NOT (repeat NOT) async-signal-safe.
 *
 * See qfs_put_float(), below
 */
extern void
qfs_put_double(qf_str qfs, double val, pf_flags_t flags,
                                                       int width, int precision)
{
  qfs_float_t qv ;

  qv.val.d   = val ;
  qv.is_long = false ;

  qfs_put_float(qfs, &qv, flags, width, precision) ;
} ;

/*------------------------------------------------------------------------------
 * Put floating point long double
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is NOT (repeat NOT) async-signal-safe.
 *
 * See qfs_put_float(), below
 */
extern void
qfs_put_long_double(qf_str qfs, long double val, pf_flags_t flags,
                                                       int width, int precision)
{
  qfs_float_t qv ;

  qv.val.ld  = val ;
  qv.is_long = true ;

  qfs_put_float(qfs, &qv, flags, width, precision) ;
} ;

/*------------------------------------------------------------------------------
 * Put IP Address.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * Accepts: pf_ipv4       -- 1.2.3.4       -- minimal decimal form
 *          pf_ipv6       -- ::            -- minimal hex form with IPv4 if
 *                                            required implicitly
 *          pf_ipv6_ipv4  -- ::1.2.3.4     -- minimal hex form with last
 *                                            32-bits rendered as IPV4
 *
 *          pf_ipv6_raw   -- hhhh:...:hhhh -- maximal hex form
 *
 *          pf_alt        -- for pf_ipv4  -- prefix by ::ffff:
 *                           for pf_ipv6  -- suppress implicit IPv4 part
 *
 *
 *          pf_uc         -- for hex digits
 */
extern void
qfs_put_ip_address(qf_str qfs, const void* p_ip, pf_flags_t flags, int width)
{
  /* Buffer is OK for:  255.255.255.255          + '\0' == 16  (4 * (3 + 1))
   *                    hhhh:...:hhhh            + '\0' == 40  (8 * (4 + 1))
   *                    hhhh:...:255.255.255.255 + '\0' == 46  (6 * (4 + 1)) +
   *                                                           (4 * (3 + 1))
   */
  char  buf[48] ;
  char* p ;

  switch (flags & pf_how_mask)
    {
      case pf_ipv4:
        p = qfs_form_ipv4(buf, p_ip, flags) ;
        break ;

      case pf_ipv6:
      case pf_ipv6_ipv4:
        p = qfs_form_ipv6(buf, p_ip, flags) ;
        break ;

      case pf_ipv6_raw:
        p = qfs_form_ipv6_raw(buf, p_ip, flags) ;
        break ;

      default:
        p = buf ;
        break ;
    } ;

  qfs_put_justified_n(qfs, buf, p - buf, width) ;
} ;

/*------------------------------------------------------------------------------
 * Put IP Prefix.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * As qfs_put_ip_address(), where address is followed by /999.
 */
extern void
qfs_put_ip_prefix(qf_str qfs, const void* p_ip, byte plen, pf_flags_t flags,
                                                                      int width)
{
  /* Buffer is OK for:  255.255.255.255          + '\0' == 16  (4 * (3 + 1))
   *                    hhhh:...:hhhh            + '\0' == 40  (8 * (4 + 1))
   *                    hhhh:...:255.255.255.255 + '\0' == 46  (6 * (4 + 1)) +
   *                                                           (4 * (3 + 1))
   *             plus:  /999 = 4 ... so 50.
   */
  char  buf[64] ;
  char* p ;

  switch (flags & pf_how_mask)
    {
      case pf_ipv4:
        p = qfs_form_ipv4(buf, p_ip, flags) ;
        break ;

      case pf_ipv6:
      case pf_ipv6_ipv4:
        p = qfs_form_ipv6(buf, p_ip, flags) ;
        break ;

      case pf_ipv6_raw:
        p = qfs_form_ipv6_raw(buf, p_ip, flags) ;
        break ;

      default:
        p = buf ;
        break ;
    } ;

  *p++ = '/' ;
  if (plen >= 100)
    *p++ = '0' + ((plen / 100) % 10) ;

  if (plen >= 10)
    {
      *p++ = '0' + ((plen/ 10) % 10) ;
      plen = plen % 10 ;
    } ;

  *p++ = '0' + plen ;

  qfs_put_justified_n(qfs, buf, p - buf, width) ;
} ;

/*------------------------------------------------------------------------------
 * Integer conversion function -- put to qfs
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * All integer conversions end up here.
 *
 * Accepts: pf_commas     -- format with commas
 *          pf_plus       -- requires '+' or '-'
 *          pf_space      -- requires ' ' or '-' (if not already added same)
 *          pf_zeros      -- zero fill to width
 *          pf_alt        -- add '0x' or '0X' if hex and not zero
 *                           add '0'          if octal and not zero.
 *                           no effect otherwise
 *          pf_plus_nz    -- requires '+' if is > 0
 *
 *          pf_precision  -- explicit precision (needed if precision == 0)
 *
 *          pf_hex        -- render in hex
 *          pf_oct        -- render in octal
 *          pf_uc         -- render in upper case
 *
 *          pf_unsigned   -- value is unsigned
 *          pf_ptr        -- value is a void* pointer
 *
 * NB: pf_hex does NOT imply pf_unsigned.
 *     pf_uc  does NOT imply pf_hex
 *
 * If the width is < 0  -- left justify in abs(width) -- zero fill ignored
 *                == 0  -- no width                   -- zero fill ignored
 *                 > 0  -- right justify in width     -- zero filling if req.
 *
 * If there is an explicit precision -- ie pf_precision is set -- it overrides
 * zero fill.
 *
 * An explicit precision == 0 has no effect, unless the value is zero, in which
 * case the result of the conversion is "", not "0".
 *
 * Otherwise all precisions < 1 are treated as 1, except for -1 and -2 with
 * pf_hex -- see below.
 *
 * Precedence issues:
 *
 *   * precision comes first.  Disables zero fill.
 *
 *   * commas come before zero fill.
 *
 *   * signs and prefixes come before zero fill
 *
 *   * pf_plus takes precedence over pf_space
 *
 *   * pf_unsigned or sign == 0 takes precedence over pf_plus and pf_space.
 *
 * For decimal output, pf_commas groups digits in 3's, separated by ','.
 * For hex output,     pf_commas groups digits in 4's, separated by '_'.
 * For oct output,     pf_commas is ignored.
 *
 * Note that pf_commas is a glibc extension, which does not apply to hex !
 *
 * For hex output if precision is:
 *
 *   -1 set precision to multiple of 2, just long enough for the value
 *   -2 set precision to multiple of 4, just long enough for the value
 */
static void
qfs_put_integer(qf_str qfs, uintmax_t val, int sign, pf_flags_t flags,
                                                       int width, int precision)
{
  char  buf[buf_size] ;
  char* p, * e ;
  int   len ;

  /* Deal with the precision issues
   *
   * An explicit precision turns off zero fill.
   *
   * An implicit precision == 0, is treated as == 1
   *
   * Clamp to max_precision.
   *
   * A precision < 0 is treated as 1 (ignored) except for special cases for
   * pf_hex.  Note that for the printf() stuff, -ve precisions are rejected,
   * so the handling here is for direct use of qfs_put_integer() and for
   * the %'0..x "special".
   */
  if      (flags & pf_precision)
    flags &= ~pf_zeros ;
  else if (precision == 0)
    precision = 1 ;

  if      (precision > max_precision)
    precision = max_precision ;
  else if (precision < 0)
    {
      if (((flags & pf_how_mask) == pf_int_hex) && (precision >= -2))
        {
          /* special precision for hex output
           */
          int unit ;
          umax v ;

          unit = (precision == -1) ? 2 : 4 ;

          precision = 0 ;
          v = val | 1 ;
          while (v != 0)
            {
              precision += unit ;
              v >>= (unit * 4) ;
            } ;
        }
      else
        {
          /* mostly, -ve precision is ignored
           */
          precision = 1 ;
        } ;
    } ;

  /* Conversion and special case of zero
   *
   * At this point we have: precision = 0 => explicit 0 precision
   *                                  > 0 => explicit or default precision
   */
  e = buf + sizeof(buf) ;

  if (val == 0)
    {
      /* For 0 we depend on the precision to generate a 0 digit, which
       * it will do, unless precision *explicitly* == 0
       *
       * The radix production is suppressed for zero.
       */
      flags &= ~(pf_alt | pf_how_mask | pf_uc) ;    /* turn off radix   */
      confirm((pf_int_dec == 0) && (pf_uc != 0)) ;

      p = e ;
    }
  else
    {
      uint  base ;

      switch (flags & pf_how_mask)
        {
          case pf_int_dec:
          default:
            base = 10 ;
            break ;

          case pf_int_hex:
            base = 16 ;
            break ;

          case pf_int_oct:
            base =  8 ;
            break ;
        } ;

      confirm(pf_uc != 0) ;

      p = umaxtostr(e, val, base, flags & pf_uc) ;
    } ;

  len = e - p ;

  /* Worry about the precision
   */
  while (precision > len)
    {
      *--p = '0' ;
      ++len ;
    } ;

  /* Now deal with sign, radix, commas, zero fill, justification etc.
   *
   * The pointer we pass to qfs_put_number must have enough space *before*
   * it for sign, radix, commas and expanding first group of digits before the
   * first comma to a full group (for zero fill).
   *
   * So for decimal, if the max_precision were:
   *
   *    5:     12345 ->     012,345  -- 1 comma,  1 zero fill -- total =  7
   *    6:    123456 ->     123,456  -- 1 comma,  0 zero fill -- total =  7
   *    7:   1234567 -> 001,234,567  -- 2 commas, 2 zero fill -- total = 11
   *    8:  12345678 -> 012,345,678  -- 2 commas, 1 zero fill -- total = 11
   *    9: 123456789 -> 123,456,789  -- 2 commas, 0 zero fill -- total = 11
   *
   * etc.
   *
   * So the absolute minimum requirement -- commas + zero fill -- is:
   *
   *   ((max_precision - 1) / 3) + (2 - ((max_precision - 1) % 3))
   *
   * Noting that the total buffer size is:
   *
   *   (((max_precision + 2) / 3) * 4) - 1
   *
   * And for hex, the requirement -- commas + zero fill -- is:
   *
   *   ((max_precision - 1) / 4) + (3 - ((max_precision - 1) % 4))
   *
   * For decimal we need space for the sign (1).  For hex we need space for
   * the sign (1) and radix (2).  We don't do commas for octal.
   */
  assert((p - buf) >= (buf_size - max_precision)) ;

  confirm((buf_size - max_precision)
          > (1 + ((max_precision - 1) / 3) + (2 - ((max_precision - 1) % 3)))) ;
  confirm((buf_size - max_precision)
          > (3 + ((max_precision - 1) / 4) + (3 - ((max_precision - 1) % 4)))) ;

  qfs_put_number(qfs, buf, p, len, len, sign, flags, width) ;
} ;

/*------------------------------------------------------------------------------
 * Floating point value conversion function -- "puts" to the qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is NOT (repeat NOT) async-signal-safe.
 *
 * Accepts: pf_commas     -- format with commas  (ignored for pf_float_a)
 *          pf_plus       -- requires '+' or '-'
 *          pf_space      -- requires ' ' or '-' (if not already added same)
 *          pf_zeros      -- zero fill to width
 *          pf_alt        -- include '.', even if precision = 0
 *          pf_plus_nz    -- requires '+' if is > 0
 *
 *          pf_precision  -- explicit precision (needed if precision == 0)
 *
 *          pf_uc         -- render in upper case
 *
 * If the width is < 0  -- left justify in abs(width) -- zero fill ignored
 *                == 0  -- no width                   -- zero fill ignored
 *                 > 0  -- right justify in width     -- zero filling if req.
 *
 * Unlike integer stuff, float always produces at least "0".  If an explicit
 * precision == 0 is given, the '.' is suppressed, unless pf_alt.
 *
 * If no explicit precision is given, and precision == 0, uses precision = 6.
 * (Any precision < 0 is treated as 6.)
 *
 * Precedence issues:
 *
 *   * commas come before zero fill -- suppressed if pf_float_a.
 *
 *   * signs come before zero fill
 *
 *   * pf_plus takes precedence over pf_space
 *
 * For the whole number part, pf_commas groups digits in 3's, separated by ','.
 *
 * Note that pf_commas is a glibc extension.
 *
 * Note: if the precision is explicitly 0, and the value is 0, and no other
 *       characters are to be generated -- ie no: pf_plus, pf_space, pf_zeros,
 *       or pf_alt (with pf_hex) -- then nothing is generated.
 *
 * This operation is async-signal-safe.  Takes into account the offset, and
 * adds up any overflow
 */
static void
qfs_put_float(qf_str qfs, qfs_float qv, pf_flags_t flags,
                                                       int width, int precision)
{
  char  buf[buf_size] ;
  char* format ;
  char* digits ;
  char* p ;
  char  f_ch ;
  int   rem, len, ilen, sign ;
  uint  how ;

  /* We place the format string at the start of the buffer, and generate the
   * digits at the end.
   */
  format = &buf[0] ;
  digits = &buf[buf_size - max_float_size] ;

  confirm((buf_size - max_float_size) > sizeof("%+#.99Lf")) ;

  /* Worry about the precision
   */
  if    (precision > 0)
    flags |= pf_precision ;             /* treat any precision > 0 as
                                         * explicit.                    */
  else if (precision < 0)
    flags &= ~pf_precision ;            /* treat and precision < 0 as
                                         * default.                     */
  /* Construct format string.
   *
   * Will be: "%+Lq"      if no explicit precision
   *          "%+#.0Lq"   if explicit zero precision with pf_alt
   *          "%+.99Lq"   otherwise
   *
   * We use "+" so that in the unlikely event that max_float_size is too small,
   * it has the same effect on +ve and -ve values !
   */
  p = format ;

  *p++ = '%' ;
  *p++ = '+' ;

  if (flags & pf_precision)
    {
      if ((flags & pf_alt) && (precision == 0))
        *p++ = '#' ;

      *p++ = '.' ;

      confirm(max_precision < 100) ;

      rem = precision ;

      if (precision > 10)
        {
          if (precision > max_precision)
            rem = max_precision ;       /* limit precision      */

          *p++ = '0' + (rem / 10) ;
          rem %= 10 ;
        } ;

        *p++ = '0' + rem ;
    } ;

  how = flags & (pf_how_mask | pf_uc) ;

  flags &= ~(pf_how_mask | pf_uc | pf_alt) ;    /* discard pf_alt and...   */
  confirm(pf_int_dec == 0) ;                    /* ...treat as decimal     */

  switch (how)
    {
      case pf_float_g:
        f_ch = 'g' ;
        break ;

      case pf_float_g | pf_uc:
        f_ch = 'G' ;
        break ;

      case pf_float_f:
        f_ch = 'f' ;
        break ;

      case pf_float_f | pf_uc:
        f_ch = 'F' ;
        break ;

      case pf_float_e:
        f_ch = 'e' ;
        break ;

      case pf_float_e | pf_uc:
        f_ch = 'E' ;
        break ;

      case pf_float_a:
      case pf_float_a | pf_uc:
      default:
        f_ch = (flags & pf_uc) ? 'A' : 'a' ;

        flags = ~pf_commas ;            /* turn off commas      */
        flags |= pf_int_hex | pf_alt ;  /* treat as hex with 0x */
        break ;
    } ;

  if (qv->is_long)
    *p++ = 'L' ;

  *p++ = f_ch ;
  *p   = '\0' ;

  /* Crunch out the digits
   *
   * Look out for overflowing the buffer -- which can happen with %f format
   * if the number is very big.
   */
  if (qv->is_long)
    len = snprintf(digits, max_float_size, format, qv->val.ld) ;
  else
    len = snprintf(digits, max_float_size, format, qv->val.d) ;

  if (len < 0)
    {
      qfs_put_str(qfs, "<< ") ;
      qfs_put_str(qfs, format) ;
      qfs_put_str(qfs, " failed >>") ;

      return ;
    } ;

  p = digits ;

  if (len >= max_float_size)
    {
      static const char over[] = "..." ;

      memcpy(p + max_float_size - sizeof(over), over, sizeof(over)) ;

      len = max_float_size ;
    } ;

  /* Discover and discard sign
   *
   * Would be shocked not to find one !
   */
  sign = +1 ;                   /* worry about zero, later              */

  qassert((*p == '-') || (*p == '+')) ;

  if ((*p == '-') || (*p == '+'))
    {
      sign = (*p == '+') ? +1 : -1 ;

      p    += 1 ;               /* past the '-'/'+'                     */
      len  -= 1 ;               /* discount                             */
    } ;

  /* Is this an inf or nan ?
   */
  if (!isdigit(*p))
    {
      /* inf or nan
       */
      if (sign < 0)
        *(--p) = '-' ;
      else if (flags & pf_plus)
        *(--p) = '+' ;
      else if (flags & pf_space)
        *(--p) = ' ' ;

      qfs_put_str(qfs, digits) ;
      return ;
    } ;

  /* Worry about exactly zero
   */
  if (sign == +1)
    {
      if (qv->is_long)
        {
          if (qv->val.ld == 0.0L)
            sign = 0 ;
        }
      else
        {
          if (qv->val.d  == 0.0)
            sign = 0 ;
        } ;
    }

  /* For 'a' and 'A', strip the leading "0x" or "0X".
   *
   * We do this so that if leading zeros are inserted, they will come after
   * the prefix.  The flags will be set for qfs_put_number() to put the
   * prefix on.
   */
  if (flags & pf_alt)
    {
      qassert((flags & pf_how_mask) == pf_int_hex) ;

      if ((*p == '0') && ((*(p + 1) =='x') || (*(p + 1) =='X')))
        {
          p   += 2 ;
          len -= 2 ;
        } ;
    } ;

  /* If want commas (which have been suppressed for %a/%A, then we need to
   * find where the '.' is -- or, failing that, the 'E' or 'e'.
   */
  ilen = 0 ;

  if (flags & pf_commas)
    {
      qassert((flags & pf_alt) == 0) ;  /* suppressed for %a/%A */

      /* Have stepped past leading sign, so we need the length of the digits,
       * upto first non-digit: ie '.', 'e', 'E' or '\0'.
       */
      ilen = strspn(p, "0123456789") ;

      qassert(ilen < max_commas) ;
    } ;

  /* Now deal with sign, radix, commas, zero fill, justification etc.
   *
   * The pointer we pass to qfs_put_number must have enough space *before*
   * it for sign, radix, commas and expanding first group of digits before the
   * first comma to a full group (for zero fill).
   *
   * We don't do commas and radix together.  The digit string is limited to
   * max_float_size - 1 (because of the '\0').  (In fact, one less than that
   * for the '+'/'-' we asked for.)
   *
   * See qfs_put_integer() for the calculation of the space required for
   * commas.
   */
  qassert((p - buf) >= (buf_size - max_float_size)) ;

  confirm((buf_size - max_float_size)
          > ( 1 + (((max_float_size - 1) - 1) / 3)
                                   + (2 - (((max_float_size - 1) - 1) % 3)) )) ;

  qfs_put_number(qfs, buf, p, len, ilen, sign, flags, width) ;
} ;

/*------------------------------------------------------------------------------
 * Put the given digit string.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * Takes digit string, with without fraction part and/or exponent, decorates as
 * required, and outputs doing field width and justification stuff.
 *
 * The digit string MUST be in a buffer with at least enough space BEFORE
 * the digit string for any:
 *
 *   * sign
 *
 *   * radix
 *
 *   * commas + any zero fill of the first group of digits
 *
 * Note that the digit string MUST NOT include any of the above.
 *
 * The given len is the total length of the digit string, plus (for floating
 * point) any point and exponent.
 *
 * The given ilen is the length of the (leading) integer part of the digit
 * string.  This is used only if pf_commas is set.
 *
 * All precision issues must be dealt with when constructing the digit string.
 *
 * Accepts: pf_commas     -- format with commas
 *          pf_plus       -- requires '+' or '-'
 *          pf_space      -- requires ' ' or '-'
 *          pf_zeros      -- zero fill to width -- if width > 0
 *          pf_alt        -- add '0x' or '0X' if hex -- depending on pf_uc
 *                           add '0'          if octal
 *                           no effect otherwise
 *          pf_plus_nz    -- requires '+' if is > 0
 *
 *          pf_hex        -- hex          )
 *          pf_oct        -- octal        ) for number prefix (if any)
 *          pf_uc         -- upper case   )
 *
 * If the width is < 0  -- left justify in abs(width) -- zero fill ignored
 *                == 0  -- no width                   -- zero fill ignored
 *                 > 0  -- right justify in width     -- zero filling if req.
 *
 * Precedence issues:
 *
 *   * commas come before zero fill.
 *
 *   * signs and prefixes come before zero fill
 *
 *   * pf_plus takes precedence over pf_space
 *
 *   * pf_unsigned or sign == 0 takes precedence over pf_plus and pf_space.
 *
 * For decimal output, pf_commas groups digits in 3's, separated by ','.
 * For hex output,     pf_commas groups digits in 4's, separated by '_'.
 * For oct output,     pf_commas is ignored.
 *
 * Note that pf_commas is a glibc extension, which does not apply to hex !
 */
static void
qfs_put_number(qf_str qfs, char* buf, char* digits, int len, int ilen,
                                         int sign, pf_flags_t flags, int width)
{
  const char* radix_str ;
  const char* sign_str ;

  char* p ;
  char* e ;

  int   radix_len ;
  int   sign_len ;

  char  comma ;
  int   interval ;

  int   zeros ;

  qassert(len < max_float_size) ;       /* excludes '\0' terminator     */

  /* Point at the start and end of the digits -- which are at the far end of
   * the digit buffer.
   */
  e = digits + len ;            /* end of the buffer    */
  p = digits ;

  /* Set up any required sign and radix prefix
   */
  if (flags & pf_unsigned)
    {
      sign_str = "" ;
      sign_len = 0 ;
    }
  else if (sign < 0)
    {
      sign_str = "-" ;
      sign_len = 1 ;
    }
  else if ((flags & pf_plus) || ((flags & pf_plus_nz) && (sign > 0)))
    {
      sign_str = "+" ;
      sign_len = 1 ;
    }
  else if (flags & pf_space)
    {
      sign_str = " " ;
      sign_len = 1 ;
    }
  else
    {
      sign_str = "" ;
      sign_len = 0 ;
    } ;

  radix_str = "" ;
  radix_len = 0 ;
  comma     = '\0' ;
  interval  = 0 ;

  switch (flags * pf_how_mask)
    {
      case pf_int_dec:
      default:
        /* For decimal we implement commas if required.
         *
         * No action required for pf_alt
         */
        if (flags & pf_commas)
          {
            comma     = ',' ;
            interval  = 3 ;
          } ;
        break ;

      case pf_int_hex:
        /* For hex we implement "commas" if required.
         *
         * If pf_alt, add the radix prefix upper/lower case.
         */
        if (flags & pf_commas)
          {
            comma     = '_' ;
            interval  = 4 ;
          } ;

        if (flags & pf_alt)
          {
            radix_str = (flags & pf_uc) ? "0X" : "0x" ;
            radix_len = 2 ;
          } ;
        break ;

      case pf_int_oct:
        /* For octal we ignore "commas".
         *
         * If pf_alt, add the radix prefix "0".
         */
        if (flags & pf_alt)
          {
            radix_str = "0" ;
            radix_len = 1 ;
          } ;
        break ;
    } ;

  /* Work out how many leading zeros will be required.
   */
  if (flags & pf_zeros)
    zeros = width - (sign_len + radix_len + len) ;
                                 /* <= 0 => no leading zeros required    */
  else
    zeros = 0 ;

  /* Worry about commas
   */
  if ((interval > 0) && (ilen > 0))
    {
      int   c ;
      int   t ;
      char* cq ;
      char* cp ;

      c = (ilen - 1) / interval ;       /* number of commas to insert   */
      t = ilen % interval ;             /* digits before first comma    */
      if (t == 0)
        t = interval ;

      assert(c <= max_commas) ;

      len += c ;                        /* account for the commas       */

      cq = p ;
      p -= c ;
      cp = p ;

      assert(p >= buf) ;

      while (c--)
        {
          while (t--)
            *cp++ = *cq++ ;
          *cp++ = comma ;
          t = interval ;
        } ;

      assert(len == (e - p)) ;

      /* commas and zero fill interact.  Here fill the leading group.
       */
      if (zeros > 0)
        {
          int f ;

          f = interval - (ilen % (interval + 1)) ;
          qassert(f < interval) ;

          if (f > zeros)
            f = zeros ;

          len   += f ;
          zeros -= f ;

          while (f--)
            {
              assert(p > buf) ;
              *--p = '0' ;
            } ;
        } ;
    } ;

  assert(len == (e - p)) ;

  /* See if still need to worry about zero fill
   */
  if (zeros > 0)
    {
      /* Need to insert zeros and possible commas between sign and radix
       * and the start of the number.
       *
       * Note that for commas the number has been arranged to have a full
       * leading group.
       *
       * The width can be large... so do this by appending any sign and
       * radix to the qf_str, and then the required leading zeros (with or
       * without commas).
       */
      if (sign_len != 0)
        qfs_put_n(qfs, sign_str, sign_len) ;

      if (radix_len != 0)
        qfs_put_n(qfs, radix_str, radix_len) ;

      if (interval != 0)
        {
          /* Leading zeros with commas !  zeros > 0
           *
           * Start with '0', '0,', '00,' etc to complete the leading group.
           * Thereafter add complete groups.
           *
           * Calculate: g = number of groups, including the leading group
           *            r = number of zeros in the leading group
           */
          int g ;
          int r ;
          g = (zeros + interval - 1) / (interval + 1) ;
          r = (zeros - 1)            % (interval + 1) ;

          if (r == 0)
            {
              /* If leading group has no zeros, we write '0', not comma,
               * and reduce the number of groups.
               */
              qfs_put_ch_x_n(qfs, '0', 1) ;
              g -= 1 ;
              r  = interval ;
            } ;

          while (g--)
            {
              qfs_put_ch_x_n(qfs, '0', r) ;
              qfs_put_ch_x_n(qfs, comma, 1) ;
              r = interval ;
            } ;
        }
      else
        qfs_put_ch_x_n(qfs, '0', zeros) ;

      width = 0 ;               /* have dealt with the width.   */
    }
  else
    {
      /* No leading zeros, so complete the number by adding any sign
       * and radix.
       */
      char* q ;

      p   -= sign_len + radix_len ;
      len += sign_len + radix_len ;
      assert(p >= buf) ;

      q = p ;
      while (sign_len--)
        *q++ = *sign_str++ ;
      while (radix_len--)
        *q++ = *radix_str++ ;
    } ;

  /* Finally, can append the number -- respecting any remaining width
   */
  qassert(len == (e - p)) ;

  qfs_put_justified_n(qfs, p, len, width) ;
} ;

/*------------------------------------------------------------------------------
 * Form minimum decimal IPv4 address -- address in Network Order
 *
 * Accepts: pf_alt        -- render as IPv4-Mapped
 *
 *          pf_uc         -- upper case
 */
static char*
qfs_form_ipv4(char* p, const byte* p_ip, pf_flags_t flags)
{
  uint i ;

  if (flags & pf_alt)
    {
      const char* ipv4_mapped ;

      ipv4_mapped = (flags & pf_uc) ? "::FFFF:" : "::ffff:" ;

      memcpy(p, ipv4_mapped, 7) ;
      p += 7 ;

      confirm(strlen("::FFFF:") == 7) ;
    } ;

  for (i = 0 ; i < 4 ; ++i)
    {
      byte b ;

      if (i != 0)
        *p++ = '.' ;

      b = p_ip[i] ;

      if (b >= 100)
        *p++ = '0' + (b / 100) ;

      if (b >= 10)
        {
          *p++ = '0' + ((b / 10) % 10) ;
          b = b % 10 ;
        } ;

      *p++ = '0' + b ;
    } ;

  return p ;
} ;

/*------------------------------------------------------------------------------
 * Form minimum hex IPv6 address
 *
 * Accepts: pf_ipv6       -- general IPv6 formatting.
 *                           renders last 2 words as IPv4 if the address is
 *                           IPv4-Compatible (and is not 0/8) or if the address
 *                           is IPv4-Mapped.
 *
 *          pf_ipv6_ipv4  -- first 6 words as IPv6, last 2 words as IPv4.
 *
 *          pf_alt        -- for pf_ipv6 -- ignore IPv4-Compatible &
 *                                          IPv4-Mapped -- do all as IPv6
 *
 *                        -- for pf_ipv6_ipv4 -- no effect
 *
 *          pf_uc         -- upper case
 *
 * Follows: RFC5952 and RFC4291 (for IPv4-Compatible and IPv4-Mapped).
 */
static char*
qfs_form_ipv6(char* p, const byte* p_ip, pf_flags_t flags)
{
  uint     i, z, r, zl, rl, h ;
  uint16_t w ;
  const char* hex ;

  qassert( ((flags & pf_how_mask) == pf_ipv6) ||
           ((flags & pf_how_mask) == pf_ipv6_ipv4) ) ;

  hex = (flags & pf_uc) ? uc_hex : lc_hex ;

  /* Want to replace longest available string of 0:..:0 by ::
   *
   * Where there is a run of 4 or more zeros, that must be the longest run of
   * zeros, so we just take it.
   *
   * Otherwise, if there is a run of 3 we take it -- taking the first if there
   * is a choice *and* stepping past any run of 2.
   *
   * Otherwise, if there is a run of 2 zeros we take it -- taking the first, if
   * there is a choice.
   *
   * Ignores individual zeros.
   *
   * Render ::x:y as ::x.x.y.y -- provided MS Byte of x != 0.
   *
   * Render ::FFFF:x:y as ::FFFF:x.x.y.y -- for all values of x and y.
   */
  z  = r  = 0 ;
  zl = rl = 0 ;

  h = ((flags & pf_how_mask) == pf_ipv6) ? 16 : 12 ;

  for (i = 0 ; i < h ; i += 2)
    {
      w = load_ns(&p_ip[i]) ;

      if (w == 0)
        {
          /* Start or extend a run of zeros.
           */
          if (zl == 0)
            zl = i ;
          rl += 1 ;
        }
      else if (rl != 0)
        {
          /* Terminate a run of zeros if run is longer than longest so far,
           * take it.
           */
          if ((rl > 1) && (rl > r))
            {
              z = zl ;
              r = rl ;
            } ;

          zl = rl = 0 ;
        } ;
    } ;

  if ((rl > 1) && (rl > r))
    {
      z = zl ;
      r = rl ;
    } ;

  /* Look out for special cases where automatically turn on IPv4 last part.
   *
   * Note that we avoid rendering :: and ::1 as IPv4 !
   */
  if ((flags & (pf_how_mask | pf_alt)) == pf_ipv6)
    {
      if ((r >= 5) && (z == 0))
        {
          if (   ( (r == 6) && (load_ns(&p_ip[12]) >= 0x0100) )
              || ( (r == 5) && (load_ns(&p_ip[10]) == 0xFFFF) ))
            {
              /* First 6 words zero, and 7th >= 0x0100 -> ipv4 last part.
               *
               *   This is IPv4-Compatible address, which is now decremented.
               *
               *   The test for 6th word >= 0x0100 rules out 0/8.
               *
               * First 5 words zero, and 6th == 0xFFFF -> ipv4 last part.
               *
               *   This is IPv4-Mapped address.
               */
              h = 12 ;
            } ;
        } ;
    } ;

  /* Knock out the hex and ':' and '::' separators
   */
  i = 0 ;
  while (i < h)
    {
      if ((r != 0) && (i == z))
        {
          /* Start of run of zeros
           */
          *p++ = ':' ;

          i += r * 2 ;
          r = 0 ;

          if (i == 16)
            *p++ = ':' ;        /* if nothing more to come      */
        }
      else
        {
          /* Output hex, preceded by ':' if not first.
           */
          if (i != 0)
            *p++ = ':' ;

          w = load_ns(&p_ip[i]) ;

          if (w & (0x000F < 12))
            *p++ = hex[(w >> 12) & 0xF] ;

          if (w & (0x00FF <  8))
            *p++ = hex[(w >>  8) & 0xF] ;

          if (w & (0x0FFF <  4))
            *p++ = hex[(w >>  4) & 0xF] ;

          *p++ = hex[w & 0xF] ;

          i += 2 ;
        }
    } ;

  /* Knock out any trailing IPv4.
   */
  if (h == 12)
    return qfs_form_ipv4(p, &p_ip[12], flags) ;

  return p ;
} ;

/*------------------------------------------------------------------------------
 * Form raw hex IPv6 address -- 8 x 4 hex digits, separated by ':'
 *
 * Accepts: pf_uc       -- upper case
 */
static char*
qfs_form_ipv6_raw(char* p, const byte* p_ip, pf_flags_t flags)
{
  uint     i ;
  const char* hex ;

  hex = (flags & pf_uc) ? uc_hex : lc_hex ;

  for (i = 0 ; i < 16 ; i += 2)
    {
      uint16_t w ;

      w = load_ns(&p_ip[i]) ;

      *p++ = hex[(w >> 12) & 0xF] ;
      *p++ = hex[(w >>  8) & 0xF] ;
      *p++ = hex[(w >>  4) & 0xF] ;
      *p++ = hex[ w        & 0xF] ;
    } ;

  return p ;
} ;

/*==============================================================================
 * printf() and vprintf() type functions
 */

enum pf_phase
{
  pfp_null,             /* in ascending order   */
  pfp_flags,
  pfp_width,
  pfp_precision,
  pfp_int_type,
  pfp_float_type,

  pfp_done,
  pfp_failed
} ;
typedef enum pf_phase pf_phase_t ;

CONFIRM(pfp_float_type > pfp_int_type) ;

/* Number types for printing                                    */
enum arg_num_type
{
  ant_char,             /* hh           */
  ant_short,            /* h            */
  ant_int,              /* default      */
  ant_long,             /* l            */
  ant_long_long,        /* ll           */
  ant_intmax_t,         /* j            */
  ant_size_t,           /* z            */
  ant_ptr_t,            /* void*        */
  ant_long_double,      /* L for float  */

  ant_default    = ant_int,
} ;
typedef enum arg_num_type arg_num_type_t ;

static pf_phase_t qfs_arg_string(qf_str qfs, const char* src, pf_flags_t flags,
                                                     int width, int precision) ;
static pf_phase_t qfs_arg_char(qf_str qfs, char ch, pf_flags_t flags,
                                                     int width, int precision) ;
static pf_phase_t qfs_arg_integer(qf_str qfs, va_list* p_va, pf_flags_t flags,
                                 int width, int precision, arg_num_type_t ant) ;
static pf_phase_t qfs_arg_float(qf_str qfs, va_list* p_va, pf_flags_t flags,
                        int width, int precision, arg_num_type_t ant, char ch) ;

/*------------------------------------------------------------------------------
 * Formatted print to qfb_gen_t -- cf printf() -- fills and returns qfb_get_t.
 *
 * This is for use when wish to construct modest size strings out of a mix
 * of other strings numbers etc.  If constructed string does not fit, it is
 * quietly truncated.
 *
 * Starts with an empty qfb_gen_t.
 *
 * This operation is async-signal-safe -- EXCEPT for floating point values.
 *
 * Returns:  the resulting qfb_gen_t -- '\0' terminated
 *
 * NB: this returns a qfb_gen_t so it is the caller's responsibility to ensure
 *     that has the required lifetime -- which may only be the life of a called
 *     function, but if that function wishes to keep the value, then it had
 *     better copy it !
 */
extern qfb_gen_t
qfs_gen(const char* format, ...)
{
  qfb_gen_t QFB_QFS(buf, qfs) ;
  va_list va ;

  va_start (va, format);
  qfs_vprintf(qfs, format, va);
  va_end (va);

  qfs_term(qfs) ;
  return buf ;
} ;

/*------------------------------------------------------------------------------
 * Put formatted print to qf_str -- cf printf()
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe -- EXCEPT for floating point values.
 *
 * [In common with all other put operations, has no effect on qfs->len.]
 */
extern void
qfs_printf(qf_str qfs, const char* format, ...)
{
  va_list va ;

  va_start (va, format);
  qfs_vprintf(qfs, format, va);
  va_end (va);
} ;

/*------------------------------------------------------------------------------
 * Put formatted print to qf_str -- cf vprintf()
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe -- EXCEPT for floating point values.
 *
 * Operates on a copy of the va_list -- so the original is *unchanged*.
 *
 * [In common with all other put operations, has no effect on qfs->len.]
 */
extern void
qfs_vprintf(qf_str qfs, const char *format, va_list va)
{
  va_list vac ;
  char*  str ;
  uint   size ;

  if (format == NULL)
    return ;

  va_copy(vac, va) ;

  str  = qfs->body.c ;
  size = qfs->size ;

  while (1)
    {
      char   ch ;
      const char* start ;
      bool star, digit ;
      int d, width_sign, width, precision ;
      arg_num_type_t ant ;
      pf_flags_t     flags ;
      pf_phase_t     phase ;

      ch = *format++ ;

      if (ch != '%')
        {
          /* Copy stuff across until hit '%' or '\0'
           */
          uint   cp ;

          if (ch == '\0')
            break ;             /* stop immediately     */

          cp = qfs->cp ;        /* pick up for loop     */

          do
            {
              if (cp < size)
                str[cp] = ch ;
              cp += 1 ;

              ch = *format++ ;
            }
          while ((ch != '%') && (ch != '\0')) ;

          qfs->cp = cp ;        /* put back down again  */

          if (ch == '\0')
            break ;             /* stop                 */
        } ;

      /* Deal with "%...." -- format points after the '%'.
       */
      start      = format ;     /* start points after the '%'   */
      star       = false ;
      digit      = false ;
      d          = 0 ;
      width_sign = +1 ;
      width      = 0 ;
      precision  = 0 ;
      ant        = ant_default ;
      flags      = pf_none ;
      phase      = pfp_null ;

      while (phase < pfp_done)
        {
          switch (ch = *format++)       /* get next and step past it    */
          {
            case '%':           /* %% only                              */
              if (phase == pfp_null)
                {
                  qfs_put(qfs, '%') ;
                  phase = pfp_done ;
                }
              else
                phase = pfp_failed ;
              break ;

            case '\'':
              flags |= pf_commas ;
              phase = (phase <= pfp_flags) ? pfp_flags : pfp_failed ;
              break ;

            case '-':
              width_sign = -1 ;
              phase = (phase <= pfp_flags) ? pfp_flags : pfp_failed ;
              break ;

            case '+':
              flags |= pf_plus ;
              phase = (phase <= pfp_flags) ? pfp_flags : pfp_failed ;
              break ;

            case '#':
              flags |= pf_alt ;
              phase = (phase <= pfp_flags) ? pfp_flags : pfp_failed ;
              break ;

            case ' ':
              flags |= pf_space ;
              phase = (phase <= pfp_flags) ? pfp_flags : pfp_failed ;
              break ;

            case '0':
              if (phase <= pfp_flags)
                {
                  flags |= pf_zeros ;
                  phase = pfp_flags ;
                  break ;
                } ;
                fall_through ;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
              d = *(format - 1) - '0' ;
              if      (!star && (phase <= pfp_width))
                {
                  phase = pfp_width ;
                  width = (width * 10) + (d * width_sign) ;
                }
              else if (!star && (phase == pfp_precision))
                precision = (precision * 10) + d ;
              else
                phase = pfp_failed ;

              digit = true ;
              break ;

            case '*':
              if      (!star && !digit && (phase <= pfp_width))
                {
                  phase = pfp_width ;
                  width = va_arg(vac, int) ;
                }
              else if (!star && !digit && (phase == pfp_precision))
                {
                  precision = va_arg(vac, int) ;
                  if (precision < 0)
                    {
                      precision = 0 ;
                      flags &= ~pf_precision ;  /* completely ignore */
                    } ;
                }
              else
                phase = pfp_failed ;

              star = true ;
              break ;

            case '.':
              phase = (phase < pfp_precision) ? pfp_precision : pfp_failed ;
              flags |= pf_precision ;
              precision = 0 ;
              break ;

            case 'l':       /* 1 or 2 'l', not 'h', 'j' or 'z'      */
              phase = (phase <= pfp_int_type) ? pfp_int_type : pfp_failed ;
              if      (ant == ant_default)
                ant = ant_long ;
              else if (ant == ant_long)
                ant = ant_long_long ;
              else
                phase = pfp_failed ;
              break ;

            case 'h':       /* 1 or 2 'h', not 'l', 'j' or 'z'      */
              phase = (phase <= pfp_int_type) ? pfp_int_type : pfp_failed ;
              if      (ant == ant_default)
                ant = ant_short ;
              else if (ant == ant_short)
                ant = ant_char ;
              else
                phase = pfp_failed ;
              break ;

            case 'j':           /* 1 'j', not 'h', 'l' or 'z'           */
              phase = (phase <= pfp_int_type) ? pfp_int_type : pfp_failed ;
              ant = ant_intmax_t ;
              break ;

            case 'z':           /* 1 'z', not 'h', 'l' or 'j'           */
              phase = (phase <= pfp_int_type) ? pfp_int_type : pfp_failed ;
              ant = ant_size_t ;
              break ;

            case 'L':           /* 1 'L', not for integers !            */
              phase = (phase < pfp_int_type) ? pfp_float_type : pfp_failed ;
              ant = ant_long_double ;
              break ;

            case 's':
              if (phase == pfp_int_type)
                phase = pfp_failed ;    /* don't do 'l' etc.    */
              else
                phase = qfs_arg_string(qfs, va_arg(vac, char*),
                                                  flags, width, precision) ;
              break ;

            case 'c':
              if (phase == pfp_int_type)
                phase = pfp_failed ;    /* don't do 'l' etc.    */
              else
                phase = qfs_arg_char(qfs, (char)va_arg(vac, int),
                                                  flags, width, precision) ;
              break ;

            case 'd':
            case 'i':
              phase = qfs_arg_integer(qfs, &vac, flags, width, precision,
                                                                      ant) ;
              break ;

            case 'u':
              phase = qfs_arg_integer(qfs, &vac, flags | pf_unsigned, width,
                                                           precision, ant) ;
              break ;

            case 'o':
              phase = qfs_arg_integer(qfs, &vac, flags | pf_int_oct, width,
                                                           precision, ant) ;
              break ;

            case 'x':
              phase = qfs_arg_integer(qfs, &vac, flags | pf_hex_x, width,
                                                           precision, ant) ;
              break ;

            case 'X':
              phase = qfs_arg_integer(qfs, &vac, flags | pf_hex_X, width,
                                                           precision, ant) ;
              break ;

            case 'p':
              if (phase == pfp_int_type)
                phase = pfp_failed ;
              else
                phase = qfs_arg_integer(qfs, &vac, flags | pf_void_p, width,
                                                     precision, ant_ptr_t) ;
              break ;

            case 'e':
            case 'E':
            case 'f':
            case 'F':
            case 'g':
            case 'G':
            case 'a':
            case 'A':
              if (phase == pfp_int_type)
                phase = pfp_failed ;
              else
                {
                  if (phase < pfp_int_type)
                    qassert(ant == ant_default) ;       /* ie double    */
                  else
                    qassert((ant == ant_long_double) &&
                                                (phase == pfp_float_type)) ;

                  phase = qfs_arg_float(qfs, &vac, flags, width,
                                                       precision, ant, ch) ;
                } ;
              break ;

            default:                    /* unrecognised format          */
              phase = pfp_failed ;
              break ;
          } ;
        } ;

      if (phase == pfp_failed)
        {
          qfs_put(qfs, '%') ;       /* put the original '%'         */
          format = start ;          /* back to after the '%'        */
        } ;
    } ;

  va_end(vac) ;
} ;

/*------------------------------------------------------------------------------
 * %s handler -- tolerates NULL pointer -- "puts" to the qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * Accepts:    width
 *             precision    -- ignored if < 0
 *             pf_precision -- explicit precision
 *
 * Rejects:    pf_commas    -- "'" seen
 *             pf_plus      -- "+" seen
 *             pf_space     -- " " seen
 *             pf_zeros     -- "0" seen
 *             pf_alt       -- "#" seen
 *
 * Won't get:  pf_hex
 *             pf_uc
 *             pf_unsigned
 *             pf_ptr
 */
static pf_phase_t
qfs_arg_string(qf_str qfs, const char* src, pf_flags_t flags,
                                                       int width, int precision)
{
  int len ;

  if (flags != (flags & pf_precision))
    return pfp_failed ;

  if (precision < 0)            /* make sure            */
    {
      precision = 0 ;
      flags &= ~pf_precision ;
    } ;

  len = 0 ;
  if (src != NULL)
    while (*(src + len) != '\0') ++len ;

  if (((precision > 0) || (flags & pf_precision)) && (len > precision))
    len = precision ;

  qfs_put_justified_n(qfs, src, len, width) ;

  return pfp_done ;
} ;

/*------------------------------------------------------------------------------
 * %c handler -- "puts" to the qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * Accepts:    width
 *
 * Rejects:    precision
 *             pf_precision -- explicit precision
 *             pf_commas    -- "'" seen
 *             pf_plus      -- "+" seen
 *             pf_space     -- " " seen
 *             pf_zeros     -- "0" seen
 *             pf_alt       -- "#" seen
 *
 * Won't get:  pf_hex
 *             pf_uc
 *             pf_unsigned
 *             pf_ptr
 */
static pf_phase_t
qfs_arg_char(qf_str qfs, char ch, pf_flags_t flags, int width, int precision)
{
  if ((flags != 0) || (precision != 0))
    return pfp_failed ;

  qfs_put_justified_n(qfs, (char*)&ch, 1, width) ;

  return pfp_done ;
} ;

/*------------------------------------------------------------------------------
 * %d, %i, %u, %o, %x, %X and %p handler -- "puts" to the qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is async-signal-safe.
 *
 * Accepts: pf_commas     -- format with commas or '_' for hex (non-standard)
 *                           ignored for octal.
 *          pf_minus      -- left justify (any width will be -ve)
 *          pf_plus       -- requires sign
 *          pf_space      -- requires space or '-'
 *          pf_zeros      -- zero fill to width
 *          pf_alt        -- '0x' or '0X' for hex
 *                           '0' for octal
 *
 *          pf_precision  -- precision specified
 *
 *          pf_unsigned   -- value is unsigned
 *          pf_ptr        -- value is a void* pointer
 *          pf_hex        -- render in hex
 *          pf_uc         -- render hex in upper case
 *
 *     and: all the number argument types.
 *
 * Rejects: ant == ant_long_double -- which is how the parser spots an
 *          erroneous %Ld for example.
 */
static pf_phase_t
qfs_arg_integer(qf_str qfs, va_list* p_va, pf_flags_t flags,
                                int width, int precision, arg_num_type_t ant)
{
  uintmax_t     u_val ;
  intmax_t      s_val ;

  /* Reject if seen an 'L'
   */
  if (ant == ant_long_double)
    return pfp_failed ;

  /* Special for hex with '0...  if no explicit precision, set -1 for byte
   * and -2 for everything else -- see qfs_put_integer().
   */
  if ((flags & (pf_how_mask | pf_precision)) == pf_int_hex)
    {
      if ((flags & (pf_commas | pf_zeros)) == (pf_commas | pf_zeros))
        {
          precision = (ant == ant_char) ? -1 : -2 ;
          flags |= pf_precision ;
        } ;
    } ;

  /* It is assumed that all values can be mapped to a uintmax_t         */
  confirm(sizeof(uintmax_t) >= sizeof(uintptr_t)) ;

  if (flags & pf_unsigned)
    {
      switch (ant)
      {
        case ant_char:
        case ant_short:
        case ant_int:
          u_val = va_arg(*p_va, unsigned int) ;
          break ;

        case ant_long:
          u_val = va_arg(*p_va, unsigned long) ;
          break ;

        case ant_long_long:
          u_val = va_arg(*p_va, unsigned long long) ;
          break ;

        case ant_intmax_t:
          u_val = va_arg(*p_va, uintmax_t) ;
          break ;

        case ant_size_t:
          u_val = va_arg(*p_va, size_t) ;
          break ;

        case ant_ptr_t:
          u_val = va_arg(*p_va, uintptr_t) ;
          break ;

        default:
          zabort("impossible integer size") ;
      } ;

      qfs_put_unsigned(qfs, u_val, flags, width, precision) ;
    }
  else
    {
      switch (ant)
      {
        case ant_char:
        case ant_short:
        case ant_int:
          s_val = va_arg(*p_va, signed int) ;
          break ;

        case ant_long:
          s_val = va_arg(*p_va, signed long) ;
          break ;

        case ant_long_long:
          s_val = va_arg(*p_va, signed long long) ;
          break ;

        case ant_intmax_t:
          s_val = va_arg(*p_va, intmax_t) ;
          break ;

        case ant_size_t:
          s_val = va_arg(*p_va, ssize_t) ;
          break ;

        case ant_ptr_t:
          s_val = va_arg(*p_va, intptr_t) ;
          break ;

        default:
          zabort("impossible integer size") ;
      } ;

      qfs_put_signed(qfs, s_val, flags, width, precision) ;
    } ;

  return pfp_done ;
} ;

/*------------------------------------------------------------------------------
 * %e, %E, %f, %F, %g, %G, %a and %A handler -- "puts" to the qf_str.
 *
 * May put nothing at all -- see notes above.
 *
 * This operation is NOT, repeat NOT, async-signal-safe.
 *
 * This uses the standard library sprintf() to do the business, so this is
 * NOT async-signal-safe.  This means that we get the full precision supported
 * by the system !  Attempting to construct async-signal-safe conversion is
 * doomed to failure, because any floating point operation may affect flags
 * and other state in the processor :-(
 *
 * Accepts: pf_commas     -- format whole part with commas (non-standard)
 *          pf_minus      -- left justify (any width will be -ve)
 *          pf_plus       -- requires sign
 *          pf_space      -- requires space or '-'
 *          pf_zeros      -- zero fill to width
 *          pf_alt        -- include '.' if precision = 0
 *
 *          pf_precision  -- precision specified
 *
 *     and: ant_default (=> double) or ant_long_double.
 */
static pf_phase_t
qfs_arg_float(qf_str qfs, va_list* p_va, pf_flags_t flags,
                          int width, int precision, arg_num_type_t ant, char ch)
{
  qfs_float_t qv ;

  switch (ant)
    {
      case ant_default:
         qv.val.d   = va_arg(*p_va, double) ;
         qv.is_long = false ;
         break ;

      case ant_long_double:
         qv.val.ld  = va_arg(*p_va, long double) ;
         qv.is_long = true ;
         break ;

      default:
        return pfp_failed ;
    } ;

  flags &= ~(pf_how_mask | pf_uc) ;     /* make sure clear      */

  switch (ch)
    {
      case 'f':
        flags |= pf_float_f ;
        break ;

      case 'F':
        flags |= pf_float_f | pf_uc ;
        break ;

      case 'g':
        flags |= pf_float_g ;
        break ;

      case 'G':
        flags |= pf_float_g | pf_uc ;
        break ;

      case 'e':
        flags |= pf_float_e ;
        break ;

      case 'E':
        flags |= pf_float_e | pf_uc ;
        break ;

      case 'a':
        flags |= pf_float_a ;
        break ;

      case 'A':
        flags |= pf_float_a | pf_uc ;
        break ;

      default:
        return pfp_failed ;
    } ;

  qfs_put_float(qfs, &qv, flags, width, precision) ;

  return pfp_done ;
} ;

/*==============================================================================
 * Construction of scaled numbers.
 *
 */

enum { scale_max = 6 } ;

static const char* scale_d_tags [] =
{
    [0] = " " ,
    [1] = "k",
    [2] = "m",
    [3] = "g",
    [4] = "t",          /* Tera 10^12   */
    [5] = "p",          /* Peta 10^15   */
    [6] = "e",          /* Exa  10^18   */
} ;
CONFIRM((sizeof(scale_d_tags) / sizeof(char*)) == (scale_max + 1)) ;

static const char* scale_b_tags [] =
{
    [0] = " " ,
    [1] = "K",
    [2] = "M",
    [3] = "G",
    [4] = "T",
    [5] = "P",
    [6] = "E",
} ;
CONFIRM((sizeof(scale_b_tags) / sizeof(char*)) == (scale_max + 1)) ;

static const urlong p10 [] =
{
    [ 0] = 1l,
    [ 1] = 10l,
    [ 2] = 100l,
    [ 3] = 1000l,
    [ 4] = 10000l,
    [ 5] = 100000l,
    [ 6] = 1000000l,
    [ 7] = 10000000l,
    [ 8] = 100000000l,
    [ 9] = 1000000000l,
    [10] = 10000000000l,
    [11] = 100000000000l,
    [12] = 1000000000000l,
    [13] = 10000000000000l,
    [14] = 100000000000000l,
    [15] = 1000000000000000l,
    [16] = 10000000000000000l,
    [17] = 100000000000000000l,
    [18] = 1000000000000000000l,
    [19] = URLONG_MAX,          /* all abs(signed values) < this        */
} ;
CONFIRM((sizeof(p10) / sizeof(urlong)) == ((scale_max * 3) + 2)) ;
CONFIRM((RLONG_MAX / 10) < 1000000000000000000l) ;  /* RLONG_MAX < 10^19  */

static const urlong q10 [] =
{
    [ 0] = 1l / 2,
    [ 1] = 10l / 2,
    [ 2] = 100l / 2,
    [ 3] = 1000l / 2,
    [ 4] = 10000l / 2,
    [ 5] = 100000l / 2,
    [ 6] = 1000000l / 2,
    [ 7] = 10000000l / 2,
    [ 8] = 100000000l / 2,
    [ 9] = 1000000000l / 2,
    [10] = 10000000000l / 2,
    [11] = 100000000000l / 2,
    [12] = 1000000000000l / 2,
    [13] = 10000000000000l / 2,
    [14] = 100000000000000l / 2,
    [15] = 1000000000000000l / 2,
    [16] = 10000000000000000l / 2,
    [17] = 100000000000000000l / 2,
    [18] = 1000000000000000000l / 2,
} ;
CONFIRM((sizeof(q10) / sizeof(urlong)) == ((scale_max * 3) + 1)) ;

static urlong qfs_form_sign(qf_str qfs, rlong val, pf_flags_t flags) ;

static void qfs_form_scaled(qf_str qfs, urlong v, int d,
                                            const char* tag, pf_flags_t flags) ;

/*------------------------------------------------------------------------------
 * Form value scaled to 4 significant digits, or as simple decimal.
 *
 * When scaling, scale by powers of 1,000, to produce (with pf_commas):
 *
 *        0..999            1, 2 or 3 digits     ) optionally followed by ' '
 *    1,000..9,999          4 digits with comma  )
 *
 *    10,000..99,994        as 99.99k -- rounded
 *    99,995..999,949       as 999.9k -- rounded
 *    999,950..9,999,499    as 9,999k -- rounded
 *
 *    thereafter, as for 'k', but with 'm', 'g', etc.
 *
 * When not scaling, produce simple decimal with optional trailing space.
 *
 * In any case, produce a leading sign if required.
 *
 * Accepts the following pf_xxx flags:
 *
 *   pf_scale    -- scale as above (if not, no scaling)
 *   pf_trailing -- include blank scale for units
 *   pf_commas   -- format with commas
 *   pf_plus     -- add '+' sign if >= 0
 *   pf_plus_nz  -- add '+' sign if >  0
 *   pf_space    -- add ' ' sign if >= 0 *and* not already added '+'
 *
 * Produces the minimum number of characters possible.  With pf_trailing, the
 * result can be right aligned to line up the digits -- a field of 6 is
 * required -- or 7 with sign character.
 */
extern qfs_num_str_t
qfs_put_dec_value(rlong val, pf_flags_t flags)
{
  qfs_num_str_t QFB_QFS(str, qfs) ;
  int   d, t ;
  urlong v ;

  flags &= (pf_commas | pf_plus | pf_plus_nz | pf_space
                                                     | pf_scale | pf_trailing) ;
  v = qfs_form_sign(qfs, val, flags) ;

  t = 0 ;
  d = 0 ;

  if ((flags & pf_scale) != 0)
    {
      int i ;

      /* Find 'i' such that:
       *
       *   1) i is multiple of 3
       *
       *   2) v < 10^(i + 4)
       *
       *   3) i <= (scale_max - 1) * 3
       *
       * For:          0..9,999          i = 0
       *          10,000..9,999,999      i = 3
       *      10,000,000..9,999,999,999  i = 6
       *      etc.
       *
       * So, where i > 0, need to divide by 10^(i), 10^(i-1) or 10^(i-2) in
       * in order to get the ms 4 digits.
       */
      i = 0 ;
      while ((v >= p10[i + 4]) && (i < ((scale_max - 1) * 3)))
        i += 3 ;

      if (i > 0)
        {
          /* Maximum i == (scale_max - 1) * 3 -- and have p10 upto and
           * including scale_max * 3.
           */
          qassert(v >= p10[i + 1]) ;

          if      (v < p10[i + 2])
            d = 2 ;
          else if (v < p10[i + 3])
            d = 1 ;
          else
            d = 0 ;

          /* Scale down to required number of decimals and round.
           *
           * If is thousands, then i = 3, if value = 10,000 (smallest possible)
           * then d == 2.  So divide by 5 (q10[3 - 2]) to make ls bit the
           * rounding bit, add one and shift off the rounding bit.
           *
           * The result should be 1000..9999, unless value is greater than our
           * ability to scale, or has rounded up one decade.
           */
          v = ((v / q10[i - d]) + 1) >> 1 ;
          t = i / 3 ;

          qassert(v >= 1000) ;

          /* Deal with having rounded up to too many digits.
           *
           * Adjusts the number of digits after the '.' and divides the
           * value by 10 -- changes up the thousands scaling if required.
           *
           * Unless have d == 0 and t == scale_max, in which case we leave the
           * rounded up value as it is.
           */
          if ((v > 9999) && !((d == 0) && (t == scale_max)))
            {
              qassert(v == (9999 + 1)) ;

              --d ;
              v /= 10 ;

              if (d < 0)
                {
                  d = 2 ;       /* wrap round   */
                  ++t ;         /* upscale      */
                } ;
            } ;
        } ;
    } ;

  qfs_form_scaled(qfs, v, d, scale_d_tags[t], flags) ;
  qfs_term(qfs) ;

  return str ;
} ;

/*------------------------------------------------------------------------------
 * Form value scaled to 4 significant digits, or as simple decimal.
 *
 * When scaling, scale by powers of 1,024, to produce:
 *
 *            0..999         1, 2 or 3 digits, optionally followed by " "
 *
 *         1000..10239       0.977K..9.999K  )
 *        10240..102394      10.00K..99.99K  )
 *       102395..1023948     100.0K..999.9K  ) -- rounded
 *      1023949..10485235    1.000M..9.999M  )
 *     10485236..104852357   10.00M..99.99M  )
 *
 *    ..etc for 'G', 'T', 'P' etc.
 *
 * When not scaling, produce simple decimal with optional trailing space.
 *
 * In any case, produce a leading sign if required.
 *
 * Accepts the following pf_xxx flags:
 *
 *   pf_scale    -- scale as above (if not, no scaling)
 *   pf_trailing -- include blank scale for units
 *   pf_commas   -- format with commas
 *   pf_plus     -- add '+' sign if >= 0
 *   pf_plus_nz  -- add '+' sign if >  0
 *   pf_space    -- add ' ' sign if >= 0 *and* not already added '+'
 *
 * Produces the minimum number of characters possible.  With pf_trailing, the
 * result can be right aligned to line up the digits -- a field of 6 is
 * required -- or 7 with sign character.
 */
extern qfs_num_str_t
qfs_put_bin_value(rlong val, pf_flags_t flags)
{
  qfs_num_str_t QFB_QFS(str, qfs) ;
  ulong v ;
  int d, p ;

  flags &= (pf_commas | pf_plus | pf_plus_nz | pf_space
                                                     | pf_scale | pf_trailing) ;
  v = qfs_form_sign(qfs, val, flags) ;

  p = 0 ;
  d = 0 ;

  if ((flags & pf_scale) != 0)
    {
      ulong vs ;

      /* Find the power of 1024 which leaves the value < 1000,
       * and set v = val / 1024^p -- subject to p <= scale_max
       */
      vs = v ;
      while ((vs >= 1000) && (p < scale_max))
        {
          vs >>= 10 ;           /* find power of 1024 scale     */
          p += 1 ;
        } ;

      if (p > 0)
        {
          ulong e ;
          int   is ;

          /* value is >= 1024, so v is whole number of KiB, MiB, ...
           *
           * Need to know how many decimal fraction digits we need to get to
           * 4 significant figures (3 if v is zero).
           *
           * Will scale up by 10^d.  d == 0 iff p == scale_max
           */
          if      (vs < 10)
            d = 3 ;             /* number of decimals expected  */
          else if (vs < 100)
            d = 2 ;
          else if (vs < 1000)
            d = 1 ;
          else
            d = 0 ;             /* where p == scale_max         */

          /* Scale up to the required number of decimals, shift down so that
           * only ms bit of fraction is left, round and shift off rounding bit.
           *
           * If d != 0, then will scale up by 10, 100 or 1000.  If the value is
           * greater than ULONG_MAX / 1024, then we do the bottom 10 bits
           * separately, and scale the calculation down by 10 bits.
           */
          e  = 0 ;              /* assume no extra bits         */
          is = p * 10 ;         /* the shift down               */

          if ((d != 0) && (v > (ULONG_MAX >> 10)))
            {
              e = (v & 0x3FF) * p10[d] ;        /* take bottom 10 bits  */
              e >>= 10 ;        /* discard 10 bits of extra part        */
              v >>= 10 ;        /* scale down value                     */
              is -= 10 ;        /* reduce shift                         */
            } ;

          v = ((((v * p10[d]) + e) >> (is - 1)) + 1) >> 1 ;

          qassert(v >= 975) ; /* 999 / 1024 = 0.9756                  */

          /* Deal with having rounded up to too many digits.
           *
           * Adjusts the number of digits after the '.' and divides the
           * value by 10 -- changes up the thousands scaling if required.
           *
           * Will have d == 0 iff p == scale_max, in which case we leave the
           * rounded up value as it is.
           */
          if (d == 0)
            qassert(p == scale_max) ;

          if ((v > 9999) && (d > 0))
            {
              qassert(v == (9999 + 1)) ;

              --d ;
              v /= 10 ;

              if (d == 0)
                {
                  d = 3 ;       /* wrap round   */
                  ++p ;         /* upscale      */
              } ;

            } ;
       } ;
    } ;

  qfs_form_scaled(qfs, v, d, scale_b_tags[p], flags) ;
  qfs_term(qfs) ;

  return str ;
} ;

/*------------------------------------------------------------------------------
 * Form a time period value.
 *
 *    +/-999d99h99m99h99.999s
 *
 * Accepts the following pf_xxx flags:
 *
 *   pf_commas   -- format with commas
 *   pf_plus     -- add '+' sign if >= 0
 *   pf_plus_nz  -- add '+' sign if >  0
 *   pf_space    -- add ' ' sign if >= 0 *and* not already added '+'
 */
extern qfs_num_str_t
qfs_put_time_period(qtime_t val, pf_flags_t flags)
{
  qfs_num_str_t QFB_QFS(str, qfs) ;
  urlong v ;
  int w ;

  confirm(sizeof(v) >= sizeof(qtime_t)) ;

  /* Worry about the sign
   */
  v = qfs_form_sign(qfs, val, flags) ;

  flags &= pf_commas ;  /* unlikely though that is !    */

  /* Round value to milli seconds
   */
  v = (v + (QTIME_SECOND / 2000)) / (QTIME_SECOND / 1000) ;

  w = 0 ;

  if (v >= (2 * 24 * 60 * 60 * 1000))
    {
      qfs_put_unsigned(qfs, v / (24 * 60 * 60 * 1000), flags, w, w) ;
      qfs_put(qfs, 'd') ;

      v %= (24 * 60 * 60 * 1000) ;
      flags = pf_zeros ;
      w = 2 ;
    } ;

  if ((v >= (2 * 60 * 60 * 1000)) || (w > 0))
    {
      qfs_put_unsigned(qfs, v / (60 * 60 * 1000), flags, w, w) ;
      qfs_put(qfs, 'h') ;

      v %= (60 * 60 * 1000) ;
      flags = pf_zeros ;
      w = 2 ;
    } ;

  if ((v >= (2 * 60 * 1000)) || (w > 0))
    {
      qfs_put_unsigned(qfs, v / (60 * 1000), flags, w, w) ;
      qfs_put(qfs, 'm') ;

      v %= (60 * 1000) ;
      flags = pf_zeros ;
      w = 2 ;
    } ;

  qfs_put_unsigned(qfs, v / 1000, flags, w, w) ;
  qfs_put(qfs, '.') ;
  qfs_put_unsigned(qfs, v % 1000, pf_zeros, 3, 3) ;
  qfs_put(qfs, 's') ;

  qfs_term(qfs) ;

  return str ;
} ;

/*------------------------------------------------------------------------------
 * Form string for number, with commas and "d" decimal digits, followed
 * by the given tag -- where d = 0..4
 *
 * Flags:  pf_commas     => insert commas before '.' if required
 *         pf_trailing   => include blank scale for units
 *
 * So: val=1234567, d=2, tag="k" -> "12,345.67k" (with pf_commas)
 *     val=1234,    d=0, tag=""  -> "1,234"
 */
static void
qfs_form_scaled(qf_str qfs, urlong v, int d, const char* tag, pf_flags_t flags)
{
  if (d == 0)
    qfs_put_unsigned(qfs, v, flags, 0, 0) ;
  else
    {
      rldiv_t r = rldiv((rlong)v, p10[d]) ;

      qfs_put_unsigned(qfs, r.quot, flags, 0, 0) ;
      qfs_put(qfs, '.') ;
      qfs_put_unsigned(qfs, r.rem, pf_zeros, d, 0) ;
    } ;

  if ((*tag != ' ') || ((flags & pf_trailing) != 0))
    qfs_put_str(qfs, tag) ;
} ;

/*------------------------------------------------------------------------------
 * Sort out sign for value and return the abs(val)
 */
static urlong
qfs_form_sign(qf_str qfs, rlong val, pf_flags_t flags)
{
  if       (val < 0)
    {
      qfs_put(qfs, '-') ;

      return urlabs(val) ;
    }
  else if ((flags & pf_plus) || ((flags & pf_plus_nz) && (val > 0)))
    qfs_put(qfs, '+') ;
  else if (flags & pf_space)
    qfs_put(qfs, ' ') ;

  return val ;
} ;

/*==============================================================================
 * Simple keyword handling
 */

static qfs_keyword_t deny_permit_table[] =
{
  { .word = "deny",    .val = 0 },
  { .word = "permit",  .val = 1 },
  { .word = NULL }
} ;

extern void test_keyword(void) ;
extern void
test_keyword(void)
{
  qfs_keyword_lookup(deny_permit_table, "den", true) ;
} ;

/*------------------------------------------------------------------------------
 * Keyword lookup -- case sensitive, optional partial match.
 *
 * Given a keyword table, see if given string matches.
 *
 * Keyword table is an array of qfs_keyword_t items.  Each item is a keyword
 * (const char*) and an unsigned value 0..INT_MAX.  Table is terminated by a
 * NULL keyword.
 *
 * This is not very clever, but does not require the keyword table to be in any
 * particular order.
 *
 * If "strict", requires string to completely match a keyword.  Otherwise,
 * requires the string to be the leading substring of only one of the given
 * keywords -- but stops immediately if gets a complete match.
 *
 * Returns: >=  0 => found -- this is value from table
 *          == -1 => not found
 *          == -2 => found 2 or more matches (and no exact match)
 *
 * NB: match is case sensitive.
 */
extern int
qfs_keyword_lookup(qfs_keyword_t* table, const char* str, bool strict)
{
  qfs_keyword_t* e ;
  const char* word ;
  uint len, wlen ;
  int  r ;

  len = strlen(str) ;

  e = table ;
  r = -1 ;

  while ((word = e->word) != NULL)
    {
      qassert(e->val <= INT_MAX) ;

      wlen = strlen(word) ;

      if      (wlen > len)
        {
          if (!strict && (strncmp(str, word, len) == 0))
            {
              if (r == -1)
                r = e->val ;
              else
                r = -2 ;                /* ambiguous    */
            } ;
        }
      else if (wlen == len)
        {
          if (strcmp(str, word) == 0)
            return e->val ;             /* exact match  */
        } ;

      ++e ;
    } ;

  return r ;
} ;

/*------------------------------------------------------------------------------
 * Keyword lookup -- case *insensitive*, optional partial match.
 *
 * Same as qfs_keyword_lookup() except case insensitive.
 *
 * strncasecmp() and strcasecmp() appear to have been POSIX Base since 2001.
 */
extern int
qfs_keyword_lookup_nocase(qfs_keyword_t* table, const char* str, bool strict)
{
  qfs_keyword_t* e ;
  const char* word ;
  uint len, wlen ;
  int  r ;

  len = strlen(str) ;

  e = table ;
  r = -1 ;

  while ((word = e->word) != NULL)
    {
      qassert(e->val <= INT_MAX) ;

      wlen = strlen(word) ;

      if      (wlen > len)
        {
          if (!strict && (strncasecmp(str, word, len) == 0))
            {
              if (r == -1)
                r = e->val ;
              else
                r = -2 ;                /* ambiguous    */
            } ;
        }
      else if (wlen == len)
        {
          if (strcasecmp(str, word) == 0)
            return e->val ;             /* exact match  */
        } ;

      ++e ;
    } ;

  return r ;
} ;

/*------------------------------------------------------------------------------
 * Keyword extract -- case sensitive, optional partial match.
 *
 * Extracts keyword from an abstract array, accessed using the given function,
 * starting from 0 and increasing by 1 until function returns NULL.
 *
 * Note that the function can return an empty string, for index values which
 * are to be ignored.
 *
 * Returns: >=  0 => found -- this is the index of the abstract array entry
 *          == -1 => not found
 *          == -2 => found 2 or more matches (and no exact match)
 *
 * NB: match is case sensitive.
 */
extern int
qfs_keyword_lookup_abstract(void* a_array, const char* str, bool strict,
                             const char* (*a_lookup)(void* a_array, uint index))
{
  uint i ;
  const char* word ;
  uint len, wlen ;
  int  r ;

  len = strlen(str) ;

  i =  0 ;
  r = -1 ;

  while (1)
    {
      word = a_lookup(a_array, i) ;

      if (word == NULL)
        break ;

      wlen = strlen(word) ;

      if      (wlen > len)
        {
          if (!strict && (strncmp(str, word, len) == 0))
            {
              if (r == -1)
                r = i ;
              else
                r = -2 ;                /* ambiguous    */
            } ;
        }
      else if (wlen == len)
        {
          if (strcmp(str, word) == 0)
            return i ;                  /* exact match  */
        } ;

      ++i ;
    } ;

  return r ;
} ;
