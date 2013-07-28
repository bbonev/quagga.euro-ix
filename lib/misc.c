/* Miscellaneous extended functions
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

#include "misc.h"
#include <inttypes.h>

#include "errno.h"
#include "ctype.h"
#include "miyagi.h"

/*==============================================================================
 * Miscellaneous extended functions
 *
 * To qualify for inclusion here a function must be of general use and depend
 * only on standard system functions -- typically overcoming some clunky
 * standard interface.
 *
 */

/*==============================================================================
 * strtol and strtoul extensions.
 *
 * These extensions:
 *
 *   * work with 'rlong' -- so definitely longer than 'int' !
 *
 *   * deal with the error handling issues
 *
 *   * allow complete numbers only -- disallow empty numbers
 *
 *   * deal with trailing whitespace
 *
 *   * allow decimal or 0x/0X prefixed hex -- but NOT octal.
 *     (allows leading zeros).
 *
 *   * allow "_" in numbers (inside -- not at start or end.
 *
 *   * signal presence of sign character
 *
 * Syntax is: \s*([+-]\s*_*)?<number>\s*  -- sign only if signed
 *                                        -- followed by '\0' if required
 *
 * where <number> is:  0(_*0+)*
 *                     (0[_0]*)?[1-9](_*[0-9])*
 *                     0[xX](_*[0-9a-fA-F])+
 *
 * In essence number must contain at least one digit, may contain '_' but may
 * not start or end in '_'.  Leading and trailing whitespace is allowed, as is
 * whitespace after any sign.
 *
 * If the follower character is asked for, will return pointer to whatever
 * strtol()/stroul() stops on.  Otherwise, strips trailing whitespace and
 * rejects number if not the at end of string.
 */

/*------------------------------------------------------------------------------
 * Extended strtol()
 *
 * If p_end == NULL, requires string (ignoring leading and trailing whitespace)
 * to contain just a number.  Note that trailing '_' are not part of a number,
 * so if present will trigger strtox_invalid error.
 *
 * If p_end != NULL, if leading part of string is a valid number, returns
 * pointer to first character after the number.  Since trailing '_' are not part
 * of a number, the pointer may point at a '_'.  If the leading part of the
 * string is not a valid number, returns pointer to first non-whitespace
 * character in the string.  Note that number can be valid and still overflow !
 *
 * Returns:  *signed* rlong -- RLONG_MIN if out of range and -ve, or if invalid
 *                             RLONG_MAX if out of range and +ve
 *
 *           *p_tox  ==  strtox_signed  => OK, sign seen (+ or -)
 *                   ==  strtox_ok      => OK, no sign
 *                   ==  strtox_invalid => badly formed or empty number
 *                   ==  strtox_range   => out of range for signed rlong
 */
extern rlong
strtol_x(const char* restrict str, strtox_t* p_tox, const char** p_end)
{
  const char* start ;
  urlong uval ;
  int   sign ;

  /* Establish sign if any -- eats leading whitespace, then if finds sign,
   * any following whitespace/'_'.
   */
  while (isspace((int)*str))
    ++str ;

  start = str ;

  sign = 0 ;
  if ((*str == '-') || (*str == '+'))
    {
      sign = (*str == '-') ? -1 : +1 ;

      do
        ++str ;
      while (isspace((int)*str) || (*str == '_')) ;
    } ;

  /* Now get unsigned value.
   */
  uval = strtoul_x(str, p_tox, p_end) ;

  if (*p_tox < 0)
    {
      /* Number no good -- if is badly formed, set any p_end back to the
       *                   start of the number (before any sign).
       */
      if ((*p_tox == strtox_invalid) && (p_end != NULL))
        *p_end = miyagi(start) ;

      if ((*p_tox == strtox_range) && (sign >= 0))
        return RLONG_MAX ;

      return RLONG_MIN ;
    } ;

  /* Worry about sign and range.
   *
   * By C99 DEFINITION: an unsigned integer type is: 0..((2**N)-1)
   *
   *                       the signed equivalent is:  -(2**M)   ..((2**M)-1)
   *                                             or: -((2**M)-1)..((2**M)-1)
   *
   *             where: M <= N
   *
   * Conversion signed -> unsigned of the same type is trivial for +ve values.
   * For -ve values, adds 2**N.
   *
   * Conversion unsigned -> signed is "implementation defined" for values
   * greater than ((2**M)-1)
   *
   * Usually M == N-1 -- but that is not guaranteed.
   */
  if (sign >= 0)
    {
      qassert((sign == strtox_signed) || (sign == strtox_ok)) ;
      qassert(strtox_ok == 0) ;         /* as promised for *p_tox */
      *p_tox = sign ;

      /* +ve is easy -- is OK unless > RLONG_MAX
       */
      if (uval <= (urlong)RLONG_MAX)
        return uval ;                   /* +ve success          */
    }
  else
    {
      *p_tox = strtox_signed ;

      /* -ve is not so easy -- is OK if <= RLONG_MAX
       *                       is OK if == -RLONG_MIN
       *
       * If OK, need to negate.
       *
       * Getting -RLONG_MIN is tricky -- (theoretically) possible M != N-1
       *
       * Negating value > RLONG_MAX is also tricky !
       */
      confirm(((RLONG_MIN + RLONG_MAX) ==  0) ||
              ((RLONG_MIN + RLONG_MAX) == -1)) ;

      if (uval <= (urlong)RLONG_MAX)
        return -((rlong)uval) ;         /* -ve success          */

      if ((RLONG_MIN + RLONG_MAX) == -1)
        if (uval == ((urlong)RLONG_MAX + 1))
          return RLONG_MIN ;            /* extreme -ve success  */
    } ;

  /* Range error
   */
  *p_tox = strtox_range ;

  return (sign < 0) ? RLONG_MIN : RLONG_MAX ;
} ;

/*------------------------------------------------------------------------------
 * Simple strtoul() -- where the string is already known to be a valid number.
 *
 * NB: requires string to contain a number and only a number, apart from
 *     leading and trailing white-space.
 *
 * Returns:  *signed* rlong -- RLONG_MIN if out of range and -ve, or if invalid
 *                             RLONG_MAX if out of range and +ve
 */
extern rlong
strtol_s(const char* restrict str)
{
  strtox_t tox ;
  return strtol_x(str, &tox, NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Extended strtoul()
 *
 * See strtol_x() for description of p_end.
 *
 * Returns:  *unsigned* rlong --         0 if invalid
 *                              URLONG_MAX if out of range
 *
 *           *p_tox  ==  strtox_ok      => OK, no sign
 *                   ==  strtox_invalid => badly formed or empty number
 *                   ==  strtox_range   => out of range for *unsigned* rlong
 *
 * NB: does not allow a leading zign.
 */
extern urlong
strtoul_x(const char* restrict str, strtox_t* p_tox, const char** p_end)
{
  urlong uval ;
  int   base ;
  char  stripped[sizeof(urlong) * 3] ;
  const char* start ;
  char* q, * e ;
  int   (* isd)(int c) ;
  bool  expect_overflow ;

  /* We want stripped buffer which is long enough so that a digit string which
   * is truncated to fit will overflow, even if the first digit is '1' (and
   * assuming the first digit is not '0' !).
   *
   * The estimate of the number of digits to achieve this is based on 3 bits
   * per digit, which is an overestimate, since we don't do octal !
   */
  confirm((((sizeof(urlong) * 8) + 5) / 3) < sizeof(stripped)) ;

  /* Establish base -- eats leading whitespace, base marker and leading zeros
   *                   with any '_'.
   *
   * Ends up pointing at first character which is either the first significant
   * digit, or some invalid character (possibly a leading '_' !)
   *
   * We set start to point at the first non-whitespace.
   */
  while (isspace((int)*str))
    ++str ;

  start = str ;                 /* for invalid return   */
  base  = 10 ;
  isd   = isdigit ;

  if (*str == '0')
    {
      /* Leading base marker and/or zeros
       */
      if ((*(str+1) == 'x') || (*(str+1) == 'X'))
        {
          /* Switch to base 16 and step past "0x"/"0X" and any following '_'.
           *
           * If next character is not a digit, then whole thing is invalid, and
           * we return the "start" pointer.
           */
          base = 16 ;
          isd  = isxdigit ;
          str += 2 ;

          while (*str == '_')
            ++str ;
        } ;

      /* Now, strip leading zeros and any '_', until find a non-zero digit.
       *
       * Note that if we hit something which is not a digit, we backtrack to
       * the last '0' -- which mat or may not have trailing '_'.
       */
      while (*str == '0')
        {
          const char* s ;

          s = str ;

          ++str ;
          while (*str == '_')
            ++str ;

          if (!isd((int)*str))
            {
              str = s ;
              break ;
            } ;
        } ;
    } ;

  /* Must now have a digit -- otherwise is invalid.
   */
  if (!isd((int)*str))
    goto invalid ;              /* require at least one digit   */

  /* Have at least one significant digit -- move all significant digits to the
   * stripped buffer, removing any embedded '_'.
   *
   * Sets expect_overflow if exhaust the stripped buffer.
   *
   * Note that from now on, if p_end != NULL the result is a valid number,
   * even if overflows, so p_end will be set to the first character after the
   * number.
   */
  q = stripped ;
  e = stripped + sizeof(stripped) - 1 ;

  expect_overflow = false ;     /* so far so good               */

  while (1)
    {
      const char* s ;

      if (q < e)
        *q++ = *str ;
      else
        expect_overflow = true ;

      ++str ;
      if (isd((int)*str))
        continue ;              /* easy decision                */

      if (*str != '_')
        break ;                 /* ditto                        */

      /* Found a '_' -- skip across and continue if then get a digit, otherwise
       *                backtrack to first '_' and exit.
       */
      s = str ;

      do
        ++str ;
      while (*str == '_') ;

      if (isd((int)*str))
        continue ;

      str = s ;
      break ;
    } ;

  *q = '\0' ;                   /* complete stripped    */

  /* Worry about p_end or trailing whitespace or '_'.
   */
  if (p_end == NULL)
    {
      /* Require number and only number, but allow trailing whitespace.
       */
      if (*str != '\0')
        {
          while (isspace((int)*str))
            ++str ;

          if (*str != '\0')
            goto invalid ;
        } ;
    }
  else
    *p_end = miyagi(str) ;

  /* Let strtoul() rip on the digits we have stripped out of the given
   * string -- it should read them all, and if we expect_overflow, return
   * that.
   */
  errno = 0 ;
  uval = strtoul(stripped, &e, base) ;

  qassert(*e == '\0') ;
  if (*e != '\0')
    {
      /* Rats... the string we gave to strtoul contains a character which
       * is not part of the number according to strtoul !
       *
       * This is something of a puzzle, because have only given it decimal or
       * hex digits !
       */
      goto invalid ;            /* treat entire number as invalid !     */
    } ;

  if ((errno == 0) && (!expect_overflow))
    {
      *p_tox = strtox_ok ;
      return uval ;             /* Success !                            */
    } ;

  /* Reject the number -- set p_end to current str, errno already set.
   *
   * NB: we expect only ERANGE here... force it in any case.
   *
   * NB: if we expect_overflow, but do not get it, the qassert should spring,
   *     but otherwise we force a range error.
   */
  qassert((errno == ERANGE) || expect_overflow) ;

  *p_tox = strtox_range ;
  if (p_end != NULL)
    *p_end = miyagi(str) ;
  return URLONG_MAX ;

  /* Invalid -- number is not well formed, or is not the only thing in the
   *            given string.
   */
invalid:
  *p_tox = strtox_invalid ;
  if (p_end != NULL)
    *p_end = miyagi(start) ;
  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Simple strtoul() -- where the string is already known to be a valid number.
 *
 * NB: requires string to contain a number and only a number, apart from
 *     leading and trailing white-space.
 *
 * Returns:  *unsigned* rlong --         0 if invalid
 *                              URLONG_MAX if out of range
 */
extern urlong
strtoul_s(const char* restrict str)
{
  strtox_t tox ;
  return strtoul_x(str, &tox, NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Extended strtol() with check against given range.
 *
 * See strtol_x() for description of p_end.
 *
 * Returns:  *signed* rlong -- min if < min, or if invalid
 *                             max if > max
 *
 *           *p_tox  ==  strtox_signed  => OK, sign seen (+ or -)
 *                   ==  strtox_ok      => OK, no sign
 *                   ==  strtox_invalid => badly formed or empty number
 *                   ==  strtox_range   => out of range (< min or > max)
 */
extern rlong
strtol_xr(const char* restrict str, strtox_t* p_tox, const char** p_end,
                                                           rlong min, rlong max)
{
  rlong val ;

  val = strtol_x(str, p_tox, p_end) ;   /* returns RLONG_MIN if invalid */

  if (*p_tox >= strtox_ok)
    {
      if ((val >= min) && (val <= max))
        return val ;

      *p_tox = strtox_range ;
    } ;

  return (val < 0) ? min : max ;
} ;

/*------------------------------------------------------------------------------
 * Simple strtol_sr() -- where the string is already known to be a valid number.
 *
 * NB: requires string to contain a number and only a number, apart from
 *     leading and trailing white-space.
 *
 * Returns:  *signed* rlong -- min if < min, or if invalid
 *                             max if > max
 */
extern rlong
strtol_sr(const char* restrict str, rlong min, rlong max)
{
  strtox_t tox ;
  return strtol_xr(str, &tox, NULL, min, max) ;
} ;

/*------------------------------------------------------------------------------
 * Extended strtoul() with check against given range.
 *
 * See strtol_x() for description of p_end.
 *
 * Returns:  *unsigned* rlong -- min if < min, or if invalid
 *                               max if > max
 *
 *           *p_tox  ==  strtox_ok      => OK, no sign
 *                   ==  strtox_invalid => badly formed or empty number
 *                   ==  strtox_range   => out of range for signed rlong
 */
extern urlong
strtoul_xr(const char* restrict str, strtox_t* p_tox, const char** p_end,
                                                         urlong min, urlong max)
{
  urlong uval ;

  uval = strtoul_x(str, p_tox, p_end) ;

  if (*p_tox >= strtox_ok)
    {
      if ((uval >= min) && (uval <= max))
        return uval ;

      *p_tox = strtox_range ;
    } ;

  /* If *p_tox == strtox_invalid, return min.  uval will be zero.
   *
   * If *p_tox == strtox_range, return min if uval <= min, otherwise max
   *
   * Since the smallest possible min is zero, we don't need to worry about
   * the state of *p_tox.
   *
   * Note that if get impossibly large number in strtoul_x() it returns
   * URLONG_MAX.  (So, if min == URLONG_MAX, then that's fine !)
   */
  return (uval <= min) ? min : max ;
} ;

/*------------------------------------------------------------------------------
 * Simple strtol_sr() -- where the string is already known to be a valid number.
 *
 * NB: requires string to contain a number and only a number, apart from
 *     leading and trailing white-space.
 *
 * Returns:  *unsigned* rlong -- min if < min, or if invalid
 *                               max if > max
 */
extern urlong
strtoul_sr(const char* restrict str, urlong min, urlong max)
{
  strtox_t tox ;

  return strtoul_x(str, &tox, NULL) ;
} ;

/*==============================================================================
 * Miscellaneous string functions.
 */

/*------------------------------------------------------------------------------
 * Force string to lower case
 *
 * Return:  address of string as given
 */
extern char*
strtolower(char* str)
{
  char* start ;
  char ch ;

  if (str == NULL)
    return NULL ;

  start = str ;

  while ((ch = *str) != '\0')
    *str++ = tolower(ch) ;

  return start ;
} ;

/*------------------------------------------------------------------------------
 * Trim isspace() characters from front and back of the given string.
 *
 * Return:  address of first not isspace() character -- may be the trailing '\0'
 *
 * NB: address returned is not the original address if there were any leading
 *     isspace() characters.
 *
 * NB: if there are any trailing isspace(), then they are *all* replaced by
 *     '\0' -- this writes to the given string.
 */
extern char*
strtrim_space(char* str)
{
  char* end ;

  if (str == NULL)
    return NULL ;

  while (isspace(*str))
    ++str ;

  end = strchr(str, '\0') ;
  while ((end > str) && isspace(*(end - 1)))
    {
      --end ;
      *end = '\0' ;
    } ;

  return str ;
} ;

/*------------------------------------------------------------------------------
 * Trim isblank() characters from front and back of the given string.
 *
 * Return:  address of first not isblank() character -- may be the trailing '\0'
 *
 * NB: address returned is not the original address if there were any leading
 *     isblank() characters.
 *
 * NB: if there are any trailing isblank(), then they are *all* replaced by
 *     '\0' -- this writes to the given string.
 */
extern char*
strtrim_blank(char* str)
{
  char* end ;

  if (str == NULL)
    return NULL ;

  while (isblank(*str))
    ++str ;

  end = strchr(str, '\0') ;
  while ((end > str) && isblank(*(end - 1)))
    {
      --end ;
      *end = '\0' ;
    } ;

  return str ;
} ;

/*------------------------------------------------------------------------------
 * Compare two strings, where any substrings of decimal digits are treated as
 * numbers, and numbers are less than all other characters.
 *
 * That is: "a1b" < "a10b" but "za1b" > "z1b" and "z!1b" > "z1b"
 *
 * Leading zeros are ignored, unless the strings are otherwise equal.
 *
 * That is: "a01" < "a2" BUT "a01" > "a1"
 *
 * The comparison effectively breaks the two stings into alternating substings
 * of digits and non-digits.  Then the comparison between substrings is:
 *
 *   *     digits cmp     digits     -- numeric comparison.
 *
 *   *     digits cmp non-digits     -- digits rank smaller
 *
 *   * non-digits cmp     digits     -- digits rank smaller
 *
 *   * non-digits cmp non-digits     -- string comparison
 *
 * If the number of substrings differs, and all substrings match up to the end
 * of the string with fewer substrings, then the string with more substrings is
 * the larger.
 *
 * If the number of substrings is the same, and all substrings match, then if
 * we stepped across more leading zeros in one string, then it is the larger.
 * The first such difference takes precedence, so:
 *
 *   "a0001b2" > "a1b00000002"
 *
 * For two strings to be equal, they must be exactly the same (including
 * leading zeros).
 */
extern int
strcmp_mixed(const void* restrict a, const void* restrict b)
{
  const uchar* ap ;
  const uchar* bp ;
  int  match ;

  ap = a ;
  bp = b ;
  match = 0 ;

  while (1)
    {
      bool da, db ;

      da = isdigit(*ap) ;
      db = isdigit(*bp) ;

      if (da || db)
        {
          const uchar* as ;
          const uchar* bs ;
          uint la, lb ;

          /* One or both are digits.
           *
           * If they are not both digits, then: empty < digit < everything else
           */
          if (!(da && db))
            {
              if (da)
                return (*bp != '\0') ? -1 : +1 ;
              else
                return (*ap != '\0') ? +1 : -1 ;
            } ;

          /* Before comparing one or more digits in the two strings, we:
           *
           *   (a) step past any leading zeros
           *
           *   (b) count the number of digits after any leading zeros.
           *
           * If the counts of significant digits are not equal, then the longer
           * number is the larger.
           *
           * If the counts of significant digits are equal, then we can compare
           * the two digit substrings character-wise.  If the substrings are
           * equal, we continue, with *ap and *bp both pointing at something
           * which is not a digit.
           */
          as = ap ;
          while ((*ap == '0') && (*(ap+1) == '0'))
            ++ap ;                /* step past leading zeros      */

          la = 0 ;
          do
            ++la ;                /* get significant length       */
          while (isdigit(ap[la])) ;

          bs = bp ;
          while ((*bp == '0') && (*(bp+1) == '0'))
            ++bp ;                /* step past leading zeros      */

          lb = 0 ;
          do
            ++lb ;                /* get significant length       */
          while (isdigit(bp[lb])) ;

          if (la != lb)
            return (la < lb) ? -1 : +1 ;

          do
            {
              if (*ap != *bp)
                return (*ap < *bp) ? -1 : +1 ;

              ++ap ;
              ++bp ;
              --la ;
            }
          while (la > 1) ;

          /* The digit strings are equal, ignoring leading zeros.
           *
           * If the "match" has not already been set, and if the number of
           * leading zeros is not the same, set the "match" as the final
           * result of everything else is equal.
           */
          if (match == 0)
            {
              la = ap - as ;
              lb = bp - bs ;
              if (la != lb)
                match = (la < lb) ? -1 : +1 ;
            } ;
        } ;

      if (*ap != *bp)
        return (*ap < *bp) ? -1 : +1 ;

      if (*ap == '\0')
        break ;                         /* *ap == &bp == '\0'   */

      ++ap ;
      ++bp ;
    } ;

  /* The comparison has stopped at the end of both strings.
   *
   * The result is a match, unless we stepped across more leading zeros in
   * one of the strings.  Noting that the first instance of that takes
   * precedence over any further instances.
   */
  return match ;
} ;

/*------------------------------------------------------------------------------
 * Compare "string" and "pattern" in "lax" fashion.
 *
 * The comparison ignores case.
 *
 * All isspace() characters are deemed equal to each other, and equal to ' '.
 *
 * For each isspace() in the pattern, there must be a matching isspace()
 * in the string.
 *
 * Otherwise, isspace() in the string is ignored if:
 *
 *   * at start of end of pattern
 *
 *   * last pattern character matched was ispunct()
 *
 *   * next pattern character to match is ispunct()
 *
 *   * last pattern character matched was isspace()
 *
 * Note that 2 or more spaces in the string will match 2 spaces in the
 * pattern, but 1 space in the string will not.
 *
 * Note that spaces in the pattern are never ignored.  So spaces around
 * punctuation in the pattern are mandatory.
 *
 * Returns:  0  <=> string and pattern match                )
 *          -1  <=> first mismatch has the string < pattern ) in the usual way
 *          +1  <=> first mismatch has the string > pattern )
 */
extern int
strcmp_lax(const void* restrict a, const void* restrict b)
{
  uint ppch, pch, sch ;

  const uchar* restrict str = a ;
  const uchar* restrict pat = b ;

  ppch = ' ' ;          /* start of string looks like matching spaces   */

  sch  = *str++ ;       /* prime the pump       */
  pch  = *pat++ ;
  while (1)
    {
      /* At the top of the loop we have:
       *
       *   * sch and pch   -- current characters to consider
       *
       *   * pat and str   -- pointers to next characters to consider
       *
       *   * ppch          -- last patching pattern character
       *
       * Eat as much simple match or caseless match as we can.  Generally
       * we expect match to proceed without incident... so will generally
       * start and finish here.
       *
       * Emerges from the loop with ppch set to the last match.
       */
      while ((sch == pch) || (tolower(sch) == tolower(pch)))
        {
          if (sch == '\0')
            return 0 ;

          ppch = pch ;

          sch  = *str++ ;
          pch  = *pat++ ;
        } ;

      /* We do not have a match.
       *
       * We have some latitude iff the current string character isspace().
       * (Since we can have more spaces in the string, but not fewer.)
       *
       * But otherwise the comparison is over -- arrange sch and pch for
       * the return.
       */
      if (!isspace(sch))
        {
          sch = tolower(sch) ;
          pch = isspace(pch) ? ' ' : tolower(pch) ;
          break ;
        } ;

      /* Space in the string.
       */
      if (isspace(pch))
        {
          /* Space in both pattern and string.
           *
           * Each space in the pattern must match a space in the string.
           *
           * Sets ppch so that if next string character isspace, but next
           * pattern character is not, then will eat the remain string
           * isspace().
           */
          ppch = pch ;

          sch  = *str++ ;
          pch  = *pat++ ;

          continue ;
        } ;

      /* Space in the string, but not in the pattern
       */
      if ( ispunct(ppch) || ispunct(pch) || isspace(ppch) || (pch == '\0') )
        {
          /* Can step past spaces in the string, because:
           *
           *   * previous match was punctuation
           *   * current pattern character is punctuation.
           *   * previous match was space or start of string
           *   * have reached end of the pattern
           *
           * We don't change ppch, since there has been no match.  But it
           * doesn't matter what it is, since sch emerges as not space, so will
           * not get here again unless there is another match !
           */
          do { sch = *str++ ; } while (isspace(sch)) ;

          continue ;
        } ;

      /* Space in the string, but no excuse to step past it -- in particular,
       * pattern character is not space.
       *
       * The comparison is over -- arrange sch and pch for the return.
       */
      sch = ' ' ;
      pch = tolower(pch) ;
      break ;
    } ;

  /* Comparison failed.
   *
   * We have sch and pch:  if isspace() == ' '
   *                       otherwise, lower case
   */
  return (sch < pch) ? -1 : + 1 ;
} ;

/*==============================================================================
 * Generating strings for integer values -- itostr, utostr etc.
 *
 * These are passed a pointer to a umax_buf_t, in which the digits and any
 * sign are placed, with a trailing '\0'.  The pointer returned is the address
 * of the ms digit or the sign.
 *
 * NB: the string is generated LS digit first, and the ptr argument MUST
 *     point at the END of the buffer to be used.
 *
 *     The LS digit is written at ptr - 1.  Nothing is written at or after ptr.
 *
 *     So:
 *
 *       umax_buf_t  buf ;
 *       char* p, *e ;
 *
 *       e = buf + sizeof(buf) ;
 *       p = umaxtostr(e, ...) ;
 *
 *     will work.  And (e - p) is the length of the result.
 *
 * NB: does NOT insert a trailing '\0'.
 *
 *     So:
 *
 *       umax_buf_t  buf ;
 *       char* p, *e ;
 *
 *       e = buf + sizeof(buf) - 1 ;
 *       p = umaxtostr(e, ...) ;
 *
 *       *e = '\0' ;
 *
 *     will do the trick.
 *
 * The base is expected to be 8, 10 or 16:
 *
 *   * bases > 32 produce nonsense, and will probably SEGV.
 *
 *   * bases <  8 will may generate more digits that will fit in the
 *     standard buffer.
 *
 *     So, for base 2 just need a much longer buffer.
 *
 *   * bases < 2 are hopeless, and will crash and burn.
 */
                               /*........10........20........30..*/
static const char lc_digits[] = "0123456789abcdefghijklmnopqrstuv" ;
static const char uc_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV" ;

extern char*
itostr(char* ptr,    int v, uint base, bool uc)
{
  if (v >= 0)
    return utostr(ptr, v, base, uc) ;

  ptr = utostr(ptr, uabs(v), base, uc) ;

  *(--ptr) = '-' ;

  return ptr ;
} ;

extern char*
utostr(char* ptr,   uint v, uint base, bool uc)
{
  const char* digits ;
  div_t       dv ;

  digits = uc ? uc_digits : lc_digits ;

  if (v > INT_MAX)
    {
      confirm((UINT_MAX / 2) <= INT_MAX) ;

      dv.quot = (int)(v / base) ;
      dv.rem  = (int)(v % base) ;
    }
  else
    dv = div((int)v, base) ;

  while (1)
    {
      *(--ptr) = *(digits + dv.rem) ;

      if (dv.quot == 0)
        break ;

      dv = div(dv.quot, base) ;
    } ;

  return ptr ;
} ;

extern char*
iltostr(char* ptr,   long v, uint base, bool uc)
{
  if (v >= 0)
    return ultostr(ptr, v, base, uc) ;

  ptr = ultostr(ptr, ulabs(v), base, uc) ;

  *(--ptr) = '-' ;

  return ptr ;
} ;

extern char*
ultostr(char* ptr,  ulong v, uint base, bool uc)
{
  const char* digits ;
  ldiv_t      dv ;

  digits = uc ? uc_digits : lc_digits ;

  if (v > LONG_MAX)
    {
      confirm((ULONG_MAX / 2) <= LONG_MAX) ;

      dv.quot = (long)(v / base) ;
      dv.rem  = (long)(v % base) ;
    }
  else
    dv = ldiv((long)v, base) ;

  while (1)
    {
      *(--ptr) = *(digits + dv.rem) ;

      if (dv.quot == 0)
        break ;

      dv = ldiv(dv.quot, base) ;
    } ;

  return ptr ;
} ;

extern char*
illtostr(char* ptr,  llong v, uint base, bool uc)
{
  if (v >= 0)
    return ulltostr(ptr, v, base, uc) ;

  ptr = ulltostr(ptr, ullabs(v), base, uc) ;

  *(--ptr) = '-' ;

  return ptr ;
} ;

extern char*
ulltostr(char* ptr, ullong v, uint base, bool uc)
{
  const char* digits ;
  lldiv_t     dv ;

  digits = uc ? uc_digits : lc_digits ;

  if (v > LLONG_MAX)
    {
      confirm((ULLONG_MAX / 2) <= LLONG_MAX) ;

      dv.quot = (llong)(v / base) ;
      dv.rem  = (llong)(v % base) ;
    }
  else
    dv = lldiv((llong)v, base) ;

  while (1)
    {
      *(--ptr) = *(digits + dv.rem) ;

      if (dv.quot == 0)
        break ;

      dv = lldiv(dv.quot, base) ;
    } ;

  return ptr ;
} ;

extern char*
imaxtostr(char* ptr,   imax v, uint base, bool uc)
{
  if (v >= 0)
    return umaxtostr(ptr, v, base, uc) ;

  ptr = umaxtostr(ptr, umaxabs(v), base, uc) ;

  *(--ptr) = '-' ;

  return ptr ;
} ;

extern char*
umaxtostr(char* ptr,   umax v, uint base, bool uc)
{
  const char* digits ;
  imaxdiv_t   dv ;

  digits = uc ? uc_digits : lc_digits ;

  if (v > INTMAX_MAX)
    {
      confirm((UINTMAX_MAX / 2) <= INTMAX_MAX) ;

      dv.quot = (imax)(v / base) ;
      dv.rem  = (imax)(v % base) ;
    }
  else
    dv = imaxdiv((imax)v, base) ;

  while (1)
    {
      *(--ptr) = *(digits + dv.rem) ;

      if (dv.quot == 0)
        break ;

      dv = imaxdiv(dv.quot, base) ;
    } ;

  return ptr ;
} ;
