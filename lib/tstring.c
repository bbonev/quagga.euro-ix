/* Temporary string handling
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
#include "tstring.h"
#include "memory.h"

/*==============================================================================
 * Private functions for dynamically allocated string bodies.
 */

/*------------------------------------------------------------------------------
 * Ensure the tstring "foo" can accommodate at least "len" characters plus the
 * terminating '\0'.
 *
 * Returns: address of buffer
 *
 * NB: address of buffer may not be the same as returned by a previous
 *     operation
 *
 * NB: whatever happens, preserves contents of the buffer, and zeroizes any
 *     new allocation.
 *
 * NB: does nothing if the new size is actually less than or equal to the
 *     current -- though that won't happen unless this is called directly !
 */
Private char*
tstringP_need(tstring ts, usize len)
{
  uint  size_new ;

  size_new = uround_up_up(len, 16) ;

  if (size_new > ts->size)
    {
      char* str_new ;

      if (ts->alloc)
        str_new = XREALLOC(MTYPE_TMP, ts->str, size_new) ;
      else
        {
          str_new = XMALLOC(MTYPE_TMP, size_new) ;
          memcpy(str_new, ts->str, ts->size) ;
        } ;

      memset(&str_new[ts->size], 0, size_new - ts->size) ;

      ts->str  = str_new ;
      ts->size = size_new ;
    } ;

  return ts->str ;
} ;

/*------------------------------------------------------------------------------
 * Release dynamically allocated buffer.
 *
 * There is some paranoia at work here:
 *
 *   * does nothing if not, in fact, allocated.
 *
 *   * after freeing the dynamically allocated buffer, sets the tstring to
 *     a trivial, but valid, buffer inside the tstring itself... so that it
 *     is at least safe to continue to use the tstring -- even though that is
 *     not expected.
 */
Private void
tstringP_free(tstring ts)
{
  if (ts->alloc)
    {
      XFREE(MTYPE_TMP, ts->str) ;

      ts->str   = ts->fb ;
      ts->size  = sizeof(struct tstring) - offsetof(struct tstring, fb) ;
      ts->alloc = false ;

      ts->str[0] = '\0' ;
    } ;
} ;

/*==============================================================================
 * Functions for filling tstrings.
 */

/*------------------------------------------------------------------------------
 * Set tstring with given pattern to given length.
 *
 * Repeats the given pattern as many times as necessary to get to the given
 * length -- using a final partial piece of the pattern as required.
 *
 * If the pattern is NULL or zero length, fills with spaces !
 */
extern char*
tstring_set_fill(tstring ts, usize len, const char* src)
{
  return tstring_set_fill_n(ts, len, src, (src != NULL ? strlen(src) : 0)) ;
} ;

/*------------------------------------------------------------------------------
 * Set tstring with given pattern to given length.
 *
 * Repeats the given pattern as many times as necessary to get to the given
 * length -- using a final partial piece of the pattern as required.
 *
 * If the pattern is NULL or zero length, fills with spaces !
 */
extern char*
tstring_set_fill_n(tstring ts, usize len, const char* src, usize flen)
{
  char*  b ;
  char*  p ;

  p = b = tstring_need(ts, len) ;

  if (len != 0)
    {
      if (flen == 0)
        {
          src  = "          " ;
          flen = strlen(src) ;
        } ;

      while (len > flen)
        {
          memcpy(p, src, flen) ;

          p   += flen ;
          len -= flen ;

          if (src != b)
            src = b ;
          else
            flen += flen ;
        } ;

      memcpy(p, src, len) ;
      p += len ;
    } ;

  *p = '\0' ;
  return b ;
} ;

/*==============================================================================
 * Functions for appending to tstrings.
 */

/*==============================================================================
 * Appending to a tstring
 *
 * Copy the given stuff to the end of the given tstring -- assuming that is
 * '\0' terminated in the usual way, and adds '\0'.
 *
 * Returns: address of the tstring body (allocated if required).
 */

/*------------------------------------------------------------------------------
 * Append given string to a tstring -- cf strcat
 *
 * Treats src == NULL as an empty string.  Otherwise src must be a '\0'
 * terminated string.
 *
 * Returns:  address of body of tstring -- '\0' terminated
 */
extern char*
tstring_append_str(tstring ts, const char* src)
{
  return tstring_append_str_n(ts, src, (src != NULL) ? strlen(src) : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Append leading 'n' bytes of given string to a tstring, and add '\0'
 *
 * If n == 0, src may be NULL
 * If n > 0, src string MUST be at least 'n' bytes long.
 *
 * Returns:  address of body of tstring -- '\0' terminated
 */
extern char*
tstring_append_str_n(tstring ts, const void* src, usize n)
{
  ulen  len ;
  char* b ;

  if (n == 0)
    return ts->str ;

  len = strlen(ts->str) ;
  b   = tstring_need(ts, len + n) ;

  memcpy(b + len, src, n) ;
  b[len + n] = '\0' ;

  return b ;
} ;

/*------------------------------------------------------------------------------
 * Append 'n' copies of given char to a tstring (created if NULL).
 *
 * See notes above.
 */
extern char*
tstring_append_ch_x_n(tstring ts, char ch, uint n)
{
  ulen  len ;
  char* b ;

  if (n == 0)
    return ts->str ;

  len = strlen(ts->str) ;
  b   = tstring_need(ts, len + n) ;

  memset(b + len, ch, n) ;
  b[len + n] = '\0' ;

  return b ;
} ;

/*------------------------------------------------------------------------------
 * Append given char to a tstring.
 *
 * See notes above.
 */
extern char*
tstring_append_ch(tstring ts, char ch)
{
  ulen  len ;
  char* b ;

  len = strlen(ts->str) ;
  b   = tstring_need(ts, len + 1) ;

  b[len]     = ch ;
  b[len + 1] = '\0' ;

  return b ;
} ;

