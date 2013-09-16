/* Temporary string handling -- header
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

#ifndef _ZEBRA_TSTRING_H
#define _ZEBRA_TSTRING_H

#include "misc.h"

/*==============================================================================
 * tstrings are allocated on the stack, but if (unexpectedly) the standard
 * size is not enough, then they can be allocated dynamically.
 *
 * To declare a "tstring":
 *
 *   tstring(foo, 64) ;   // creates a "tstring" variable called "foo"
 *                        // with (at least) 64 char buffer (called "fooBuf").
 *
 * The size is rounded "up-up" to multiple of sizeof(void*) -- so will be
 * at least sizeof(void*) bigger than the nominal size, which allows for
 * trailing '\0' and a touch more.
 *
 * The variable foo and the buffer fooBuf are initialised with a '\0' at the
 * start of fooBuf.
 *
 * Can then:
 *
 *   s = tstring_set_len(foo, n) ;  // ensures have buffer for n+1 chars
 *   s = tstring_set(foo, "...") ;  // copies "..." (with '\0') to buffer
 *   s = tstring_set_n(foo, q, n) ; // copies n characters from q to buffer
 *                                     and '\0' terminates
 *
 * If can fit stuff in the buffer, will do so.  Otherwise will allocate an
 * MTYPE_TMP buffer to work in.
 *
 * And before leaving the scope of "foo" must:
 *
 *   tstring_free(foo) ;    // releases any dynamically allocated memory.
 */
struct tstring
{
  char*   str ;
  usize   size ;
  bool    alloc ;
  char    fb[1] ;
} ;

typedef struct tstring tstring[1] ;

/* tstring(foo, 93) ;   -- declare the variable "foo", and initialise it
 *                         empty.
 */
#define tstring_t(name, sz) \
  char    name##Buf[          ROUND_UP_UP(sz, sizeof(void*))] = { '\0' } ; \
  tstring name = { { .size  = ROUND_UP_UP(sz, sizeof(void*)), \
                     .str   = name##Buf, \
                     .alloc = false } }

/*==============================================================================
 * Functions
 */
Inline char* tstring_need(tstring ts, usize len) ;
Inline void tstring_clear(tstring ts) ;
Inline void tstring_free(tstring ts) ;

Private char* tstringP_need(tstring ts, usize len) ;
Private void tstringP_free(tstring ts) ;

Inline char* tstring_set_str(struct tstring* ts, const char* str) ;
Inline char* tstring_set_str_n(tstring ts, const char* str, usize len) ;
extern char* tstring_set_fill(tstring ts, usize len, const char* src) ;
extern char* tstring_set_fill_n(tstring ts, usize len, const char* src,
                                                                   usize flen) ;

extern char* tstring_append_str(tstring ts, const char* src) ;
extern char* tstring_append_str_n(tstring ts, const void* src, usize n) ;
extern char* tstring_append_ch_x_n(tstring ts, char ch, uint n) ;
extern char* tstring_append_ch(tstring ts, char ch) ;

/*==============================================================================
 * The Inline stuff.
 */

/*------------------------------------------------------------------------------
 * Ensure the tstring "foo" can accommodate at least "len" characters *plus* a
 * terminating '\0'.
 *
 * Returns: address of buffer
 *
 * NB: address of buffer may not be the same as returned by a previous
 *     operation on foo.
 *
 * NB: the contents of foo are preserved, and the extended portion set to
 *     all zeros.
 */
Inline char*
tstring_need(tstring ts, usize len)
{
  return (len < ts->size) ? ts->str : tstringP_need(ts, len) ;
} ;

/*------------------------------------------------------------------------------
 * Clear the given tstring to zero.
 */
Inline void
tstring_clear(tstring ts)
{
  memset(ts->str, 0, ts->size) ;
} ;

/*------------------------------------------------------------------------------
 * If have dynamically allocated buffer for tstring "foo", release it now.
 *
 * Once a buffer has been dynamically allocated there is no real need to
 * free it until the tstring is no longer required -- so makes no attempt
 * to set the tstring back to the original buffer.
 *
 * NB: for safety, freeing a dynamically allocated buffer sets the size and
 *     pointer to the 'fb' inside the tstring.  So, it is possible to continue
 *     to use it... but not advised.
 */
Inline void
tstring_free(tstring ts)
{
  if (ts->alloc)
    tstringP_free(ts) ;
 } ;

/*------------------------------------------------------------------------------
 * Copy the string "str" to the tstring "foo", with terminating '\0'.
 *
 * If "str" is NULL, sets "foo" to be an empty string.
 *
 * Returns: address of buffer
 *
 * NB: address of buffer may not be the same as returned by a previous operation
 *     on foo.  Also, previous contents of foo may be lost.
 */
Inline char*
tstring_set_str(tstring ts, const char* src)
{
  return tstring_set_str_n(ts, src, (src != NULL) ? strlen(src) : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Copy "len" characters from "src" to the tstring "foo", and append a
 * terminating '\0'.
 *
 * The "src" address is ignored if "len" == 0 (sets "foo" to be empty string).
 *
 * Returns: address of buffer
 *
 * NB: address of buffer may not be the same as returned by a previous operation
 *     on foo.  Also, previous contents of foo may be lost.
 */
Inline char*
tstring_set_str_n(tstring ts, const char* src, usize len)
{
  char* tss = tstring_need(ts, len) ;

  if (len > 0)
    memcpy(tss, src, len) ;
  *(tss + len) = '\0' ;

  return tss ;
} ;

#endif /* _ZEBRA_TSTRING_H */
