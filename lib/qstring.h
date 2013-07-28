/* Some string handling -- header
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

#ifndef _ZEBRA_QSTRING_H
#define _ZEBRA_QSTRING_H

#include "misc.h"
#include "vargs.h"
#include "memory.h"
#include "qlump.h"
#include "qfstring.h"
#include "elstring.h"

/*==============================================================================
 * These "qstrings" address address the lack of a flexible length string in 'C'.
 *
 * This is not a general purpose strings module, but provides a limited number
 * of useful string operations such that the caller does not need to worry
 * about the length of the string, and allocating space and so on.
 *
 * The caller does, however, have to explicitly release the qstring when it is
 * done with.
 *
 * The mechanics of a qstring work on a length/pointer basis.  The body of a
 * qstring is not guaranteed to be '\0' terminated, but when memory is
 * allocated provision is always made for a terminator beyond the 'len'.
 * The qs_string() function will add a '\0' at the 'len' position.
 *
 * The body of a qstring is allocated and extended automatically as the length
 * or the size is set.  The address of the body can, therefore, change -- so
 * should be careful when handling pointers to the body.  The qstring handling
 * tends to hold on to any body that has been allocated -- only qs_reset() will
 * free the body.
 *
 * The qstring supports an "alias" state.  A qstring can be set to be an
 * "alias" for another length/pointer string, and at some later date that
 * can be copied to the qstring body -- to be changed or for any other
 * reason.
 *
 * The underlying qlump "limits" qstrings to 1G bytes.  The 'cp' can be -ve,
 * for some purposes, which we hold as 2's complement unsigned, so that
 * inadvertent use of a -ve cp will be trapped as an insanely large 'cp'.
 */
typedef qlump_t  qstring_t[1] ;
typedef qlump_t  qstring_s ;
typedef qlump_t* qstring ;

/* Setting an qstring object to all zeros is enough to initialise it to
 * be "unset".
 *
 * An "unset" qstring is completely empty, and MUST be initialised before use.
 * The following will accept an "unset" qstring:
 *
 * XXX ................................................................................
 */
CONFIRM(QLUMP_UNSET_ALL_ZEROS) ;
enum
{
  QSTRING_UNSET_ALL_ZEROS = true
} ;

/*------------------------------------------------------------------------------
 * Access functions for body of qstring -- to take care of casting pointers
 *
 * There are generally two versions of each function:
 *
 *   xxxx_nn    -- where the argument may NOT be NULL
 *
 *   xxxx       -- where a NULL or zero value is returned if the argument
 *                 is NULL
 *
 * NB: the various 'cp', 'len' and 'at' functions do not guarantee that these
 *     positions exist within the current body of the string.
 *
 */
Inline void* qs_body_nn(qstring qs) ;
Inline char* qs_char_nn(qstring qs) ;
Inline char* qs_char_at_nn(qstring qs, usize off) ;
Inline char* qs_cp_char_nn(qstring qs) ;
Inline char* qs_ep_char_nn(qstring qs) ;
Inline ulen qs_len_nn(qstring qs) ;
Inline ulen qs_cp_nn(qstring qs) ;
Inline usize qs_size_nn(qstring qs) ;

Inline void qs_set_len_nn(qstring qs, ulen len) ;
Inline void qs_set_strlen_nn(qstring qs) ;
Inline void qs_set_cp_nn(qstring qs, usize cp) ;
Inline void qs_move_cp_nn(qstring qs, int delta) ;

Inline void* qs_body(qstring qs) ;
Inline char* qs_char(qstring qs) ;
Inline char* qs_char_at(qstring qs, usize off) ;
Inline char* qs_cp_char(qstring qs) ;
Inline char* qs_ep_char(qstring qs) ;
Inline ulen qs_len(qstring qs) ;
Inline ulen qs_cp(qstring qs) ;
Inline usize qs_size(qstring qs) ;

Inline ulen qs_after_cp(qstring qs) ;
Inline ulen qs_after_cp_nn(qstring qs) ;

Inline void qs_pp_nn(pp p, qstring qs) ;
Inline void qs_cpp_nn(cpp p, qstring qs) ;
Inline void qs_pp(pp p, qstring qs) ;
Inline void qs_cpp(cpp p, qstring qs) ;

/*------------------------------------------------------------------------------
 * Functions to get properties of the qstring -- which MUST *NOT* be NULL
 *
 * See below for functions which tolerate a NULL qstring.
 *
 * NB: all values returned must be treated with care -- any operation on the
 *     qstring may invalidate the value.
 */

/* Start of qstring body -- void* -- qstring *not* NULL
 */
Inline void*
qs_body_nn(qstring qs)
{
  return qs->body.v ;
} ;

/* Start of qstring body -- char* -- qstring *not* NULL
*/
Inline char*
qs_char_nn(qstring qs)
{
  return qs->body.c ;
} ;

/* Offset in qstring body  -- char* -- qstring *not* NULL
 *
 * NB: returns *nonsense if body is NULL and 'off' != 0
 */
Inline char*
qs_char_at_nn(qstring qs, usize at)
{
  return qs->body.c + at ;
} ;

/* 'cp' in qstring body  -- char* -- qstring *not* NULL
 *
 * NB: returns *nonsense if body is NULL and len != 0
 */
Inline char*
qs_cp_char_nn(qstring qs)
{
  return qs->body.c + qs->cp ;
} ;

/* 'len' in qstring body -- char* -- qstring *not* NULL
 *
 * NB: returns *nonsense if body is NULL and len != 0
 */
Inline char*
qs_ep_char_nn(qstring qs)
{
  return qs->body.c + qs->len ;
} ;

/* 'len' of qstring -- qstring *not* NULL
 */
Inline ulen
qs_len_nn(qstring qs)
{
  return qs->len ;
} ;

/* 'cp' of qstring -- qstring *not* NULL
 */
Inline ulen
qs_cp_nn(qstring qs)
{
  return qs->cp ;
} ;

/* 'len' - 'cp' of qstring -- qstring *not* NULL -- zero if 'len' < 'cp'
 */
Inline ulen
qs_after_cp_nn(qstring qs)
{
  ulen len ;
  ulen cp ;

  len = qs->len ;
  cp  = qs->cp ;

  return (len > cp) ? len - cp : 0 ;
} ;

/* Size of qstring  -- qstring *not* NULL
 */
Inline usize
qs_size_nn(qstring qs)
{
  return qs->size ;
} ;

/*------------------------------------------------------------------------------
 * Functions to set properties of qstring -- which MUST *NOT* be NULL.
 */

/* set 'len' of qstring (not NULL) -- caller responsible for validity
 */
Inline void
qs_set_len_nn(qstring qs, ulen len)
{
  qs->len = len ;
} ;

/* set 'len' of qstring (not NULL) according to strlen(body) (not NULL) !
 */
Inline void
qs_set_strlen_nn(qstring qs)
{
  qs->len = strlen(qs->body.c) ;
} ;

/* set 'cp' of qstring (not NULL) -- caller responsible for validity
 */
Inline void
qs_set_cp_nn(qstring qs, usize cp)
{
  qs->cp = cp ;
} ;

/* move 'cp' of qstring (not NULL) -- caller responsible for validity
 */
Inline void
qs_move_cp_nn(qstring qs, int delta)
{
  qs->cp += delta ;
} ;

/*------------------------------------------------------------------------------
 * Functions to get/set properties of the qstring -- even NULL qstrings.
 *
 * A NULL qstring has a NULL body, zero length, zero size, etc.
 *
 * NB: all values returned must be treated with care -- any operation on the
 *     qstring may invalidate the value.
 */

/* Start of qstring body -- void* -- NULL if qstring is NULL, or body is.
 */
Inline void*
qs_body(qstring qs)
{
  return (qs != NULL) ? qs->body.v : NULL ;
} ;

/* Start of qstring body -- void* -- NULL if qstring is NULL, or body is.
 */
Inline char*
qs_char(qstring qs)
{
  return qs->body.c ;
} ;

/* Offset in qstring body -- returns NULL if qstring is NULL or body is NULL
 */
Inline char*
qs_char_at(qstring qs, usize at)
{
  return ((qs != NULL) && (qs->body.v != NULL)) ? qs->body.c + at
                                                : NULL ;
} ;

/* 'cp' in qstring body -- returns NULL if qstring is NULL or body is NULL.
 */
Inline char*
qs_cp_char(qstring qs)
{
  return ((qs != NULL) && (qs->body.c != NULL)) ? qs->body.c + qs->cp
                                                : NULL ;
} ;

/* 'len' in qstring body -- returns NULL if qstring is NULL or body is NULL
 */
Inline char*
qs_ep_char(qstring qs)
{
  return ((qs != NULL) && (qs->body.c != NULL)) ? qs->body.c + qs->len
                                                : NULL ;
} ;

/* 'len' of qstring -- returns 0 if qstring is NULL
 */
Inline ulen
qs_len(qstring qs)
{
  return (qs != NULL) ? qs->len : 0 ;
} ;

/* 'cp' of qstring -- returns 0 if qstring is NULL
 */
Inline ulen
qs_cp(qstring qs)
{
  return (qs != NULL) ? qs->cp : 0 ;
} ;

/* Size of qstring body -- zero if qstring is NULL, or is alias.
 */
Inline usize
qs_size(qstring qs)
{
  return (qs != NULL) ? qs->size : 0 ;
} ;

/*----------------------------------------------------------------------------*/

/* 'len' - 'cp' of qstring -- zero if NULL or 'len' < 'cp'
 */
Inline ulen
qs_after_cp(qstring qs)
{
  return (qs != NULL) ? qs_after_cp_nn(qs) : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Functions to fetch various pointer pairs.
 */
Inline void
qs_pp_nn(pp p, qstring qs)
{
  char* b ;

  b = qs->body.v ;

  p->p = b ;
  p->e = b + qs->len ;
} ;

Inline void
qs_cpp_nn(cpp p, qstring qs)
{
  const char* b ;

  b = qs->body.v ;

  p->p = b ;
  p->e = b + qs->len ;
} ;

Inline void
qs_pp(pp p, qstring qs)
{
  if (qs != NULL)
    qs_pp_nn(p, qs) ;
  else
    pp_null(p) ;
} ;

Inline void
qs_cpp(cpp p, qstring qs)
{
  if (qs != NULL)
    qs_cpp_nn(p, qs) ;
  else
    cpp_null(p) ;
} ;

/*==============================================================================
 * Functions
 */
extern void qs_start_up(void) ;
extern void qs_finish(void) ;

extern qstring qs_new(usize slen) ;
extern qstring qs_init_new(qstring qs, usize len) ;
extern qstring qs_reset(qstring qs, free_keep_b free_structure) ;
Inline qstring qs_free(qstring qs) ;
Inline qstring qs_free_body(qstring qs) ;

extern char* qs_make_string(qstring qs) ;
extern const char* qs_string(qstring qs) ;
extern qstring qs_new_size(qstring qs, usize slen) ;
Inline void* qs_extend(qstring qs, ulen req) ;
Inline void* qs_store(qstring qs) ;
Inline void qs_clear(qstring qs) ;

extern qstring qs_set_str(qstring qs, const char* src) ;
extern qstring qs_set_n(qstring qs, const void* src, usize n) ;
extern qstring qs_set(qstring qs, qstring src) ;
extern qstring qs_set_els(qstring qs, elstring src) ;
extern qstring qs_set_fill(qstring qs, usize len, const char* src) ;
extern qstring qs_set_fill_n(qstring qs, usize len, const char* src,
                                                                   usize flen) ;

extern qstring qs_append_str(qstring qs, const char* src) ;
extern qstring qs_append_n(qstring qs, const void* src, usize n) ;
extern qstring qs_append(qstring qs, qstring src) ;
extern qstring qs_append_els(qstring qs, elstring src) ;
extern qstring qs_append_ch_x_n(qstring qs, char ch, uint n) ;
extern qstring qs_append_ch(qstring qs, char ch) ;

extern qstring qs_set_alias_str(qstring qs, const char* src) ;
extern qstring qs_set_alias_n(qstring qs, const void* src, usize len) ;
extern qstring qs_set_alias(qstring qs, qstring src) ;
extern qstring qs_set_alias_els(qstring qs, elstring src) ;
extern qstring qs_set_alias_els_str(qstring qs, elstring src) ;

extern qstring qs_copy(qstring dst, qstring src) ;

extern qstring qs_printf(qstring qs, const char* format, ...)
                                                       PRINTF_ATTRIBUTE(2, 3) ;
extern qstring qs_vprintf(qstring qs, const char *format, va_list va) ;
extern qstring qs_printf_a(qstring qs, const char* format, ...)
                                                       PRINTF_ATTRIBUTE(2, 3) ;
extern qstring qs_vprintf_a(qstring qs, const char *format, va_list va) ;

extern qstring qs_ip_address(qstring qs, void* p_ip,
                                                  pf_flags_t flags, int width) ;
extern qstring qs_ip_prefix(qstring qs, void* p_ip, byte plen,
                                                  pf_flags_t flags, int width) ;
extern qstring qs_ip_address_a(qstring qs, void* p_ip,
                                                  pf_flags_t flags, int width) ;
extern qstring qs_ip_prefix_a(qstring qs, void* p_ip, byte plen,
                                                  pf_flags_t flags, int width) ;

extern usize qs_replace_str(qstring qs, usize r, const char* src) ;
extern usize qs_replace_n(qstring qs, usize r, const void* src, usize n) ;
extern usize qs_replace(qstring qs, usize r, qstring src) ;
Inline usize qs_insert_n(qstring qs, const void* src, usize n) ;
Inline usize qs_delete_n(qstring qs, usize n) ;
extern usize qs_find_str(qstring qs, const char* src) ;
extern usize qs_find_n(qstring qs, const void* src, usize n) ;
extern usize qs_globex_str(qstring qs, const char* find, const char* replace) ;

extern void qs_reduce(qstring qs, const char* seps, const char* terms) ;
extern const char* qs_next_word(qstring qs) ;
extern qstring qs_trim(qstring qs, char term) ;

Inline int qs_cmp(qstring a, qstring b) ;
Inline int qs_cmp_word(qstring a, qstring w) ;
Inline int qs_cmp_sig(qstring a, qstring b) ;
Inline bool qs_equal(qstring a, qstring b) ;
Inline bool qs_substring(qstring a, qstring b) ;

/*==============================================================================
 * The Inline functions.
 */

/*------------------------------------------------------------------------------
 * Clear contents of qstring -- preserves any qstring body, but sets len = 0.
 *
 * Does nothing if qstring is NULL
 *
 * Sets 'cp' = 'len' = 0
 *
 * If is an alias qstring, discard the alias.
 *
 * NB: does not create a qstring body if there isn't one.
 *
 * NB: does not change the qstring body if there is one.
 */
Inline void
qs_clear(qstring qs)
{
  if (qs != NULL)
    qlump_clear(qs) ;
} ;

/*------------------------------------------------------------------------------
 * Extend the body -- allowing for a terminating '\0'
 *
 * The 'req' is the required new length, not including terminating '\0'.
 *
 * Does NOT change or use qs->len.
 *
 * Returns:  address of the body -- NOT NULL
 *
 * NB: because we have size_term != 0, this guarantees to allocate a body.
 */
Inline void*
qs_extend(qstring qs, ulen req)
{
  return qlump_extend((qlump)qs, req, MTYPE_QSTRING_BODY) ;
} ;

/*------------------------------------------------------------------------------
 * 'Store' the qstring -- allowing for a terminating '\0' if is not empty.
 *
 * Returns:  (new) address of the body -- NULL if len == 0
 *
 * Uses qlump_store(), so will reallocate body to a smaller one if required.
 */
Inline void*
qs_store(qstring qs)
{
  return qlump_store((qlump)qs) ;
} ;

/*------------------------------------------------------------------------------
 * Return address of elstring for given qstring -- *not* NULL
 */
Inline elstring
qs_els_nn(qstring qs)
{
  confirm(offsetof(elstring_s, body.v) == 0) ;
  confirm(offsetof(qstring_s,  body.v) == 0) ;

  confirm(offsetof(elstring_s, len)    == offsetof(qstring_s, len)) ;
  confirm(offsetof(elstring_s, cp)     == offsetof(qstring_s, cp)) ;

  confirm(sizeof(elstring_s) == (sizeof(void*) + (sizeof(ulen) * 2))) ;

  return (elstring)qs ;
} ;

/*------------------------------------------------------------------------------
 * Return address of elstring for given qstring -- if any
 */
Inline elstring
qs_els(qstring qs)
{
  return (qs != NULL) ? qs_els_nn(qs) : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Free given qstring -- does nothing if qs == NULL
 *
 * Returns:  NULL
 */
Inline qstring
qs_free(qstring qs)
{
  return qs_reset(qs, free_it) ;
} ;

/*------------------------------------------------------------------------------
 * Free given qstring body -- does nothing if qs == NULL
 *
 * Returns:  NULL
 */
Inline qstring
qs_free_body(qstring qs)
{
  return qs_reset(qs, keep_it) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two qstrings -- returns the usual -ve, 0, +ve cmp result.
 *
 * NULL qstring is treated as empty.
 */
Inline int
qs_cmp(qstring a, qstring b)
{
  return els_cmp(qs_els(a), qs_els(b)) ;
} ;

/*------------------------------------------------------------------------------
 * Compare qstrings to given word -- see els_cmp_word
 */
Inline int
qs_cmp_word(qstring a, qstring w)
{
  return els_cmp_word(qs_els(a), qs_els(w)) ;
} ;

/*------------------------------------------------------------------------------
 * Compare significant parts of two qstrings -- returns the usual -ve, 0, +ve
 * cmp result.
 *
 * By significant, mean excluding leading/trailing isspace() and treating
 * multiple isspace() as single isspace().
 *
 * NULL qstring is treated as empty.
 */
Inline int
qs_cmp_sig(qstring a, qstring b)
{
  return els_cmp_sig(qs_els(a), qs_els(b)) ;
} ;

/*------------------------------------------------------------------------------
 * Are two qstrings equal ?  -- returns true if they are.
 */
Inline bool
qs_equal(qstring a, qstring b)
{
  return els_equal(qs_els(a), qs_els(b)) ;
} ;

/*------------------------------------------------------------------------------
 * Is 'b' a leading substring of 'a' ?  -- returns true if it is.
 *
 * If 'b' is empty it is always a leading substring.
 */
Inline bool
qs_substring(qstring a, qstring b)
{
  return els_substring(qs_els(a), qs_els(b)) ;
} ;

/*------------------------------------------------------------------------------
 * qs_insert_n is mapped, trivially, to qs_replace_n
 */
Inline usize qs_insert_n(qstring qs, const void* src, usize n)
{
  return qs_replace_n(qs, 0, src, n) ;
} ;

/*------------------------------------------------------------------------------
 * qs_delete_n is mapped, trivially, to qs_replace_n
 */
Inline usize qs_delete_n(qstring qs, usize n)
{
  return qs_replace_n(qs, n, NULL, 0) ;
} ;

#endif /* _ZEBRA_QSTRING_H */
