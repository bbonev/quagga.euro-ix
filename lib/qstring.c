/* Some string handling
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
#include "stdio.h"

#include "qstring.h"
#include "qfstring.h"
#include "memory.h"

/*==============================================================================
 * Initialise, allocate etc.
 */
static usize qs_qlump_alloc(qlump ql, usize new_size, bool store,
                                                              qlump_type_c qt) ;
static void qs_qlump_free(qlump ql, void* body, usize size, qlump_type_c qt) ;

/*------------------------------------------------------------------------------
 * The body of a qstring is a qlump.
 */
static const qlump_type_t qs_body_qt[1] =
{
  { .alloc        = qs_qlump_alloc,
    .free         = qs_qlump_free,

    .unit         = 1,

    .size_add     = 32,
    .size_unit_m1 = 16 - 1,       /* 16 byte boundaries   */

    .size_min     = 32,           /* if have to allocate  */

    .size_min_unit_m1 = 1 - 1,    /*  4 byte boundaries   */

    .embedded_size   = 0,
    .embedded_offset = 0,

    .size_term    = 1,
  }
} ;

/*------------------------------------------------------------------------------
 * Early morning start-up
 */
extern void
qs_start_up(void)
{
  qlump_register_type(MTYPE_QSTRING_BODY, qs_body_qt, false /* not test */) ;
} ;

/*------------------------------------------------------------------------------
 * Final termination
 */
extern void
qs_finish(void)
{
} ;

/*------------------------------------------------------------------------------
 * This is called by the qlump handler, when the body needs to be extended.
 *
 * The qlump handler looks after aliases.
 */
static usize
qs_qlump_alloc(qlump ql, usize new_size, bool store, qlump_type_c qt)
{
  size_t new_byte_size ;
  bool   extend ;

  extend = false ;

  if (ql->state == qls_normal)
    extend = (ql->size != 0) && !store ;
  else
    ql->state = qls_normal ;

  new_byte_size = (size_t)new_size * qt->unit ;

  if (extend)
    ql->body.v = XREALLOC(ql->mtype, ql->body.v, new_byte_size) ;
  else
    ql->body.v = XMALLOC(ql->mtype, new_byte_size) ;

  return ql->size = new_size ;
} ;

/*------------------------------------------------------------------------------
 * This is called by the qlump handler, when the body needs to be freed.
 *
 * Will not be called if the size is zero -- but we are cautious.
 */
static void
qs_qlump_free(qlump ql, void* body, usize size, qlump_type_c qt)
{
  XFREE(ql->mtype, body) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise the qlump of the given qstring
 */
inline static void
qs_qlump_init(qstring qs, usize slen)
{
  qlump_init(qs, slen, MTYPE_QSTRING_BODY) ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, empty qs
 *
 * If non-zero slen is given, a body is allocated -- plus space for '\0'.
 *
 * If zero slen is given, no body is allocated.
 *
 * Sets 'len' = 'cp' = 0.
 *
 * Returns: address of qstring
 */
extern qstring
qs_new(usize slen)
{
  qstring qs ;

  qs = XMALLOC(MTYPE_QSTRING, sizeof(qstring_t)) ;

  qs_qlump_init(qs, slen) ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Initialise qstring -- allocate if required.
 *
 * If non-zero slen is given, a body is allocated -- plus space for '\0'.
 *
 * If zero slen is given, no body is allocated.
 *
 * Sets 'len' = 'cp' = 0.
 *
 * Returns: address of qstring
 *
 * NB: assumes initialising a new structure.  If not, then caller should
 *     use qs_reset() or qs_clear().
 */
extern qstring
qs_init_new(qstring qs, usize slen)
{
  if (qs == NULL)
    return qs_new(slen) ;

  qs_qlump_init(qs, slen) ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Reset qstring -- free body and, if required, free the structure.
 *
 * Does nothing if qs == NULL.
 *
 * If not freeing the structure, zeroise size, len and cp and set body == NULL
 *
 * Returns: NULL if freed the structure (or was NULL to start with)
 *          address of structure (if any), otherwise
 */
extern qstring
qs_reset(qstring qs, free_keep_b free_structure)
{
  if (qs != NULL)
    {
      /* NB: qlump_free_body does *nothing* if the size is zero, so won't
       *     attempt to free an alias.
       */
      qlump_free_body(qs) ;             /* sets size = len = cp = 0
                                         * sets body = NULL             */

      if (free_structure)
        XFREE(MTYPE_QSTRING, qs) ;      /* sets qs = NULL               */
    } ;
  return qs ;
} ;

/*------------------------------------------------------------------------------
 * If the given qs is qls_unset, initialise with the given slen.
 *
 * Otherwise, do nothing -- not even if slen exceeds the current body.
 *
 * NB: if slen == 0 will NOT allocate a body.
 */
inline static void
qs_init_if_unset(qstring qs, ulen slen)
{
  if (qs->state == qls_unset)
    qs_qlump_init(qs, slen) ;
} ;

/*------------------------------------------------------------------------------
 * If the given qs is NULL, make a new qstring with the given slen
 *
 * If the given qs is qls_unset, initialise with the given slen.
 *
 * Otherwise, do nothing -- not even if slen exceeds the current body.
 *
 * NB: if slen == 0 will NOT allocate a body.
 *
 * NB: if makes or initialises, sets len = cp = 0.
 */
inline static qstring
qs_make_or_init(qstring qs, ulen slen)
{
  if (qs== NULL)
    return qs_new(slen) ;

  qs_init_if_unset(qs, slen) ;

  return qs ;
} ;

/*==============================================================================
 * Basic operations
 */

static char qs_empty[1] ;       /* for qs_make_string/qs_string */

/*------------------------------------------------------------------------------
 * Return pointer to '\0' terminated string value -- ensure not alias.
 *
 * This may be used when the caller wishes to fiddle with the value of
 * the qstring.
 *
 * Sets the '\0' terminator at the 'len' position, extending string if that
 * is required.
 *
 * NB: qstring should NOT be NULL -- but if it is, a pointer to a static one
 *     byte '\0' terminated string is returned !  The caller MUST treat this
 *     as len == 0 and size == 0 !
 *
 * NB: The qstring should not be changed or reset until this pointer has been
 *     discarded !
 *
 * NB: It is the caller's responsibility to update 'cp' and 'len' as required.
 *     Caller must not set 'len' >= 'size'.
 */
extern char*
qs_make_string(qstring qs)
{
  char* p ;
  usize len ;

  if (qs == NULL)
    {
      len = 0 ;
      p   = qs_empty ;
    }
  else if ((len = qs->len) < qs->size)
    {
      /* This is the standard case -- have a non-zero size qstring, with
       * space for the '\0'.
       */
      qassert( (qs->state == qls_normal) ||
               (qs->state == qls_embedded)) ;

      p = qs->body.c ;
    }
  else if (len == 0)
    {
      /* Deal with zero length, zero size qstring (of any kind).
       */
      p = qs_empty ;
    }
  else
    {
      /* Catch-all -- for strings which for some reason do not have space
       *              for the '\0'.
       *
       *           -- for alias strings of both kinds.
       *
       *           -- for completely empty strings with len > 0
       */
      p = qs_extend(qs, len) ;
    } ;

  *(p + len) = '\0' ;

  return p ;
} ;

/*------------------------------------------------------------------------------
 * Return pointer to string value.
 *
 * Writes '\0' at 'len' in order to return a terminated string, if required.
 *
 * If qs == NULL or body == NULL, or 'len' == 0 returns pointer to constant
 * empty '\0' terminated string (ie "").
 *
 * NB: if 'len' is beyond the current 'size' of the of the qstring, then
 *     will extend the string.
 *
 * NB: if string is an alias, and that is not '\0' terminated, will make a
 *     copy, before writing '\0' at end.
 *
 * NB: In any event, the string should not be changed or reset until this
 *     pointer has been discarded !
 */
extern const char*
qs_string(qstring qs)
{
  char* p ;
  usize len ;

  if (qs == NULL)
    {
      len = 0 ;
      p   = qs_empty ;
    }
  else if ((len = qs->len) < qs->size)
    {
      /* This is the standard case -- have a non-zero size qstring, with
       * space for the '\0'.
       */
      qassert( (qs->state == qls_normal) ||
               (qs->state == qls_embedded)) ;

      p = qs->body.c ;
    }
  else if (len == 0)
    {
      /* Deal with zero length, zero size qstring (of any kind).
       */
      len = 0 ;
      p   = qs_empty ;
    }
  else if (qs->state == qls_alias_term)
    {
      /* Special case for aliases which are known to be '\0' terminated.
       */
      return qs->body.c ;
    }
  else
    {
      /* Catch-all -- for strings which for some reason do not have space
       *              for the '\0'.
       *
       *           -- for alias strings with unknown '\0' state.
       *
       *           -- for completely empty strings with len > 0
       */
      p = qs_extend(qs, len) ;
    } ;

  *(p + len) = '\0' ;

  return p ;
} ;

/*------------------------------------------------------------------------------
 * Ensure have space for 'slen' + 1 characters, discarding any alias.
 *
 * Allocate new qstring if required.
 *
 * Set len = cp = 0.
 *
 * Returns: address of qstring -- with body that can be written upto and
 *          including 'slen' + 1.
 *
 * If this is a aliased qstring, the alias is discarded.
 */
extern qstring
qs_new_size(qstring qs, usize slen)
{
  if (qs == NULL)
    qs = qs_new(0) ;                    /* sets len = cp = 0            */
  else
    {
      qs->len = 0 ;
      qs->cp  = 0 ;

      if (slen < qs->size)
        return qs ;                     /* no extension required        */

      qlump_alias_clear((qlump)qs) ;    /* if is alias, discard         */
    } ;

  /* qs_extend() will create body even if slen == 0 -- because size_term != 0
   *
   * This is unlike the xxx_new() and xxx_init() operations, which will not
   * create a body if the request length is zero.
   *
   * NB: an unset qstring has qs->size == 0, and qs_extend() will set
   *     MTYPE_QSTRING_BODY if the qstring is unset.
   */
  qs_extend(qs, slen) ;
  return qs ;
} ;

/*==============================================================================
 * Setting value of qstring
 *
 * Copy the given string to the qstring, allocating qstring and/or extending
 * it as required.
 *
 * Any alias is simply discarded.
 *
 * Sets 'len' to new length
 * Sets 'cp'  = 0
 *
 * New size allows for a '\0' terminator beyond the 'len'.
 *
 * Returns: address of the qstring (allocated if required).
 */

/*------------------------------------------------------------------------------
 * Set qstring to be copy of the given string.
 *
 * Treats src == NULL as an empty string.  Otherwise src must be a '\0'
 * terminated string.
 *
 * Does not copy or count the '\0' terminator.
 *
 * See notes above.
 */
extern qstring
qs_set_str(qstring qs, const char* src)
{
  return qs_set_n(qs, src, (src != NULL ? strlen(src) : 0)) ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring to be copy of leading 'n' bytes of given string.
 *
 * If n == 0, src is ignored (and may be NULL)
 * If n > 0, src string MUST be at least 'n' bytes long.
 *
 * See notes above.
 */
extern qstring
qs_set_n(qstring qs, const void* src, usize len)
{
  qs = qs_new_size(qs, len) ;           /* ensures have body > len      */

  if (len != 0)
    memcpy(qs->body.v, src, len) ;

  qs->len = len ;
  qs->cp  = 0 ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring to be copy of given qstring contents.
 *
 * If the given qstring is an alias, then the contents of the alias are copied
 * (so the result is not an alias).
 *
 * See notes above -- and note that 'cp' is set to 0.
 */
extern qstring
qs_set(qstring qs, qstring src)
{
  return qs_set_n(qs, qs_body(src), qs_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring to be copy of given elstring contents.
 *
 * See notes above.
 */
extern qstring
qs_set_els(qstring qs, elstring src)
{
  return qs_set_n(qs, els_body(src), els_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring with given pattern to given length.
 *
 * Repeats the given pattern as many times as necessary to get to the given
 * length -- using a final partial piece of the pattern as required.
 *
 * If the pattern is NULL or zero length, fills with spaces !
 *
 * See notes above.
 */
extern qstring
qs_set_fill(qstring qs, usize len, const char* src)
{
  return qs_set_fill_n(qs, len, src, (src != NULL ? strlen(src) : 0)) ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring with given pattern to given length.
 *
 * Repeats the given pattern as many times as necessary to get to the given
 * length -- using a final partial piece of the pattern as required.
 *
 * See notes above.
 */
extern qstring
qs_set_fill_n(qstring qs, usize len, const char* src, usize flen)
{
  char*  p ;
  char*  q ;
  usize  left ;

  qs = qs_new_size(qs, len) ;   /* ensures have body > len      */

  if (len != 0)
    {
      if (flen == 0)
        {
          src  = "          " ;
          flen = strlen(src) ;
        } ;

      if (len < flen)
        flen = len ;

      q = p = qs->body.c ;
      memcpy(p, src, flen) ;
      p    += flen ;
      left  = len - flen ;

      while (left > 0)
        {
          if (left < flen)
            flen = left ;

          memcpy(p, q, flen) ;
          p    += flen ;
          left -= flen ;

          flen += flen ;
        } ;
    } ;

  qs->len = len ;
  qs->cp  = 0 ;

  return qs ;
} ;

/*==============================================================================
 * Appending to a qstring
 *
 * Copy the given string to the end of the given qstring (at 'len'),
 * allocating qstring and/or extending it as required.
 *
 * If this is an alias, it is copied to before being appended to (even if
 * appending nothing).
 *
 * Can append to NULL or empty qstring.
 *
 * Sets 'len' to new length.
 * Does not affect 'cp'.
 *
 * Returns: address of the qstring (allocated if required).
 */

/*------------------------------------------------------------------------------
 * Append given qstring (may be NULL) to a qstring (created if NULL).
 *
 * See notes above.
 */
extern qstring
qs_append(qstring qs, qstring src)
{
  return qs_append_n(qs, qs_body(src), qs_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Append given string to a qstring (created if NULL).
 *
 * Treats src == NULL as an empty string.  Otherwise src must be a '\0'
 * terminated string.
 *
 * Does not copy or count the '\0' terminator.
 *
 * See notes above.
 */
extern qstring
qs_append_str(qstring qs, const char* src)
{
  return qs_append_n(qs, src, (src != NULL) ? strlen(src) : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Append 'n' copies of given char to a qstring (created if NULL).
 *
 * See notes above.
 */
extern qstring
qs_append_ch_x_n(qstring qs, char ch, uint n)
{
  ulen  len, nlen ;

  if (qs == NULL)
    qs = qs_new(0) ;

  len  = qs->len ;

  nlen = len + n ;

  /* NB: an unset qstring has qs->size == 0, and qs_extend() will set
   *     MTYPE_QSTRING_BODY if the qstring is unset.
   */
  if (nlen >= qs->size)                 /* demand space of '\0' */
    qs_extend(qs, nlen) ;

  if (n != 0)
    memset(qs->body.c + len, ch, n) ;

  qs->len = nlen ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Append given char to a qstring.
 *
 * See notes above.
 */
extern qstring
qs_append_ch(qstring qs, char ch)
{
  ulen  len, nlen ;

  if (qs == NULL)
    qs = qs_new(0) ;

  len  = qs->len ;

  nlen = len + 1 ;

  /* NB: an unset qstring has qs->size == 0, and qs_extend() will set
   *     MTYPE_QSTRING_BODY if the qstring is unset.
   */
  if (nlen >= qs->size)                 /* demand space of '\0' */
    qs_extend(qs, nlen) ;

  *(qs->body.c + len) = ch ;

  qs->len = nlen ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Append given elstring to a qstring.
 *
 * See notes above.
 */
extern qstring
qs_append_els(qstring qs, elstring src)
{
  return qs_append_n(qs, els_body(src), els_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Append leading 'n' bytes of given string to a qstring.
 *
 * If n == 0, src may be NULL
 * If n > 0, src string MUST be at least 'n' bytes long.
 *
 * See notes above.
 */
extern qstring
qs_append_n(qstring qs, const void* src, usize n)
{
  ulen  len, nlen ;

  if (qs == NULL)
    qs = qs_new(0) ;

  len  = qs->len ;

  nlen = len + n ;

  /* NB: an unset qstring has qs->size == 0, and qs_extend() will set
   *     MTYPE_QSTRING_BODY if the qstring is unset.
   */
  if (nlen >= qs->size)                 /* demand space of '\0' */
    qs_extend(qs, nlen) ;

  if (n != 0)
    memcpy(qs->body.c + len, src, n) ;

  qs->len = nlen ;

  return qs ;
} ;

/*==============================================================================
 * Setting of alias.
 *
 * Does NOT copy the given string, but sets the qstring to be a pointer to it.
 * This means that:
 *
 * NB: it is the caller's responsibility to ensure that the original string
 *     stays put for however long the qstring is an alias for it.
 *
 * NB: if the qstring is changed in any way, a copy of the aliased string will
 *     be made first.
 *
 * NB: if a pointer to the body of the qstring is taken, then that's a pointer
 *     to the alias.  If the qstring is altered, that will no longer be the
 *     value of the qstring !
 *
 * Discards any existing qstring body.
 *
 * Returns: address of the qstring (allocated if required).
 */

/*------------------------------------------------------------------------------
 * Set qstring to be an alias for the given string.
 *
 * Treats src == NULL as an empty string.  Otherwise src must be a '\0'
 * terminated string.
 *
 * Does not count the '\0' terminator.
 *
 * Sets the state of the qlump to qls_alias_str -- so qs_string() will return
 * pointer to the alias.
 *
 * See notes above.
 */
extern qstring
qs_set_alias_str(qstring qs, const char* src)
{
  if (src == NULL)
    return qs_set_alias_n(qs, NULL, 0) ;

  if (qs == NULL)
    qs = qs_new(0) ;

  qlump_set_alias(qs, qls_alias_term, src, strlen(src), MTYPE_QSTRING_BODY) ;
  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring to be an alias for the leading 'n' bytes of given string.
 *
 * If n == 0, ignores src and simply empties out the qstring.
 *
 * If n >  0, src string MUST be at least 'n' bytes long.
 *
 * Sets the state of the qlump to qls_alias -- so qs_string() will make a copy
 * before adding '\0' terminator.
 *
 * See notes above.
 */
extern qstring
qs_set_alias_n(qstring qs, const void* src, usize n)
{
  if (qs == NULL)
    qs = qs_new(0) ;

  qlump_set_alias(qs, qls_alias, src, n, MTYPE_QSTRING_BODY) ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Set qstring to be an alias for the given qstring.
 *
 * If the src is not an alias, then the qstring is an alias for the body of
 * src -- so must be careful not to disturb that !
 *
 * If the src is an alias, then the qstring is another alias.
 *
 * Sets the state of the qlump to qls_alias -- so qs_string() will make a copy
 * before adding '\0' terminator.
 *
 * See notes above.
 */
extern qstring
qs_set_alias(qstring qs, qstring src)
{
  return qs_set_alias_n(qs, qs_body(src), qs_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Construct a qstring which is an alias for the given elstring.
 *
 * If n == 0, src may be NULL
 * If n >  0, src string MUST be at least 'n' bytes long.
 *
 * Sets the state of the qlump to qls_alias -- so qs_string() will make a copy
 * before adding '\0' terminator.
 *
 * See notes above.
 */
extern qstring
qs_set_alias_els(qstring qs, elstring src)
{
  return qs_set_alias_n(qs, els_body(src), els_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Construct a qstring which is an alias for the given elstring -- where the
 * elstring is known to be '\0' terminated.
 *
 * If n == 0, src may be NULL
 * If n >  0, src string MUST be at least 'n' bytes long.
 *
 * Sets the state of the qlump to qls_alias_term -- so qs_string() will return
 * pointer to the alias.
 *
 * See notes above.
 */
extern qstring
qs_set_alias_els_str(qstring qs, elstring src)
{
  ulen len ;

  if ((len = els_len(src)) == 0)
    return qs_set_alias_n(qs, NULL, 0) ;

  if (qs == NULL)
    qs = qs_new(0) ;

  qlump_set_alias(qs, qls_alias_term, els_body_nn(src), len,
                                                           MTYPE_QSTRING_BODY) ;
  return qs ;
} ;

/*==============================================================================
 * Copying of qstring
 */

/*------------------------------------------------------------------------------
 * Copy one qstring to another -- allocating/extending as required.
 *
 * If both are NULL, returns NULL.
 * Otherwise if dst is NULL, creates a new qstring.
 *
 * If src is NULL it is treated as zero length, with 'cp' == 0.
 *
 * If src is not an alias, a copy is made to dst.
 * If src is an alias, dst becomes a copy of the alias.
 *
 * If dst is an alias, that is discarded.
 *
 * Copies the src 'cp' to the dst.
 *
 * Returns: the destination qstring (allocated if required).
 */
extern qstring
qs_copy(qstring dst, qstring src)
{
  if (src == NULL)
    qs_clear(dst) ;                     /* if dst not NULL, clear it    */
  else
    {
      dst = qs_make_or_init(dst, 0) ;
      qlump_copy(dst, src) ;
    } ;

  return dst ;
} ;

/*==============================================================================
 * printf() and vprintf() type functions
 *
 * Allocate and/or extend qstring as required.
 *
 * Any alias is discarded, unless is being appended to.
 *
 *   Sets 'len'  = length of the '\0' terminated result (less the '\0').
 *   Sets 'cp'   = 0
 *
 * Returns: address of (new) qstring
 *
 * NB: uses qfs_vprintf().
 *
 * NB: when appending, if the current 'len' is beyond the 'size', will
 *     extend the string to accommodate the 'len' -- which is fine for alias
 *     strings, but will introduce undefined bytes between the old 'size'
 *     and 'len'.
 */

/*------------------------------------------------------------------------------
 * Formatted print to qstring -- cf printf() -- replacing any current contents.
 *
 * See notes above.
 */
extern qstring
qs_printf(qstring qs, const char* format, ...)
{
  va_list va;

  va_start (va, format);
  qs = qs_vprintf(qs, format, va);
  va_end (va);

  return qs;
} ;

/*------------------------------------------------------------------------------
 * Formatted print to qstring -- cf vprintf() -- replacing any current contents.
 *
 * See notes above.
 */
extern qstring
qs_vprintf(qstring qs, const char *format, va_list va)
{
  qs_clear(qs) ;        /* does nothing if qs == NULL   */

  return qs_vprintf_a(qs, format, va);
} ;

/*------------------------------------------------------------------------------
 * Formatted print to qstring -- cf printf() -- appending to qstring.
 *
 * See notes above.
 */
extern qstring
qs_printf_a(qstring qs, const char* format, ...)
{
  va_list va;

  va_start (va, format);
  qs = qs_vprintf_a(qs, format, va);
  va_end (va);

  return qs;
} ;

/*------------------------------------------------------------------------------
 * Formatted print to qstring -- cf vprintf() -- appending to qstring.
 *
 * See notes above.
 */
extern qstring
qs_vprintf_a(qstring qs, const char *format, va_list va)
{
  uint len ;

  qs = qs_make_or_init(qs, 0) ;

  /* qfs_vprintf() will write to the qs body etc from qs->cp forwards,
   * advancing cp -- it does not touch qs->len.
   *
   * We start with cp == len, so:
   *
   *  * if everything fits, cp == new length of the qstring.
   *
   *  * if does not fit, cp will be where the end should be
   *
   *    If len > size (notably for alias strings), the first call of
   *    qfs_vprintf() will establish the length of the result, including
   *    the current len.
   *
   * When extending the qstring, we have the original qs->len, and will then
   * copy any alias.
   */
  len = qs->len ;

  qs->cp = len ;
  qfs_vprintf(qs, format, va) ;

  if (qs->cp > qs->size)
    {
      qassert(len == qs->len) ;         /* unchanged    */

      qs_extend(qs, qs->cp) ;

      qs->cp = len ;
      qfs_vprintf(qs, format, va) ;
    } ;

  len     = qs->cp ;
  qs->len = len ;
  qs->cp  = 0 ;

  /* The qfs_vprintf() succeeds if it fills the fixed length string completely,
   * so may not leave room for '\0' terminator.
   *
   * If cp->len == cp->size == 0, and the result of the qfs_vprintf() is also
   * zero length, then we need to qs_extend() before putting down the '\0'.
   */
  if (len >= qs->size)
    qs_extend(qs, len) ;

  *(qs->body.c + len) = '\0' ;

  return qs ;
} ;

/*==============================================================================
 * Put ip address or ip prefix to qstring -- in field of the given width.
 *
 * Allocate and/or extend qstring as required.
 *
 * Any alias is discarded, unless is being appended to.
 *
 *   Sets 'len'  = length of the '\0' terminated result (less the '\0').
 *   Sets 'cp'   = 0
 *
 * Returns: address of (new) qstring
 *
 * NB: uses qfs_ip_address() and qfs_ip_prefix().
 *
 * NB: when appending, if the current 'len' is beyond the 'size', will
 *     extend the string to accommodate the 'len' -- which is fine for alias
 *     strings, but will introduce undefined bytes between the old 'size'
 *     and 'len'.
 */

/*------------------------------------------------------------------------------
 * Put ip address to qstring -- replacing any current contents.
 *
 * See notes above.
 */
extern qstring
qs_ip_address(qstring qs, void* p_ip, pf_flags_t flags, int width)
{
  qs_clear(qs) ;        /* does nothing if qs == NULL   */

  return qs_ip_address_a(qs, p_ip, flags, width) ;
} ;

/*------------------------------------------------------------------------------
 * Put ip prefix to qstring -- replacing any current contents.
 *
 * See notes above.
 */
extern qstring
qs_ip_prefix(qstring qs, void* p_ip, byte plen, pf_flags_t flags, int width)
{
  qs_clear(qs) ;        /* does nothing if qs == NULL   */

  return qs_ip_prefix_a(qs, p_ip, plen, flags, width) ;
} ;

/*------------------------------------------------------------------------------
 * Put ip address to qstring -- appending to qstring.
 *
 * See notes above.
 */
extern qstring
qs_ip_address_a(qstring qs, void* p_ip, pf_flags_t flags, int width)
{
  uint len ;

  qs = qs_make_or_init(qs, 0) ;

  /* qfs_put_ip_address() will write to the qs body etc from qs->cp forwards,
   * advancing cp -- it does not touch qs->len.
   *
   * We start with cp == len, so:
   *
   *  * if everything fits, cp == new length of the qstring.
   *
   *  * if does not fit, cp will be where the end should be
   *
   *    If len > size (notably for alias strings), the first call of
   *    qfs_vprintf() will establish the length of the result, including
   *    the current len.
   *
   * When extending the qstring, we have the original qs->len, and will then
   * copy any alias.
   */
  len = qs->len ;

  qs->cp = len ;
  qfs_put_ip_address(qs, p_ip, flags, width) ;

  if (qs->cp > qs->size)
    {
      qassert(len == qs->len) ;         /* unchanged    */

      qs_extend(qs, qs->cp) ;

      qs->cp = len ;
      qfs_put_ip_address(qs, p_ip, flags, width) ;
    } ;

  len     = qs->cp ;
  qs->len = len ;
  qs->cp  = 0 ;

  /* The qfs_put_ip_address() succeeds if it fills the fixed length string
   * completely,  so may not leave room for '\0' terminator.
   *
   * If cp->len == cp->size == 0, and the result of the qfs_put_ip_address() is
   * also zero length, then we need to qs_extend() before putting down the '\0'.
   */
  if (len >= qs->size)
    qs_extend(qs, len) ;

  *(qs->body.c + len) = '\0' ;

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Put ip prefix to qstring -- appending to qstring.
 *
 * See notes above.
 */
extern qstring
qs_ip_prefix_a(qstring qs, void* p_ip, byte plen, pf_flags_t flags, int width)
{
  uint len ;

  qs = qs_make_or_init(qs, 0) ;

  /* See qs_ip_address_a() for discussion of logic.
   */
  len = qs->len ;

  qs->cp = len ;
  qfs_put_ip_prefix(qs, p_ip, plen, flags, width) ;

  if (qs->cp > qs->size)
    {
      qassert(len == qs->len) ;         /* unchanged    */

      qs_extend(qs, qs->cp) ;

      qs->cp = len ;
      qfs_put_ip_prefix(qs, p_ip, plen, flags, width) ;
    } ;

  len     = qs->cp ;
  qs->len = len ;
  qs->cp  = 0 ;

  if (len >= qs->size)
    qs_extend(qs, len) ;

  *(qs->body.c + len) = '\0' ;

  return qs ;
} ;

/*==============================================================================
 * Other operations
 */

/*------------------------------------------------------------------------------
 * Replace 'r' bytes at 'cp' by given string -- see qs_replace_n()
 */
extern usize
qs_replace_str(qstring qs, usize r, const char* src)
{
  return qs_replace_n(qs, r, src, (src != NULL) ? strlen(src) : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Replace 'r' bytes at 'cp' by 'n' bytes -- extending if required.
 *
 * May increase or decrease 'len'. but does not affect 'cp'.
 *
 * If the given src is NULL, do not insert anything, just leave the space
 * ready for it.
 *
 * Returns: number of bytes beyond 'cp' that now exist.
 *
 * Guarantees at least one spare byte after the new 'len', for '\0'.
 *
 * qstring SHOULD NOT be NULL -- but if it is, returns 0.
 *
 * If 'cp' > 'len', then works as if 'len' = 'cp' -- which will introduce
 * one or more undefined bytes.
 *
 * If the (effective) 'len' is beyond the size of the qstring, that will
 * also introduce one or more undefined bytes.
 *
 * If this is a aliased qstring, a copy is made, so is no longer an alias.
 */
extern usize
qs_replace_n(qstring qs, usize r, const void* src, usize n)
{
  char* dst ;

  if (qs == NULL)
    return 0 ;

  qs_init_if_unset(qs, 0) ;

  dst = qlump_bubble(qs, qs->cp, r, n) ;

  qassert(((qs->cp + n) <= qs->len) && (qs->len < qs->size)) ;

  if ((n != 0) && (src != NULL))
    memcpy(dst + qs->cp, src, n) ;

  return qs->len - qs->cp ;
} ;

/*------------------------------------------------------------------------------
 * Replace 'r' bytes at 'cp' by given qstring -- see qs_replace_n()
 *
 * NULL src qstring -> empty string.
 */
extern usize
qs_replace(qstring qs, usize r, qstring src)
{
  return qs_replace_n(qs, r, qs_char(src), qs_len(src)) ;
} ;

/*------------------------------------------------------------------------------
 * Find string in qstring -- see qs_find_n()
 */
extern usize
qs_find_str(qstring qs, const char* src)
{
  return qs_find_n(qs, src, (src != NULL) ? strlen(src) : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Find 'n' bytes in qstring, searching from 'cp' (inclusive) -- sets 'cp'.
 *
 * Searching for zero bytes immediately succeeds !
 *
 * Returns: number of bytes found (zero if zero sought !)
 *
 * qstring MUST NOT be NULL
 *
 * src may be NULL iff n == 0
 *
 * If 'cp' > 'len', then finds nothing -- sets cp == len.
 *
 * If this is a aliased qstring, that does not change.
 */
extern usize
qs_find_n(qstring qs, const void* src, usize n)
{
  usize cp, len ;
  const char* p ;

  len  = qs->len ;
  cp   = qs->cp ;

  /* Deal with edge cases
   */
  if ((cp + n) > len)
    {
      qs->cp = len ;
      return 0 ;
    } ;

  if (n == 0)
    return 0 ;

  /* Search
   */
  p = qs->body.c + cp ;
  len -= cp - (n - 1) ;                         /* worth searching      */

  while (len > 0)
    {
      const char* q ;

      q = memchr(p, *(const char*)src, len) ;   /* seek first char      */

      if (q == NULL)
        break ;

      ++q ;                                     /* step past first      */

      if ((n == 1) || (memcmp(q, (const char*)src + 1, n - 1) == 0))
        {
          /* Found it !
           */
          qs->cp = (q - qs->body.c) - 1 ;
          return n ;
        } ;

      len -= (q - p) ;
      p = q ;
    } ;

  /* Reaches here if string is not found
   */
  qs->cp = qs->len ;

  return 0 ;
} ;

/*------------------------------------------------------------------------------
 * Global exchange across qstring -- does nothing if qstring is NULL
 *
 * Resets 'cp' to zero, before and after.  May increase or decrease 'len' (!)
 *
 * Does nothing if the find string is NULL or empty.  The replace string may
 * be NULL or empty.
 *
 * Returns:  (new) length of string.
 *
 * If makes any changes, the result will no longer be an alias.
 */
extern usize
qs_globex_str(qstring qs, const char* find, const char* replace)
{
  ulen  find_len ;
  ulen  replace_len ;

  if (qs == NULL)
    return 0 ;

  find_len    = (find != NULL)    ? strlen(find)    : 0 ;
  replace_len = (replace != NULL) ? strlen(replace) : 0 ;

  if (find_len > 0)
    {
      qs->cp = 0 ;

      while (qs_find_n(qs, find, find_len))
        {
          qs_replace_n(qs, find_len, replace, replace_len) ;
          qs->cp += replace_len ;
        } ;
    } ;

  qs->cp = 0 ;
  return qs->len ;
} ;

/*------------------------------------------------------------------------------
 * Reduce given qstring to a number of "words".
 *
 * The result is the "words" found, each one terminated by '\0'.  The resulting
 * qstring 'len' *includes* these terminators.  If the result qstring 'len' is
 * zero, then the input contained only whitespace, and possibly a terminator.
 * The 'cp' is set to zero, see qs_next_word().
 *
 * Words may be separated and/or terminated by the given characters.  Note that
 * '\0' is implicitly a separator and terminator.  Also note that control
 * characters and space may be separators.
 *
 * For our purposes we define whitespace to be any character <= ' ', and which
 * is not a separator -- noting that '\0' is implictly a separator.
 *
 * All whitespace (as defined above) is treated as ' '.
 *
 * Multiple spaces are treated as one (and returned as one, if required).
 *
 * Spaces before and after a "word" are discarded.
 *
 * The difference between a separator and a terminator is that a terminator
 * at the end of the string is ignored.  Note that this is true even if the
 * string contains just the terminator (and spaces/controls).
 *
 * Spaces around a separator/terminator are ignored.
 *
 * Adjacent separators/terminators create empty words.
 *
 * If seps == NULL, treat as "".  If terms == NULL, treat as "".
 *
 * If there are no separators, result is single "word", with leading/trailing
 * spaces (and controls) removed, and multiple spaces (and controls) reduced
 * to single space.
 *
 * NB: the terms MUST be a subset of seps -- anything in terms which is not in
 *     seps will be ignored.
 *
 * NB: if space is a separator, it is implicitly a terminator -- no need to
 *     include space in terms.
 *
 * NB: if space is a separator, best if is the first separator
 *     (but not required).
 */
extern void
qs_reduce(qstring qs, const char* seps, const char* terms)
{
  const char* sp ;
  uchar ch ;
  char* s ;
  char* p ;
  char* q ;
  char* e ;
  bool  post_sep, post_term ;
  char  ctrl_map[' '] ;
  char  space_sep ;

  /* Preset the ctrl_map so that all < ' '.
   *
   * The ctrl_map maps ch < ' ' to: ' ' for all whitespace
   *                         or to: itself if it is a separator
   */
  memset(ctrl_map, ' ', ' ') ;

  /* Make sure we have seps and terms, so that '\0' is accounted for.
   *
   * Scan the seps, including the '\0', and adjust the ctrl_map as required.
   */
  space_sep = ' ' ;     /* Assume NOT a separator       */

  if (seps == NULL)
    seps = "" ;         /* '\0' is a separator !        */

  sp = seps ;
  do
    {
      ch = *sp++ ;
      if      (ch <  ' ')
        ctrl_map[ch] = '\0' ;
      else if (ch == ' ')
        space_sep    = '\0' ;
    }
  while (ch != '\0') ;

  if (terms == NULL)
    terms = "" ;       /* '\0' is a terminator          */

  /* Scan through the string:
   *
   *  * remove all unwanted whitespace (including around other separators)
   *
   *  * replacing separators by '\0'
   *
   *  * discarding trailing terminator.
   */
  q = p = s = qs_make_string(qs) ;
  e = p + qs->len ;

  post_sep = post_term = true ;

  while (p < e)
    {
      bool  wsp ;

      wsp = false ;

      /* Get the first significant character, skipping whitespace.
       *
       * If hits end of string before have seen anything significant, break
       * out of the loop.
       *
       * Otherwise, leaves ch  == first char > ' '
       *                   wsp == !post_sep
       */
      ch = *p++ ;
      if (ch < ' ')
        ch = ctrl_map[ch] ;

      if (ch == ' ')
        {
          /* Look for non-whitespace -- including separator control char
           */
          while (p < e)
            {
              ch = *p++ ;

              if (ch < ' ')
                ch = ctrl_map[ch] ;

              if (ch != ' ')
                break ;
            } ;

          /* Found non-whitespace, or end of string.
           *
           * If end of string, get out *now* if is whitespace immediately
           * after a terminator or at start.
           */
          if (p >= e)
            {
              if (post_term)
                break ;                 /* all empty !          */
              else
                ch = '\0' ;             /* implicit terminator  */
            } ;

          /* Have a non-whitespace -- possibly a separator -- preceded by at
           * least one whitespace.
           *
           * Record presence of whitespace if not whitespace immediately
           * after separator or at start.
           */
          wsp = !post_sep ;
        } ;

      /* ch is not whitespace -- see if we have a separator on our hands
       *
       * If ch is not a separator:
       *
       *   * leave wsp and ch alone -- ch is not separator and not whitespace.
       *
       *     If have wsp: if space is a separator, will terminate previous word
       *                  and start the next with ch.
       *
       *                  otherwise, insert space followed by ch.
       *
       *     If no wsp:   insert the ch
       *
       *   * clear post_sep and post_term, so that whitespace processing knows
       *     that just
       *
       * If ch is a separator:
       *
       *   * clear wsp -- discarding preceding whitespace
       *
       *   * set ch = '\0' -- word terminator.
       *
       *   * set post_sep -- so any following whitespace will be discarded.
       *
       *   * set post_term if this is also a terminator -- so not only will
       *     any following whitespace be discarded, but will not create an
       *     empty word if end of string is met.
       */
      if (strchr(seps, ch) == NULL)
        {
          /* ch is not a separator
           */
          post_sep = post_term = false ;
        }
      else
        {
          /* ch is a separator and may be a terminator
           */
          post_sep  = true ;
          post_term = strchr(terms, ch) != NULL ;

          wsp = false ;         /* discard space(s) before      */
          ch  = '\0' ;          /* convert separator to '\0'    */
        } ;

      /* If we've seen significant whitespace, insert space_sep.
       *
       * Then insert the current ch -- which is not whitespace.
       */
      if (wsp)
        *q++ = space_sep ;      /* ' ' or '\0', as required     */

      *q++ = ch ;
    } ;

  /* Done -- set new len and clear cp
   */
  qs->len = q - s ;
  qs->cp  = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Return next "word" from suitably set up qstring -- or NULL if none.
 *
 * Expects the body of the qstring to be divided into "words" separated by
 * '\0' -- and possibly terminated by '\0' (within 'len').  'cp' is expected to
 * point at the next word to return.
 *
 * Note that the '\0' at the end of the last word may, or may not be inside
 * the 'len'.  So, 'cp' may advance to 'len' + 1.
 *
 * Returns:  address of next word, or NULL if none.
 *
 * If qs == NULL or 'len' == 0 or 'len' <= 'cp' returns NULL.
 *
 * NB: if 'len' is beyond the current 'size' of the of the qstring, then
 *     will extend the string -- introducing garbage !!
 *
 * NB: if string is an alias, and that is not '\0' terminated, will make a
 *     copy, before writing '\0' at end.
 *
 * NB: In any event, the string should not be changed or reset until this
 *     pointer has been discarded !
 */
extern const char*
qs_next_word(qstring qs)
{
  const char* body ;
  const char* word ;
  const char* next ;
  ulen cp ;

  if (qs == NULL)
    return NULL ;               /* no string => no words                */

  cp  = qs->cp ;

  if (cp >= qs->len)
    return NULL ;               /* deal with at or beyond end           */

  /* qs_make_string ensures that the string is terminated at 'len'.
   *
   * (If for some bizarre reason len > size, then will extend the sting,
   *  introducing garbage !)
   */
  body = qs_make_string(qs) ;
  word = body + cp ;
  next = strchr(word, '\0') ;

  qs->cp = (next + 1) - body ;

  return word ;
} ;

/*------------------------------------------------------------------------------
 * Trim and, optionally, terminate given qstring -- allocate if required.
 *
 * Creates empty qstring if none provided.
 *
 * Removes trailing whitespace from the end of the qstring -- where whitespace
 * is anything <= ' '.
 *
 * If the result is not an empty string, and a terminator is given, add
 * terminator.
 *
 * Returns: the result qstring (allocated if required).
 */
extern qstring
qs_trim(qstring qs, char term)
{
  ulen  len ;
  char* s, * p ;

  if (qs == NULL)
    return qs_new(0) ;

  len = qs->len ;
  if (len == 0)
    return qs ;

  s = qs_make_string(qs) ;
  p = s + len ;

  while ((p > s) && ((unsigned)*(p - 1) <= ' '))
    --p ;

  len = p - s ;
  qs->len = len ;

  if ((len != 0) && (term != '\0'))
    qs_append_ch(qs, term) ;

  return qs ;
} ;
