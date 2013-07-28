/* Lumps of Memory
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#include "qlump.h"

/*==============================================================================
 * The qlump type handling.
 *
 * Have an array indexed by mtype to get pointer to the qlump_type structure
 * for that type of memory.
 *
 * This is initialised empty pretty early in the morning, and all mtypes
 * which require the qlump handler must register the type before second stage ????????
 *
 * XXX .................................................................................

 */
static qlump_type_c qlump_type_table[MTYPE_MAX] ;

/*------------------------------------------------------------------------------
 * Initialise the table of memory types.
 */
extern void
qlump_start_up(void)
{
  memset(qlump_type_table, 0, sizeof(qlump_type_table)) ;
} ;

/*------------------------------------------------------------------------------
 * Final termination
 */
extern void
qlump_finish(void)
{
} ;

/*------------------------------------------------------------------------------
 * Register the given qlump_type for use with the given MTYPE.
 *
 * This must be done before a qlump of the given MTYPE can be allocated.
 *
 * Expect that this will be done very early in the morning, and if the
 * properties of the qlump are not valid, will crash immediately.
 *
 * For testing, can avoid the crash and receive the error code -- so can test
 * the error detection !
 *
 * Note: can register the same qlump_type for a given MTYPE more than once,
 *       *provided* the second and subsequent registrations are *identical*.
 */
static const char* const qlump_register_errors[] =
{
  [qlrr_ok] = NULL,

  [qlrr_invalid_mtype]    = "invalid mtype",
  [qlrr_reregister]       = "cannot re-register a different qlump type",
  [qlrr_functions]        = ".alloc and .free functions must be set",
  [qlrr_zero_unit]        = ".unit must be non-zero",
  [qlrr_size_unit_m1]     = ".size_unit_m1 must be (2^n) - 1",
  [qlrr_size_min_unit_m1] = ".size_min_unit_m1 must be (2^n) - 1",
} ;

static qlump_register_ret_t
qlump_abort(qlump_register_ret_t ret, bool test)
{
  if (!test && (ret != qlrr_ok))
    zabort(qlump_register_errors[ret]) ;

  return ret ;
} ;

extern qlump_register_ret_t
qlump_register_type(mtype_t mtype, qlump_type_c qt, bool test)
{
  if ((mtype >= MTYPE_MAX) || (mtype == MTYPE_NULL))
    return qlump_abort(qlrr_invalid_mtype, test) ;

  if (qlump_type_table[mtype] != NULL)
    {
      if (memcmp(qlump_type_table[mtype], qt, sizeof(qlump_type_t)) != 0)
        return qlump_abort(qlrr_reregister, test) ;

      return qlrr_ok ;
    } ;

  /* Must have alloc/free functions
   */
  if ((qt->alloc == NULL) || (qt->free == NULL))
    return qlump_abort(qlrr_functions, test) ;

  /* Must have a non-zero unit -- recommend 1, 2 or n * (4 or 8).
   */
  if (qt->unit == 0)
    return qlump_abort(qlrr_zero_unit, test) ;

  /* size_unit_m1 must be (2^n) - 1
   */
  if ((qt->size_unit_m1 & (qt->size_unit_m1 + 1)) != 0)
    return qlump_abort(qlrr_size_unit_m1, test) ;

  /* size_min_unit must be (2^n) - 1
   */
  if ((qt->size_min_unit_m1 & (qt->size_min_unit_m1 + 1)) != 0)
    return qlump_abort(qlrr_size_min_unit_m1, test) ;

  /* OK -- register
   */
  qlump_type_table[mtype] = qt ;

  return qlrr_ok ;
} ;

/*==============================================================================
 * Service functions
 */
static bool qlump_do_alloc(qlump ql, usize req, bool store, qlump_type_c qt) ;
static void qlump_copy_alias(qlump ql) ;

/*------------------------------------------------------------------------------
 * Get address of given item in given qlump body.
 *
 * NB: if is unset ql->unit == 0 !
 */
inline static void*
qlump_item(qlump ql, uint index, qlump_type_c qt)
{
  return ql->body.c + (index * qt->unit) ;
} ;

/*------------------------------------------------------------------------------
 * Get sizeof 'n' items in qlump.
 *
 * NB: if is unset ql->unit == 0 !
 */
inline static size_t
qlump_sizeof(uint index, qlump_type_c qt)
{
  return index * qt->unit ;
} ;

/*------------------------------------------------------------------------------
 * Get address of embedded body, if any
 *
 * NB: this is not a test for a usable body -- does not care if embedded_size
 *     is 1 and not usable because a terminator is required.
 */
inline static qlump_body
qlump_embedded_body(qlump ql, qlump_type_c qt)
{
  if (qt->embedded_size != 0)
    return (char*)ql + qt->embedded_offset ;
  else
    return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get the qlump_type for the given qlump.
 *
 * At this point:
 *
 *   * it is a FATAL error for the qlump to be qls_unset
 *
 *   * it is a FATAL error if the mytpe is not registered
 *
 * There is no way around this -- just cannot proceed without the information
 * in the qlump_type.
 *
 * Also -- for qdebug, check the state.
 */
inline static qlump_type_c
qlump_get_type(qlump ql)
{
  qlump_type_c  qt ;

  assert((mtype_t)ql->mtype < MTYPE_MAX) ;

  qt = qlump_type_table[ql->mtype] ;

  assert(qt != NULL) ;

  if (qdebug)
    {
      switch (ql->state)
        {
          case qls_normal:
            qassert((ql->size == 0) ? ql->body.v == NULL : ql->body.v != NULL) ;
            break ;

          case qls_embedded:
            qassert(ql->size == qt->embedded_size) ;
            qassert(ql->body.v == qlump_embedded_body(ql, qt)) ;
            break ;

          case qls_alias:
          case qls_alias_term:
            qassert(ql->size == 0) ;
            break ;

          default:
            qassert(false) ;
            break ;
        } ;
    } ;

  return qt ;
} ;

/*==============================================================================
 * The qlump handling
 */

/*------------------------------------------------------------------------------
 * Default allocator
 */
extern usize
qlump_alloc(qlump ql, usize new_size, bool store, qlump_type_c qt)
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
 * Default free
 */
extern void
qlump_free(qlump ql, void* body, usize size, qlump_type_c qt)
{
  XFREE(ql->mtype, body) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise the given qlump, for the given memory type, with the given
 * initial length requirement.
 *
 * If the initial requirement is zero, leaves the size zero and the body NULL.
 *
 * Otherwise, allocate suitable body -- using any embedded body, if possible.
 *
 * Sets len = cp = 0.
 *
 * Returns: address of body, if req != 0
 *          otherwise NULL
 *
 * NB: whatever the qlump previously held is lost.
 *
 * NB: it is a *FATAL* error to attempt to use a memory type that has not been
 *     registered -- there is really no way to avoid this.
 */
extern qlump_body
qlump_init(qlump ql, usize req, mtype_t mtype)
{
  qlump_type_c  qt ;

  /* Must qlump_init to a registered mtype -- note that cannot register
   * MTYPE_NULL.
   */
  assert(mtype < MTYPE_MAX) ;
  qt = qlump_type_table[mtype] ;
  assert(qt != NULL) ;

  /* Zeroising sets:
   *
   *   * body       -- NULL
   *   * len        -- 0
   *   * cp         -- 0
   *   * size       -- 0
   *
   *   * mtype      -- X  -- set below
   *   * state      -- X  -- set below
   */
  memset(ql, 0, sizeof(qlump_t)) ;

  ql->mtype = mtype ;
  ql->state = qls_normal ;

  if (req == 0)
    return NULL ;

  return qlump_extend(ql, req, mtype) ;
} ;

/*------------------------------------------------------------------------------
 * Set qlump to the given alias.
 *
 * If the qlump is unset, set the given mtype -- otherwise ignore the mytpe.
 *
 * If there is an existing body, discard it.
 *
 * Sets cp = 0.
 *
 * Set alias of the given type -- but if len == 0, leave as an empty qlump.
 */
extern void
qlump_set_alias(qlump ql, qlump_state_t atype, const void* alias, ulen len,
                                                                  mtype_t mtype)
{
  qassert((atype == qls_alias) || (atype == qls_alias_term)) ;

  if (ql->state == qls_unset)
    qlump_init(ql, 0, mtype) ;  /* sets size = len = cp = 0,
                                 * sets body = NULL                     */
  else
    qlump_free_body(ql) ;       /* sets size = len = cp = 0,
                                 * sets body = NULL                     */

  qassert((ql->size == 0) && (ql->body.v == NULL)) ;

  if (len != 0)
    {
      ql->body.cv = alias ;
      ql->len     = len ;

      ql->state   = atype ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Clear contents of qlump -- preserves any qlump body, but discards any alias.
 *
 * Sets 'cp' = 'len' = 0
 *
 * NB: does not create a body if there isn't one.
 *
 * NB: does not change the body if there is one (and is not alias), .
 */
extern void
qlump_clear(qlump ql)
{
  ql->len = 0 ;
  ql->cp  = 0 ;

  switch (ql->state)
    {
      case qls_unset:
        break ;

      case qls_normal:
        if (ql->size == 0)
          ql->body.v = NULL ;           /* tidy                 */
        break ;

      case qls_embedded:
        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(ql->size == 0) ;

        ql->state  = qls_normal ;       /* discard any alias    */
        ql->body.v = NULL ;
        ql->size   = 0 ;                /* will already be      */
        break ;

      default:
        qassert(false) ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Re-initialise the given qlump, with the given length requirement.
 *
 * If the qlump is unset, this is the same as qlump_init().  If the qlump is
 * set, the given mtype is ignored.
 *
 * If there is is no current body or the qlump is set to an alias, the qlump
 * is set empty.
 *
 * Otherwise, extends the current body if the given length requirement cannot
 * currently be met.
 *
 * Sets: len = cp = 0
 *
 * Returns: address of body, if req != 0 or has an allocated body
 *          otherwise NULL
 *
 * NB: will not reduce the size of the qlump, unless req == 0 and is currently
 *     set to use the embedded body.
 *
 * NB: whatever the qlump previously held is lost.
 */
extern qlump_body
qlump_re_init(qlump ql, usize req, mtype_t mtype)
{
  qlump_type_c qt ;

  switch (ql->state)
    {
      case qls_unset:
        return qlump_init(ql, req, mtype) ;

      case qls_normal:
      case qls_embedded:
        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(ql->size == 0) ;

        ql->state  = qls_normal ;
        ql->body.v = NULL ;
        ql->size   = 0 ;        /* will already be      */

        break ;

      default:
        assert(false) ;
    } ;

  qt = qlump_get_type(ql) ;

  ql->len = 0 ;
  ql->cp  = 0 ;

  if (((req + qt->size_term) > ql->size) && ((req != 0) || (ql->size != 0)))
    return qlump_extend(ql, req, mtype) ;
  else
    return ql->body.v ;
} ;

/*------------------------------------------------------------------------------
 * Extend the given qlump so that can reach at least the required length.
 *
 * It is assumed that this will not be called if the required length can
 * be accommodated in the current size -- but that is not a requirement.
 *
 * If no mtype is set, set the given mytpe.  Otherwise, ignore the given
 * mtype -- this allows for a default mtype to be set.
 *
 * If the qlump contains an alias, copies *min* of ql->len and the req length
 * to the new body.
 *
 * Does not use or change ql->len or ql->cp, except: uses ql->len if there is
 * an alias, and will set it to req, if req is < ql->len.
 *
 * Will use any embedded body, if that is sufficient.
 *
 * Otherwise, allocate a new body if the current body is insufficient.
 *
 * Returns:  address of (new) body -- unlikely to be NULL, see below
 *
 *           updates: ql->size and ql->body, as required.
 *
 * NB: never reduces the size of the qlump.
 *
 *     Result can be NULL with ql->size == 0, iff:
 *
 *        req == ql->size == size_term == 0
 *
 *     In particular: *cannot* be NULL if size_term != 0.
 *
 * NB: if the size is zero, takes no notice of the current body -- if it is
 *     not NULL it is simply overwritten.
 */
extern qlump_body
qlump_extend(qlump ql, usize req, mtype_t mtype)
{
  qlump_type_c qt ;
  usize        copy_len ;
  qlump_body   copy_body ;

  switch (ql->state)
    {
      case qls_unset:
        qlump_init(ql, 0, mtype) ;

        copy_len = 0 ;                  /* nothing to copy              */
        break ;

      case qls_normal:
        copy_len = 0 ;                  /* realloc does the copying     */
        break ;

      case qls_embedded:
        /* Note that when allocating a new body to replace an embedded one,
         * we copy all the embedded body.
         *
         * Does not use ql->len -- so that does not have to be up to date.
         *
         * It is unlikely that an embedded body will be large.  When it is
         * replaced it may well be pretty full.  So not depending on ql->len
         * should not be a big overhead, and saves some effort elsewhere,
         * where the current actual len may be in a working variable/register.
         */
        copy_body = ql->body.v ;        /* copy if have to allocate     */
        copy_len  = ql->size ;
        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(ql->size == 0) ;

        copy_len = ql->len ;            /* assume takes what there is   */

        if (copy_len > req)
          {
            copy_len = req ;            /* copy min(req, ql->len)       */
            ql->len  = req ;            /* new ql->len                  */
          } ;

        if (copy_len != 0)
          copy_body = ql->body.v ;      /* copy alias stuff             */

        break ;

      default:
        assert(false) ;
    } ;

  /* Account for any required terminator, and see if we need to allocate,
   * or can use the embedded body (if any).
   */
  qt = qlump_get_type(ql) ;

  if (qlump_do_alloc(ql, req, false /* not store */, qt))
    {
      /* Have allocated new body or set the embedded body.
       *
       * If there was either an alias, or a previously used embedded body, copy
       * it across to the new body.
       */
      if (copy_len != 0)
        memcpy(ql->body.b, copy_body, qlump_sizeof(copy_len, qt)) ;
    } ;

  /* We are all set -- return new body.
   */
  if (ql->size == 0)
    qassert(((req + qt->size_term) == 0) && (ql->body.v == NULL)) ;
  else
    qassert(((req + qt->size_term) <= ql->size) && (ql->body.v != NULL)) ;

  return ql->body.v ;
} ;

/*------------------------------------------------------------------------------
 * Prepare to store the given qlump:
 *
 *   * if is unset, set empty: size = len = cp = 0, body = NULL
 *                    remains: qls_unset
 *                        and: mtype is not touched.
 *
 *   * if ql->len == 0, discard body (and any alias) altogether.
 *                       sets: size = len = cp = 0, body = NULL
 *                        and: qls_normal
 *                        but: mtype is not touched.
 *
 *   * if is an alias, make a copy of it -- with space for size_term
 *
 *     copies ql->len items to either qls_normal or qls_embedded
 *
 *   * if ql->len + size_term > ql->size -- allocate space
 *
 *     this is an edge case, where the ql->len is beyond the current size.
 *
 *   * if ql->size is larger than it need be -- in particular if ql->len
 *     + size_term will fit in the embedded body -- then move to a new body
 *     to reduce the memory requirement.
 *
 *     this is the expected case, where the standard allocation is reasonably
 *     generous, but now that the length of the object is known, spare space
 *     can be released.
 *
 * Does not change ql->len.
 *
 * Does not change ql->cp, unless qls_unset or ql->len == 0, when is zeroized.
 *
 * NB: if size_term != 0, then this is taken into account, unless ql->len == 0.
 *
 * Returns:  the (new) current body
 */
extern qlump_body
qlump_store(qlump ql)
{
  uint         len ;
  qlump_type_c qt ;
  usize        old_size, copy_len ;
  qlump_body   old_body ;

  len = ql->len ;

  if ((len == 0) || (ql->state == qls_unset))
    {
      qlump_free_body(ql) ;     /* sets size  = len = cp = 0
                                 * sets body  = NULL
                                 * sets state = qls_normal, unless is qls_unset
                                 * leaves mtype                         */
      return NULL ;
    } ;

  /* Set up:  old_size  == current size of *normal* body
   *
   *                       0 <=> qls_normal but no body, or qls_embedded,
   *                             ir qls_alias etc.
   *
   *                       no-zero signals that old_body must be freed if we
   *                       allocate a new body.
   *
   *          old_body  == current contents of the qlump
   *
   *          copy_len  == number of items to copy from the old_body to any
   *                       new body.
   *
   *                       This will be the same as ql->len, unless ql->len
   *                       is currently > ql->size and this is not an alias.
   */
  old_size = ql->size ;
  old_body = ql->body.v ;
  copy_len = len ;

  switch (ql->state)
    {
      case qls_normal:
        if (copy_len > old_size)
          copy_len = old_size ;

        break ;

      case qls_embedded:
        if (copy_len > old_size)
          copy_len = old_size ;

        old_size = 0 ;          /* nothing to free      */
        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(old_size == 0) ;
        break ;

      default:
        assert(false) ;
    } ;

  /* Want at least one byte.
   *
   * If can use embedded body, do so.
   *
   * If current body is acceptable, use it.
   *
   * If need to allocate a new body, either to make it bigger or smaller, do
   * so now -- note that the store flag forces a malloc() of a new piece
   * of memory.
   */
  qassert(len > 0) ;

  qt = qlump_get_type(ql) ;

  if (qlump_do_alloc(ql, len, true /* store */, qt))
    {
      /* Copy what we have to the new body and free the old_body, if required.
       */
      if (copy_len != 0)
        memcpy(ql->body.v, old_body, qlump_sizeof(copy_len, qt)) ;

      if (old_size != 0)
        qt->free(ql, old_body, old_size, qt) ;
    } ;

  if (ql->size > copy_len)      // XXX zeroize back end ???..............................
    memset(qlump_item(ql, copy_len, qt), 0,
                                        qlump_sizeof(ql->size - copy_len, qt)) ;

  qassert((len + qt->size_term) <= ql->size) ;
  qassert(ql->body.v != NULL) ;

  return ql->body.v ;
} ;

/*------------------------------------------------------------------------------
 * Copy one qlump to another.
 *
 * If the src is unset, dst is cleared -- see qlump_clear() ;
 *
 * Otherwise: the dst qlump MUST NOT be qls_unset, and MUST have the same type
 * as the src.  This avoids issues of mismatched unit sizes and of different
 * embedded body properties.
 *
 * If the dst is an alias, the alias is discarded.
 *
 * Uses the existing dst body, if at all possible.
 *
 * Copies the src->len items, ensuring space for and size_term.  Effect on
 * the dst is exactly as qlump_extend().
 *
 * Copies src->len and src->cp -- result will be qls_normal or qls_embedded.
 */
extern void
qlump_copy(qlump dst, qlump src)
{
  qlump_type_c qt ;
  uint copy_len ;

  copy_len = src->len ;

  switch (src->state)
    {
      case qls_normal:
      case qls_embedded:
        if (copy_len > src->size)
          copy_len = src->size ;

        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(src->size == 0) ;
        break ;

      default:
        qassert(false) ;
        fall_through ;

      case qls_unset:
        qlump_clear(dst) ;
        return ;
    } ;

  assert((dst->state >= qls_set_first) && (dst->state <= qls_set_last)) ;
  assert(dst->mtype == src->mtype) ;

  qt = qlump_get_type(dst) ;

  qlump_do_alloc(dst, src->len, false /* not store */, qt) ;

  if (copy_len > 0)
    memcpy(dst->body.v, src->body.v, qlump_sizeof(copy_len, qt)) ;

  dst->len = src->len ;
  dst->cp  = src->cp ;
} ;

/*------------------------------------------------------------------------------
 * Copy one qlump to another, for storing the result.
 *
 * Principal difference between qlump_copy() and qlump_copy_store(), is that
 * allocates space using the allocation rules of qlump_store().
 *
 * Effect is exactly as qlump_copy() followed by qlump_store() -- but done in
 * one go.
 */
extern void
qlump_copy_store(qlump dst, qlump src)
{
  qlump_type_c qt ;
  usize        old_size, copy_len ;
  qlump_body   old_body ;

  copy_len = src->len ;

  switch (src->state)
    {
      case qls_normal:
      case qls_embedded:
        if (copy_len > src->size)
          copy_len = src->size ;
        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(src->size == 0) ;
        break ;

      default:
        qassert(false) ;
        fall_through ;

      case qls_unset:
        qlump_clear(dst) ;
        return ;
    } ;

  assert((dst->state >= qls_set_first) && (dst->state <= qls_set_last)) ;
  assert(dst->mtype == src->mtype) ;

  qt = qlump_get_type(dst) ;

  if (dst->state == qls_normal)
    {
      old_size = dst->size ;
      old_body = dst->body.v ;
    }
  else
    {
      old_size = 0 ;
      old_body = NULL ;
    } ;

  if (qlump_do_alloc(dst, src->len, true /* store */, qt))
    if (old_size != 0)
      qt->free(dst, old_body, old_size, qt) ;

  if (copy_len > 0)
    memcpy(dst->body.v, src->body.v, qlump_sizeof(copy_len, qt)) ;

  if (dst->size > copy_len)      // XXX zeroize back end ???..............................
    memset(qlump_item(dst, copy_len, qt), 0,
                                       qlump_sizeof(dst->size - copy_len, qt)) ;

  dst->len = src->len ;
  dst->cp  = src->cp ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Make a replacement body -- using the 'store' rules for its size.
 *
 * Does not disturb the current body.
 */
extern qlump_body
qlump_make_replacement(qlump ql, ulen* p_old_size)
{
  qlump_type_c qt ;
  qlump_body old_body ;
  usize      old_size, new_size ;

  if ((ql->len == 0) || (ql->state == qls_unset))
    {
      qlump_free_body(ql) ;             /* sets ql->len = 0     */

      *p_old_size = 0 ;
      return NULL ;
    } ;

  qt = qlump_get_type(ql) ;

  old_body = ql->body.v ;
  old_size = ql->size ;


  new_size = ql->len + qt->size_term ;

  if (new_size <= qt->embedded_size)
    {
      /* The replacement body can be the embedded body.
       *
       * This is easy if the old_body is not the embedded body.
       */
      qlump_body embedded_body ;

      embedded_body = qlump_embedded_body(ql, qt) ;

      if (ql->state != qls_embedded)
        {
          qassert(old_body != embedded_body) ;

          ql->body.v = embedded_body ;
          ql->size   = qt->embedded_size ;
        }
      else
        {
          /* The replacement and the original are the embedded body.
           *
           * We allocate a new body in the usual way, which can be prepared
           * for storage, as normal.  This case is detected by qlump_replace(),
           * and the new body will be copied to the embedded one, and then
           * discarded.
           */
          qassert( (old_body == embedded_body) &&
                   (old_size == qt->embedded_size) ) ;

          new_size = (new_size + qt->size_unit_m1) & ~ qt->size_unit_m1 ;

          qt->alloc(ql, new_size, true /* store */, qt) ;
        } ;
    }
  else
    {
      /* Allocate a new 'store' body.
       *
       * Note that this does NOT affect the old body.
       */
      new_size = (new_size + qt->size_min_unit_m1) & ~ qt->size_min_unit_m1 ;

      qt->alloc(ql, new_size, true /* store */, qt) ;
    } ;

  *p_old_size = old_size ;
  return old_body ;
} ;

/*------------------------------------------------------------------------------
 * Complete a replacement operation.
 *
 */
extern void
qlump_replace(qlump ql, qlump_body old_body, ulen old_size)
{
  if (old_size != 0)
    {
      qlump_type_c qt ;

      qt = qlump_get_type(ql) ;

      if (old_body == qlump_embedded_body(ql, qt))
        {
          /* Special case -- have created replacement in a scratch buffer,
           * so now is the time to copy it back and release it.
           */
          ulen copy_len ;

          qassert((ql->len + qt->size_term) <= qt->embedded_size) ;

          copy_len = ql->len ;
          if (copy_len > qt->embedded_size)
            copy_len = qt->embedded_size ;
          if (copy_len > ql->size)
            copy_len = ql->size ;

          if (copy_len != 0)
            memcpy(old_body, ql->body.v, qlump_sizeof(copy_len, qt)) ;

          if (ql->size != 0)
            qt->free(ql, ql->body.v, ql->size, qt) ;

          ql->body.v = old_body ;
          ql->size   = qt->embedded_size ;
        }
      else
        {
          /* Simple case -- can now discard the old body
           */
          qt->free(ql, old_body, old_size, qt) ;
        } ;
    } ;
} ;
#endif

/*------------------------------------------------------------------------------
 * After cloning a structure which contains a qlump, fix-up the body,
 * as required.
 *
 * By cloning, we mean an operation which has copied the qlump_t verbatim PLUS
 * any embedded body.
 *
 * If the cloned value is an alias, copies the alias -- same like qlump_copy().
 *
 * Also like qlump_copy(), the size of the result, and the extent of what
 * is copied both depend on ql->len.
 *
 * Note that the cloning preserves the current ql->len and ql->cp.  And, if
 * is qls_unset, everything is preserved.
 */
extern void
qlump_post_clone(qlump ql)
{
  qlump_type_c qt ;
  void* copy_body ;
  uint  copy_len ;

  copy_len = ql->len ;                  /* default copy         */

  switch (ql->state)
    {
      case qls_embedded:
        qt = qlump_get_type(ql) ;

        qassert(ql->size == qt->embedded_size) ;

        if ((copy_len + qt->size_term) <= qt->embedded_size)
          {
            /* We can continue to use the embedded body, the contents of
             * which have already been cloned.
             */
            ql->body.v = qlump_embedded_body(ql, qt) ;

            return ;
          } ;

        ql->state = qls_normal ;        /* about to force empty */
        fall_through ;

      case qls_normal:
        if (copy_len > ql->size)
          copy_len = ql->size ;         /* limit copy           */

        break ;

      case qls_alias:
      case qls_alias_term:
        qassert(ql->size == 0) ;

        ql->state = qls_normal ;        /* about to force empty */

        break ;

      default:
        qassert(false) ;
        fall_through ;

      case qls_unset:
        return ;
    } ;

  qt = qlump_get_type(ql) ;

  copy_body = ql->body.v ;

  ql->body.v = NULL ;
  ql->size   = 0 ;

  qlump_do_alloc(ql, copy_len, false /* not store */, qt) ;

  if (copy_len > 0)
    memcpy(ql->body.v, copy_body, qlump_sizeof(copy_len, qt)) ;
} ;

/*------------------------------------------------------------------------------
 * After cloning a structure which contains a qlump, fix-up the body,
 * as required -- allocating space on a 'store' basis.
 *
 * By cloning, we mean an operation which has copied the qlump_t verbatim PLUS
 * any embedded body.
 *
 * If the cloned value is an alias, copies the alias -- same like qlump_copy().
 *
 * Also like qlump_copy_store(), the size of the result, and the extent of what
 * is copied both depend on ql->len.
 *
 * Note that the cloning preserves the current ql->len and ql->cp.  And, if
 * is qls_unset, everything is preserved.
 */
extern void
qlump_post_clone_store(qlump ql)
{
  qlump_type_c qt ;
  void* copy_body ;
  uint  copy_len ;

  copy_len = ql->len ;

  switch (ql->state)
    {
      case qls_normal:
        if (copy_len > ql->size)
          copy_len = ql->size ;

        break ;

      case qls_embedded:
        qt = qlump_get_type(ql) ;

        qassert(ql->size == qt->embedded_size) ;

        ql->body.v = qlump_embedded_body(ql, qt) ;

        return ;

      case qls_alias:
      case qls_alias_term:
        qassert(ql->size == 0) ;

        ql->state = qls_normal ;        /* about to force empty */

        break ;

      default:
        qassert(false) ;
        fall_through ;

      case qls_unset:
        return ;
    } ;

  qt = qlump_get_type(ql) ;

  copy_body = ql->body.v ;

  ql->body.v = NULL ;
  ql->size   = 0 ;

  qlump_do_alloc(ql, copy_len, true /* store */, qt) ;

  if (copy_len > 0)
    memcpy(ql->body.v, copy_body, qlump_sizeof(copy_len, qt)) ;

  if (ql->size > copy_len)      // XXX zeroize back end ???..............................
    memset(qlump_item(ql, copy_len, qt), 0,
                                       qlump_sizeof(ql->size - copy_len, qt)) ;
} ;

/*------------------------------------------------------------------------------
 * If the current body (if any) is not the embedded body (if any), free the
 * body.
 *
 * In all cases, reset the the qlump to completely empty:
 *
 *      body  = NULL
 *
 *      size  = len = cp = 0
 *
 *      state = qls_normal -- unless was qls_unset
 *
 *      mtype = unchanged
 */
extern void
qlump_free_body(qlump ql)
{
  switch (ql->state)
    {
      case qls_unset:
        break ;

      case qls_normal:
        if (ql->size != 0)
          {
            qlump_type_c qt ;

            qt = qlump_get_type(ql) ;
            qt->free(ql, ql->body.v, ql->size, qt) ;
          } ;
        break ;

      case qls_embedded:
      case qls_alias:
      case qls_alias_term:
        ql->state = qls_normal ;
        break ;

      default:
        qassert(false) ;
        return ;
    } ;

  ql->body.v  = NULL ;
  ql->size    = 0 ;
  ql->len     = 0 ;
  ql->cp      = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Sort given qlump
 *
 * If is an alias, makes a copy, first.
 *
 * If ql->len > ql->size -- sorts what there is.  Leaves ql->len as was.
 */
extern void
qlump_sort(qlump ql, qlump_cmp_func* cmp)
{
  ulen         sort_count ;

  sort_count = ql->len ;

  switch (ql->state)
    {
      case qls_unset:
        qlump_clear(ql) ;
        return ;

      case qls_normal:
      case qls_embedded:
        if (sort_count > ql->size)
          sort_count = ql->size ;
        break ;

      case qls_alias:
      case qls_alias_term:
        qlump_copy_alias(ql) ;
        break ;

      default:
        qassert(false) ;
        return ;
    } ;

  if (sort_count > 1)
    {
      qlump_type_c qt ;

      qt = qlump_get_type(ql) ;

      qsort(ql->body.v, sort_count, qt->unit, cmp) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Sort given qlump and remove duplicates
 *
 * Assumes that for duplicates, can check for equality by simple memcmp().
 *
 * If is an alias, makes a copy, first.
 *
 * If ql->len > ql->size -- sorts and de-dups what there is.
 *
 * Sets ql->len to what there is left.  (So if q->len > ql->size, the new
 * ql->len is at most ql->size.)
 */
extern void
qlump_sort_dedup(qlump ql, qlump_cmp_func* cmp)
{
  ulen         sort_count ;

  sort_count = ql->len ;

  switch (ql->state)
    {
      case qls_unset:
        qlump_clear(ql) ;
        return ;

      case qls_normal:
      case qls_embedded:
        if (sort_count > ql->size)
          sort_count = ql->size ;
        break ;

      case qls_alias:
      case qls_alias_term:
        qlump_copy_alias(ql) ;
        break ;

      default:
        qassert(false) ;
        return ;
    } ;

  if (sort_count > 1)
    {
      qlump_type_c qt ;
      usize  unit ;
      byte* p, * q, * e, * n, * k ;
      bool  d ;

      qt = qlump_get_type(ql) ;
      unit = qt->unit ;

      qsort(ql->body.v, sort_count, unit, cmp) ;

      /* Now we de-dup.
       *
       * Tries to minimize the amount of moving of stuff that is required.
       *
       * If there are no duplicates, then moves nothing at all !
       *
       * When finds a duplicate (or run of) does not move anything until finds
       * another duplicate (or run of) after a run of not duplicates.
       *
       * 0) sets p to the start, and n to p+1.  Sets k = q = NULL and d = false.
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L ....
       *      ^  ^
       *      p  n   and k = q = NULL and d = false
       *
       *    Since we don't have a duplicate, and d is false, simply advances
       *    p and n together, until...
       *
       * 1) when arrives at the second X we have:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L ....
       *                        ^  ^
       *                        p  n   and k = q = NULL and d = false
       *
       *    Since k == NULL, we don't have a drop outstanding.
       *
       *    So, sets q = p+1 and d = true.
       *
       * 2) advances n, so we have:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L  M....
       *                        ^  ^  ^
       *                        p  q  n   and k = NULL and d = true
       *
       *    Since k == NULL, we don't have a drop outstanding.
       *    Since q != NULL, nothing changes
       *
       * 3) advances n again, so we have:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L  M....
       *                        ^  ^     ^
       *                        p  q     n   and k = NULL and d = true
       *
       * 4) Now d = true, so we set k and clear d.  And since we are keeping 'G'
       *    we advance p and n, so we have:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L  M....
       *                           ^     ^  ^
       *                           q     p  n   and d = false
       *                                 k
       *
       * 5) Now d = false, so we just advance p and n, so we have:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L  M....
       *                           ^     ^  ^  ^
       *                           q     k  p  n   and d = false
       *
       * 6) Now d = false, so we just advance p and n, until we get:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  L  M....
       *                           ^     ^           ^  ^
       *                           q     k           p  n   and d = false
       *
       * 7) Found another duplicate, and since k != NULL, we have a drop
       *    pending.  So move items from k up to q, and adjust p so that we
       *    have:
       *
       *      A  B  C  D  E  F  X  G  H  I  J  Y  -  -  Y  Y  L  M....
       *                                       ^        ^
       *                                       p        n
       *
       *    This is pretty much where we were in (1), except that p and n
       *    are no longer adjacent.
       *
       *    Sets k = NULL, q = p+1 and d = true.
       *
       * 8) Steps n, so that we have:
       *
       *      A  B  C  D  E  F  X  G  H  I  J  Y  -  -  Y  Y  L  M....
       *                                       ^  ^        ^
       *         d = true & k = NULL           p  q        n
       *
       *    As in (2) k is NULL and q is not.
       *
       * 9) Steps n, so that we have:
       *
       *      A  B  C  D  E  F  X  G  H  I  J  Y  -  -  Y  Y  L  M....
       *                                       ^  ^           ^
       *         d = true & k = NULL           p  q           n
       *
       *    As in (3), because d is true, sets k = n, and sets d = false.
       *
       * ... and so on.
       *
       * When n hits the end, we can be in a number of states:
       *
       * a) no duplicates found:
       *
       *      A  B  C  D  E  F  G  H  I  J  K  L  *
       *                                       ^  ^
       *      k = q = NULL, d = false          p  n
       *
       *    The new end is p + 1.
       *
       * b) we have trailing duplicates, only:
       *
       *      A  B  C  D  E  F  G  H  I  J  K  L  X  X  X  *
       *                                          ^        ^
       *      k = q = NULL, d = false             p        n
       *
       *    The new end is p + 1.
       *
       * c) a drop is pending, cf (6), eg:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  *
       *                           ^     ^        ^  ^
       *      d = false            q     k        p  n
       *
       *    Since k != NULL we know there is a drop outstanding, so we can
       *    do that and end up with:
       *
       *      A  B  C  D  E  F  X  G  H  I  J  -  -  *
       *                                    ^        ^
       *                                    p        n
       *
       *    After the drop, the new end is p + 1.
       *
       * d) a drop is pending and we have trailing duplicates:
       *
       *      A  B  C  D  E  F  X  X  X  G  H  I  J  Y  Y  Y  *
       *                           ^     ^           ^        ^
       *      d = false            q     k           p        n
       *
       *    Since k != NULL we know there is a drop outstanding, so we can
       *    do that and end up with:
       *
       *      A  B  C  D  E  F  X  G  H  I  J  Y  -  -  Y  Y  *
       *                                       ^              ^
       *                                       p              n
       *
       *    After the drop, the new end is p + 1.
       */
      p = ql->body.b ;
      e = p + (sort_count * unit) ;

      n = p + unit ;
      k = q = NULL ;
      d = false ;
      while (n < e)
        {
          if (memcmp(p, n, unit) == 0)
            {
              /* We need to drop the item 'n', keeping item 'p'.
               *
               * If we have a drop pending, we now move stuff up, which
               * moves 'p' up, as well.
               */
              if (k != NULL)
                {
                  /* We have a drop pending
                   */
                  uint gap ;
                  byte* pp1 ;

                  pp1 = p + unit ;      /* "p + 1"              */

                  gap = k - q ;

                  qassert((gap != 0) && ((pp1 - k) != 0)) ;
                  memmove(q, k, pp1 - k) ;

                  q = k = NULL ;
                  p -= gap ;
                } ;

              if (q == NULL)
                {
                  q = p + unit ;        /* top of new drop zone */
                  d = true ;
                } ;
            }
          else
            {
              /* We are going to keep the item 'n'.
               *
               * If this is the end of a drop zone, set that now.
               */
              if (d)
                {
                  k = n ;
                  d = false ;
                } ;

              p = n ;                   /* advance                      */
            } ;

          n += unit ;
        } ;

      if (k != NULL)
        {
          /* We have a drop pending
           */
          uint  gap ;
          byte* pp1 ;

          gap = k - q ;
          pp1 = p + unit ;

          qassert((gap != 0) && ((pp1 - k) != 0)) ;

          memmove(q, k, pp1 - k) ;

          p -= gap ;
        } ;

      p += unit ;               /* step past last item          */

      sort_count = (p - ql->body.b) / unit ;
    } ;

  ql->len = sort_count ;
} ;

/*------------------------------------------------------------------------------
 * Binary search given qlump -- on the basis it is sorted.
 *
 * If is an alias, searches that, up to ql->len.
 *
 * If is not an alias, searches up to ql->len or ql->size, whichever is the
 * smaller.
 *
 * If is unset, clears the qlump, and returns as if ql->len == 0.
 *
 * Stops immediately if gets a match -- so if there are repeated values, may
 * stop on any one of them.
 *
 * Returns:  index of item found, and sets:
 *
 *   *result ==  0: found an equal value.
 *
 *                  index returned is of first entry found which is equal to
 *                  the value sought.  There may be other equal values, before
 *                  and/or after this one in the qlump.
 *
 *   *result == +1: value not found and qlump not empty.
 *
 *                  index returned is of the largest entry whose value is less
 *                  than the value sought.  (The value sought belongs after
 *                  this point.)
 *
 *   *result == -1: value is less than everything in the qlump, or the
 *                  qlump is empty.
 *
 *                  index returned is 0.  (The vaue sought belongs before this
 *                  point.)
 */
extern uint
qlump_bsearch(qlump ql, qlump_cmp_func* cmp, const void* val, int* result)
{
  ulen  search_len ;
  qlump_type_c qt ;
  uint  il, ih ;
  int c ;

  search_len = ql->len ;

  switch (ql->state)
    {
      case qls_unset:
        qlump_clear(ql) ;

        search_len = 0 ;
        break ;

      case qls_normal:
      case qls_embedded:
        if (search_len > ql->size)
          search_len = ql->size ;
        break ;

      case qls_alias:
      case qls_alias_term:
        break ;

      default:
        qassert(false) ;

        search_len = 0 ;
        break ;
    } ;

  if (search_len < 2)
    {
      if (search_len == 0)
        *result = -1 ;
      else
        *result = cmp(val, ql->body.b) ;  /* -1 <=> val < only item     */

      return 0 ;
    } ;

  /* We have at least two items.
   */
  qt = qlump_get_type(ql) ;

  il = 0 ;
  ih = search_len - 1 ;                 /* at least 1                   */

  /* Pick off the edge cases: <= first or >= last
   */
  if ((c = cmp(val, qlump_item(ql, il, qt))) <= 0)
    {
      *result = c ;     /* 0 => found.  -1 => val < first      */
      return il ;       /* index of first item                 */
    }

  if ((c = cmp(val, qlump_item(ql, ih, qt))) >= 0)
    {
      *result = c ;     /* 0 => found.  +1 => val > last        */
      return ih ;       /* index of last item                   */
    } ;

  /* Now binary chop.  We know that item il < val < item ih
   *                   We also know that il < ih
   */
  while (1)
    {
      uint  iv ;

      qassert(il < ih) ;

      iv = (il + ih) / 2 ;

      if (iv == il)     /* true if (ih == il+1)                         */
        {
          *result = +1 ;
          return il ;   /* return il: item[il] < val < item[il+1]       */
        } ;

      qassert((il < iv) && (iv < ih)) ;

      c = cmp(val, qlump_item(ql, iv, qt)) ;

      if (c == 0)
        {
          *result = 0 ;
          return iv ;   /* found !!                             */
        } ;

      if (c <  0)
        ih = iv ;       /* step down    iv > il, so new ih > il */
      else
        il = iv ;       /* step up      iv < ih, so new il < ih */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Arrange a bubble at 'at', to replace 'r' items by 'n' items.
 *
 * If 'at' is beyond ql->len, sets ql->len = 'at', first.
 *
 * If 'r' == 0, this blows a bubble for 'n' items.
 *
 * If 'n' == 0, this drops 'r' items -- or up to ql->len, whichever is smaller.
 *
 * Otherwise leaves a hole for 'n' items, at 'at', having dropped 'r' items.
 *
 * If this is an alias, creates a new body, first.
 *
 * The result ql->len will be at least 'at' + 'n', and the ql->size will be
 * at least ql->len + size_term.
 *
 * Returns:  address of (new) body -- unlikely to be NULL, see below
 *
 *           updates: ql->len, ql->size and ql->body, as required.
 *
 * NB: *FATAL* error if the qlump is unset.
 *
 * NB: never reduces the size of the qlump.
 *
 *     Result can be NULL with ql->size == 0, iff:
 *
 *        ql->size == ql->len == size_term == 'at' == 'n' == 0
 *
 *     In particular: *cannot* be NULL if size_term != 0.
 *
 * NB: contents of the bubble are undefined.
 *
 * NB: if 'at' > (original) ql->len, the stuff between the original ql->len
 *     and 'at' are undefined.
 *
 * NB: expects 'at' <= ql->len <= ql->size -- but this is not required.
 *
 *     The result ql->len will be at least 'at' + 'n' - 'r'.
 *
 *     The result ql->size will be at least: result ql->len + size_term
 */
extern qlump_body
qlump_bubble(qlump ql, uint at, ulen r, ulen n)
{
  qlump_type_c qt ;
  usize old_len, old_size, after, new_len ;

  qt = qlump_get_type(ql) ;

  /* Work out: after   = number of items beyond 'at' + 'r' which we may need to
   *                     move up or down the qlump.
   *
   *                     This is limited by min(ql->len, ql->size).
   *
   *           new_len = new length once 'n' items have replaced the 'r' items.
   */
  old_size = ql->size ;
  old_len  = ql->len ;

  if ((at + r) < old_len)
    {
      /* There is something after the section being replaced.
       *
       * For qls_normal and qls_embedded, will need to worry about old_size,
       * later.
       */
      new_len = old_len + n - r ;
      after   = old_len - (at + r) ;
    }
  else
    {
      /* There is nothing after the section being replaced.
       *
       * Where 'at' == ql->len, this is an append.
       */
      new_len = at + n ;
      after   = 0 ;
    } ;

  /* Adjust the body of the qlump.
   */
  if ((new_len + qt->size_term) <= old_size)
    {
      /* All fits in the existing body, including any size_term.
       *
       * Note that if n == r, whatever is after 'at', it doesn't move.
       */
      if (old_size < old_len)
        {
          /* Need to recalculate after, so don't read beyond the
           * end of the old_size -- minority case.
           */
          if ((at + r) < old_size)
            after = old_size - (at + r) ;
          else
            after = 0 ;
        } ;

      if ((after > 0) && (n != r))
        memmove(qlump_item(ql, at + n, qt), qlump_item(ql, at + r, qt),
                                                      qlump_sizeof(after, qt)) ;
      else if (old_size == 0)
        {
          qassert((new_len + qt->size_term) == 0) ;

          ql->state  = qls_normal ;     /* discard any alias            */
          ql->body.v = NULL ;           /* no body, no more             */
        } ;
    }
  else
    {
      /* We need to allocate a new piece of memory to satisfy the new_len.
       *
       * Note that we never reduce the size of the qlump, so if there is
       * anything to after, it will be preserved.
       *
       * Since (new_len + qt->size_term) > old_size, result ql->size > 0 !
       */
      char* ap ;
      ulen  before ;

      switch (ql->state)
        {
          case qls_normal:
            qlump_do_alloc(ql, new_len, false /* not store */, qt) ;

            /* Now fits in the existing body, including any size_term.
             *
             * Note that if n == r, whatever is after 'at', it doesn't move.
             */
            if (old_size < old_len)
              {
                /* Need to recalculate after, so don't read beyond the
                 * end of the old_size -- minority case.
                 */
                if ((at + r) < old_size)
                  after = old_size - (at + r) ;
                else
                  after   = 0 ;
              } ;

            if ((after > 0) && (n != r))
              memmove(qlump_item(ql, at + n, qt), qlump_item(ql, at + r, qt),
                                                      qlump_sizeof(after, qt)) ;
            break ;

          case qls_alias:
          case qls_alias_term:
            old_size = old_len ;        /* equivalent for alias         */

            fall_through ;

          case qls_embedded:
            ap = ql->body.v ;

            qlump_do_alloc(ql, new_len, false /* not store */, qt) ;

            qassert(ap != ql->body.v) ; /* if was embedded, was too small */

            before = at ;
            if (before > old_len)
              before = old_len ;        /* clamp to ql->len             */

            if (old_size < old_len)
              {
                /* Need to recalculate before and after, so don't read beyond
                 * the end of the old_size -- minority case.
                 *
                 * Only applies to qls_embedded.
                 */
                qassert(ql->state == qls_embedded) ;

                if ((at + r) < old_size)
                  after = old_size - (at + r) ;
                else
                  after = 0 ;

                if (before > old_size)
                  before = old_size ;   /* clamp to ql->size            */
              } ;

            if (before > 0)
              memcpy(ql->body.v, ap, qlump_sizeof(before, qt)) ;

            if (after > 0)
              memcpy(qlump_item(ql, at + n, qt), ap + qlump_sizeof(at + r, qt),
                                                      qlump_sizeof(after, qt)) ;
            break ;

          default:
            assert(false) ;
        } ;

      qassert((ql->size != 0) && (ql->body.v != NULL)) ;
    } ;

  /* We are all set -- set new len and return new body.
   */
  if (ql->size == 0)
    qassert(((new_len + qt->size_term) == 0) && (ql->body.v == NULL)) ;
  else
    qassert(((new_len + qt->size_term) <= ql->size) && (ql->body.v != NULL)) ;

  ql->len = new_len ;

  return ql->body.v ;
} ;

/*------------------------------------------------------------------------------
 * Allocate or reallocate to satisfy given requirement.
 *
 * Does not change or use ql->len or ql->cp.
 *
 * If the requested length is zero, after adding any size_term, then if
 * ql->size is zero, will discard any alias, set the ql->body NULL and
 * return.
 *
 * For 'store': will allocate a brand new body if the current body is either
 *              smaller or larger than the minimum for the given request.
 *
 *              Will use the embedded body, if at all possible (see below).
 *
 *              In any event, the existing body is NOT freed.
 *
 * Will use any embedded body, if that is sufficient.  Generally, if there is
 * an embedded body, then the ql->size will be:
 *
 *   zero            -- qls_normal, with no body -- or qls_alias/_alias_term
 *
 *   embedded_size   -- qls_embedded, using the embedded body
 *
 *   > embedded_size -- qls_normal, with an allocated body
 *
 * So, generally will not replace a qls_normal with an allocated body by the
 * embedded body.  For 'store' may do so, and this function may return the
 * embedded body as a new allocation.
 *
 * However, if not 'store' and if the rules have been broken, may find
 * ourselves replacing an allocated body, which is smaller than the embedded
 * body, by the embedded body.  We sweep this edge case under the carpet,
 * copy the allocated body contents to the embedded body, free the allocated
 * body and exit as if had been using the embedded body all along -- so
 * returns false <=> not a new body.  [Note this only happens if was qls_normal
 * and 0 < ql->size < embedded_size.]
 *
 * Returns:  true <=> have a new body -- qls_normal or qls_embedded
 *
 * NB: if the size is zero, takes no notice of the current body -- if it is
 *     not NULL it is simply overwritten.
 *
 * NB: guarantees to return a non-NULL body, with size >= 1.
 *
 *     OR a NULL body with size == 0 -- iff size was zero, req == 0
 *                                                         and size_term == 0
 */
static bool
qlump_do_alloc(qlump ql, usize req, bool store, qlump_type_c qt)
{
  uint old_size ;

  req += qt->size_term ;                /* include size_term    */

  old_size = ql->size ;

  /* If the current body is enough, get out now.
   *
   * Except: for 'store' we may want to allocate a smaller body.
   */
  if ((req <= old_size) || (req == 0))
    {
      if (old_size == 0)                /* so req == 0                  */
        {
          ql->state  = qls_normal ;     /* discard any alias            */
          ql->body.v = NULL ;           /* no body, no more             */

          return false ;
        } ;

      /* The req + size_term is <= old_size and old_size > 0.
       *
       * If is !store, then can continue to use whatever the current body is.
       */
      if (!store)
        return false ;                  /* current body will do         */

      /* Is 'store' and req + size_term is <= old_size and old_size > 0.
       *
       * If the req + size_term is zero, then we can discard any current body.
       *
       * Otherwise, continue, because we may wish to reduce the amount of
       * space used.
       */
      if (req == 0)
        {
          ql->state  = qls_normal ;     /* discard any alias            */
          ql->body.v = NULL ;           /* no body, no more             */
          ql->size   = 0 ;              /* ditto                        */

          return true ;
        } ;
    } ;

  qassert(req > 0) ;

  /* If the embedded body is enough, use that (or continue to use it).
   */
  if (req <= qt->embedded_size)
    {
      /* We can do this in the embedded body.
       *
       * NB: if 'store' -- whatever the current body is, that will be taken
       *                   care of.
       *
       *     otherwise  -- there can be no current body: ql->size == 0
       *
       *                   where there is a current body, then it is:
       *
       *                     (a) embedded body, ql->size == qt->embedded_size,
       *                         so req <= ql->size && ql->size != 0, so cannot
       *                         arrive here.
       *
       *                     (b) not embedded, ql->size > qt->embedded_size !
       */
      if (ql->state == qls_embedded)
        {
          qassert(store) ;

          qassert(ql->size   == qt->embedded_size) ;
          qassert(ql->body.v == qlump_embedded_body(ql, qt)) ;

          return false ;                /* no reallocation              */
        } ;

      if ((old_size != 0) && !store)
        {
          /* This is an unexpected case -- for some reason we have an allocated
           * body which is smaller than the embedded body !
           *
           * This should not have happened, so we tidy up by copying from the
           * allocated body, discarding that and pretending nothing has
           * changed.
           */
          void* old_body ;

          qassert((ql->state == qls_normal) && (old_size < qt->embedded_size)) ;

          old_body = ql->body.v ;

          ql->size   = qt->embedded_size ;
          ql->body.v = qlump_embedded_body(ql, qt) ;
          ql->state  = qls_embedded ;

          memcpy(ql->body.v, old_body, qlump_sizeof(old_size, qt)) ;

          qt->free(ql, old_body, old_size, qt) ;

          return false ;                /* swept under carpet           */
        } ;

      /* "Allocate" the embedded body.
       */
      ql->size   = qt->embedded_size ;
      ql->body.v = qlump_embedded_body(ql, qt) ;
      ql->state  = qls_embedded ;
    }
  else
    {
      /* Need a new allocation -- unless 'store' and current allocation is
       * exactly what we want.
       */
      uint   new_size ;

      if (store)
        {
          /* Calculate new minimum size, and see if (by any chance) that is
           * the current size.
           */
          new_size = (req + qt->size_min_unit_m1) & ~ qt->size_min_unit_m1 ;

          if (new_size == ql->size)
            {
              qassert((ql->size != 0) && (ql->body.v != NULL)) ;

              return false ;            /* no reallocation required     */
            } ;
        }
      else
        {
          new_size = req + qt->size_add ;

          if (new_size < qt->size_min)
            new_size = qt->size_min ;   /* Use minimum in any case      */

          new_size = (new_size + qt->size_unit_m1) & ~ qt->size_unit_m1 ;
        } ;

      assert(new_size <= QLUMP_SIZE_MAX) ;      /* you are KIDDING      */

      qt->alloc(ql, new_size, store, qt) ;
    } ;

  qassert((req <= ql->size) && (ql->size != 0) && (ql->body.v != NULL)) ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * If the given qlump is an alias, copy it to qls_normal/qls_embedded.
 *
 * NB: if the alias is zero length, sets qls_normal with NULL body -- even if
 *     size_term != 0.
 */
static void
qlump_copy_alias(qlump ql)
{
  if ((ql->state == qls_alias) || (ql->state == qls_alias_term))
    {
      void*  alias_body ;

      alias_body = ql->body.v ;

      ql->state  = qls_normal ;
      ql->body.v = NULL ;
      ql->size   = 0 ;

      if (ql->len != 0)
        {
          qlump_type_c qt ;

          qt = qlump_get_type(ql) ;

          qlump_do_alloc(ql, ql->len, false /* not store */, qt) ;

          memcpy(ql->body.v, alias_body, qlump_sizeof(ql->len, qt)) ;
        } ;
    } ;
} ;

/*==============================================================================
 * Swapping groups of items in a qlump.
 */
static void qlump_exch_sections(byte* p_a, byte* p_b, usize n) ;
inline static void qlump_exch_1(byte* p_a, byte* p_b) ;
inline static void qlump_exch_2(byte* p_a, byte* p_b) ;
inline static void qlump_exch_3(byte* p_a, byte* p_b) ;
inline static void qlump_exch_4(byte* p_a, byte* p_b) ;
inline static void qlump_exch_5(byte* p_a, byte* p_b) ;
inline static void qlump_exch_6(byte* p_a, byte* p_b) ;
inline static void qlump_exch_7(byte* p_a, byte* p_b) ;
inline static void qlump_exch_8(byte* p_a, byte* p_b) ;
inline static void qlump_exch_16(byte* p_a, byte* p_b) ;

static void qlump_rev_section(byte* p, ulen n) ;
inline static void qlump_rev_2(byte* p, byte* e) ;
inline static void qlump_rev_3(byte* p, byte* e) ;
inline static void qlump_rev_4(byte* p, byte* e) ;
inline static void qlump_rev_5(byte* p, byte* e) ;
inline static void qlump_rev_6(byte* p, byte* e) ;
inline static void qlump_rev_7(byte* p, byte* e) ;
inline static void qlump_rev_8(byte* p, byte* e) ;
inline static void qlump_rev_16(byte* p, byte* e) ;

/* For testing
 */
extern void qlump_t_exch_sections(byte* p_a, byte* p_b, usize n) ;
extern void qlump_t_rev_section(byte* p, ulen n) ;

extern void qlump_t_exch_sections(byte* p_a, byte* p_b, usize n)
{
  qlump_exch_sections(p_a, p_b, n) ;
} ;

extern void qlump_t_rev_section(byte* p, ulen n)
{
  qlump_rev_section(p, n) ;
} ;

/*------------------------------------------------------------------------------
 * Swap 'na' items at 'a' with 'nb' items at 'b'.
 *
 * If is alias, copy it first (unless ql->len + size_term == 0).
 *
 * Adjust the size if ql->len + size_term > size.
 *
 * Expects a < b -- but that is not a requirement.
 *
 * The behaviour is essentially undefined if the sections to swap overlap,
 * or run beyond ql->size.  Ignores ql->len, except as above.
 *
 * NB: *FATAL* error if the qlump is unset.
 *
 * NB: does not move or resize the body, except for aliases and to adjust
 *     for ql->len and size_term.
 *
 *     Result will be qls_normal or qls_embedded.
 */
extern void
qlump_swap_items(qlump ql, uint a, ulen na, uint b, ulen nb)
{
  qlump_type_c qt ;
  ulen  q, nq, eb ;
  byte* p_a, * p_b, * p_q ;
  usize unit ;
  ulen  size ;

  /* Get type and size and worry about ql->len
   *
   * If this is a not-empty alias, will make a copy.  If is an empty alias,
   * will discard and leave an empty qls_normal.
   */
  qt = qlump_get_type(ql) ;

  size = ql->size ;

  if ((ql->len + qt->size_term) > size)
    {
      qlump_extend(ql, ql->len, MTYPE_NULL) ;
      size = ql->size ;
    }
  else if (size == 0)
    {
      qassert(ql->state != qls_embedded) ;

      ql->state  = qls_normal ;     /* discard any alias            */
      ql->body.v = NULL ;           /* no body, no more             */
    } ;

  /* If a is the first of the two sections, and there is no overlap, then
   * things are simple -- provided b does not run off the ql->size.
   */
  q  = a + na ;
  eb = b + nb ;

  if ((q > b) || (eb > size))
    {
      /* Deal with the exception cases -- make a the first of the two sections
       *
       *                               -- clamp to within size
       *
       *                               -- treat any overlap as belonging to 'a'
       */
      if (a > b)
        {
          q  = a ;
          nq = na ;
          a  = b ;
          na = nb ;
          b  = q ;
          nb = nq ;

          q  = a + na ;
          eb = b + nb ;
        } ;

      /* We now have a <= b -- clamp b and nb, if required
       */
      if (eb > size)
        {
          if (b > size)
            {
              if (a > size)
                return ;        /* both start beyond size       */

              b = size ;        /* clamp                        */
            } ;

            eb = size ;         /* clamp                        */
            nb = eb - b ;
        } ;

      /* We now have a <= b and eb = (b + nb) <= size
       *
       * Worry about overlap
       */
      if (q > b)
        {
          if (q >= eb)
            return ;            /* a overlaps all of b          */

          b  = q ;              /* push to end of a             */
          nb = eb - b ;
        } ;
    } ;

  qassert(((a + na) == q) && ((q + nq) == b) && ((b + nb) <= size)) ;

  /* Prepare to swap
   *
   * Note that na, nb and nq are counts of items, while p_a, p_b and p_q are
   * *byte* pointers.
   */
  p_a = qlump_item(ql, a, qt) ;
  p_b = qlump_item(ql, b, qt) ;

  unit = qt->unit ;

  /* If the sections to be swapped are the same size, we can do the swap
   * without worrying about the stuff between.
   */
  if (na == nb)
    {
      qlump_exch_sections(p_a, p_b, unit * na) ;
      return ;
    } ;

  /* We do the wonderful trick of reversing the a, q and b sections, and then
   * reversing the whole thing.
   */
  p_q = qlump_item(ql, q, qt) ;
  nq  = b - q ;

  qlump_rev_section(p_a, na * unit) ;
  qlump_rev_section(p_q, nq * unit) ;
  qlump_rev_section(p_b, nb * unit) ;

  qlump_rev_section(p_a, (na + nq + nb) * unit) ;
} ;

/*------------------------------------------------------------------------------
 * Swap two sections of 'n' *bytes*
 *
 * We expect the unit to be a multiple of some reasonable power of 2.  Where
 * the processor allows, compilers will render memcpy() as a memory fetch/store,
 * so we try to do swaps in blocks of 1, 2, 4, 8 and then multiples of 16.
 *
 * NB: *undefined* for overlapping sections.
 */
static void
qlump_exch_sections(byte* p_a, byte* p_b, usize n)
{
  /* Crunch through multiples of 16.
   *
   * We sort of assume that large items will be aligned at 4 or 8 byte
   * so we hope that this will be dealing in nicely aligned units.
   */
  while (n >= 16)
    {
      qlump_exch_16(p_a, p_b) ;

      n   -= 16 ;
      p_a += 16 ;
      p_b += 16 ;
    } ;

  /* Crunch any "odd" multiple of 8
   */
  if (n >= 8)
    {
      qlump_exch_8(p_a, p_b) ;

      n   -=  8 ;
      p_a +=  8 ;
      p_b +=  8 ;
    } ;

  /* Deal with the fag end
   */
  if (n != 0)
    {
      switch (n)
        {
          case 7:
            qlump_exch_7(p_a, p_b) ;
            break ;

          case  6:
            qlump_exch_6(p_a, p_b) ;
            break ;

          case 5:
            qlump_exch_5(p_a, p_b) ;
            break ;

          case 4:
            qlump_exch_4(p_a, p_b) ;
            break ;

          case 3:
            qlump_exch_3(p_a, p_b) ;
            break ;

          case 2:
            qlump_exch_2(p_a, p_b) ;
            break ;

          case 1:
            qlump_exch_1(p_a, p_b) ;
            break ;

          default:
            return ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 1 byte sections
 */
inline static void
qlump_exch_1(byte* p_a, byte* p_b)
{
  byte a, b ;

  b    = *p_b ;
  a    = *p_a ;
  *p_a = b  ;
  *p_b = a ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 2 byte sections
 */
inline static void
qlump_exch_2(byte* p_a, byte* p_b)
{
  uint16_t a, b ;

  memcpy(&b,  p_b, 2) ;
  memcpy(&a,  p_a, 2) ;
  memcpy(p_a, &b,  2) ;
  memcpy(p_b, &a,  2) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 3 byte sections
 */
inline static void
qlump_exch_3(byte* p_a, byte* p_b)
{
  qlump_exch_2(p_a,     p_b) ;
  qlump_exch_1(p_a + 2, p_b + 2) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 4 byte sections
 */
inline static void
qlump_exch_4(byte* p_a, byte* p_b)
{
  uint32_t a, b ;

  memcpy(&b,  p_b, 4) ;
  memcpy(&a,  p_a, 4) ;
  memcpy(p_a, &b,  4) ;
  memcpy(p_b, &a,  4) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 5 byte sections
 */
inline static void
qlump_exch_5(byte* p_a, byte* p_b)
{
  qlump_exch_4(p_a,     p_b) ;
  qlump_exch_1(p_a + 4, p_b + 4) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 6 byte sections
 */
inline static void
qlump_exch_6(byte* p_a, byte* p_b)
{
  qlump_exch_4(p_a,     p_b) ;
  qlump_exch_2(p_a + 4, p_b + 4) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 7 byte sections
 */
inline static void
qlump_exch_7(byte* p_a, byte* p_b)
{
  uint32_t a0, b0, a1, b1 ;

  memcpy(&b0,     p_b,     4) ;
  memcpy(&a0,     p_a,     4) ;

  memcpy(&b1,     p_b + 3, 4) ;
  memcpy(&a1,     p_a + 3, 4) ;

  memcpy(p_a,     &b0,     4) ;
  memcpy(p_b,     &a0,     4) ;

  memcpy(p_a + 3, &b1,     4) ;
  memcpy(p_b + 3, &a1,     4) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 8 byte sections
 */
inline static void
qlump_exch_8(byte* p_a, byte* p_b)
{
  uint64_t a, b ;

  memcpy(&b,  p_b, 8) ;
  memcpy(&a,  p_a, 8) ;
  memcpy(p_a, &b,  8) ;
  memcpy(p_b, &a,  8) ;
} ;

/*------------------------------------------------------------------------------
 * Exchange two 16 byte sections
 */
inline static void
qlump_exch_16(byte* p_a, byte* p_b)
{
  uint64_t a0, b0, a1, b1 ;

  memcpy(&b0,     p_b,     8) ;
  memcpy(&a0,     p_a,     8) ;

  memcpy(&b1,     p_b + 8, 8) ;
  memcpy(&a1,     p_a + 8, 8) ;

  memcpy(p_a,     &b0,     8) ;
  memcpy(p_b,     &a0,     8) ;

  memcpy(p_a + 8, &b1,     8) ;
  memcpy(p_b + 8, &a1,     8) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse a section of 'n' *bytes*
 *
 * We expect the unit to be a multiple of some reasonable power of 2.  Where
 * the processor allows, compilers will render memcpy() as a memory fetch/store,
 * so we try to do swaps in blocks of 1, 2, 4, 8 and then multiples of 16.
 */
static void
qlump_rev_section(byte* p, ulen n)
{
  byte* e ;

  if (n <= 1)
    return ;

  e = p + n ;

  n >>= 1 ;

  /* Crunch through multiples of 16.
   *
   * We sort of assume that large items will be aligned at 4 or 8 byte
   * so we hope that this will be dealing in nicely aligned units.
   */
  while (n >= 16)
    {
      e -= 16 ;
      qlump_rev_16(p, e) ;

      n -= 16 ;
      p += 16 ;
    } ;

  /* Crunch any "odd" multiple of 8
   */
  if (n >= 8)
    {
      e -= 8 ;
      qlump_rev_8(p, e) ;

      n -=  8 ;
      p +=  8 ;
    } ;

  /* Deal with the fag end
   */
  if (n != 0)
    {
      e -= n ;

      switch (n)
        {
          case 7:
            qlump_rev_7(p, e) ;
            break ;

          case  6:
            qlump_rev_6(p, e) ;
            break ;

          case 5:
            qlump_rev_5(p, e) ;
            break ;

          case 4:
            qlump_rev_4(p, e) ;
            break ;

          case 3:
            qlump_rev_3(p, e) ;
            break ;

          case 2:
            qlump_rev_2(p, e) ;
            break ;

          case 1:
            qlump_exch_1(p, e) ;
            break ;

          default:
            return ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 2 byte sections
 */
inline static void
qlump_rev_2(byte* p, byte* e)
{
  uint16_t a, b ;

  memcpy(&b,  e, 2) ;
  memcpy(&a,  p, 2) ;

  b = qbswap16(b) ;
  a = qbswap16(a) ;

  memcpy(p, &b,  2) ;
  memcpy(e, &a,  2) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 3 byte sections
 */
inline static void
qlump_rev_3(byte* p, byte* e)
{
  qlump_rev_2( p,     e + 1) ;
  qlump_exch_1(p + 2, e) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 4 byte sections
 */
inline static void
qlump_rev_4(byte* p, byte* e)
{
  uint32_t a, b ;

  memcpy(&b,  e, 4) ;
  memcpy(&a,  p, 4) ;

  b = qbswap32(b) ;
  a = qbswap32(a) ;

  memcpy(p, &b,  4) ;
  memcpy(e, &a,  4) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 5 byte sections
 */
inline static void
qlump_rev_5(byte* p, byte* e)
{
  qlump_rev_4( p,     e + 1) ;
  qlump_exch_1(p + 4, e) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 6 byte sections
 */
inline static void
qlump_rev_6(byte* p, byte* e)
{
  qlump_rev_4(p,     e + 2) ;
  qlump_rev_2(p + 4, e) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 7 byte sections
 */
inline static void
qlump_rev_7(byte* p, byte* e)
{
  uint32_t a0, b0, a1, b1 ;

  memcpy(&b0,     e,     4) ;
  memcpy(&a0,     p,     4) ;

  memcpy(&b1,     e + 3, 4) ;
  memcpy(&a1,     p + 3, 4) ;

  b0 = qbswap32(b0) ;
  a0 = qbswap32(a0) ;

  b1 = qbswap32(b1) ;
  a1 = qbswap32(a1) ;

  memcpy(p + 3, &b0,     4) ;
  memcpy(e + 3, &a0,     4) ;

  memcpy(p,     &b1,     4) ;
  memcpy(e,     &a1,     4) ;
} ;

/*------------------------------------------------------------------------------
 * Reverse and exchange two 8 byte sections
 */
inline static void
qlump_rev_8(byte* p, byte* e)
{
  uint64_t a, b ;

  memcpy(&b,  e, 8) ;
  memcpy(&a,  p, 8) ;

  b = qbswap64(b) ;
  a = qbswap64(a) ;

  memcpy(p, &b,  8) ;
  memcpy(e, &a,  8) ;
} ;

/*------------------------------------------------------------------------------
 * Swap two uint128_t and reverse them -- done as two uint64_t
 */
inline static void
qlump_rev_16(byte* p, byte* e)
{
  uint64_t a0, b0, a1, b1 ;

  memcpy(&b0,     e,     8) ;
  memcpy(&a0,     p,     8) ;

  memcpy(&b1,     e + 8, 8) ;
  memcpy(&a1,     p + 8, 8) ;

  b0 = qbswap64(b0) ;
  a0 = qbswap64(a0) ;

  b1 = qbswap64(b1) ;
  a1 = qbswap64(a1) ;

  memcpy(p + 8, &b0,     8) ;
  memcpy(e + 8, &a0,     8) ;

  memcpy(p,     &b1,     8) ;
  memcpy(e,     &a1,     8) ;
} ;
