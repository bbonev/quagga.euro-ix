/* BGP Extended Communities Attribute
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman (substantially rewritten)
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
#include "vty.h"
#include "miyagi.h"

#include <ctype.h>

#include "pthread_safe.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_ecommunity.h"

/*==============================================================================
 * Storing Extended-Community Attributes
 *
 * When storing an empty ecommunity returns NULL, so NB:
 *
 *   (a) do not distinguish empty from absent ecommunity objects.
 *
 *   (b) the canonical form of the empty ecommunity is a NULL one.
 *
 * Note that an "orphan" function is not required because there is only one
 * attr_ecommunity_vhash, which we set to NULL if/when the table is reset and
 * freed.
 */
vhash_table attr_ecommunity_vhash ;     /* extern in bgp_ecommunity.h */

static vhash_hash_t attr_ecommunity_hash(vhash_data_c data) ;
static int          attr_ecommunity_vhash_equal(vhash_item_c item,
                                                            vhash_data_c data) ;
static vhash_item   attr_ecommunity_vhash_new(vhash_table table,
                                                          vhash_data_c data) ;
static vhash_item   attr_ecommunity_vhash_free(vhash_item item,
                                                            vhash_table table) ;

static const vhash_params_t attr_ecommunity_vhash_params =
{
    .hash       = attr_ecommunity_hash,
    .equal      = attr_ecommunity_vhash_equal,
    .new        = attr_ecommunity_vhash_new,
    .free       = attr_ecommunity_vhash_free,
    .orphan     = vhash_orphan_null,
    .table_free = vhash_table_free_parent,
} ;

/*------------------------------------------------------------------------------
 * The communities list in an attr_ecommunity is a qlump.
 */
static const qlump_type_t attr_ecommunity_list_qt[1] =
{
    { .alloc        = qlump_alloc,
      .free         = qlump_free,

      .unit         = sizeof(ecommunity_t),

      .size_add     = 8,
      .size_unit_m1 = 4 - 1,            /* 32 byte boundaries   */

      .size_min     = 16,               /* if have to allocate  */

      .size_min_unit_m1 = 1 - 1,        /*  4 byte boundaries   */

      .embedded_size   = ecommunity_list_embedded_size,
      .embedded_offset = qlump_embedded_offset(attr_ecommunity_t, list,
                                                                 embedded_list),
      .size_term    = 0,
    }
} ;

/*------------------------------------------------------------------------------
 * The encoded ecommunity attribute is held as a qlump
 */
static const qlump_type_t attr_ecommunity_enc_qt[1] =
{
  { .alloc       = qlump_alloc,
    .free        = qlump_free,

    .unit         = 1,                  /* bytes                */

    .size_add     = 16,
    .size_unit_m1 = 4 - 1,              /* 16 byte boundaries   */

    .size_min     = 16,

    .size_min_unit_m1 = 1 - 1,          /*  4 byte boundaries   */

    .embedded_size   = 0,
    .embedded_offset = 0,

    .size_term    = 0,
  }
} ;

/*------------------------------------------------------------------------------
 * Start-up initialisation of the attr_ecommunity handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 */
extern void
attr_ecommunity_start(void)
{
  attr_ecommunity_vhash = vhash_table_new(&attr_ecommunity_vhash,
                                                1000 /* chain bases */,
                                                 200 /* % density   */,
                                                &attr_ecommunity_vhash_params) ;

  qlump_register_type(MTYPE_ECOMMUNITY_VAL, attr_ecommunity_list_qt,
                                                       false /* not a test */) ;
  qlump_register_type(MTYPE_ECOMMUNITY_ENC, attr_ecommunity_enc_qt,
                                                       false /* not a test */) ;
} ;

/*------------------------------------------------------------------------------
 * Close down the attr_ecommunity handling
 *
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored ecommunities.  That should be achieved naturally when all routes are
 * dismantled -- which should have been done before this is called.
 *
 * If any stored ecommunities remain, they may be unlocked, but will not be
 * freed.
 */
extern void
attr_ecommunity_finish(void)
{
  attr_ecommunity_vhash = vhash_table_reset(attr_ecommunity_vhash) ;
} ;

/*------------------------------------------------------------------------------
 * Either store the given attr_ecommunity, or free it and return existing stored
 * value.
 *
 * Increment reference count on the returned stored attr_ecommunity.
 *
 * NB: returns NULL if the given ecommunity object is empty.
 */
extern attr_ecommunity
attr_ecommunity_store(attr_ecommunity new)
{
  attr_ecommunity ecomm ;
  bool added ;

  if (new == NULL)
    return NULL ;                       /* empty already                */

  qassert(!new->stored && (new->vhash.ref_count == 0)) ;

  /* Look out for empty
   */
  if (new->list.len == 0)
    return attr_ecommunity_free(new) ;  /* returns NULL                 */

  /* Store or find matching existing stored instance.
   */
  added = false ;
  ecomm  = vhash_lookup(attr_ecommunity_vhash, new, &added) ;

  if (added)
    {
      qassert(ecomm == new) ;

      qlump_store(&ecomm->list) ;       /* ensure at minimum size       */

      ecomm->stored = true ;
    }
  else
    {
      /* Found the same attr_ecommunity -- so discard the current "new" one.
       */
      qassert(ecomm->stored) ;

      attr_ecommunity_free(new) ;
    } ;

  vhash_inc_ref(ecomm) ;

  return ecomm ;
} ;

/*------------------------------------------------------------------------------
 * Generate hash for given attr_ecommunity 'data' -- vhash call-back
 *
 * For the attr_ecommunity vhash the 'data' is a new (not-stored)
 * attr_ecommunity
 */
static vhash_hash_t
attr_ecommunity_hash(vhash_data_c data)
{
  attr_ecommunity_c new = data ;

  qassert(!new->stored) ;

  return vhash_hash_bytes(new->list.body.b,
                                         new->list.len * sizeof(ecommunity_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Is the 'item's 'data' the same as the given 'data' -- vhash call-back
 *
 * For the attr_ecommunity vhash: the 'item' is an attr_community, in the vhash
 *
 *                         the 'data' is a new (not-stored) attr_ecommunity
 */
static int
attr_ecommunity_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  attr_ecommunity_c ecomm = item ;
  attr_ecommunity_c new  = data ;

  qassert(ecomm->stored && !new->stored) ;

  if (ecomm->list.len != new->list.len)
    return 1 ;

  return memcmp(ecomm->list.body.v, new->list.body.v,
                                       ecomm->list.len * sizeof(ecommunity_t)) ;
} ;

/*------------------------------------------------------------------------------
 * "Create" new item for attr_ecommunity vhash -- vhash call-back
 *
 * For the attr_ecommunity vhash: the 'data' is a new (not-stored)
 * attr_ecommunity, so this is trivial.
 */
static vhash_item
attr_ecommunity_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_ecommunity  new = miyagi(data) ;

  qassert(!new->stored) ;

  return (vhash_item)new ;
} ;

/*------------------------------------------------------------------------------
 * Free item which is being removed from the vhash -- vhash call-back
 *
 * For the attr_ecommunity vhash: the 'item' is a stored attr_ecommunity
 *
 * Returns:  NULL <=> item freed
 */
static vhash_item
attr_ecommunity_vhash_free(vhash_item item, vhash_table table)
{
  attr_ecommunity ecomm = item ;

  qassert(ecomm->stored) ;

  ecomm->stored = false ;                /* no longer stored     */

  return attr_ecommunity_free(ecomm) ;
} ;

/*==============================================================================
 * The mechanics of handling the attr_ecommunity
 */
/*------------------------------------------------------------------------------
 * Create a new, and empty attr_ecommunity.
 */
extern attr_ecommunity
attr_ecommunity_new(uint n)
{
  attr_ecommunity new ;

  new = XCALLOC(MTYPE_ECOMMUNITY, sizeof(attr_ecommunity_t)) ;

  /* Zeroizing has set:
   *
   *    * vhash           -- initialised
   *
   *    * stored          -- false
   *
   *    * state           -- ecms_null
   *
   *    * str             -- unset, embedded qstring
   *
   *    * enc             -- unset, embedded qlump
   *    * enc_trans       -- unset, embedded qlump
   *
   *    * list            -- X     -- unset qlump, initialised below
   *    * embedded_list   -- X     -- all zeros, but not relevant
   */
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  confirm(ecms_null == 0) ;
  confirm(QSTRING_UNSET_ALL_ZEROS) ;
  confirm(QLUMP_UNSET_ALL_ZEROS) ;

  qlump_init(&new->list, n, MTYPE_ECOMMUNITY_VAL) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Create a copy of the given attr_ecommunity
 *
 * If the given ecommunity is NULL or empty, returns NULL.
 *
 * Result is not 'stored'
 */
static attr_ecommunity
attr_ecommunity_copy(attr_ecommunity ecomm)
{
  attr_ecommunity new ;

  if ((ecomm == NULL) || (ecomm->list.len == 0))
    return NULL ;

  new = XMALLOC(MTYPE_ECOMMUNITY, sizeof(attr_ecommunity_t)) ;

  *new = *ecomm ;                               /* clone                */

  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  memset(&new->vhash, 0, sizeof(vhash_node_t)) ;
  new->stored = false ;

  new->state &= ~ecms_string ;
  qs_init_new(new->str, 0) ;                    /* no string            */
  qlump_init(&new->enc, 0, MTYPE_ECOMMUNITY_ENC) ;
                                                /* no encoding          */
  qlump_init(&new->enc_trans, 0, MTYPE_ECOMMUNITY_ENC) ;
                                                /* no encoding          */

  qlump_post_clone(&new->list) ;                /* fixup body of list   */

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Free given attr_ecommunity and any allocated body and other dependent data.
 *
 * Returns:  NULL
 */
extern attr_ecommunity
attr_ecommunity_free(attr_ecommunity ecomm)
{
  if (ecomm != NULL)
    {
      qassert(ecomm->vhash.ref_count == 0) ;
      qassert(!ecomm->stored) ;

      qs_free_body(ecomm->str) ;
      qlump_free_body(&ecomm->enc) ;
      qlump_free_body(&ecomm->enc_trans) ;
      qlump_free_body(&ecomm->list) ;

      XFREE(MTYPE_ECOMMUNITY, ecomm) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function for qlump_sort_dedup() & qlump_bsearch()
 */
static int
attr_ecommunity_cmp(const void* a, const void* b)
{
  const ecommunity_t av = *(const ecommunity_t*)a ;
  const ecommunity_t bv = *(const ecommunity_t*)b ;

  if (av != bv)
    return (av < bv) ? -1 : +1 ;

  return 0 ;
} ;

/*==============================================================================
 * Community List Operations
 */
static uint attr_ecommunity_encode(attr_ecommunity ecomm, uint non_trans) ;

/*------------------------------------------------------------------------------
 * Create new attr_ecommunity from body of attribute
 *
 * Return:  address of new ecommunity attribute -- NULL if count == 0
 */
extern attr_ecommunity
attr_ecommunity_set (const byte* p, uint count)
{
  attr_ecommunity new ;
  ecommunity_t* list ;
  uint i ;

  if (count == 0)
    return NULL ;

  new = attr_ecommunity_new(count) ;

  new->list.len = count ;
  qassert(count <= new->list.size) ;

  list = new->list.body.v ;
  for (i = 0 ; i < count ; ++i)
    {
      ecommunity_t  val ;

      confirm(sizeof(ecommunity_t) == 8) ;
      val = load_nq(p) ;
      p += 8 ;

      list[i] = val ;
    } ;

  qlump_sort_dedup(&new->list, attr_ecommunity_cmp) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Prepare encoded BGP_ATT_ECOMMUNITIES for output
 *
 * Can have all attributes, or only the transitive ones.
 *
 * Returns:  pointer to encoded attribute and sets p_len to length including
 *           the attribute red tape.
 *
 *        or sets p_len to zero, if the attr_community is NULL or there are no
 *           communities to send.
 */
extern byte*
attr_ecommunity_out_prepare(attr_ecommunity ecomm, bool trans, uint* p_len)
{
  if ((ecomm == NULL) || (ecomm->list.len == 0))
    {
      *p_len = 0 ;
      return NULL ;
    }

  if (!(ecomm->state & ecms_encoded))
    {
      /* We generate the all communities version first.
       *
       * If we find any non-transitive ones, we generate the transitive only
       * subset.
       */
      uint non_trans ;

      non_trans = attr_ecommunity_encode(ecomm, 0) ;

      if (non_trans != 0)
        attr_ecommunity_encode(ecomm, non_trans) ;
      else
        qlump_set_alias(&ecomm->enc_trans, qls_alias, ecomm->enc.body.v,
                                         ecomm->enc.len, MTYPE_ECOMMUNITY_ENC) ;

      ecomm->state |= ecms_encoded ;
    } ;

  if (trans)
    {
      *p_len = ecomm->enc_trans.len ;
      return ecomm->enc_trans.body.v ;
    }
  else
    {
      *p_len = ecomm->enc.len ;
      return ecomm->enc.body.v ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add ecomm_b to ecomm_a
 *
 * If ecomm_b is NULL or empty, no change is made to ecomm_a.
 *
 * If ecomm_a is NULL, returns a copy of ecomm_b.
 *
 * If ecomm_a is stored, make a new attr_ecommunity.
 *
 * So, if ecomm_a is not stored, will return that, updated as required.
 *
 * Returns:  original ecomm_a (may be NULL) or new attr_ecommunity
 *
 * We know both ecommunity lists are sorted and deduped -- so can run one
 * against the other.
 */
extern attr_ecommunity
attr_ecommunity_add_list (attr_ecommunity ecomm_a, attr_ecommunity ecomm_b)
{
  attr_ecommunity dst ;
  ecommunity_t* a, * b, * n ;
  uint ia, ib, la , lb, in ;

  /* Is there anything to do, at all at all.
   */
  if ((ecomm_b == NULL) || (ecomm_b->list.len == 0))
    return ecomm_a ;

  if (ecomm_a == NULL)
    return attr_ecommunity_copy(ecomm_b) ;

  /* If ecomm_a is stored, make a brand new ecomm_a, big enough for everything
   * in both.  Point dst at the new attr_ecommunity, and n at the new body.
   *
   * If ecomm_a is not stored, blow a bubble at the front big enough for
   * contents of ecomm_b.  Point dst at ecomm_a, and n at the resulting body.
   *
   * At this point we know that neither is NULL and ecomm_b is not empty, so
   * the result cannot be NULL or empty !
   */
  ib = 0 ;
  lb = ecomm_b->list.len ;
  b  = ecomm_b->list.body.v ;

  ia = 0 ;
  la = ecomm_a->list.len ;

  if (ecomm_a->stored)
    {
      dst = attr_ecommunity_new(la + lb) ;

      a = ecomm_a->list.body.v ;
      n = dst->list.body.v ;
    }
  else
    {
      a = qlump_add_space(&ecomm_a->list, 0, lb) ;

      ia  = lb ;        /* first item after the bubble  */
      la += lb ;        /* new length of comm_a         */

      qassert(la == ecomm_a->list.len) ;

      dst = ecomm_a ;
      n   = a ;
    } ;

  /* Now, merge a[ia] with b[ib] and write to n[in]
   */
  in = 0 ;
  while ((ia < la) && (ib < lb))
    {
      ecommunity_t va, vb ;

      va = a[ia++] ;
      vb = b[ib++] ;

      while (va != vb)
        {
          if (va < vb)
            {
              n[in++] = va ;

              if (ia < la)
                va = a[ia++] ;
              else
                {
                  n[in++] = vb ;
                  goto done ;
                } ;
            }
          else
            {
              n[in++] = vb ;

              if (ib < lb)
                vb = b[ib++] ;
              else
                {
                  n[in++] = va ;
                  goto done ;
                } ;
            } ;
        } ;

      n[in++] = va ;
    } ;

 done:
  while (ia < la)
    n[in++] = a[ia++] ;         /* copy balance of ecomm_a      */

  while (ib < lb)
    n[in++] = b[ib++] ;         /* copy balance of ecomm_b      */

  qassert(in <= dst->list.size) ;

  dst->list.len = in ;
  dst->state = ecms_null ;      /* all change                   */

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Replace contents of ecomm_a by the contents of ecomm_b
 *
 * If ecomm_a is 'stored' or NULL, create a copy of ecomm_b (will be NULL if
 * ecomm_b NULL or empty).  Otherwise, update ecomm_a.
 *
 * So, if ecomm_a is not stored, will return that, updated as required.
 *
 * Returns:  original comm_a (may be NULL) or new attr_ecommunity
 */
extern attr_ecommunity
attr_ecommunity_replace_list (attr_ecommunity ecomm_a, attr_ecommunity ecomm_b)
{
  ecommunity_t* a, * b ;

  if ((ecomm_b == NULL) || (ecomm_b->list.len == 0))
    return attr_ecommunity_clear(ecomm_a) ;

  if (ecomm_b->stored)
    return ecomm_b ;

  if ((ecomm_a == NULL) || ecomm_a->stored)
    return attr_ecommunity_copy(ecomm_b) ;

  /* We have a not-stored and not-NULL comm_a and a not-stored, not-empty and
   * not-NULL comm_b
   *
   * Empty out comm_a and copy contents of comm_b to it.
   */
  ecomm_a->list.len = 0 ;

  a = qlump_add_space(&ecomm_a->list, 0, ecomm_b->list.len) ;
  b = ecomm_b->list.body.v ;

  memcpy(a, b, ecomm_b->list.len * sizeof(ecommunity_t)) ;

  ecomm_a->state = ecms_null ;
  return ecomm_a ;
} ;

/*------------------------------------------------------------------------------
 * Delete all ecommunities listed in ecomm_b from ecomm_a
 *
 * If ecomm_b is NULL or empty, no change is made to ecomm_a.
 *
 * If ecomm_a is NULL or empty, no change is made to ecomm_a.
 *
 * Otherwise, if finds a value to delete, and ecomm_a is stored, will create
 * a new ecomm_a before deleting the value.  (It is possible that the result
 * will be a new, empty attr_ecommunity.)
 *
 * Returns:  original ecomm_a (may be NULL) or new attr_ecommunity
 *
 * We know both ecommunity lists are sorted and deduped -- so can run one
 * against the other.
 */
extern attr_ecommunity
attr_ecommunity_del_list (attr_ecommunity ecomm_a, attr_ecommunity ecomm_b)
{
  attr_ecommunity dst ;
  ecommunity_t* a, * b, * n ;
  uint ia, ib, la , lb, in ;
  bool drop ;

  /* Is there anything to do, at all at all.
   */
  if ((ecomm_b == NULL) || (ecomm_b->list.len == 0))
    return ecomm_a ;

  if ((ecomm_a == NULL) || (ecomm_a->list.len == 0))
    return ecomm_a ;

  /* Run ecomm_b against ecomm_a.  If find something to delete, then worry
   * about the state of ecomm_a, and create a new attr_ecommunity if required.
   *
   * Note that at this point neither ecomm_a nor ecomm_b are empty, but it is
   * possible that the final result will be.
   */
  dst = ecomm_a ;                /* may change if deletes something      */

  a  = ecomm_a->list.body.v ;
  ia = 0 ;
  la = ecomm_a->list.len ;

  b  = ecomm_b->list.body.v ;
  ib = 0 ;
  lb = ecomm_b->list.len ;

  drop = false ;                /* no change, yet                       */
  in = 0 ;
  n  = NULL ;

  while ((ia < la) && (ib < lb))
    {
      ecommunity_t va, vb ;

      vb = b[ib++] ;
      va = a[ia++] ;

      while (vb != va)
        {
          if (va < vb)
            {
              if (drop)
                n[in++] = va ;

              if (ia >= la)
                goto done ;

              va = a[ia++] ;
            }
          else
            {
              if (ib >= lb)
                {
                  if (drop)
                    n[in++] = va ;

                  goto done ;
                } ;

              vb = b[ib++] ;
            } ;
        } ;

      if (!drop)
        {
          /* Have found something to delete, for the first time.
           *
           * If ecomm_a is stored, do the simple thing and make a complete
           * copy.  In fact, need only copy (ia - 1) items, but does not seem
           * worth worrying about that.
           */
          if (ecomm_a->stored)
            dst = attr_ecommunity_copy(ecomm_a) ;

          n  = dst->list.body.v ;
          in = ia - 1 ;

          drop = true ;
        }
    } ;

 done:
   if (drop)
     {
       while (ia < la)
         n[in++] = a[ia++] ;    /* copy balance of ecomm_a       */

       dst->list.len = in ;
       dst->state = ecms_null ;
     } ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Delete one ecommunity, if it is present.
 *
 * Do nothing with NULL attr_ecommunity
 *
 * If the ecommunity is present, creates a new attr_ecommunity if the given
 * ecomm is 'stored'.  Otherwise, updates the given ecomm.
 *
 * Returns:  original ecomm (may be NULL) or new attr_ecommunity
 */
extern attr_ecommunity
attr_ecommunity_del_value(attr_ecommunity ecomm, ecommunity_t val)
{
  if (ecomm != NULL)
    {
      uint ic ;
      int  result ;

      ic = qlump_bsearch(&ecomm->list, attr_ecommunity_cmp, &val, &result) ;

      if (result == 0)
        ecomm = attr_ecommunity_drop_value(ecomm, ic) ;
    } ;

  return ecomm ;
} ;

/*------------------------------------------------------------------------------
 * Drop the 'i'th ecommunity value from the given attr_ecommunity.
 *
 * Creates a new attr_ecommunity if the given ecomm is 'stored'.  Otherwise,
 * updates the given ecomm.
 *
 * If does not create a new attr_ecommunity, then clears the state down to
 * ecms_null.
 *
 * Returns:  original ecomm or new attr_ecommunity
 */
extern attr_ecommunity
attr_ecommunity_drop_value(attr_ecommunity ecomm, uint ic)
{
  if (ecomm != NULL)             /* for completeness     */
    {
      if (ecomm->stored)
        ecomm = attr_ecommunity_copy(ecomm) ;

      qlump_drop_items(&ecomm->list, ic, 1) ;
      ecomm->state = ecms_null ;
    } ;

  return ecomm ;
} ;

/*------------------------------------------------------------------------------
 * Clear the given attr_ecommunity
 *
 * Returns:  NULL if given ecommunity is stored or NULL
 *           the original ecommunity, updated (set empty)
 */
extern attr_ecommunity
attr_ecommunity_clear (attr_ecommunity ecomm)
{
  if ((ecomm == NULL) || (ecomm->stored))
    return NULL ;

  ecomm->list.len = 0 ;
  ecomm->state    = ecms_null ;

  return ecomm ;
} ;

/*------------------------------------------------------------------------------
 * Does comm_a match comm_b ?
 *
 * For there to be a match, comm_a must include all elements of comm_b,
 * but may include others.  An empty comm_b always matches.
 *
 * It does not matter whether comm_a or comm_b is 'stored' or not.
 *
 * Treats a NULL atr_ecommunity as empty.
 *
 * We know both ecommunity lists are sorted and deduped -- so can run one
 * against the other.
 */
extern bool
attr_ecommunity_match (attr_ecommunity_c ecomm_a, attr_ecommunity_c ecomm_b)
{
  ecommunity_t* a, * b ;
  uint ia, ib, la , lb ;

  if ((ecomm_b == NULL) || ((lb = ecomm_b->list.len) == 0))
    return true ;       /* empty (or NULL) ecomm_b always matches       */

  if ((ecomm_a == NULL) || ((la = ecomm_a->list.len) < lb))
    return false ;      /* if ecomm_a has fewer entries, cannot match   */

  qassert((0 < lb) && (lb <= la)) ;

  a  = ecomm_a->list.body.v ;
  ia = 0 ;
  b  = ecomm_b->list.body.v ;
  ib = 0 ;
  while (1)
    {
      ecommunity_t va, vb ;

      vb = b[ib++] ;
      va = a[ia++] ;

      while (va < vb)
        {
          if (ia >= la)
            return false ;

          va = a[ia++] ;
        } ;

      if (va != vb)
        return false ;

      if (ib >= lb)
        return true ;           /* Matched everything in comm_b */

      if (ia >= la)
        return false ;          /* Run out of comm_a first      */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Are ecomm_a and ecomm_b equal ?
 *
 * For equality the two ecommunities must have the same number of values, and
 * they must be the same values.
 *
 * It does not matter whether ecomm_a or ecomm_b is 'stored' or not.
 *
 * Treats a NULL atr_ecommunity as empty.
 *
 * We know both ecommunity lists are sorted and deduped -- so can run one
 * against the other.
 */
extern bool
attr_ecommunity_equal(attr_ecommunity_c ecomm_a, attr_ecommunity_c ecomm_b)
{
  ecommunity_t* a, * b ;
  uint la , lb ;

  la = (ecomm_a != NULL) ? ecomm_a->list.len : 0 ;
  lb = (ecomm_b != NULL) ? ecomm_b->list.len : 0 ;

  if (la != lb)
    return false ;

  if (la == 0)
    return true ;

  a = ecomm_a->list.body.v ;
  b = ecomm_b->list.body.v ;

  return (memcmp(a, b, la * sizeof(ecommunity_t)) == 0) ;
} ;

/*------------------------------------------------------------------------------
 * Prepare encoded BGP_ATT_ECOMMUNITIES for output
 *
 * Can have all attributes, or only the transitive ones.
 *
 * If 'non_trans' argument is not zero, then it is the number of non-
 * transitive communities which we are going to skip (this count *has* to
 * be correct, or a broken attribute will be created).
 *
 * In any case, counts the number of non-transitive communities as the
 * attribute is created, and returns that count.
 */
static uint
attr_ecommunity_encode(attr_ecommunity ecomm, uint non_trans)
{
  ecommunity_t* list ;
  ulen b_len, a_len ;
  byte* p ;
  uint i, n, non_trans_found ;
  qlump  enc ;

  qassert(ecomm != NULL) ;

  /* Worry about which form we are encoding, and the length of same.
   */

  if (non_trans == 0)
    enc = &ecomm->enc ;
  else
    enc = &ecomm->enc_trans ;

  assert(ecomm->list.len >= non_trans) ;
  n = ecomm->list.len - non_trans ;

  if (n == 0)
    {
      qlump_clear(enc) ;
      return 0 ;
    } ;

  /* Have at least one community, so generate the encoded attribute
   */
  b_len = n * 8 ;
  a_len = b_len + ((b_len > 255) ? 4 : 3) ;
  if (a_len > enc->size)
    qlump_extend(enc, a_len, MTYPE_ECOMMUNITY_ENC) ;
  enc->len = a_len ;

  p = enc->body.v ;

  p[0] = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE
                          | ((b_len > 255) ? BGP_ATF_EXTENDED : 0) ;
  p[1] = BGP_ATT_ECOMMUNITIES ;

  if (b_len > 255)
    {
      store_ns(&p[2], b_len) ;
      p += 4 ;
    }
  else
    {
      p[2] = b_len ;
      p += 3 ;
    } ;

  non_trans_found = 0 ;
  list = ecomm->list.body.v ;
  for (i = 0 ; n != 0 ; ++i)
    {
      qassert(i < ecomm->list.len) ;

      store_nq(p, list[i]) ;

      if (*p & BGP_EXCT_NON_TRANS)      /* Byte 0 of Network form       */
        {
          non_trans_found += 1 ;        /* count non-trans              */

          if (non_trans != 0)
            continue ;                  /* ...skip non-trans            */
        } ;

      p += 8 ;
      n -= 1 ;
    } ;

  qassert((p - enc->body.b) == a_len) ;
  qassert(non_trans == non_trans_found) ;

  return non_trans_found ;
} ;

/*==============================================================================
 * String mechanics
 *
 * Due to historical reason of industry standard implementation, there
 * are three types of format.
 *
 *   * 'route-map set extcommunity' format
 *
 *       "rt 100:1 100:2"
 *       "soo 100:3"
 *
 *     where can only have one type of extended community at a time, and that
 *     is set once for all communities on the line.
 *
 *     attr_ecommunity_from_str() supports this by requiring the caller to
 *     deal with the leading "rt"/"soo" and passing in 'with_prefix' = false,
 *     and the required subtype.
 *
 *     attr_ecommunity_str() supports this by requiring the caller to
 *     generate the required "rt"/"soo", and producing no prefixes itself
 *     (ECOMMUNITY_FORMAT_ROUTE_MAP).
 *
 *   * 'extcommunity-list'
 *
 *       "rt 100:1 rt 100:2 soo 100:3"
 *
 *     where can have a mixture of types, each one prefixed by the type.
 *
 *     attr_ecommunity_from_str() supports this by ignoring case and accepting
 *     white-space or a ':' after each prefix.
 *
 *     attr_ecommunity_str() supports this (ECOMMUNITY_FORMAT_COMMUNITY_LIST).
 *
 *   * 'display format' -- used by "show ip bgp" and extcommunity-list regular
 *                         expression matching,
 *
 *       "RT:100:1 RT:100:2 SoO:100:3"
 *
 *     where can have a mixture of types, each one prefixed by the type.
 *
 *     attr_ecommunity_from_str() supports this by ignoring case and accepting
 *     white-space or a ':' after each prefix.
 *
 *     attr_ecommunity_str() supports this (ECOMMUNITY_FORMAT_DISPLAY).
 */
enum ecommunity_token           /* token types                  */
{
  ecommunity_token_end,

  ecommunity_token_val,

  ecommunity_token_unknown
} ;

/* Working version of ecommunity -- in network byte order
 */
typedef byte ecommunity_n[8] ;
CONFIRM(sizeof(ecommunity_n) == sizeof(ecommunity_t)) ;

/* Prototypes
 */
static qstring attr_ecommunity_str_make(attr_ecommunity ecomm, qstring qs,
                                                   ecommunity_format_t format) ;
static void attr_ecommunity_str_append(qstring qs, ecommunity_t val,
                                                   ecommunity_format_t format) ;

static ecommunity_t attr_ecommunity_gettoken (const char* p,
                            bool with_prefix, byte subtype,
                               enum ecommunity_token *token, const char** p_e) ;

/*------------------------------------------------------------------------------
 * Return 'display format' string representation of communities attribute.
 *
 * Create it if required.  Returns "" for NULL ecommunities.
 *
 * This is cached in the attr_ecommunity object, of regular expression use.
 */
extern const char*
attr_ecommunity_str (attr_ecommunity ecomm)
{
  if (ecomm == NULL)
    return "" ;

  if (!(ecomm->state & ecms_string))
    {
      attr_ecommunity_str_make(ecomm, ecomm->str, ECOMMUNITY_FORMAT_DISPLAY) ;
      ecomm->state |= ecms_string ;
    } ;

  return qs_char_nn(ecomm->str) ;       /* NB: known to be terminated   */
} ;

/*------------------------------------------------------------------------------
 * Return string representation of communities attribute, in the requested form.
 *
 * Formats:
 *
 *   * ECOMMUNITY_FORMAT_ROUTE_MAP
 *
 *     Does not generate any "rt"/"soo" prefixes at all.
 *
 *     The caller is responsible for:
 *
 *       * generating any leading "rt"/"so" required.
 *
 *       * ensuring that all the communities in the list are of the expected
 *         type.
 *
 *  * ECOMMUNITY_FORMAT_COMMUNITY_LIST
 *
 *    Generates "rt"/"soo" prefixes -- separated from the value by " ".
 *
 *  * ECOMMUNITY_FORMAT_DISPLAY
 *
 *    Generates "RT:"/"SoO:" prefixes -- value immediately follows the ':'.
 *
 * Fills in the given qstring, or creates one
 *
 * Returns:  qstring -- which may be a newly created one
 */
extern qstring
attr_ecommunity_str_form(qstring qs, attr_ecommunity ecomm,
                                                   ecommunity_format_t format)
{
  if (ecomm == NULL)
    return qs_set_alias_str(qs, "") ;
  else
    return attr_ecommunity_str_make(ecomm, qs, format) ;
} ;

/*------------------------------------------------------------------------------
 * Convert string to ecommunity structure
 *
 * Returns:  new attr_ecommunity if OK
 *           NULL if not a well formed string form of communities
 *
 * NB: an empty (or NULL) string is deemed malformed.
 *
 * If 'with_prefix', then expect a known 'rt' or the like prefix in front of
 * each extended community value in the string.  Ignores the 'subtype'.
 *
 * If '!with_prefix', then does not expect any 'rt' etc, but applies the given
 * subtype -- eg: BGP_EXCS_R_TARGET or BGP_EXCS_R_ORIGIN
 */
extern attr_ecommunity
attr_ecommunity_from_str (const char *str, bool with_prefix, uint subtype)
{
  attr_ecommunity new ;
  ecommunity_t* list ;
  uint len ;
  bool done ;

  new = attr_ecommunity_new(1) ;        /* expect at least 1    */

  if (str == NULL)
    str = "" ;                          /* safety first         */

  list = new->list.body.v ;
  len  = 0 ;
  done = false ;
  while (!done)
    {
      enum ecommunity_token token ;
      ecommunity_t val ;

      val = attr_ecommunity_gettoken (str, with_prefix, subtype, &token, &str) ;

      switch (token)
        {
          case ecommunity_token_val:
            if (len >= new->list.size)
              list = qlump_extend(&new->list, len + 1, MTYPE_ECOMMUNITY_VAL) ;

            list[len++] = val ;
            break;

          case ecommunity_token_end:
            done = true ;

            if (len > 0)
              break ;                   /* got something        */

            fall_through ;              /* empty is invalid     */

          case ecommunity_token_unknown:
          default:
            return attr_ecommunity_free(new) ;
        } ;
    } ;

  qassert(len <= new->list.size) ;
  new->list.len = len ;

  qlump_sort_dedup(&new->list, attr_ecommunity_cmp) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Construct qstring for given attr_ecommunity.
 *
 * See attr_ecommunity_str() for description of the formats.
 *
 * If the given qstring is NULL, creates a brand new one.
 *
 * Returns:  qstring -- which is the responsibility of the caller to dispose
 *                      of as and when.
 */
static qstring
attr_ecommunity_str_make(attr_ecommunity ecomm, qstring qs,
                                                    ecommunity_format_t format)
{
  ecommunity_t* list ;
  uint i, l ;

  l = ecomm->list.len ;

  /* If the ecommunity is empty, set the qstring to an alias empty
   * string -- to minimise footprint !
   */
  if (l == 0)
    return qs_set_alias_str(qs, "") ;

  /* Make a wild guess as to the outside size of the result, and make sure
   * that the ecomm->str is that big.
   *
   * Form is: <prefix><as2>:<num4>  -- prefix +  5 (as2)  + 1 (:) + 10 (num4)
   *      or: <prefix><ipv4>:<num2> -- prefix + 15 (ipv4) + 1 (:) +  5 (num2)
   *      or: <prefix><as4>:<num2>  -- prefix + 10 (as4)  + 1 (:) +  5 (num2)
   *      or: 0xHHHHHHHHHHHHHHHH    -- 18
   *
   * The prefix is "rt ", "soo " etc.  for 4 characters.
   *
   * Plus separator.
   *
   * Wild guess: 26 characters per ecommunity -- pretty much guarantees will
   * not need to reallocate while building the string.
   */
  qs = qs_new_size(qs, l * 26) ;

  /* Crunch the communities.
   */
  list = ecomm->list.body.v ;

  for (i = 0 ; i < l ; ++i)
    attr_ecommunity_str_append(qs, list[i], format) ;

  qs_string(qs) ;        /* make sure terminated */

  return qs ;
} ;

/*------------------------------------------------------------------------------
 * Get next Extended Communities token from the string.
 *
 * Accepts:
 *
 *   <prefix><as2>:<num4>    ) assumes is AS2 if value <= 65535
 *   <prefix><as4>:<num2>    )
 *
 *   <prefix><ipv4>:<num2>
 *
 * Where <prefix> is: absent if '!with_prefix' -- uses given 'subtype'
 *                or: "rt "  or "RT:"  for subtype = BGP_EXCS_R_TARGET
 *                or: "soo " or "SoO:" for subtype = BGP_EXCS_R_ORIGIN
 *
 * ...in fact, ignores case for the prefix and allows either white-space or
 * ':' at the end of the prefix.
 */
static ecommunity_t
attr_ecommunity_gettoken (const char* p, bool with_prefix, byte subtype,
                                 enum ecommunity_token *token, const char** p_e)
{
  ecommunity_n bval ;
  strtox_t tox ;
  const char* e ;
  uint32_t temp ;
  uint32_t num_max ;

  /* Skip leading white space.
   */
  while (isspace ((int) *p))
    p++;

  *p_e = p ;            /* if end or fails, this is where it happened   */
  *token = ecommunity_token_unknown;    /* assume the worst             */

  /* Check the end of the line.
   */
  if (*p == '\0')
    {
      *token = ecommunity_token_end ;
      return 0 ;
    } ;

  /* If want a prefix, get it and set the subtype.
   */
  if (with_prefix)
    {
      switch (tolower(*p))
        {
          case 'r':
            ++p ;
            if (tolower(*p) != 't')             /* "rt"         */
              return 0 ;

            subtype = BGP_EXCS_R_TARGET ;
            break ;

          case 's':
            ++p ;
            if (tolower(*p) != 'o')
              return 0 ;

            ++p ;
            if (tolower(*p) != 'o')             /* "soo"        */
              return 0 ;

            subtype = BGP_EXCS_R_ORIGIN ;
            break ;

          default:
            return 0 ;
        } ;

      ++p ;             /* past last character of prefix        */
      if (*p == ':')
        ++p ;           /* accept ':' separator                 */
      else if (isspace((int)*p))
        {
          do
            ++p ;       /* accept one or more white-space       */
          while (isspace((int)*p)) ;
        }
      else
        return 0 ;
    } ;

  bval[1] = subtype ;

  /* Now the body of the value.
   *
   * What a mess, there are several possibilities:
   *
   *   a) A.B.C.D:MN    => BGP_EXCT_IPV4
   *   b) EF:OPQR       => BGP_EXCT_AS2
   *   c) GHJK:MN       => BGP_EXCT_AS4
   *
   * A.B.C.D: Four Byte IP
   * EF:      Two byte ASN
   * GHJK:    Four-byte ASN
   * MN:      Two byte value
   * OPQR:    Four byte value
   *
   * Note that we are incapable of generating a BGP_EXCT_AS4 with an
   * ASN <= 65535 !
   */
  if (!isdigit((int)*p))
    return 0 ;                  /* must have at least 1 digit ! */

  temp = strtoul_xr(p, &tox, &e, 0, UINT32_MAX) ;

  if (tox != strtox_ok)
    return 0 ;

  if ((temp <= 255) && (*e == '.'))
    {
      /* We have an IPv4 Address -- can be followed by 0..65535
       */
      char  buf[16] ;           /* "255.255.255.255\0"  */
      uint  b ;
      int   ret ;
      struct in_addr ip ;

      b = 0 ;
      while (isdigit(*p) || (*p == '.'))
        {
          if (b == 15)
            return 0 ;

          buf[b++] = *p++ ;
        } ;

      buf[b] = '\0' ;

      ret = inet_aton (buf, &ip) ;
      if (ret == 0)
        return 0 ;

      bval[0] = BGP_EXCT_IPV4 ;
      memcpy(&bval[2], &ip, sizeof(in_addr_t)) ;

      num_max = 65535 ;
    }
  else if (temp <= 65535)
    {
      /* We have an AS2 -- can be followed by 0..UINT32_MAX
       *
       */
      p = e ;                   /* step past number     */

      bval[0] = BGP_EXCT_AS2 ;

      store_ns(&bval[2], temp) ;

      num_max = UINT32_MAX ;
    }
  else
    {
      /* We have an AS4 -- can be followed by 0..65535
       */
      p = e ;                   /* step past number     */

      bval[0] = BGP_EXCT_AS4 ;

      store_nl(&bval[2], temp) ;

      num_max = 65535 ;
    } ;

  if (*p != ':')
    return 0 ;

  ++p ;

  temp = strtoul_xr(p, &tox, &e, 0, num_max) ;

  if (tox != strtox_ok)
    return 0 ;

  if (!isspace((int)*e) && (*e != '\0'))
    return 0 ;

  if (num_max == 65535)
    store_ns(&bval[6], temp) ;
  else
    store_nl(&bval[4], temp) ;

  *token = ecommunity_token_val;
  *p_e   = e ;
  return load_nq(bval) ;
} ;

/*------------------------------------------------------------------------------
 * Convert extended community value to string, appending to the given qstring.
 */
static void
attr_ecommunity_str_append(qstring qs, ecommunity_t val,
                                                     ecommunity_format_t format)
{
  ecommunity_n bval ;
  byte type ;
  const char *prefix ;
  asn_t     asn ;
  uint32_t  local ;

  store_nq(bval, val) ;

  /* Sort out the type of value we are going to print, and output required
   * prefix.
   *
   * We only understand a tiny fraction of the possible encoded values, and
   * only a limited number of the defined ones.
   *
   * For all the things we don't understand, output "0xHHHHHHHHHHHHHHHH"
   */
  prefix = " 0x" ;              /* for default, "opaque" type           */

  type = bval[0] ;
  switch (type)
    {
      case BGP_EXCT_AS2:        /* AS2 Specific Ext. Community          */
      case BGP_EXCT_IPV4:       /* IPv4 Specific Ext. Community         */
      case BGP_EXCT_AS4:        /* AS4 Specific Ext. Community          */
        switch (bval[1])
          {
            case BGP_EXCS_R_TARGET:     /* Route Target                 */
              switch (format)
                {
                  case ECOMMUNITY_FORMAT_ROUTE_MAP:
                  default:
                    prefix = " " ;
                    break ;

                  case ECOMMUNITY_FORMAT_COMMUNITY_LIST:
                    prefix = " rt " ;
                    break ;

                  case ECOMMUNITY_FORMAT_DISPLAY:
                    prefix = " RT:" ;
                    break ;
                } ;
              break ;

            case BGP_EXCS_R_ORIGIN:     /* Route Origin                 */
              switch (format)
                {
                  case ECOMMUNITY_FORMAT_ROUTE_MAP:
                  default:
                    prefix = " " ;
                    break ;

                  case ECOMMUNITY_FORMAT_COMMUNITY_LIST:
                    prefix = " soo " ;
                    break ;

                  case ECOMMUNITY_FORMAT_DISPLAY:
                    prefix = " SoO:" ;
                    break ;
                } ;
              break ;

            default:
              type = BGP_EXCT_OPAQUE ;  /* Opaque Ext. Community        */
          } ;
        break ;

        default:
          type = BGP_EXCT_OPAQUE ;      /* Opaque Ext. Community        */
    } ;

  if (qs->len == 0)
    ++prefix ;                  /* discard " " separator                */

  qs_append_str(qs, prefix) ;

  /* Now the value per the effective type.
   */
  switch (type)
    {
      case BGP_EXCT_AS2:        /* AS2 Specific Ext. Community          */
        asn   = load_ns(&bval[2]) ;
        local = load_nl(&bval[4]) ;

        qs_printf_a(qs, "%u:%u", asn, local) ;
        break ;

      case BGP_EXCT_IPV4:       /* IPv4 Specific Ext. Community         */
        local = load_ns(&bval[6]) ;

        qs_printf_a(qs, "%s:%u", siptoa(AF_INET, &bval[2]).str, local) ;
        break ;

      case BGP_EXCT_AS4:        /* AS4 Specific Ext. Community          */
        asn   = load_nl(&bval[2]) ;
        local = load_ns(&bval[6]) ;

        qs_printf_a(qs, "%u:%u", asn, local) ;
        break ;

      default:
        qs_printf_a(qs, "%016lx", val) ;
        break ;
    } ;
} ;

/*==============================================================================
 * Printing functions
 */

/*------------------------------------------------------------------------------
 * Function to compare ecommunity objects by comparison of their string forms.
 */
static int
attr_ecommunity_sort_cmp(const vhash_item_c* a, const vhash_item_c* b)
{
  attr_ecommunity  ecomm_a = miyagi(*a) ;
  attr_ecommunity  ecomm_b = miyagi(*b) ;

  const char* str_a ;
  const char* str_b ;

  str_a = attr_ecommunity_str(ecomm_a) ;
  str_b = attr_ecommunity_str(ecomm_b) ;

  return strcmp(str_a, str_b) ;
} ;

/*------------------------------------------------------------------------------
 * Print all stored ecommunity attributes and hash information.
 */
extern void
attr_ecommunity_print_all_vty (struct vty *vty)
{
  vector extract ;
  uint i ;

  extract = vhash_table_extract(attr_ecommunity_vhash, NULL, NULL,
                                     true /* most */, attr_ecommunity_sort_cmp) ;

              /* 1234567890_12345678_12........*/
  vty_out (vty, "Hash       Refcnt   Communities\n");

  for (i = 0 ; i < vector_length(extract) ; ++i)
    {
      attr_ecommunity  ecomm ;

      ecomm = vector_get_item(extract, i) ;

      vty_out (vty, "[%8x] (%6u) %s\n", ecomm->vhash.hash, ecomm->vhash.ref_count,
                                                     attr_ecommunity_str(ecomm)) ;
    } ;

  vector_free(extract) ;
}

