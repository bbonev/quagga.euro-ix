/* BGP Unknown Attribute handling
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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
#include "memory.h"
#include "vhash.h"
#include "miyagi.h"

#include "stream.h"

#include "bgpd/bgp.h"
#include "bgpd/bgp_unknown.h"

/*==============================================================================
 * Storing collections of Unknown Attributes
 *
 * Note that an "orphan" function is not required because there is only one
 * attr_unknown_vhash, which we set to NULL if/when the table is reset and
 * freed.
 */
vhash_table attr_unknown_vhash ;        /* extern in bgp_unkown.h       */

static vhash_hash_t attr_unknown_hash(vhash_data_c data) ;
static int          attr_unknown_equal(vhash_item_c item, vhash_data_c data) ;
static vhash_item   attr_unknown_vhash_new(vhash_table table,
                                                          vhash_data_c data) ;
static vhash_item   attr_unknown_vhash_free(vhash_item item,
                                                            vhash_table table) ;

static const vhash_params_t attr_unknown_vhash_params =
{
    .hash   = attr_unknown_hash,
    .equal  = attr_unknown_equal,
    .new    = attr_unknown_vhash_new,
    .free   = attr_unknown_vhash_free,
    .orphan = vhash_orphan_null,
} ;

static void attr_unknown_stash(attr_unknown dst, attr_unknown src,
                                                               bool opt_trans) ;
static vector attr_unknown_get_aux(attr_unknown unk) ;

/*------------------------------------------------------------------------------
 * Start-up initialisation of the attr_unknown handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 *
 * The body of a collection of unknown attributes is a simple XMALLOC() piece
 * of memory.
 */
extern void
attr_unknown_start(void)
{
  attr_unknown_vhash = vhash_table_new(NULL, 1000 /* chain bases */,
                                             200 /* % density   */,
                                                   &attr_unknown_vhash_params) ;
} ;

/*------------------------------------------------------------------------------
 * Close down the attr_unknown handling
 *
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored unknown attribute sets.  That should be achieved naturally when all
 * routes are dismantled -- which should have been done before this is called.
 *
 * If any stored unknown attributes remain, they may be unlocked, but will not
 * be freed.
 */
extern void
attr_unknown_finish(void)
{
  attr_unknown_vhash = vhash_table_reset(attr_unknown_vhash, free_it) ;
} ;

/*------------------------------------------------------------------------------
 * Either store the given attr_unknown, or free it and return existing stored
 * value.
 *
 * A NULL attr_unknown is an empty attr_unknown.
 *
 * Increment reference count.
 *
 * Stores only the unique Optional-Transitive attributes, with BGP_ATF_PARTIAL
 * set, ready to be sent as part of an outgoing update.
 *
 * Discards any aux vector -- do not expect to need it, but if we do, it can be
 * recreated.
 *
 * NB: returns NULL if there are no Optional-Transitive attributes.
 */
extern attr_unknown
attr_unknown_store(attr_unknown new)
{
  attr_unknown unk ;
  bool added ;

  /* Reduce to just the unique Optional-Transitives
   *
   * If new is NULL or does not contain any optional-transitives, returns NULL.
   */
  if (new == NULL)
    return NULL ;

  qassert(!new->stored && (new->vhash.ref_count == 0)) ;

  if (!attr_unknown_transitive(new))
    return attr_unknown_free(new) ;

  /* We have a not empty, sorted, stashed, canonical, Optional-Transitive,
   * Partial set of attributes.
   *
   * So store or find matching existing stored instance.
   */
  qassert(new->state == (unks_stashed | unks_sorted | unks_opt_trans)) ;

  added = false ;
  unk = vhash_lookup(attr_unknown_vhash, new, &added) ;

  if (added)
    {
      qassert(unk == new) ;

      unk->stored = true ;
      unk->aux = vector_free(unk->aux) ;        /* discard, if any      */
    }
  else
    {
      /* Found the same attr_unknown -- so discard the current "new" one.
       */
      qassert(unk->stored) ;

      attr_unknown_free(new) ;
    } ;

  vhash_inc_ref(unk) ;

  return unk ;
} ;

/*------------------------------------------------------------------------------
 * Generate hash for given attr_unknown 'data' -- vhash call-back
 *
 * For the attr_unknown vhash: the 'data' is a new (not-stored) attr_unknown
 */
static vhash_hash_t
attr_unknown_hash(vhash_data_c data)
{
  attr_unknown_c new = data ;

  qassert(!new->stored) ;

  return vhash_hash_bytes(new->body, new->len) ;
} ;

/*------------------------------------------------------------------------------
 * Is the 'item's 'data' the same as the given 'data' -- vhash call-back
 *
 * For the attr_unknown vhash: the 'item' is an attr_unknown, in the vhash
 *                             the 'data' is a new (not-stored) attr_unknown
 */
static int
attr_unknown_equal(vhash_item_c item, vhash_data_c data)
{
  attr_unknown_c unk = item ;
  attr_unknown_c new = data ;

  qassert(unk->stored && !new->stored) ;

  if (unk->len != new->len)
    return 1 ;

  if (unk->len == 0)
    return 0 ;

  return memcmp(unk->body, new->body, unk->len) ;
} ;

/*------------------------------------------------------------------------------
 * "Create" new item for attr_unknown vhash -- vhash call-back
 *
 * For the attr_unknown vhash: the 'data' is a new (not-stored) attr_unknown,
 * so this is trivial.
 */
static vhash_item
attr_unknown_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_unknown new = miyagi(data) ;

  qassert(!new->stored) ;

  return (vhash_item)new ;
} ;

/*------------------------------------------------------------------------------
 * Free item which is being removed from the vhash -- vhash call-back
 *
 * For the attr_unknown vhash: the 'item' is a stored attr_unknown
 *
 * Returns:  NULL <=> item has been freed
 */
static vhash_item
attr_unknown_vhash_free(vhash_item item, vhash_table table)
{
  attr_unknown unk = item ;

  qassert(unk->stored) ;

  unk->stored = false ;                 /* no longer stored     */

  return attr_unknown_free(unk) ;
} ;

/*==============================================================================
 * The mechanics of handling the attr_unknown
 */
static int attr_unknown_cmp(const cvp* a, const cvp* b) ;

/*------------------------------------------------------------------------------
 * Create a new, and empty attr_unknown.
 */
extern attr_unknown
attr_unknown_new(void)
{
  attr_unknown new ;

  new = XCALLOC(MTYPE_BGP_UNKNOWN_ATTR, sizeof(attr_unknown_t)) ;

  /* Zeroizing has set:
   *
   *    * vhash           -- initialised
   *
   *    * stored          -- false
   *
   *    * state           -- unks_null
   *
   *    * count           -- 0      -- no stash
   *    * len             -- 0      -- ditto
   *    * body            -- NULL   -- ditto
   *
   *    * aux             -- NULL   -- no vector
   */
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  confirm(unks_null == 0) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Free given attr_unknown and any allocated body and other dependent data.
 *
 * Returns:  NULL
 */
extern attr_unknown
attr_unknown_free(attr_unknown unk)
{
  if (unk != NULL)
    {
      qassert(unk->vhash.ref_count == 0) ;      /* always               */
      qassert(!unk->stored) ;                   /* always               */

      vector_free(unk->aux) ;

      XFREE(MTYPE_BGP_UNKNOWN_BODY, unk->body) ;

      XFREE(MTYPE_BGP_UNKNOWN_ATTR, unk) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Add the given unknown attribute to the given unk.
 *
 * Allocates a new attr_unknown object, or copies the current one, if required.
 *
 * This is used when parsing a set of attributes.  As each one is found, saves
 * a pointer to it.  When the entire set of attributes has been parsed, the
 * pointers can be sorted, to get the attributes in order, and to check for
 * duplicates etc.
 *
 * An entire set of unknown attributes may be copied (so that the attributes
 * are copied to a local stash) if they are required after the incoming
 * message hase been discarded.
 *
 * The unique optional-transitive attributes may be stored as part of an
 * attribute set.
 *
 * NB: it is the caller's responsibility to ensure that the pointer to the
 *     unknown attribute:
 *
 *       (a) points to a properly formed attribute
 *
 *       (b) is stable until attr_unknown_free() discards the unk->aux.
 *
 *           or the attr_unknown is copied
 *
 *           or the attr_unknown is stored.
 *
 * NB: adding something to a stored attr_unknown copies it to a new
 *     attr_unknown first.
 */
extern attr_unknown
attr_unknown_add(attr_unknown unk, const byte* unknown)
{
  vector aux ;

  if (unk == NULL)
    {
      /* Starting a shiny new attr_unknown
       */
      unk = attr_unknown_new() ;
      aux = unk->aux = vector_new(4) ;
    }
  else if (unk->stored)
    {
      /* Starting from a stored attr_unknown, which must now make a copy of,
       * and build an aux vector for.
       */
      qassert(unk->state == (unks_stashed | unks_sorted | unks_opt_trans)) ;
      qassert(unk->aux == NULL) ;
      unk = attr_unknown_copy(unk) ;
      aux = attr_unknown_get_aux(unk) ;
    }
  else
    {
      /* Have an existing, not-stored attr_unknown -- get or make an aux vector.
       *
       * If there is an existing aux vector, we use it.  Otherwise, if is
       * stashed, we (re)create the aux vector.  Otherwise, we assume we are
       * starting from an empty attr_unknown, for which we need a new, empty
       * aux vector.
       */
      aux = attr_unknown_get_aux(unk) ;
      if (aux == NULL)
        {
          qassert(unk->state == unks_null) ;
          aux = unk->aux = vector_new(4) ;
        } ;
    } ;

  vector_push_item(aux, miyagi(unknown)) ;

  unk->state = unks_null ;      /* no longer sorted or stashed (unchanged) */

  return unk ;
} ;

/*------------------------------------------------------------------------------
 * Get the Optional-Transitive Attributes -- if any -- ready for output.
 *
 * A NULL attr_unknown is an empty attr_unknown.
 *
 * If the given attr_unknown contains other attributes or any duplicates, those
 * are discarded (from the unk) first.
 */
extern byte*
attr_unknown_out_prepare(attr_unknown unk, ulen* p_len)
{
  if (attr_unknown_transitive(unk))
    {
      *p_len = unk->len ;
      return unk->body ;
    }
  else
    {
      *p_len = 0 ;
      return NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Sort the auxiliary vector into ascending order of attribute type, and
 * ascending arrival order.
 *
 * A NULL attr_unknown is an empty attr_unknown.
 *
 * This is simply sorting the pointers in the vector -- the attributes do
 * not move.
 *
 * Can attr_unknown_add() stuff, sort it, and then add some more stuff later
 * (which clears the sorted state).
 *
 * For a NULL attr_unknown returns unks_null.  For a not NULL attr_unknown,
 * returns at least unks_sorted (even if is empty).
 *
 * NB: where an attribute is repeated, it will set the unks_duplicate state, as
 *     well as one of unks_opt_trans, unks_opt_non_trans or unks_well_known
 *     states.
 *
 * NB: it is possible for a given attribute type to be repeated, but with
 *     different optional and/or transitive flags.  If the caller cares, then
 *     they will need to establish that separately.
 */
extern attr_unknown_state_t
attr_unknown_sort(attr_unknown unk)
{
  vector_index_t i, count ;
  byte   prev_type ;
  byte   state ;

  if (unk == NULL)
    return unks_null ;

  if (unk->state & unks_sorted)
    return unk->state ;

  qassert(!unk->stored) ;                       /* stored => sorted     */
  qassert(!(unk->state & unks_stashed)) ;       /* stashed => sorted    */

  count = (unk->aux != NULL) ? vector_length(unk->aux) : 0 ;

  if (count > 1)
    vector_sort(unk->aux, attr_unknown_cmp) ;

  prev_type = 0 ;
  state     = unks_sorted ;                     /* not stashed          */

  for (i = 0 ; i < count ; ++i)
    {
      byte* pu ;
      byte  type ;
      byte  flags ;

      pu = vector_get_item(unk->aux, i) ;

      flags = pu[0] ;
      type  = pu[1] ;

      if (flags & BGP_ATF_OPTIONAL)
        state |= (flags & BGP_ATF_TRANSITIVE) ? unks_opt_trans
                                              : unks_opt_non_trans ;
      else
        state |= unks_well_known ;

      if ((type == prev_type) && (i != 0))
        state |= unks_duplicate ;

      prev_type = type ;
    } ;

  unk->state  = state ;

  return state ;
} ;

/*------------------------------------------------------------------------------
 * The unk attribute comparison function.
 *
 * Arguments are pointers to the vector entries, which are pointers to the
 * encoded unk attributes.
 */
static int
attr_unknown_cmp(const cvp* a, const cvp* b)
{
  const byte* pa = *a ;
  const byte* pb = *b ;

  byte ta, tb ;

  ta = pa[1] ;                  /* type byte following flags    */
  tb = pb[1] ;

  if (ta < tb)
    return -1 ;
  if (ta > tb)
    return +1 ;

  return (a < b) ? -1 : +1 ;
} ;

/*------------------------------------------------------------------------------
 * Fetch the 'ith' unk item from the current aux vector
 *
 * A NULL attr_unknown is an empty attr_unknown.
 */
extern attr_unknown_item
attr_unknown_get_item(attr_unknown_item item, attr_unknown unk, uint i)
{
  vector aux ;
  byte* p ;

  aux = attr_unknown_get_aux(unk) ;     /* NULL unk -> NULL aux */

  if (aux == NULL)
    return NULL ;

  p = vector_get_item(aux, i) ;

  if (p == NULL)
    return NULL ;

  item->type  = p[1] ;
  item->flags = p[0] ;

  if (item->flags & BGP_ATF_EXTENDED)
    {
      item->len = load_ns(&p[2]) ;
      item->val = p + 4 ;
    }
  else
    {
      item->len = p[2] ;
      item->val = p + 3 ;
    } ;

  if (item->len == 0)
    item->val = NULL ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Make a copy of the given set of unknown attributes.
 *
 * Creates a 'stash' in the copy, but no aux (which can be created as required).
 */
extern attr_unknown
attr_unknown_copy(attr_unknown src)
{
  attr_unknown dst ;

  if (src == NULL)
    return NULL ;

  dst = attr_unknown_new() ;

  if (src->aux == NULL)
    {
      /* If there is no aux vector in the original, then we copy its stash,
       * if any.
       */
      if (src->len != 0)
        {
          /* The src stash is not empty
           */
          qassert( (src->state & (unks_stashed | unks_sorted)) ==
                                 (unks_stashed | unks_sorted) ) ;
          qassert(src->state & unks_any) ;
          qassert(src->count != 0) ;
          qassert(src->body  != NULL) ;

          dst->state  = src->state ;        /* can copy the state   */
          dst->count  = src->count ;
          dst->len    = src->len ;

          dst->body = XMALLOC(MTYPE_BGP_UNKNOWN_BODY, src->len) ;
          memcpy(dst->body, src->body, src->len) ;
        }
      else
        {
          /* The src stash is empty
           *
           * We set the dst->state to unks_stashed | unks_sorted -- note that
           * a NULL or empty attr_unknown may also show up as unks_null.
           */
          qassert(!(src->state & (unks_any | unks_duplicate))) ;
          qassert(src->count != 0) ;

          dst->state = unks_stashed | unks_sorted ;
        } ;
    }
  else
    {
      /* There is an aux in the original, so we need to make a new stash in the
       * dst, containing whatever the aux in the src points at.
       *
       * The dst stash is created in canonical form, which we achieve by
       * first sorting the original (which doesn't do it any harm), and then
       * creating a stash from that (but in the dst attr_unknown).
       */
      attr_unknown_stash(dst, src, false /* no filtering */) ;
    } ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Stash any Optional-Transitive unknown attributes.
 *
 * A NULL attr_unknown is an empty attr_unknown.
 *
 * Sorts the attributes and discards any which have duplicate(s), or are not
 * optional-transitive.  Sets BGP_ATF_PARTIAL on all the stashed attributes.
 *
 * (Discards duplicates without regard to the flag state -- so, eg, drops an
 *  optional-transitive if there is an optional-non-transitive of the same
 *  type).
 *
 * Returns:  true <=> after discarding any other attributes and any duplicates,
 *                    have at least one optional-transitive
 *           false => was or is no empty
 */
extern bool
attr_unknown_transitive(attr_unknown unk)
{
  if (unk == NULL)
    return NULL ;

  if ((unk->state & (unks_stashed       |
                     unks_sorted        |
                     unks_opt_non_trans |
                     unks_well_known    |
                     unks_duplicate     )) != (unks_stashed | unks_sorted))
    {
      /* Not stashed or not sorted, or we have an optional-not-transitive or
       * a well-known or a duplicate.
       *
       * Sort and ensure only unique optional-transitive are left, and
       * construct a new stash, as required.
       */
      qassert(!unk->stored && (unk->vhash.ref_count == 0)) ;

      attr_unknown_stash(unk, unk, true /* opt_trans */) ;
    } ;

  return (unk->state == (unks_stashed | unks_sorted | unks_opt_trans)) ;
} ;

/*------------------------------------------------------------------------------
 * Copy unknown attributes in the src attr_unknown to a stash in the given dst.
 *
 * Requires that the dst is not stored !
 *
 * The src and dst may be the same.  Neither may be NULL.
 *
 * If a stash already exists in the dst, it is replaced by a new one, with the
 * entire contents of the src aux vector in it.
 *
 * If 'opt_trans':
 *
 *   * remove all but Optional-Transitive
 *
 *   * dropping all duplicates -- retain only the unique attributes.
 *
 *     Not that this drops an Optional-Transitive attribute of type 'x' if
 *     there are any other attributes of that type, without reference to the
 *     attribute flags -- so, for example an Optional-Non-Transitive attribute
 *     of type 'x' will cause an Optional-Transitive attribute of type 'x' to
 *     be dropped.
 *
 *   * set BGP_ATF_PARTIAL on all the stashed attributes.
 *
 *   * the dst aux vector is up to date with the new state -- creates a new
 *     dst aux vector if required.
 *
 * Otherwise:
 *
 *   * copy everything
 *
 *   * does not set BGP_ATF_PARTIAL
 *
 *   * if there was a dst aux vector, it is up to date.
 *     if there was no dst aux vector, there still is no dst aux vector.
 *
 * In both cases:
 *
 *   * clear the BGP_ATF_ZERO parts of the attribute flags
 *
 *   * use BGP_ATF_EXTENDED only where required
 *
 *     So, if attribute has BGP_ATF_EXTENDED but length <= 255, the encoding
 *     is "corrected".
 *
 * Sets:
 *
 *   * unk->state   -- sets unks_stashed and unks_sorted
 *                     other flags as required.
 *
 *   * unk->count   -- as required
 *   * unk->len     -- ditto
 *   * unk->body    -- new body, NULL if count == 0
 */
static void
attr_unknown_stash(attr_unknown dst, attr_unknown src, bool opt_trans)
{
  vector src_aux, dst_aux ;
  vector_index_t i, n, nn ;
  uint need ;
  byte* body, * q, * e ;
  attr_unknown_state_t state ;

  qassert((dst != NULL) & !dst->stored) ;
  qassert(src != NULL) ;

  /* Sort out the src aux vector, and ensure is sorted
   */
  src_aux = attr_unknown_get_aux(src) ;
  if (!(src->state & unks_sorted))
    attr_unknown_sort(src) ;

  /* Short circuit the process if is opt_trans and there are none.
   */
  if (opt_trans && !(src->state & unks_opt_trans))
    n = 0 ;             /* discard everything   */
  else
    n = vector_length(src_aux) ;

  /* Worry about the dst aux vector
   */
  if (dst == src)
    {
      /* src and dst are the same, so we are operating on the same aux
       * vector.
       */
      dst_aux = src_aux ;
    }
  else
    {
      /* src and dst are not the same.
       *
       * If there is a dst aux vector, then we will update it, so here we
       * ensure it has (at least) the required number of entries and is
       * empty.
       *
       * If is opt_trans, then we must have an aux vector, containing the
       * selected attributes.
       */
      dst_aux = dst->aux ;

      if ((dst_aux != NULL) || opt_trans)
        dst->aux = dst_aux = vector_re_init(dst_aux, n) ;
    } ;

  /* Scan the vector, filtering if 'opt_trans' and find what size stash we
   * need -- note that 'n' may be zero.
   */
  nn   = 0 ;
  need = 0 ;
  i    = 0 ;
  while (1)
    {
      uint len ;
      byte* p ;
      byte flags, type ;

      if (i >= n)
        break ;

      p = vector_get_item(src_aux, i++) ;

      flags = p[0] ;
      type  = p[1] ;

      if (opt_trans)
        {
          /* For opt_trans drop duplicates and filter for Optional-Transitive.
           */
          if ((src->state & unks_duplicate) && (i < n))
            {
              byte* q ;

              q = vector_get_item(src_aux, i) ;
              if (q[1] == type)
                {
                  while (1)
                    {
                      i += 1 ;
                      if (i >= n)
                        break ;

                      q = vector_get_item(src_aux, i) ;
                      if (q[1] != type)
                        break ;
                    } ;

                  continue ;
                } ;
            } ;

          if ( (flags & (BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE)) !=
                        (BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE) )
            continue ;

          vector_set_item(dst_aux, nn++, p) ;
        } ;

      /* Update the amount of space we need in the stash, and the number of
       * attributes.
       */
      if (flags & BGP_ATF_EXTENDED)
        len = load_ns(&p[2]) ;
      else
        len = p[2] ;

      need += 2 + (len > 255 ? 2 : 1) + len ;
    } ;

  /* On the basis of the scan, allocate a body for the stash.
   *
   * Also, set the state of the dst -- which is the same as the src, plus
   * unks_stashed, unless we are taking only the unique opt_trans.
   */
  if (need != 0)
    {
      body = XMALLOC(MTYPE_BGP_UNKNOWN_BODY, need) ;

      if (opt_trans)
        state = unks_sorted | unks_opt_trans ;
      else
        state = src->state ;
    }
  else
    {
      body  = NULL ;
      state = unks_sorted ;
    } ;

  dst->state = state | unks_stashed ;

  /* If is opt_trans, then we have collected the 'nn' attributes to be
   * extracted in the dst_aux.
   */
  if (opt_trans)
    {
      n = nn ;
      src_aux = dst_aux ;
    } ;

  /* Now copy the attributes to the stash -- note that 'n' and 'need' may be
   * zero, and dst->body may be NULL.
   */
  q = body ;
  e = body + need ;
  for (i = 0 ; i < n ; ++i)
    {
      byte flags, type ;
      uint len, nlen ;
      byte* p ;

      p = vector_get_item(src_aux, i) ;

      if (dst_aux != NULL)              /* can be same as src_aux !     */
        vector_set_item(dst_aux, i, q) ;

      flags = p[0] ;
      type  = p[1] ;

      if (flags & BGP_ATF_EXTENDED)
        {
          len = load_ns(&p[2]) ;
          p  += 4 ;
        }
      else
        {
          len = p[2] ;
          p  += 3 ;
        } ;

      nlen = 3 + (len > 255 ? 1 : 0) + len ;

      if (qcritical_failed((q + nlen) <= e))
        break ;

      flags &= ~(BGP_ATF_EXTENDED | BGP_ATF_ZERO) ;
      if (len > 255)
        flags |= BGP_ATF_EXTENDED ;

      if (opt_trans)
        flags |= BGP_ATF_PARTIAL ;

      *q++ = flags ;
      *q++ = type ;
      if (len > 255)
        {
          store_ns(q, len) ;
          q += 2 ;
        }
      else
        *q++ = len ;

      if (len != 0)
        memcpy(q, p, len) ;

      q += len ;
    } ;

  qcritical_failed(i == nn) ;
  qcritical_failed(q == e) ;

  if (dst->body != NULL)
    XFREE(MTYPE_BGP_UNKNOWN_BODY, dst->body) ;

  /* Set the stash.
   */
  dst->count = i ;
  dst->len   = (q - body) ;
  dst->body  = body ;
} ;

/*------------------------------------------------------------------------------
 * We want an aux vector.
 *
 * If the attr_unknown is NULL the aux vector is implicitly NULL.
 *
 * If we have an aux vector, then it must be up to date.
 *
 * Otherwise, if the attributes are stashed, we can (re)create the aux vector.
 *
 * Returns:  the current or rebuilt aux vector
 *           NB: may be NULL, which => no attributes (or NULL attr_unknown)
 */
static vector
attr_unknown_get_aux(attr_unknown unk)
{
  vector aux ;
  byte* p, * e ;

  if (unk == NULL)
    return NULL ;               /* no unknowns => no aux                */

  aux = unk->aux ;

  if (aux != NULL)
    return aux ;                /* use the existing aux                 */

  if (!(unk->state & unks_stashed))
    return aux ;                /* not stashed, so aux is what it is    */

  /* Attributes are stashed but have no aux vector, so we (re)fill it now.
   */
  unk->aux = aux = vector_re_init(aux, unk->count) ;    /* create or reset */

  p = unk->body ;
  e = p + unk->len ;

  while (p < e)
    {
      uint step ;

      if (p[0] & BGP_ATF_EXTENDED)
        {
          step = 4 ;

          if ((p + 4) <= e)
            step += load_ns(&p[2]) ;
        }
      else
        {
          step = 3 ;

          if ((p + 3) <= e)
            step += (uint)p[2] ;
        } ;

      if (qcritical_failed((p + step) <= e))
        break ;

      vector_push_item(aux, p) ;

      p += step ;
    } ;

  qcritical_failed(p == e) ;

  if (vector_length(aux) != unk->count)
    {
      zcritical("vector_length(aux) == unk->count") ;
      unk->count = vector_length(aux) ;
    } ;

  return aux ;
} ;

