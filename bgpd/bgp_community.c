/* Community attribute related functions.
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
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
#include "miyagi.h"

#include <ctype.h>

#include "bgpd/bgp.h"
#include "bgpd/bgp_community.h"

/*==============================================================================
 * Storing Community Attributes
 *
 * When storing an empty community returns NULL, so NB:
 *
 *   (a) do not distinguish empty from absent community objects.
 *
 *   (b) the canonical form of the empty community is a NULL one.
 *
 * Note that an "orphan" function is not required because there is only one
 * attr_community_vhash, which we set to NULL if/when the table is reset and
 * freed.
 */
vhash_table attr_community_vhash ;      /* extern in bgp_community.h    */

static vhash_hash_t attr_community_hash(vhash_data_c data) ;
static int          attr_community_vhash_equal(vhash_item_c item,
                                                            vhash_data_c data) ;
static vhash_item   attr_community_vhash_new(vhash_table table,
                                                          vhash_data_c data) ;
static vhash_item   attr_community_vhash_free(vhash_item item,
                                                            vhash_table table) ;

static const vhash_params_t attr_community_vhash_params =
{
    .hash       = attr_community_hash,
    .equal      = attr_community_vhash_equal,
    .new        = attr_community_vhash_new,
    .free       = attr_community_vhash_free,
    .orphan     = vhash_orphan_null,
    .table_free = vhash_table_free_parent,
} ;

/*------------------------------------------------------------------------------
 * The communities list in an attr_community is a qlump.
 */
static const qlump_type_t attr_community_list_qt[1] =
{
    { .alloc        = qlump_alloc,
      .free         = qlump_free,

      .unit         = sizeof(community_t),

      .size_add     = 8,
      .size_unit_m1 = 4 - 1,            /* 16 byte boundaries   */

      .size_min     = 16,               /* if have to allocate  */

      .size_min_unit_m1 = 1 - 1,        /*  4 byte boundaries   */

      .embedded_size   = community_list_embedded_size,
      .embedded_offset = qlump_embedded_offset(attr_community_t, list,
                                                               embedded_list),
      .size_term    = 0,
    }
} ;

/*------------------------------------------------------------------------------
 * The encoded community attribute is held as a qlump
 */
static const qlump_type_t attr_community_enc_qt[1] =
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
 * Start-up initialisation of the attr_community handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 */
extern void
attr_community_start(void)
{
  attr_community_vhash = vhash_table_new(&attr_community_vhash,
                                                1000 /* chain bases */,
                                                 200 /* % density   */,
                                                 &attr_community_vhash_params) ;

  qlump_register_type(MTYPE_COMMUNITY_VAL, attr_community_list_qt,
                                                       false /* not a test */) ;
  qlump_register_type(MTYPE_COMMUNITY_ENC, attr_community_enc_qt,
                                                       false /* not a test */) ;
} ;

/*------------------------------------------------------------------------------
 * Close down the attr_community handling
 *
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored communities.  That should be achieved naturally when all routes are
 * dismantled -- which should have been done before this is called.
 *
 * If any stored communities remain, they may be unlocked, but will not be
 * freed.
 */
extern void
attr_community_finish(void)
{
  attr_community_vhash = vhash_table_reset(attr_community_vhash) ;
} ;

/*------------------------------------------------------------------------------
 * Either store the given attr_community, or free it and return existing stored
 * value.
 *
 * Increment reference count on the returned stored attr_community.
 *
 * NB: returns NULL if the given community object is empty.
 */
extern attr_community
attr_community_store(attr_community new)
{
  attr_community comm ;
  bool added ;

  if (new == NULL)
    return NULL ;                       /* empty already                */

  qassert(!new->stored && (new->vhash.ref_count == 0)) ;

  /* Look out for empty
   */
  if (new->list.len == 0)
    return attr_community_free(new) ;   /* returns NULL                 */

  /* Store or find matching existing stored instance.
   */
  added = false ;
  comm  = vhash_lookup(attr_community_vhash, new, &added) ;

  if (added)
    {
      qassert(comm == new) ;

      qlump_store(&comm->list) ;        /* ensure at minimum size       */

      comm->stored = true ;
    }
  else
    {
      /* Found the same attr_community -- so discard the current "new" one.
       */
      qassert(comm->stored) ;

      attr_community_free(new) ;
    } ;

  vhash_inc_ref(comm) ;

  return comm ;
} ;

/*------------------------------------------------------------------------------
 * Generate hash for given attr_community 'data' -- vhash call-back
 *
 * For the attr_community vhash the 'data' is a new (not-stored) attr_community
 */
static vhash_hash_t
attr_community_hash(vhash_data_c data)
{
  attr_community_c new = data ;

  qassert(!new->stored) ;

  return vhash_hash_bytes(new->list.body.b,
                                          new->list.len * sizeof(community_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Is the 'item's 'data' the same as the given 'data' -- vhash call-back
 *
 * For the attr_community vhash: the 'item' is an attr_community, in the vhash
 *
 *                        the 'data' is a new (not-stored) attr_community
 */
static int
attr_community_vhash_equal(vhash_item_c item, vhash_data_c data)
{
  attr_community_c comm = item ;
  attr_community_c new  = data ;

  qassert(comm->stored && !new->stored) ;

  if (comm->list.len != new->list.len)
    return 1 ;

  return memcmp(comm->list.body.v, new->list.body.v,
                                         comm->list.len * sizeof(community_t)) ;
} ;

/*------------------------------------------------------------------------------
 * "Create" new item for attr_community vhash -- vhash call-back
 *
 * For the attr_community vhash: the 'data' is a new (not-stored)
 * attr_community, so this is trivial.
 */
static vhash_item
attr_community_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_community new = miyagi(data) ;

  qassert(!new->stored) ;

  return (vhash_item)new ;
} ;

/*------------------------------------------------------------------------------
 * Free item which is being removed from the vhash -- vhash call-back
 *
 * For the attr_community vhash: the 'item' is a stored attr_community
 *
 * Returns:  NULL <=> item freed
 */
static vhash_item
attr_community_vhash_free(vhash_item item, vhash_table table)
{
  attr_community comm = item ;

  qassert(comm->stored) ;

  comm->stored = false ;                /* no longer stored     */

  return attr_community_free(comm) ;
} ;

/*==============================================================================
 * The mechanics of handling the attr_community
 */
static attr_community attr_community_copy(attr_community comm) ;

/*------------------------------------------------------------------------------
 * Create a new, and empty (not-stored) attr_community.
 *
 * The canonical, stored form of an attr_community is NULL, but here we are
 * creating an attr_community to be filled in !
 *
 * Result is empty, but with enough space for at least 'n' communities, if
 * 'n' is not zero.
 */
extern attr_community
attr_community_new(uint n)
{
  attr_community new ;

  new = XCALLOC(MTYPE_COMMUNITY, sizeof(attr_community_t)) ;

  /* Zeroizing has set:
   *
   *    * vhash           -- initialised
   *
   *    * stored          -- false
   *
   *    * state           -- cms_null
   *
   *    * str             -- unset, embedded qstring
   *
   *    * enc             -- unset, embedded qlump
   *
   *    * list            -- X     -- unset qlump, initialised below
   *    * embedded_list   -- X     -- all zeros, but not relevant
   *
   *    * text_v          -- NULL  -- no vector
   *    * text_form       -- unset, embedded qstring
   */
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  confirm(cms_null == 0) ;
  confirm(QSTRING_UNSET_ALL_ZEROS) ;
  confirm(QLUMP_UNSET_ALL_ZEROS) ;

  qlump_init(&new->list, n, MTYPE_COMMUNITY_VAL) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Create a copy of the given attr_community
 *
 * If the given community is NULL or empty, returns NULL.
 *
 * Result is not 'stored'
 */
static attr_community
attr_community_copy(attr_community comm)
{
  attr_community new ;

  if ((comm == NULL) || (comm->list.len == 0))
    return NULL ;

  new = XMALLOC(MTYPE_COMMUNITY, sizeof(attr_community_t)) ;

  *new = *comm ;                                /* clone                */

  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  memset(&new->vhash, 0, sizeof(vhash_node_t)) ;
  new->stored = false ;

  new->state &= ~(cms_string | cms_encoded | cms_text) ;
  qs_init_new(new->str, 0) ;                    /* no string            */
  qlump_init(&new->enc, 0, MTYPE_AS_PATH_ENC) ; /* no encoding          */

  new->text_v   = NULL ;                        /* no text vector       */
  qs_init_new(new->text_form, 0) ;              /* no text form         */

  qlump_post_clone(&new->list) ;                /* fixup body of list   */

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Free given attr_community and any allocated body and other dependent data.
 *
 * Does nothing with NULL attr_community
 *
 * Returns:  NULL
 */
extern attr_community
attr_community_free(attr_community comm)
{
  if (comm != NULL)
    {
      qassert(comm->vhash.ref_count == 0) ;
      qassert(!comm->stored) ;

      qs_free_body(comm->str) ;
      qlump_free_body(&comm->enc) ;
      qlump_free_body(&comm->list) ;

      vector_free(comm->text_v) ;
      qs_free_body(comm->text_form) ;

      XFREE(MTYPE_COMMUNITY, comm) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function for qlump_sort_dedup() & qlump_bsearch()
 */
static int
attr_community_cmp(const void* a, const void* b)
{
  const community_t av = *(const community_t*)a ;
  const community_t bv = *(const community_t*)b ;

  if (av != bv)
    return (av < bv) ? -1 : +1 ;

  return 0 ;
} ;

/*==============================================================================
 * Community List Operations
 */

/*------------------------------------------------------------------------------
 * Create new attr_community from body of attribute
 *
 * Return:  address of new community attribute -- NULL if count == 0
 */
extern attr_community
attr_community_set(const byte* p, uint count)
{
  attr_community new ;
  community_t* list ;
  uint i ;

  if (count == 0)
    return NULL ;

  new = attr_community_new(count) ;

  new->list.len = count ;
  qassert(count <= new->list.size) ;

  list = new->list.body.v ;
  for (i = 0 ; i < count ; ++i)
    {
      community_t  val ;

      confirm(sizeof(community_t) == 4) ;
      val = load_nl(p) ;
      p += 4 ;

      list[i] = val ;
    } ;

  qlump_sort_dedup(&new->list, attr_community_cmp) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Prepare encoded BGP_ATT_COMMUNITIES for output
 *
 * Returns:  pointer to encoded attribute and sets p_len to length including
 *           the attribute red tape.
 *
 *        or NULL and sets p_len to zero, if the attr_community is NULL or
 *           empty
 */
extern byte*
attr_community_out_prepare(attr_community comm, uint* p_len)
{
  if ((comm == NULL) || (comm->list.len == 0))
    {
      *p_len = 0 ;
      return NULL ;
    }

  if (!(comm->state & cms_encoded))
    {
      community_t* list ;
      ulen len, enc_len ;
      byte* p ;
      uint i ;

      len = comm->list.len * 4 ;

      enc_len = len + ((len > 255) ? 4 : 3) ;
      if (enc_len > comm->enc.size)
        qlump_extend(&comm->enc, enc_len, MTYPE_COMMUNITY_ENC) ;

      comm->enc.len = enc_len ;
      p = comm->enc.body.v ;

      p[0] = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE
                              | ((len > 255) ? BGP_ATF_EXTENDED : 0) ;
      p[1] = BGP_ATT_COMMUNITIES ;

      if (len > 255)
        {
          store_ns(&p[2], len) ;
          p += 4 ;
        }
      else
        {
          p[2] = len ;
          p += 3 ;
        } ;

      list = comm->list.body.v ;
      for (i = 0 ; i < comm->list.len ; ++i)
        {
          store_nl(p, list[i]) ;
          p += 4 ;
        } ;

      comm->state |= cms_encoded ;
    } ;

  *p_len = comm->enc.len ;
  return comm->enc.body.v ;
} ;

/*------------------------------------------------------------------------------
 * Add comm_b to comm_a
 *
 * If comm_b is NULL or empty, no change is made to comm_a.
 *
 * If comm_a is NULL, returns a copy of comm_b.
 *
 * If comm_a is stored, make a new attr_community.
 *
 * So, if comm_a is not stored, will return that, updated as required.
 *
 * Returns:  original comm_a (may be NULL) or new attr_community
 *
 * We know both community lists are sorted and deduped -- so can run one
 * against the other.
 */
extern attr_community
attr_community_add_list (attr_community comm_a, attr_community comm_b)
{
  attr_community dst ;
  community_t* a, * b, * n ;
  uint ia, ib, la , lb, in ;

  /* Is there anything to do, at all at all.
   */
  if ((comm_b == NULL) || (comm_b->list.len == 0))
    return comm_a ;

  if (comm_a == NULL)
    return attr_community_copy(comm_b) ;

  /* If comm_a is stored, make a brand new comm_a, big enough for everything
   * in both.  Point dst at the new attr_community, and n at the new body.
   *
   * If comm_a is not stored, blow a bubble at the front big enough for
   * contents of comm_b.  Point dst at comm_a, and n at the resulting body.
   *
   * At this point we know that neither is NULL and comm_b is not empty, so the
   * result cannot be NULL or empty !
   */
  ib = 0 ;
  lb = comm_b->list.len ;
  b  = comm_b->list.body.v ;

  ia = 0 ;
  la = comm_a->list.len ;

  if (comm_a->stored)
    {
      dst = attr_community_new(la + lb) ;

      a = comm_a->list.body.v ;
      n = dst->list.body.v ;
    }
  else
    {
      a = qlump_add_space(&comm_a->list, 0, lb) ;

      ia  = lb ;        /* first item after the bubble  */
      la += lb ;        /* new length of comm_a         */

      qassert(la == comm_a->list.len) ;

      dst = comm_a ;
      n   = a ;
    } ;

  /* Now, merge a[ia] with b[ib] and write to n[in]
   */
  in = 0 ;
  while ((ia < la) && (ib < lb))
    {
      community_t va, vb ;

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
    n[in++] = a[ia++] ;         /* copy balance of comm_a       */
  while (ib < lb)
    n[in++] = b[ib++] ;         /* copy balance of comm_b       */

  qassert(in <= dst->list.size) ;

  dst->list.len = in ;
  dst->state = cms_null ;       /* all change                   */

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Replace contents of comm_a by the contents of comm_b
 *
 * If comm_b is NULL or empty -> attr_community_clear(comm_a) -- will give
 * NULL if comm_a is NULL or stored.
 *
 * If comm_b is 'stored', return that.  NB: it is the caller's responsibility
 * to lock comm_b if required.
 *
 * If comm_a is 'stored' or NULL, create a copy of comm_b.
 * Otherwise, update comm_a.
 *
 * So, if comm_a is not stored, will return that, updated as required.
 *
 * Returns:  original comm_b (may be NULL), or the original comm_a,
 *           or a new attr_community
 */
extern attr_community
attr_community_replace_list (attr_community comm_a, attr_community comm_b)
{
  community_t* a, * b ;

  if ((comm_b == NULL) || (comm_b->list.len == 0))
    return attr_community_clear(comm_a) ;

  if (comm_b->stored)
    return comm_b ;

  if ((comm_a == NULL) || comm_a->stored)
    return attr_community_copy(comm_b) ;

  /* We have a not-stored and not-NULL comm_a and a not-stored, not-empty and
   * not-NULL comm_b
   *
   * Empty out comm_a and copy contents of comm_b to it.
   */
  comm_a->list.len = 0 ;

  a = qlump_add_space(&comm_a->list, 0, comm_b->list.len) ;
  b = comm_b->list.body.v ;

  memcpy(a, b, comm_b->list.len * sizeof(community_t)) ;

  comm_a->state = comm_b->state & (cms_known | cms_no_export
                                             | cms_no_advertise
                                             | cms_local_as) ;
  return comm_a ;
} ;

/*------------------------------------------------------------------------------
 * Delete one community, if it is present.
 *
 * Do nothing with NULL attr_community
 *
 * If the community is present, creates a new attr_community if the given comm
 * is 'stored'.  Otherwise, updates the given comm.
 *
 * Returns:  original comm (may be NULL) or new attr_community
 */
extern attr_community
attr_community_del_value(attr_community comm, community_t val)
{
  if (comm != NULL)
    {
      uint ic ;
      int  result ;

      ic = qlump_bsearch(&comm->list, attr_community_cmp, &val, &result) ;

      if (result == 0)
        comm = attr_community_drop_value(comm, ic) ;
    } ;

  return comm ;
} ;

/*------------------------------------------------------------------------------
 * Drop the 'i'th community value from the given attr_community.
 *
 * Creates a new attr_community if the given comm is 'stored'.  Otherwise,
 * updates the given comm.
 *
 * If creates a new attr_community, then the old one is (obviously) untouched.
 * In particular, any text_v remains valid.
 *
 * If does not create a new attr_community, then clears the state down to
 * cms_null, but does NOT change any existing 'str', 'enc' or 'text_v' etc.
 * In particular, any text_v remains valid for the *previous* state of the
 * attr_community.
 *
 * Returns:  original comm or new attr_community
 */
extern attr_community
attr_community_drop_value(attr_community comm, uint ic)
{
  if (comm != NULL)             /* for completeness     */
    {
      if (comm->stored)
        comm = attr_community_copy(comm) ;

      qlump_drop_items(&comm->list, ic, 1) ;
      comm->state = cms_null ;
    } ;

  return comm ;
} ;

/*------------------------------------------------------------------------------
 * Delete all communities listed in comm_b from comm_a
 *
 * If comm_b is NULL or empty, no change is made to comm_a.
 *
 * If comm_a is NULL or empty, no change is made to comm_a.
 *
 * Otherwise, if finds a value to delete, and comm_a is stored, will create
 * a new comm_a before deleting the value.  (It is possible that the result
 * will be a new, empty attr_community.)
 *
 * Returns:  original comm_a (may be NULL) or new attr_community
 *
 * We know both community lists are sorted and deduped -- so can run one
 * against the other.
 */
extern attr_community
attr_community_del_list (attr_community comm_a, attr_community comm_b)
{
  attr_community dst ;
  community_t* a, * b, * n ;
  uint ia, ib, la , lb, in ;
  bool drop ;

  /* Is there anything to do, at all at all.
   */
  if ((comm_b == NULL) || (comm_b->list.len == 0))
    return comm_a ;

  if ((comm_a == NULL) || (comm_a->list.len == 0))
    return comm_a ;

  /* Run comm_b against comm_a.  If find something to delete, then worry about
   * the state of comm_a, and create new community if required.
   *
   * Note that at this point neither comm_a nor comm_b are empty, but it is
   * possible that the final result will be.
   */
  dst = comm_a ;                /* may change if deletes something      */

  a  = comm_a->list.body.v ;
  ia = 0 ;
  la = comm_a->list.len ;

  b  = comm_b->list.body.v ;
  ib = 0 ;
  lb = comm_b->list.len ;

  drop = false ;                /* no change, yet                       */
  in = 0 ;
  n  = NULL ;

  while ((ia < la) && (ib < lb))
    {
      community_t va, vb ;

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
           * If comm_a is stored, do the simple thing and make a complete
           * copy.  In fact, need only copy (ia - 1) items, but does not seem
           * worth worrying about that.
           */
          if (comm_a->stored)
            dst = attr_community_copy(comm_a) ;

          n  = dst->list.body.v ;
          in = ia - 1 ;

          drop = true ;
        }
    } ;

 done:
   if (drop)
     {
       while (ia < la)
         n[in++] = a[ia++] ;    /* copy balance of comm_a       */

       dst->list.len = in ;
       dst->state = cms_null ;
     } ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Clear the given attr_community
 *
 * Returns:  NULL if given community is stored or NULL
 *           the original community, updated (set empty)
 */
extern attr_community
attr_community_clear (attr_community comm)
{
  if ((comm == NULL) || (comm->stored))
    return NULL ;

  comm->list.len = 0 ;
  comm->state    = cms_null ;

  return comm ;
} ;

/*------------------------------------------------------------------------------
 * Get the state of any well-known communities
 *
 * Returns:  some combination of: cms_no_export, cms_no_advertise & cms_local_as
 */
extern attr_community_state_t
attr_community_known (attr_community comm)
{
  attr_community_state_t state, known ;

  if (comm == NULL)
    return 0 ;

  state = comm->state ;
  known = state & (cms_no_export | cms_no_advertise | cms_local_as) ;

  if (!(state & cms_known))
    {
      community_t* list ;
      uint i ;

      state ^= known ;                  /* make sure    */
      known  = 0 ;

      list = comm->list.body.v ;
      i    = comm->list.len ;
      while (i > 0)
        {
          community_t val ;

          val = list[--i] ;

          if (val < BGP_ATT_COM_KNOWN_FIRST)
            break ;

          switch (val)
            {
              case BGP_ATT_COM_NO_EXPORT:
                known |= cms_no_export ;
                break ;

              case BGP_ATT_COM_NO_ADVERTISE:
                known |= cms_no_advertise ;
                break ;

              case BGP_ATT_COM_LOCAL_AS:
                known |= cms_local_as ;
                break ;

              default:
                break ;
            } ;
        } ;

      comm->state = state | cms_known | known ;
    } ;

  return known ;
} ;

/*------------------------------------------------------------------------------
 * Does comm_a match comm_b ?
 *
 * For there to be a match, comm_a must include all elements of comm_b,
 * but may include others.  An empty comm_b always matches.
 *
 * It does not matter whether comm_a or comm_b is 'stored' or not.
 *
 * Treats a NULL atr_community as empty.
 *
 * We know both community lists are sorted and deduped -- so can run one
 * against the other.
 */
extern bool
attr_community_match (attr_community_c comm_a, attr_community_c comm_b)
{
  community_t* a, * b ;
  uint ia, ib, la , lb ;

  if ((comm_b == NULL) || ((lb = comm_b->list.len) == 0))
    return true ;       /* empty (or NULL) comm_b always matches        */

  if ((comm_a == NULL) || ((la = comm_a->list.len) < lb))
    return false ;      /* if comm_a has fewer entries, cannot match    */

  qassert((0 < lb) && (lb <= la)) ;

  a  = comm_a->list.body.v ;
  ia = 0 ;
  b  = comm_b->list.body.v ;
  ib = 0 ;
  while (1)
    {
      community_t va, vb ;

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
 * Are comm_a and comm_b equal ?
 *
 * For equality the two communities must have the same number of values, and
 * they must be the same values.
 *
 * It does not matter whether comm_a or comm_b is 'stored' or not.
 *
 * Treats a NULL attr_community as empty.
 *
 * We know both community lists are sorted and deduped -- so can run one
 * against the other.
 */
extern bool
attr_community_equal(attr_community_c comm_a, attr_community_c comm_b)
{
  community_t* a, * b ;
  uint la , lb ;

  la = (comm_a != NULL) ? comm_a->list.len : 0 ;
  lb = (comm_b != NULL) ? comm_b->list.len : 0 ;

  if (la != lb)
    return false ;

  if (la == 0)
    return true ;

  a = comm_a->list.body.v ;
  b = comm_b->list.body.v ;

  return (memcmp(a, b, la * sizeof(community_t)) == 0) ;
} ;

/*==============================================================================
 * String mechanics
 */
enum community_token
{
  community_token_end,

  community_token_val,
  community_token_no_export,
  community_token_no_advertise,
  community_token_local_as,

  community_token_none,
  community_token_additive,
  community_token_internet,
  community_token_any,

  community_token_unknown
} ;
typedef enum community_token community_token_t ;

static void attr_community_to_str(attr_community comm) ;
static community_t attr_community_gettoken (const char* p,
                                              community_token_t *token,
                                                             const char** p_e) ;

/*------------------------------------------------------------------------------
 * Return string representation of communities attribute.
 *
 * Create it if required.
 *
 * Returns "" for NULL community object.
 *
 * For well-known communities produces:
 *
 *    0xFFFFFF01      "no-export"
 *    0xFFFFFF02      "no-advertise"
 *    0xFFFFFF03      "local-AS"
 *
 * For all other values, "AS:VAL" format is used.
 */
extern const char*
attr_community_str (attr_community comm)
{
  if ((comm == NULL) || (comm->list.len == 0))
    return "" ;

  if ((comm->state & cms_string) == 0)
    attr_community_to_str(comm) ;

  return qs_char_nn(comm->str) ;
} ;

/*------------------------------------------------------------------------------
 * Convert string to community structure -- treats NULL string as empty string.
 *
 * Returns:  new attr_community if OK and sets 'p_act' as below.
 *           NULL if was an invalid string, or is empty.
 *
 * Will accept:
 *
 *   * any non-empty sequence of community values  -- sets 'act_simple'
 *
 *   * 'additive' -- if it is the last token and not the only token
 *                                                 -- sets 'act_additive'
 *                                                    returns attr_community
 *
 *   * 'none'     -- if it is the only token       -- sets 'act_none'
 *                                                    returns NULL
 *
 *   * 'internet' -- if it is the only token       -- sets 'act_internet'
 *                                                    returns NULL
 *
 *   * 'any'      -- if it is the only token       -- sets 'act_any'
 *                                                    returns NULL
 *
 *   * empty string                                -- sets 'act_empty'
 *                                                    returns NULL
 */
extern attr_community
attr_community_from_str (const char *str, attr_community_type_t* p_act)
{
  attr_community new ;
  community_t* list ;
  uint len ;
  attr_community_type_t act ;
  enum community_token token ;

  new = attr_community_new(1) ;         /* expect at least 1    */

  act = act_empty ;                     /* so far               */

  if (str == NULL)
    str = "" ;

  list = new->list.body.v ;
  len  = 0 ;
  do
    {
      community_t val ;

      val = attr_community_gettoken (str, &token, &str);

      switch (token)
        {
          case community_token_val:
          case community_token_no_export:
          case community_token_no_advertise:
          case community_token_local_as:
            if (act != act_simple)
              {
                if (act == act_empty)
                  act = act_simple ;
                else
                  goto invalid ;
              } ;

            if (len >= new->list.size)
              list = qlump_extend(&new->list, len + 1, MTYPE_COMMUNITY_VAL) ;

            list[len++] = val ;
            break;

          case community_token_none:
            if (act != act_empty)
              goto invalid ;

            act = act_none ;
            break ;

          case community_token_additive:
            if (act != act_simple)
              goto invalid ;

            act = act_additive ;
            break ;

          case community_token_internet:
            if (act != act_empty)
              goto invalid ;

            act = act_internet ;
            break ;

          case community_token_any:
            if (act != act_empty)
              goto invalid ;

            act = act_any ;
            break ;

          case community_token_end:
            break ;

          case community_token_unknown:
          default:
            goto invalid ;
        } ;
    }
  while (token != community_token_end) ;

  qassert(len <= new->list.size) ;

  if (len > 0)
    {
      new->list.len = len ;
      qlump_sort_dedup(&new->list, attr_community_cmp) ;
    }
  else
    new = attr_community_free(new) ;

  *p_act = act ;
  return new ;

 invalid:
  *p_act = act_invalid ;
  return attr_community_free(new) ;
} ;

/*------------------------------------------------------------------------------
 * Fill comm->str with string for the current list.
 *
 * Sets cms_string.
 */
static void
attr_community_to_str(attr_community comm)
{
  community_t* list ;
  uint i, l ;

  comm->state |= cms_string ;           /* when we have done the work   */

  l = comm->list.len ;

  /* If the community is empty, set the qstring to an alias empty
   * string -- to minimise footprint !
   */
  if (l == 0)
    {
      qs_set_alias_str(comm->str, "") ;
      return ;
    }

  /* We have a big guess at the length of string required.
   *
   * 12 characters per community covers the worst case of " 65535:65535"
   * and also (coincidentally) "no-advertise".  If "no-advertise" appears on
   * its own, that's fine.  If it appears with anything else, the budget of
   * 12 characters for the others includes the space separator !
   */
  confirm(sizeof(" 65535:65535") == (12 + 1)) ;
  confirm(sizeof("no-advertise") == (12 + 1)) ;

  qs_new_size(comm->str, l * 12) ;      /* sets len = 0         */

  /* Crunch the communities.
   */
  list = comm->list.body.v ;

  for (i = 0 ; i < l ; ++i)
    {
      community_t val ;
      char  buf[16] ;
      const char* p ;
      char* e, * q ;
      uint  n ;

/* Set p to given string, with a leading " ".
 * and n to the length of that (including the leading " ").
 */
#define community_name(str) p = " "str ; n = sizeof(str) ;

      switch ((val = list[i]))
        {
#if 0
          case 0:
            community_name("internet") ;
            break;
#endif
          case BGP_ATT_COM_NO_EXPORT:
            community_name("no-export") ;
            break;

          case BGP_ATT_COM_NO_ADVERTISE:
            community_name("no-advertise") ;
            break;

          case BGP_ATT_COM_LOCAL_AS:
            community_name("local-AS") ;
            break;

          default:
            e = buf + sizeof(buf) ;

            q = utostr(e, val & 0xFFFF, 10, false /* not uc */) ;
            *(--q) = ':' ;
            q = utostr(q, (val >> 16) & 0xFFFF, 10, false /* not uc */) ;
            *(--q) = ' ' ;

            p = q ;
            n = e - q ;
            break;
        } ;

      if (i == 0)
        {
          p += 1 ;              /* discard the leading " "      */
          n -= 1 ;
        } ;

      qs_append_n(comm->str, p, n) ;
    } ;

  qs_string(comm->str) ;        /* make sure terminated */
} ;

/*------------------------------------------------------------------------------
 * Get next community token from string.
 *
 * Tokens separated by whitespace and string terminated by '\0'.
 *
 * Accepts:  "no-export"     )
 *           "no-advertise"  )
 *           "local-AS"      ) community values
 *           0..UINT32_MAX   )
 *           65535:65535     )
 *
 *           "additive"      )
 *           "any"           ) other keywords
 *           "internet"      )
 *           "none"          )
 *
 * Where the token is not numeric, accepts string which uniquely matches
 * leading characters of one of the words above -- ignoring case.
 *
 * Sets: *token  to the token found
 *       *p_e    address of separator/terminator -- or start of unknown token
 *
 * Returns: value -- if not community_token_end or community_token_unknown
 */
static community_t
attr_community_gettoken (const char* p, enum community_token *token,
                                                               const char** p_e)
{
  /* Skip leading white space.
   */
  while (isspace ((int) *p))
    p++;

  /* Check the end of the line.
   */
  if (*p == '\0')
    {
      *token = community_token_end ;
      *p_e   = p ;
      return 0;
    } ;

  /* Well known community string check.
   */
  struct community_word
    {
      const char*       word ;
      community_token_t token ;
      community_t       val ;
    } ;

  static const struct community_word words[] =
    {
      { .word = "additive",      .token = community_token_additive       },
      { .word = "any",           .token = community_token_any            },
      { .word = "internet",      .token = community_token_internet       },
      { .word = "local-as",      .token = community_token_local_as,
                                 .val   = BGP_ATT_COM_LOCAL_AS           },
      { .word = "no-advertise",  .token = community_token_no_advertise,
                                 .val   = BGP_ATT_COM_NO_ADVERTISE       },
      { .word = "no-export",     .token = community_token_no_export,
                                 .val   = BGP_ATT_COM_NO_EXPORT          },
      { .word = "none",          .token = community_token_none           }
    } ;

  if (isalpha ((int) *p))
    {
      char  tb[32] ;    /* no valid word is anything like this long     */
      uint  tl ;
      const char* e ;
      const struct community_word* pw ;
      const struct community_word* found ;
      const char* w ;

      e  = p ;
      tl = 0 ;
      while (!isspace((int)*e) && (*e != '\0'))
        {
          if (tl < sizeof(tb))
            tb[tl++] = tolower(*e++) ;
          else
            goto bad ;          /* cannot possibly be valid     */
        } ;

      found = NULL ;
      pw = words ;
      while ((w = pw->word) != NULL)
        {
          if (strncmp(tb, w, tl) == 0)
            {
              /* Found at least a partial match
               */
              if (found != NULL)
                goto bad ;              /* second match is bad          */

              found = pw ;

              if (w[tl] == '\0')
                break ;                 /* stop on complete match       */
            } ;

          ++pw ;
        } ;

      if (found == NULL)
        goto bad ;

      *p_e = e ;

      *token = found->token ;
      return found->val ;
    } ;

  /* Community value: 0..UINT32_MAX or 65535:65535
   */
  if (isdigit ((int) *p))
    {
      community_t val ;
      strtox_t    tox ;
      const char* e ;

      val = strtoul_xr(p, &tox, &e, 0, UINT32_MAX) ;

      if (tox != strtox_ok)
        goto bad ;

      if (*e == ':')
        {
          if (val > 65535)
            goto bad ;

          val = (val << 16) + strtoul_xr(e + 1, &tox, &e, 0, 65535) ;

          if (tox != strtox_ok)
            goto bad ;
        } ;

      if (isspace((int)*e) || (*e == '\0'))
        {
          *token = community_token_val;
          *p_e   = e ;
          return val ;
        } ;
    }

 bad:
  *token = community_token_unknown ;
  *p_e   = p ;

  return 0;
}

/*==============================================================================
 * Text form mechanics.
 *
 * Text form is a vector of pointers into a qstring, where the qstring is a
 * copy of the comm->str, with '\0' replacing the space separators.  So each
 * pointer in the vector refers to the text form of a community.
 */

/*------------------------------------------------------------------------------
 * Get text vector for given attr_community.
 *
 * The text_v contains pointers to the text form of each community value.
 *
 * Returns:  vector -- may be NULL if the attr_community is empty
 *                     (but may also return an empty vector).
 */
extern vector
attr_community_text_vector(attr_community comm)
{
  if (comm == NULL)
    return NULL ;

  if (!(comm->state & cms_text))
    {
      comm->text_v = vector_clear(comm->text_v, comm->list.len) ;

      if (comm->list.len != 0)
        {
          const char* p ;

          /* Construct string form (if required).  Copy that to the text_form,
           * and reduce that to "words", setting 'cp' so can fetch same.
           */
          attr_community_str(comm) ;
          qs_set(comm->text_form, comm->str) ;
          qs_reduce(comm->text_form, " ", "") ;

          /* Set text_v to point at each of the "words".
           */
          while ((p = qs_next_word(comm->text_form)) != NULL)
            vector_push_item(comm->text_v, miyagi(p)) ;

          qassert(vector_length(comm->text_v) == comm->list.len) ;
        } ;

      comm->state |= cms_text ;
    } ;

  return comm->text_v ;
} ;

/*==============================================================================
 * Printing functions
 */

/*------------------------------------------------------------------------------
 * Function to compare community objects by comparison of their string forms.
 */
static int
attr_community_sort_cmp(const vhash_item_c* a, const vhash_item_c* b)
{
  attr_community  comm_a = miyagi(*a) ;
  attr_community  comm_b = miyagi(*b) ;

  const char* str_a ;
  const char* str_b ;

  str_a = attr_community_str(comm_a) ;
  str_b = attr_community_str(comm_b) ;

  return strcmp(str_a, str_b) ;
} ;

/*------------------------------------------------------------------------------
 * Print all stored community attributes and hash information.
 */
extern void
attr_community_print_all_vty (struct vty *vty)
{
  vector extract ;
  uint i ;

  extract = vhash_table_extract(attr_community_vhash, NULL, NULL,
                                     true /* most */, attr_community_sort_cmp) ;

              /* 1234567890_12345678_12........*/
  vty_out (vty, "Hash       Refcnt   Communities\n");

  for (i = 0 ; i < vector_length(extract) ; ++i)
    {
      attr_community  comm ;

      comm = vector_get_item(extract, i) ;

      vty_out (vty, "[%8x] (%6u) %s\n", comm->vhash.hash, comm->vhash.ref_count,
                                                     attr_community_str(comm)) ;
    } ;

  vector_free(extract) ;
}

