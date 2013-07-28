/* BGP Cluster Attribute handling
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
#include "miyagi.h"
#include "memory.h"
#include "vhash.h"

#include "qstring.h"

#include "bgpd/bgp.h"
#include "bgpd/bgp_cluster.h"

/*==============================================================================
 * Storing Cluster Attributes
 *
 * When storing an empty cluster returns NULL, so NB:
 *
 *   (a) do not distinguish empty from absent cluster objects.
 *
 *   (b) the canonical form of the empty cluster is a NULL one.
 *
 * Note that an "orphan" function is not required because there is only one
 * attr_cluster_vhash, which we set to NULL if/when the table is reset and
 * freed.
 */
vhash_table attr_cluster_vhash ;        /* extern in bgp_cluster.h      */

static vhash_hash_t attr_cluster_hash(vhash_data_c data) ;
static int          attr_cluster_equal(vhash_item_c item, vhash_data_c data) ;
static vhash_item   attr_cluster_vhash_new(vhash_table table,
                                                          vhash_data_c data) ;
static vhash_item   attr_cluster_vhash_free(vhash_item item,
                                                            vhash_table table) ;

static const vhash_params_t attr_cluster_vhash_params =
{
    .hash   = attr_cluster_hash,
    .equal  = attr_cluster_equal,
    .new    = attr_cluster_vhash_new,
    .free   = attr_cluster_vhash_free,
    .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * The cluster list in an attr_cluster is a qlump.
 */
static const qlump_type_t attr_cluster_list_qt[1] =
{
    { .alloc        = qlump_alloc,
      .free         = qlump_free,

      .unit         = sizeof(cluster_id_t),

      .size_add     = 8,
      .size_unit_m1 = 4 - 1,            /* 16 byte boundaries   */

      .size_min     = 16,               /* if have to allocate  */

      .size_min_unit_m1 = 1 - 1,        /*  4 byte boundaries   */

      .embedded_size   = cluster_list_embedded_size,
      .embedded_offset = qlump_embedded_offset(attr_cluster_t, list,
                                                               embedded_list),
      .size_term    = 0,
    }
} ;

/*------------------------------------------------------------------------------
 * Start-up initialisation of the attr_cluster handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 */
extern void
attr_cluster_start(void)
{
  attr_cluster_vhash = vhash_table_new(NULL, 1000 /* chain bases */,
                                             200 /* % density   */,
                                                   &attr_cluster_vhash_params) ;
  qlump_register_type(MTYPE_CLUSTER_VAL, attr_cluster_list_qt,
                                                       false /* not a test */) ;
} ;

/*------------------------------------------------------------------------------
 * Close down the attr_cluster handling
 *
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored cluster lists.  That should be achieved naturally when all routes are
 * dismantled -- which should have been done before this is called.
 *
 * If any stored cluster lists remain, they may be unlocked, but will not be
 * freed.
 */
extern void
attr_cluster_finish(void)
{
  attr_cluster_vhash = vhash_table_reset(attr_cluster_vhash, free_it) ;
} ;

/*------------------------------------------------------------------------------
 * Either store the given attr_cluster, or free it and return existing stored
 * value.
 *
 * A NULL attr_cluster is an empty attr_cluster.
 *
 * Increment reference count on the returned stored attr_cluster.
 *
 * NB: returns NULL if the given cluster object is empty (or NULL).
 */
extern attr_cluster
attr_cluster_store(attr_cluster new)
{
  attr_cluster clust ;
  bool added ;

  if (new == NULL)
    return NULL ;                       /* empty already                */

  qassert(!new->stored && (new->vhash.ref_count == 0)) ;

  /* Look out for empty
   */
  if (new->list.len == 0)
    return attr_cluster_free(new) ;     /* returns NULL                 */

  /* Store or find matching existing stored instance.
   */
  added = false ;
  clust = vhash_lookup(attr_cluster_vhash, new, &added) ;

  if (added)
    {
      qassert(clust == new) ;

      qlump_store(&clust->list) ;       /* ensure at minimum size       */

      clust->stored = true ;
    }
  else
    {
      /* Found the same attr_cluster -- so discard the current "new" one.
       */
      qassert(clust->stored) ;

      attr_cluster_free(new) ;
    } ;

  vhash_inc_ref(clust) ;

  return clust ;
} ;

/*------------------------------------------------------------------------------
 * Generate hash for given attr_cluster 'data' -- vhash call-back
 *
 * For the attr_cluster vhash the 'data' is a new (not-stored) attr_cluster
 */
static vhash_hash_t
attr_cluster_hash(vhash_data_c data)
{
  attr_cluster_c new = data ;

  qassert(!new->stored) ;

  return vhash_hash_bytes(new->list.body.b,
                                        new->list.len * sizeof(cluster_id_t)) ;
} ;

/*------------------------------------------------------------------------------
 * Is the 'item's 'data' the same as the given 'data' -- vhash call-back
 *
 * For the attr_cluster vhash: the 'item' is an attr_cluster, in the vhash
 *                             the 'data' is a new (not-stored) attr_cluster
 */
static int
attr_cluster_equal(vhash_item_c item, vhash_data_c data)
{
  attr_cluster_c clust = item ;
  attr_cluster_c new   = data ;

  qassert(clust->stored && !new->stored) ;

  if (clust->list.len != new->list.len)
    return 1 ;

  if (clust->list.len == 0)
    return 0 ;

  return memcmp(clust->list.body.v, new->list.body.v,
                                           new->list.len * sizeof(cluster_id_t)) ;
} ;

/*------------------------------------------------------------------------------
 * "Create" new item for attr_cluster vhash -- vhash call-back
 *
 * For the attr_cluster vhash: the 'data' is a new (not-stored) attr_cluster,
 * so this is trivial.
 */
static vhash_item
attr_cluster_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_cluster new = miyagi(data) ;

  qassert(!new->stored) ;

  return (vhash_item)new ;
} ;

/*------------------------------------------------------------------------------
 * Free item which is being removed from the vhash -- vhash call-back
 *
 * For the attr_cluster vhash: the 'item' is a stored attr_cluster
 *
 * Returns:  NULL <=> item freed
 */
static vhash_item
attr_cluster_vhash_free(vhash_item item, vhash_table table)
{
  attr_cluster clust = item ;

  qassert(clust->stored) ;

  clust->stored = false ;                 /* no longer stored     */

  return attr_cluster_free(clust) ;
} ;

/*==============================================================================
 * The mechanics of handling the attr_cluster
 */

/*------------------------------------------------------------------------------
 * Create a new, and empty attr_cluster.
 *
 * The canonical, stored form of an attr_cluster is NULL, but here we are
 * creating an attr_cluster to be filled in !
 *
 * Result is empty, but with enough space for at least 'n' cluster-id, if
 * 'n' is not zero.
 */
extern attr_cluster
attr_cluster_new(uint n)
{
  attr_cluster new ;

  new = XCALLOC(MTYPE_CLUSTER, sizeof(attr_cluster_t)) ;

  /* Zeroizing has set:
   *
   *    * vhash           -- initialised
   *
   *    * stored          -- false
   *
   *    * state           -- clst_null
   *
   *    * str             -- unset, embedded qstring
   *
   *    * originator      -- X     -- all zeros, but not relevant
   *
   *    * list            -- X     -- unset qlump, initialised below
   *    * embedded_list   -- X     -- all zeros, but not relevant
   */
  confirm(VHASH_NODE_INIT_ALL_ZEROS) ;
  confirm(clst_null == 0) ;
  confirm(QSTRING_UNSET_ALL_ZEROS) ;

  qlump_init(&new->list, n, MTYPE_CLUSTER_VAL) ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Free given attr_cluster and any allocated body and other dependent data.
 *
 * Returns:  NULL
 */
extern attr_cluster
attr_cluster_free(attr_cluster clust)
{
  if (clust != NULL)
    {
      qassert(clust->vhash.ref_count == 0) ;    /* always               */
      qassert(!clust->stored) ;                 /* always               */

      qs_free_body(clust->str) ;
      qlump_free_body(&clust->list) ;

      XFREE(MTYPE_CLUSTER, clust) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set a new attr_cluster from the body of a CLUSTER_LIST attribute
 *
 * Takes pointer to body of attribute, and count of the number of cluster-ids.
 * The caller guarantees that there are that many ids to be read.
 *
 * If the given count is zero, return NULL.
 *
 * If the given count is not zero: make a new not-stored cluster.
 *
 * Returns:  address of new cluster, if count != 0
 *           or NULL, if count == 0
 *
 * NB: the cluster_id's remain in Network Order.
 */
extern attr_cluster
attr_cluster_set(const byte* p, uint count)
{
  attr_cluster clust ;

  if (count == 0)
    return NULL ;

  clust = attr_cluster_new(count) ;
  clust->list.len = count ;
  memcpy(clust->list.body.v, p, count * sizeof(cluster_id_t)) ;

  return clust ;
} ;

/*------------------------------------------------------------------------------
 * Prepare encoded BGP_ATT_CLUSTER_LIST for output
 *
 * A NULL attr_cluster is an empty attr_cluster.
 *
 * Expects given 'out' structure to contain a cluster_id to prepend to the
 * given cluster list.
 *
 * Fills in:  len[0] and part[0] to be the attribute header and the
 *                               prepended cluster-id -- uses the
 */
extern void
attr_cluster_out_prepare(attr_cluster_out out, attr_cluster clust)
{
  uint  len ;
  byte* p ;
  byte  flags ;

  /* Worry about whether we have any cluster attribute stuff, and if so,
   * what the tail end of the CLUSTER_LIST will be.
   */
  if ((clust != NULL) && (clust->list.len != 0))
    {
      len = clust->list.len * 4 ;
      out->part[1] = clust->list.body.v ;
    }
  else
    {
      len = 0 ;
      out->part[1] = NULL ;
    } ;

  out->len[1] = len ;

  /* Prepare the leading part of the CLUSTER_LIST attribute
   */
  len += 4 ;                            /* account for prepend          */
  flags = BGP_ATF_OPTIONAL ;

  if (len > 255)
    {
      p = ((byte*)&out->cluster_id) - 4 ;

      flags |= BGP_ATF_EXTENDED ;
      store_ns(&p[2], len) ;

      out->len[0] = 8 ;
    }
  else
    {
      p = ((byte*)&out->cluster_id) - 3 ;

      p[2] = len ;

      out->len[0] = 7 ;
    } ;

  out->part[0] = p ;

  p[0] = flags ;
  p[1] = BGP_ATT_CLUSTER_LIST ;
} ;

/*------------------------------------------------------------------------------
 * If there is an CLUSTER_LIST, is it the given CLUSTER_ID in it ?
 *
 * A NULL attr_cluster is an empty attr_cluster.
 *
 * Returns:  true <=> given id does NOT appear in the CLUSTER_LIST (if any)
 */
extern bool
attr_cluster_check(attr_cluster clust, cluster_id_t id)
{
  if (clust != NULL)
    {
      cluster_id_t* list ;
      uint i ;

      list = clust->list.body.v ;

      for (i = 0 ; i < clust->list.len ; ++i)
        if (list[i] == id)
          return false ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * If there is an CLUSTER_LIST, how long is it ?
 *
 * A NULL attr_cluster is an empty attr_cluster.
 */
extern uint
attr_cluster_length(attr_cluster clust)
{
  return (clust != NULL) ? clust->list.len : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Construct and/or return string form of CLUSTER_LIST.
 *
 * A NULL attr_cluster is an empty attr_cluster.
 *
 * Returns:  address of string
 *           "" if the cluster is NULL or the list is empty.
 */
extern const char*
attr_cluster_str (attr_cluster clust)
{
  if ((clust == NULL) || (clust->list.len == 0))
    return "" ;

  if (!(clust->state & clst_string))
    {
      uint len, i ;
      cluster_id_t* list ;

      qs_clear(clust->str) ;            /* reset len & cp       */

      len  = clust->list.len * 16 ;     /* worst case           */
      if (len > clust->str->size)
        qs_extend(clust->str, len) ;

      list = clust->list.body.v ;
      len = 0 ;
      for (i = 0 ; i < clust->list.len ; ++i)
        {
          if (i != 0)
            qs_append_ch(clust->str, ' ') ;

          qs_ip_address_a(clust->str, &list[i], pf_ipv4, 0) ;
        } ;

      qs_string(clust->str) ;           /* '\0' terminate       */
    } ;

  return clust->str->body.c ;
} ;
