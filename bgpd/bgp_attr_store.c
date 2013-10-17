/* BGP Attributes Store
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
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
#include <misc.h>

#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_adj_out.h"
#include "lib/prefix.h"

/*==============================================================================
 * Management of sets of attributes.
 *
 * Here we store complete sets of attributes, and sub-attributes.
 *
 * The store is global, across all bgp instances.
 */
attr_set bgp_attr_null ;                /* Global value         */

static void bgp_attr_set_start(void) ;
static void bgp_attr_set_finish(void) ;
static attr_set bgp_attr_set_init(attr_set new) Unused ;
static attr_set bgp_attr_set_dup(attr_set dst, attr_set_c src) ;
static attr_set bgp_attr_set_store(attr_set set, attr_new_bits_t new_subs) ;
static attr_set bgp_attr_set_free(attr_set set, attr_new_bits_t process,
                                                              bool was_stored) ;

/*------------------------------------------------------------------------------
 * Initialise the store of main and sub-attributes.
 */
extern void
bgp_attr_start(void)
{
  bgp_attr_set_start() ;

  as_path_start() ;
  attr_community_start() ;
  attr_ecommunity_start() ;
  attr_cluster_start() ;
  attr_unknown_start() ;
} ;

/*------------------------------------------------------------------------------
 * Empty the store of main and sub-attributes at shut-down.
 *
 * If "final" then the caller is guaranteeing that no further attribute
 * actions will be attempted.
 */
extern void
bgp_attr_finish(void)
{
  bgp_attr_set_finish() ;

  as_path_finish() ;
  attr_community_finish() ;
  attr_ecommunity_finish() ;
  attr_cluster_finish() ;
  attr_unknown_finish() ;
} ;

/*==============================================================================
 * Working with attributes -- the attribute pair.
 *
 * Operations are:
 *
 *   load_new  -- load an attribute pair with a brand new working set.
 *
 *                sets:  stored  -> NULL
 *                       working -> scratch working set
 *                       new     = 0 -- empty
 *                       scratch = empty working set
 *
 *                nothing is locked -- the working attribute set belongs to
 *                the attribute pair.
 *
 *                The working->asp is set to as_path_empty_asp.  It is not
 *                marked as 'new', so the working set does not have a lock
 *                on the as_path_empty_asp.  If the working set is stored, then
 *                the as_path_empty_asp will be locked.
 *
 *   load      -- load an attribute set into an attribute pair
 *
 *                sets:  stored  -> attribute set ) both point at the stored
 *                       working -> attribute set ) attribute set
 *                       new     = 0 -- empty
 *
 *                Locks the stored set.
 *
 *   load_default -- as load_new, and then sets some default values
 *
 *   store     -- store the current contents of the attribute pair.
 *
 *                If the working set == current stored set, nothing to do.
 *
 *                Otherwise:
 *
 *                  * store the working set in the attribute store, and
 *                    lock it.
 *
 *                    We do this before unlocking the old stored set, because
 *                    some of the working set sub-attributes may be copies
 *                    of those in the stored set.
 *
 *                  * unlock the (old) stored set (if any).
 *
 *                  * set: stored  -> attribute set ) both point at the stored
 *                         working -> attribute set ) attribute set
 *                         new     = 0 -- empty
 *
 *                The result is as if the (now) current stored set had just
 *                been loaded.
 *
 *   assign    -- assign the current contents of the attribute pair.
 *
 *                If required, store the attribute pair.
 *
 *                Lock the (now) stored set and return a pointer to it.
 *
 *                So, the assignee is the owner of their own lock on the
 *                attribute set.
 *
 *   unload    -- discard attribute pair.
 *
 *                If the working set != current stored set, discard the
 *                contents of the working set.
 *
 *                Unlock the stored set (if any).
 *
 * See below for the operations which make changes to the working set of
 * an attribute pair which has been loaded, or loaded_new.
 */

/*------------------------------------------------------------------------------
 * Load New: load an attribute pair with a brand new, empty working set.
 *
 * Sets stored pointer NULL.
 *
 * Returns:  address of the working set
 */
extern attr_set
bgp_attr_pair_load_new(attr_pair pair)
{
  /* Zeroizing the attr_pair sets:
   *
   *   * stored           -- NULL      -- no stored set, yet
   *
   *   * working          -- X         -- initialised below
   *
   *   * new              -- all zero  -- no new sub-attributes, yet
   *
   *   * scratch          -- all zero  -- embedded attr_set_t
   *
   * NB: an attr_set MUST be zeroized when it is initialised, to ensure that
   *     any holes in it due to alignment are zeroized.
   *
   *     A zeroized attr_set is an empty attr_set, except for:
   *
   *       * origin    -- which must be set, at least to BGP_ATT_ORG_UNSET.
   *
   *       * asp       -- which must be set to something (eg as_path_empty_asp)
   */
  memset(pair, 0, sizeof(attr_pair_t)) ;

  pair->scratch->origin = BGP_ATT_ORG_UNSET ;
  pair->scratch->asp    = as_path_empty_asp ;

  return pair->working = pair->scratch ;
} ;

/*------------------------------------------------------------------------------
 * Load: load an attribute set into an attribute pair
 *
 * Sets stored and working pointers the same and not NULL, which => have a
 * stored and locked set of attributes.
 *
 * Returns:  address of the working set
 */
extern attr_set
bgp_attr_pair_load(attr_pair pair, attr_set set)
{
  qassert(vhash_is_set(set)) ;

  return pair->stored = pair->working = bgp_attr_lock(set) ;
} ;

/*------------------------------------------------------------------------------
 * Load Default: load an attribute pair with a brand new working set, and
 *               set some default values:
 *
 *                 * the given origin -- sets BGP_ATT_ORG_UNSET if is not
 *                                       a valid origin.
 *
 *                 * an empty (not-stored) AS_PATH
 *
 *                 * the BGP_ATTR_DEFAULT_WEIGHT
 *
 * NB: does not set up a next_hop.
 *
 * Returns:  address of the working set
 */
extern attr_set
bgp_attr_pair_load_default(attr_pair pair, byte origin)
{
  attr_set def ;

  def = bgp_attr_pair_load_new(pair) ;

  if (origin > BGP_ATT_ORG_MAX)
    origin = BGP_ATT_ORG_UNSET ;
  confirm(BGP_ATT_ORG_MIN == 0) ;

  def->origin = origin ;
  def->weight = BGP_ATTR_DEFAULT_WEIGHT ;

  return def;
} ;

/*------------------------------------------------------------------------------
 * Store: store the current contents of the attribute pair, if required.
 *
 * Returns:  address of stored set
 *
 * NB: the returned stored set is locked by virtue of the pointer which remains
 *     in the attribute pair.
 *
 *     The caller must lock the set again before saving the returned pointer.
 *     (Or must avoid unloading the attribute pair !)
 *
 *     Unloading the attribute pair looks after the lock which it owns.
 *
 * NB: the pair MUST have been loaded -- by bgp_attr_pair_load_new()/_load()/
 *     _load_default() -- so pair->working is not NULL and is valid.
 */
extern attr_set
bgp_attr_pair_store(attr_pair pair)
{
  attr_set set ;

  set = pair->stored ;

  qassert(pair->working != NULL) ;
  qassert((pair->working == pair->stored) || (pair->working == pair->scratch)) ;

  if (set != pair->working)
    {
      /* Do the attribute store mechanics and return with a newly locked,
       * stored attribute.
       */
      set = bgp_attr_set_store(pair->working, pair->new) ;

      /* If we have a (now previous) stored set, time to unlock it.
       */
      if (pair->stored != NULL)
        bgp_attr_unlock(pair->stored) ;

      /* Finally, reload the pair.
       */
      qassert(vhash_is_set(set)) ;

      pair->stored = pair->working = set ;
    } ;

  return set ;
} ;

/*------------------------------------------------------------------------------
 * Assign: assign the current contents of the attribute pair.
 *
 * Stores the current working set if required.
 *
 * Returns:  address of stored set -- with an EXTRA lock applied.
 *
 * NB: the pair MUST have been loaded -- by bgp_attr_pair_load_new()/_load()/
 *     _load_default() -- so pair->working is not NULL and is valid.
 */
extern attr_set
bgp_attr_pair_assign(attr_pair pair)
{
  qassert(pair->working != NULL) ;
  qassert((pair->working == pair->stored) || (pair->working == pair->scratch)) ;

  if (pair->stored != pair->working)
    bgp_attr_pair_store(pair) ;

  return bgp_attr_lock(pair->working) ;
} ;

/*------------------------------------------------------------------------------
 * Unload: discard attribute pair.
 *
 * NB: the pair MUST have been loaded -- by bgp_attr_pair_load_new()/_load()/
 *     _load_default() -- so pair->working is not NULL and is valid.
 *
 * Returns:  NULL
 */
extern attr_set
bgp_attr_pair_unload(attr_pair pair)
{
  qassert(pair->working != NULL) ;
  qassert((pair->working == pair->stored) || (pair->working == pair->scratch)) ;

  if (pair->stored != pair->working)
    {
      qassert(vhash_is_unused(pair->working)) ;
      bgp_attr_set_free(pair->working, pair->new, false /* not stored */) ;
    } ;

  if (pair->stored != NULL)
    {
      bgp_attr_unlock(pair->stored) ;
      pair->stored = NULL ;
    } ;

  return pair->working = NULL ;
} ;

/*==============================================================================
 * Making changes to a loaded attribute pair.
 *
 * Once an attribute pair has been loaded -- bgp_attr_pair_load_new() or
 * bgp_attr_pair_load() -- may then wish to change attribute or sub-attribute
 * values.
 *
 * The following functions make changes to an attribute pair, encapsulating
 * the mechanics of making a copy of a stored attribute set before can make
 * changes to it.  These functions also avoid changing anything if the new
 * value of an attribute is the same as the current value.
 *
 * The caller may be caring around a pointer to the "working" set of attributes.
 * To support that, all these functions return the (possibly new) address of
 * the working attribute set.
 */
inline static attr_set bgp_attr_get_working(attr_pair pair) Always_Inline ;

/*------------------------------------------------------------------------------
 * Get working attribute set -- copying the stored set if required.
 */
inline static attr_set
bgp_attr_get_working(attr_pair pair)
{
  attr_set working ;

  working = pair->working ;

  if (working == pair->stored)
    {
      working = pair->working = bgp_attr_set_dup(pair->scratch, pair->stored) ;
      pair->new = 0 ;
    }
  else
    qassert(working == pair->scratch) ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set as_path
 *
 * Sets as_path_empty_asp if the given as_path is NULL !!
 */
extern attr_set
bgp_attr_pair_set_as_path(attr_pair pair, as_path asp)
{
  attr_set current, working ;
  as_path  asp_was ;

  if (asp == NULL)
    asp = as_path_empty_asp ;           /* make sure !  */

  current = pair->working ;
  asp_was = current->asp ;

  if (asp == asp_was)
    return current ;                    /* debounce     */

  working = bgp_attr_get_working(pair) ;

  if (pair->new & atnb_as_path)
    as_path_release(asp_was) ;

  working->asp = asp ;

  if (asp->stored)
    as_path_lock(asp) ;

  pair->new |= atnb_as_path ;
  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set community
 *
 * NB: setting a NULL community unsets it
 */
extern attr_set
bgp_attr_pair_set_community(attr_pair pair, attr_community comm)
{
  attr_set current, working ;
  attr_community comm_was ;

  current = pair->working ;
  comm_was = current->community ;
  if (comm == comm_was)
    return current ;                    /* debounce     */

  working = bgp_attr_get_working(pair) ;

  if (pair->new & atnb_community)
    attr_community_release(comm_was) ;

  working->community = comm ;

  if ((comm != NULL) && (comm->stored))
    attr_community_lock(comm) ;

  pair->new |= atnb_community ;
  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set ecommunity
 *
 * NB: setting a NULL ecommunity unsets it
 */
extern attr_set
bgp_attr_pair_set_ecommunity(attr_pair pair, attr_ecommunity ecomm)
{
  attr_set current, working ;
  attr_ecommunity ecomm_was ;

  current = pair->working ;
  ecomm_was = current->ecommunity ;
  if (ecomm == ecomm_was)
    return current ;                    /* debounce     */

  working = bgp_attr_get_working(pair) ;

  if (pair->new & atnb_ecommunity)
    attr_ecommunity_release(ecomm_was) ;

  working->ecommunity = ecomm ;

  if ((ecomm != NULL) && (ecomm->stored))
    attr_ecommunity_lock(ecomm) ;

  pair->new |= atnb_ecommunity ;
  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set cluster list sub-attribute
 *
 * NB: setting a NULL cluster list unsets it
 */
extern attr_set
bgp_attr_pair_set_cluster(attr_pair pair, attr_cluster clust)
{
  attr_set current, working ;
  attr_cluster clust_was ;

  current = pair->working ;
  clust_was = current->cluster ;
  if (clust == clust_was)
    return current ;                    /* debounce     */

  working = bgp_attr_get_working(pair) ;

  if (pair->new & atnb_cluster)
    attr_cluster_release(clust_was) ;

  working->cluster = clust ;

  if ((clust != NULL) && (clust->stored))
    attr_cluster_lock(clust) ;

  pair->new |= atnb_cluster ;
  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set transitive/unknown attributes sub-attribute
 *
 * NB: setting a NULL transitive/unknown attributes unsets same
 *
 * NB: if or when this is stored, discards all but the Optional Transitives,
 *     and sets Partial.
 */
extern attr_set
bgp_attr_pair_set_transitive(attr_pair pair, attr_unknown unk)
{
  attr_set current, working ;
  attr_unknown trans_was ;

  current = pair->working ;
  trans_was = current->transitive ;
  if (unk == trans_was)
    return current ;                    /* debounce     */

  working = bgp_attr_get_working(pair) ;

  if (pair->new & atnb_transitive)
    attr_unknown_release(trans_was) ;

  working->transitive = unk ;

  if ((unk != NULL) && (unk->stored))
    attr_unknown_lock(unk) ;

  pair->new |= atnb_transitive ;
  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set next_hop attribute -- debouncing if possible.
 *
 * If setting:
 *
 *   * nh_none, zeroizes the entire value
 *
 *   * nh_ipv4, zeroizes everything before setting the new value.
 *
 *     NB: ip may NOT be NULL
 *
 *   * nh_ipv6_1:
 *
 *      - if is nh_ipv6_2, preserves the existing link_local address
 *                         and leaves as nh_ipv6_2
 *
 *        NB: setting a new nh_ipv6_1 does NOT affect the link_local state.
 *
 *      - otherwise, zeroizes everything before setting the value
 *                   and sets nh_ipv6_1
 *
 *     NB: ip may NOT be NULL
 *
 *   * nh_ipv6_2 & ip != NULL:
 *
 *      - if is nh_ipv6_2, replaces the link_local (preserving the global)
 *                         and leaves as nh_ipv6_2
 *
 *      - if is nh_ipv6_1, sets the link local (preserving the global)
 *                         and sets nh_ipv6_2
 *
 *      - otherwise, zeroizes and sets the link local (leaving a zero global)
 *                   and sets nh_ipv6_2
 *
 *   * nh_ipv6_2 & ip == NULL -- special case:
 *
 *      - if is nh_ipv6_2, zeroises the link_local (preserving the global)
 *                         and leaves as nh_ipv6_1
 *
 *        NB: this is how to clear nh_ipv6_2 down to nh_ipv6_1.
 *
 *      - if is nh_ipv6_1 (already), no effect
 *
 *      - otherwise, treat as setting nh_none.
 *
 * NB: setting a new nh_ipv6_1 value does not affect any existing link_local.
 *
 *     So, if there was a link_local (so the next_hop state was nh_ipv6_2) then
 *     the state and the link_local address are preserved.
 *
 *     When there is no link_local (ie state is not nh_ipv6_2), setting
 *     nh_ipv6_1 sets a global address with no associated link_local.
 *
 *     This allows global to be set on its own (if there is no existing
 *     link_local) and for global and link_local to be set in any order.
 *
 *     If there is an existing link_local, it also REQUIRES the caller to
 *     either clear or set a new link_local when a new global is set...
 *     otherwise a stale/invalid link_local address may be left.
 *
 * NB: setting a new nh_ipv6_2 value does not affect any existing global.
 *
 *     When there is no global (ie state is not nh_ipv6_1 or / nh_ipv6_2),
 *     setting nh_ipv6_2 sets a zero global address.
 *
 *     There is no (other) mechanism for setting a link_local address without
 *     a global one.
 */
extern attr_set
bgp_attr_pair_set_next_hop(attr_pair pair, nh_type_t type, const void* ip)
{
  attr_set current, working ;

  current = pair->working ;
  switch (current->next_hop.type)
    {
      case nh_none:
        if (type == nh_none)
          return current ;      /* debounce     */

        if ((type == nh_ipv6_2) && (ip == NULL))
          return current ;      /* debounce     */

        break ;

      case nh_ipv4:
        if ((type == nh_ipv4)
                         && (current->next_hop.ip.v4 == *(const in_addr_t*)ip))
          return current ;      /* debounce     */
        break ;

#ifdef HAVE_IPV6
      case nh_ipv6_1:
        if ((type == nh_ipv6_1)
                  && IPV6_ADDR_SAME(&current->next_hop.ip.v6[in6_global], ip))
          return current ;      /* debounce     */

        if ((type == nh_ipv6_2) && (ip == NULL))
          return current ;      /* debounce     */

        break ;

      case nh_ipv6_2:
        if ((type == nh_ipv6_1)
                  && IPV6_ADDR_SAME(&current->next_hop.ip.v6[in6_global], ip))
          return current ;      /* debounce     */

        if ((type == nh_ipv6_2) && (ip != NULL)
              && IPV6_ADDR_SAME(&current->next_hop.ip.v6[in6_link_local], ip))
          return current ;      /* debounce     */

        break ;
#endif
      default:
        qassert(false) ;
    } ;

  working = bgp_attr_get_working(pair) ;

  switch (type)
    {
      case nh_none:
      default:
        memset(&working->next_hop, 0, sizeof(attr_next_hop_t)) ;
        confirm(nh_none == 0) ;
        break ;

      case nh_ipv4:
        memset(&working->next_hop, 0, sizeof(attr_next_hop_t)) ;
        working->next_hop.type  = nh_ipv4 ;
        working->next_hop.ip.v4 = *(const in_addr_t*)ip ;
        break ;

      case nh_ipv6_1:
        if (working->next_hop.type != nh_ipv6_2)
          {
            memset(&working->next_hop, 0, sizeof(attr_next_hop_t)) ;
            working->next_hop.type  = nh_ipv6_1 ;
          } ;

        IPV6_ADDR_COPY(&working->next_hop.ip.v6[in6_global], ip) ;
        break ;

      case nh_ipv6_2:
        if (ip != NULL)
          {
            if (working->next_hop.type != nh_ipv6_2)
              {
                if (working->next_hop.type != nh_ipv6_1)
                  memset(&working->next_hop, 0, sizeof(attr_next_hop_t)) ;
                working->next_hop.type  = nh_ipv6_2 ;
              } ;

            IPV6_ADDR_COPY(&working->next_hop.ip.v6[in6_link_local], ip) ;
          }
        else if (working->next_hop.type != nh_ipv6_1)
          {
            if (working->next_hop.type == nh_ipv6_2)
              {
                memset(&working->next_hop.ip.v6[in6_link_local], 0,
                                                           sizeof(in6_addr_t)) ;
                working->next_hop.type = nh_ipv6_1 ;
              }
            else
              {
                memset(&working->next_hop, 0, sizeof(attr_next_hop_t)) ;
                confirm(nh_none == 0) ;
              } ;
          } ;

        break ;
  } ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set local_pref attribute -- debouncing if no change
 *
 * NB: sets atb_local_pref -- so setting local_pref == 0 creates a different
 *     set of attributes to one with no local_pref set.
 */
extern attr_set
bgp_attr_pair_set_local_pref(attr_pair pair, uint32_t local_pref)
{
  attr_set current, working ;

  current = pair->working ;
  if ((current->local_pref == local_pref) && (current->have & atb_local_pref))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->local_pref = local_pref ;
  working->have      |= atb_local_pref ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Clear local pref attribute -- debouncing no change
 *
 * NB: clears atb_local_pref -- so no local_pref != local_pref == 0.
 */
extern attr_set
bgp_attr_pair_clear_local_pref(attr_pair pair)
{
  attr_set current, working ;

  current = pair->working ;
  if (!(current->have & atb_local_pref))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->local_pref = 0 ;
  working->have      &= ~atb_local_pref ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set weight attribute -- debouncing no change
 *
 * NB: do not distinguish weight == 0 from "no weight"
 */
extern attr_set
bgp_attr_pair_set_weight(attr_pair pair, uint16_t weight)
{
  attr_set current, working ;

  current = pair->working ;
  if (current->weight == weight)
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->weight = weight ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set med attribute -- debouncing no change
 *
 * NB: sets atb_med -- so setting med == 0 creates a different
 *     set of attributes to one with no med set.
 */
extern attr_set
bgp_attr_pair_set_med(attr_pair pair, uint32_t med)
{
  attr_set current, working ;

  current = pair->working ;
  if ((current->med == med) && (current->have & atb_med))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->med   = med ;
  working->have |= atb_med ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Clear med attribute -- debouncing no change
 *
 * NB: clears atb_med -- so no med != med == 0.
 */
extern attr_set
bgp_attr_pair_clear_med(attr_pair pair)
{
  attr_set current, working ;

  current = pair->working ;
  if (!(current->have & atb_med))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->med   = 0 ;
  working->have &= ~atb_med ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set origin attribute -- debouncing no change
 *
 * Ensures the origin is valid -- setting INCOMPLETE if the given value is not
 * recognised.
 */
extern attr_set
bgp_attr_pair_set_origin(attr_pair pair, uint origin)
{
  attr_set current, working ;

  if (origin > BGP_ATT_ORG_MAX)
    origin = BGP_ATT_ORG_INCOMP ;       /* avoid setting invalid value  */
  confirm(BGP_ATT_ORG_MIN == 0) ;

  current = pair->working ;
  if (current->origin == origin)
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->origin = origin ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Clear origin attribute -- debouncing no change
 */
extern attr_set
bgp_attr_pair_clear_origin(attr_pair pair)
{
  attr_set current, working ;

  current = pair->working ;
  if (current->origin == BGP_ATT_ORG_UNSET)
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->origin = BGP_ATT_ORG_UNSET ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set/Clear atomic aggregate attribute -- debouncing no change
 */
extern attr_set
bgp_attr_pair_set_atomic_aggregate(attr_pair pair, bool flag)
{
  attr_set current, working ;

  current = pair->working ;
  if (flag)
    {
      if (current->have & atb_atomic_aggregate)
        return current ;        /* debounce     */
    }
  else
    {
      if (!(current->have & atb_atomic_aggregate))
        return current ;        /* debounce     */
    } ;

  working = bgp_attr_get_working(pair) ;

  working->have ^= atb_atomic_aggregate ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set originator_id attribute -- debouncing no change
 */
extern attr_set
bgp_attr_pair_set_originator_id(attr_pair pair, bgp_id_t id)
{
  attr_set current, working ;

  current = pair->working ;

  if ((current->originator_id == id) && (current->have & atb_originator_id))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->originator_id = id ;
  working->have         |= atb_originator_id ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Clear originator_id attribute -- debouncing no change
 *
 * NB: clears atb_originator_id -- so no originator_id  != originator_id  == 0.
 */
extern attr_set
bgp_attr_pair_clear_originator_id(attr_pair pair)
{
  attr_set current, working ;

  current = pair->working ;
  if (!(current->have & atb_originator_id))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->originator_id = 0 ;
  working->have         &= ~atb_originator_id ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set/Clear route is being reflected state -- debouncing no change
 *
 * NB: clears atb_originator_id -- so no originator_id  != originator_id  == 0.
 */
extern attr_set
bgp_attr_pair_set_reflected(attr_pair pair, bool reflected)
{
  attr_set current, working ;
  bool now_reflected ;

  current = pair->working ;
  now_reflected = (current->have & atb_reflected) ;
  if (now_reflected == reflected)
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->have ^= atb_reflected ;

  return working ;
} ;

/*------------------------------------------------------------------------------
 * Set aggregator_as and aggregator_ip attribute -- debouncing no change
 */
extern attr_set
bgp_attr_pair_set_aggregator(attr_pair pair, as_t as, in_addr_t ip)
{
  attr_set current, working ;

  current = pair->working ;

  if (as == BGP_ASN_NULL)
    ip = 0 ;                    /* If unsetting, ensure unset ip also   */

  if ((current->aggregator_as == as) && (current->aggregator_ip == ip))
    return current ;            /* debounce     */

  working = bgp_attr_get_working(pair) ;

  working->aggregator_as = as ;
  working->aggregator_ip = ip ;

  return working ;
} ;

/*==============================================================================
 * The attribute set store.
 *
 * Note that an "orphan" function is not required because there is only one
 * bgp_attr_vhash, which we set to NULL if/when the table is reset and freed.
 */
static vhash_table bgp_attr_vhash ;

static vhash_hash_t bgp_attr_set_hash(vhash_data_c data) ;
static int          bgp_attr_set_equal(vhash_item_c item, vhash_data_c data) ;
static vhash_item   bgp_attr_set_vhash_new(vhash_table table,
                                                            vhash_data_c data) ;
static vhash_item   bgp_attr_set_vhash_free(vhash_item item,
                                                            vhash_table table) ;
static const vhash_params_t bgp_attr_set_vhash_params =
{
    .hash       = bgp_attr_set_hash,
    .equal      = bgp_attr_set_equal,
    .new        = bgp_attr_set_vhash_new,
    .free       = bgp_attr_set_vhash_free,
    .orphan     = vhash_orphan_null,
    .table_free = vhash_table_free_parent,
} ;

/*------------------------------------------------------------------------------
 * Start-up initialisation of the Attribute Set Handling
 *
 * This is done once, early in the morning.
 *
 * Does not need to be done at SIGHUP time -- the resetting of all sessions
 * will discard as much as can be freed.
 */
static void
bgp_attr_set_start(void)
{
  bgp_attr_vhash = vhash_table_new(&bgp_attr_vhash,
                                    1000 /* chain bases */,
                                     200 /* % density   */,
                                                  &bgp_attr_set_vhash_params) ;
  bgp_attr_null = XCALLOC(MTYPE_ATTR, sizeof(attr_set_t)) ;

  vhash_set_held(bgp_attr_null) ;       /* 'held' <=> stored    */
} ;

/*------------------------------------------------------------------------------
 * Close down the Attribute Set Handling
*
 * This is done once, late in the evening (though can be called more than once).
 *
 * This dismantles the vhash.  What it cannot and does not do is free all
 * stored attribute sets.  That should be achieved naturally when all routes
 * are dismantled -- which should have been done before this is called.
 *
 * If any attribute sets remain, they may be unlocked, but will not be freed.
 */
static void
bgp_attr_set_finish(void)
{
  bgp_attr_vhash = vhash_table_reset(bgp_attr_vhash) ;

  XFREE(MTYPE_ATTR, bgp_attr_null) ;
} ;

/*------------------------------------------------------------------------------
 * Return count of stored attribute sets
 */
extern uint
bgp_attr_count (void)
{
  return (bgp_attr_vhash != NULL) ? bgp_attr_vhash->entry_count : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Initialise a new attribute set
 *
 * Returns:  the new set
 */
static attr_set
bgp_attr_set_init(attr_set new)
{
  memset(new, 0, sizeof(attr_set_t)) ;

  new->origin = BGP_ATT_ORG_UNSET ;
  new->asp    = as_path_empty_asp ;

  return new ;
} ;

/*------------------------------------------------------------------------------
 * Copy of an existing attribute set
 *
 * Copies to the given set, zeroises the initial part and copying the value
 * part of the existing set, verbatim.
 *
 * Returns:  the destination set
 */
static attr_set
bgp_attr_set_dup(attr_set dst, attr_set_c src)
{
  memset(dst, 0, attr_set_value_offset) ;
  memcpy(attr_set_value(dst), attr_set_value_c(src), attr_set_value_size) ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: hash the given data
 *
 * The "data" is a complete attr_set (will be the working set).
 */
static vhash_hash_t
bgp_attr_set_hash(vhash_data_c data)
{
  attr_set_c set = data ;

  return vhash_hash_bytes(attr_set_value_c(set), attr_set_value_size) ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: is given item's data == the given data ?
 *
 * Both the "item" and the "data" are complete attr_sets (the item will be
 * a current stored set, and the data will be the current working set).
 */
static int
bgp_attr_set_equal(vhash_item_c item, vhash_data_c data)
{
  attr_set_c a = item ;
  attr_set_c b = data ;

  return memcmp(attr_set_value_c(a), attr_set_value_c(b),
                                                         attr_set_value_size) ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: create a new item
 *
 * The "data" is the working attr_set, which is the scratch set.
 *
 * We create a new structure, and which will now copy to a new.
 */
static vhash_item
bgp_attr_set_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_set_c set = data ;
  attr_set   new ;

  new = XMALLOC(MTYPE_ATTR, sizeof(attr_set_t)) ;

  return bgp_attr_set_dup(new, set) ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: free an item whose reference count has been reduced to zero
 *
 * The "item" is a stored attr_set, which we can now free.
 *
 * Returns:  NULL <=> item has been freed
 */
static vhash_item
bgp_attr_set_vhash_free(vhash_item item, vhash_table table)
{
  attr_set set = item ;

  qassert(vhash_is_set(set)) ;

  return bgp_attr_set_free(set, atnb_all, true /* was stored */) ;
} ;

/*------------------------------------------------------------------------------
 * Store the given set of attributes.
 *
 * The 'new_subs' argument specifies the sub-attributes which are new since
 * the attribute set was copied from the original (if any).  Any other
 * sub-attributes must have need copied, without increasing their lock count,
 * but are still locked in the original.
 *
 * NB: a sub-attribute may be marked 'new' and may be NULL.  (We have to
 *     look out for NULL in any case !)
 *
 * NB: storing a sub-attribute may return NULL (where do not distinguish
 *     empty from absent) -- so may be 'new' and NULL.
 *
 * Returns:  address of stored set
 *
 * The set returned may be the set passed in, which has now been stored.
 *
 * If the set returned is not the set passed in, the set passed in has been
 * discarded, and the set returned is a pre-existing set
 *
 * In any case, the set returned has been locked.
 */
static attr_set
bgp_attr_set_store(attr_set set, attr_new_bits_t new_subs)
{
  attr_set  found ;
  bool      added ;

  qassert(vhash_is_unused(set)) ;

  /* Store any new attributes.
   *
   * The store operation implicitly increments the reference count, reflecting
   * the fact that the attribute set now holds a pointer to the stored sub-
   * attribute.
   *
   * If the sub-attribute already exists, the current (new) sub-attribute is
   * freed, and the existing one replaces it in the attribute set.
   *
   * If the sub-attribute really is new, it is stored in the sub-attribute
   * store, and the result reference count will be 1.
   */
  if (new_subs != 0)
    {
      if ((new_subs & atnb_as_path) && !set->asp->stored)
        set->asp = as_path_store(set->asp) ;

      if ((new_subs & atnb_community) && (set->community != NULL)
                                      && !set->community->stored)
        set->community  = attr_community_store(set->community) ;

      if ((new_subs & atnb_ecommunity) && (set->ecommunity != NULL)
                                       && !set->ecommunity->stored)
        set->ecommunity = attr_ecommunity_store(set->ecommunity) ;

      if ((new_subs & atnb_cluster) && (set->cluster != NULL)
                                    && !set->cluster->stored)
        set->cluster    = attr_cluster_store(set->cluster) ;

      if ((new_subs & atnb_transitive) && (set->transitive != NULL)
                                       && !set->transitive->stored)
        set->transitive = attr_unknown_store(set->transitive) ;
    } ;

  /* That's the heavy lifting complete, can now find or create the attribute
   * set.
   *
   * If the set is added, then what is "found" will be that set -- which we
   * can now mark "stored".
   *
   * If the set is not added, then we can discard the set we just went to all
   * the trouble to complete !
   */
  found = vhash_lookup(bgp_attr_vhash, set, &added) ;

  if (added)
    {
      qassert(found != set) ;
      set = found ;

      /* Lock any attributes which exist and are not new.
       *
       * These attributes were copied from the original attribute set, but
       * not locked at that time, so now need to be locked.
       */
      if (!(new_subs & atnb_as_path))
        as_path_lock(set->asp) ;

      if ((set->community != NULL) && !(new_subs & atnb_community))
        attr_community_lock(set->community) ;

      if ((set->ecommunity != NULL) && !(new_subs & atnb_ecommunity))
        attr_ecommunity_lock(set->ecommunity) ;

      if ((set->cluster != NULL) && !(new_subs & atnb_cluster))
        attr_cluster_lock(set->cluster) ;

      if ((set->transitive != NULL) && !(new_subs & atnb_transitive))
        attr_unknown_lock(set->transitive) ;

      /* The set is now stored -- all stored attribute sets are 'held' in vhash
       * terms.
       */
      vhash_set_held(set) ;
    }
  else
    {
      /* No longer need the set we constructed.
       *
       * We own a lock on all the 'new' sub-attributes of that set.
       */
      qassert(vhash_is_unused(set)) ;

      bgp_attr_set_free(set, new_subs, false /* not stored */) ;

      set = found ;
    } ;

  bgp_attr_lock(set) ;

  return set ;
} ;

/*------------------------------------------------------------------------------
 * Free the given set of attributes.
 *
 * Reduces the reference count or frees any and all sub-attributes which need
 * to be processed:
 *
 *   * if the set is "stored" then must process all the sub-attributes
 *     there are.
 *
 *     Those sub-attributes must themselves be stored, and the processing
 *     required is to unlock each one.
 *
 *   * if the set is not "stored" then must process all the new sub-
 *     attributes there are.  For each one:
 *
 *       if is "stored", then need to unlock
 *
 *       otherwise, need to free
 *
 *     Note that for the working set of an attribute pair, the sub-attributes
 *     copied from the original set are not 'new', and do not need to be
 *     unlocked.
 *
 * Then, if the set is "stored", free what remains.
 *
 * NB: a sub-attribute may be marked 'new' and may be NULL.  (We have to
 *     look out for NULL in any case !)
 *
 * NB: if is not stored, then the caller is responsible for freeing the set, if
 *     required.
 *
 * NB: the bgp_attr_null set should never be presented to be freed here, but if
 *     it is, nothing happens !
 */
static attr_set
bgp_attr_set_free(attr_set set, attr_new_bits_t process, bool was_stored)
{
  if (set == bgp_attr_null)
    return NULL ;                       /* Never releases this !        */

  qassert(!vhash_has_references(set)) ;
  qassert(was_stored == vhash_is_set(set)) ;

  /* Process the sub-attributes as required.
   */
  if (process & atnb_as_path)
    {
      if (was_stored)
        qassert(set->asp->stored) ;

      as_path_release(set->asp) ;
    } ;

  if (process & atnb_community)
    {
      if (was_stored && (set->community != NULL))
        qassert(set->community->stored) ;

      attr_community_release(set->community) ;
    } ;

  if ((process & atnb_ecommunity) && (set->ecommunity != NULL))
    {
      if (was_stored && (set->ecommunity != NULL))
        qassert(set->ecommunity->stored) ;

      attr_ecommunity_release(set->ecommunity) ;
    } ;

  if (process & atnb_cluster)
    {
      if (was_stored && (set->cluster != NULL))
        qassert(set->cluster->stored) ;

      attr_cluster_release(set->cluster) ;
    }

  if (process & atnb_transitive)
    {
      if (was_stored && (set->transitive != NULL))
        qassert(set->transitive->stored) ;

      attr_unknown_release(set->transitive) ;
    }

  /* That's the heavy lifting complete, can now free the attribute set.
   */
  if (qdebug)
    memset(set, 0xA5, sizeof(attr_set_t)) ;

  if (was_stored)
    XFREE(MTYPE_ATTR, set) ;

  return NULL ;
} ;

/*==============================================================================
 * Printing Functions
 */
#include "miyagi.h"

/*------------------------------------------------------------------------------
 * Function to compare attribute sets by comparison of their next hop, origin
 * and as path.
 */
static int
bgp_attr_show_cmp(const vhash_item_c* a, const vhash_item_c* b)
{
  attr_set  set_a = miyagi(*a) ;
  attr_set  set_b = miyagi(*b) ;
  const char* str_a ;
  const char* str_b ;
  int cmp ;

  if (set_a->next_hop.type != set_b->next_hop.type)
    return (set_a->next_hop.type < set_b->next_hop.type) ? -1 : +1 ;

  switch (set_a->next_hop.type)
    {
      case nh_none:
      default:
        cmp = 0 ;
        break ;

      case nh_ipv4:
        cmp = memcmp(&set_a->next_hop.ip.v4, &set_b->next_hop.ip.v4,
                                                           sizeof(in_addr_t)) ;
        break ;

      case nh_ipv6_1:
      case nh_ipv6_2:
        cmp = memcmp(&set_a->next_hop.ip.v6, &set_b->next_hop.ip.v6,
                                                           sizeof(in6_addr_t)) ;
        break ;
    } ;

  if (cmp != 0)
    return cmp ;

  if (set_a->origin != set_b->origin)
    return (set_a->origin < set_b->origin) ? -1 : +1 ;

  str_a = as_path_str(set_a->asp) ;
  str_b = as_path_str(set_b->asp) ;

  return strcmp(str_a, str_b) ;
} ;

/*------------------------------------------------------------------------------
 * Print all stored community attributes and hash information.
 */
extern void
bgp_attr_show_all (struct vty *vty)
{
  vector extract ;
  uint i ;

  extract = vhash_table_extract(attr_community_vhash, NULL, NULL,
                                           true /* most */, bgp_attr_show_cmp) ;

              /* 1234567890_12345678_123456789012345_123_12...*/
  vty_out (vty, "Hash       Refcnt   Next-Hop        Org AS_PATH\n");

  for (i = 0 ; i < vector_length(extract) ; ++i)
    {
      attr_set  set ;
      const char* org_str ;

      set = vector_get_item(extract, i) ;

      vty_out (vty, "[%8x] (%6u) ", set->vhash.hash, set->vhash.ref_count) ;

      switch (set->next_hop.type)
        {
          case nh_none:
          default:
            vty_out(vty, "%s-15", "   ----") ;
            break ;

          case nh_ipv4:
            vty_out(vty, "%s-15", siptoa(AF_INET, &set->next_hop.ip.v4).str) ;
            break ;

          case nh_ipv6_1:
          case nh_ipv6_2:
            vty_out(vty, "%s-15", siptoa(AF_INET6, &set->next_hop.ip.v6).str) ;
            break ;
        } ;

      switch (set->origin)
        {
          case BGP_ATT_ORG_IGP:
            org_str = "igp" ;
            break ;

          case BGP_ATT_ORG_EGP:
            org_str = "egp" ;
            break ;

          case BGP_ATT_ORG_INCOMP:
            org_str = "inc" ;
            break ;

          case BGP_ATT_ORG_UNSET:
            org_str = " - " ;
            break ;

          default:
            org_str = "???" ;
            break ;
        } ;

      vty_out (vty, " %s %s\n", org_str, as_path_str(set->asp)) ;
    } ;

  vector_free(extract) ;
}

