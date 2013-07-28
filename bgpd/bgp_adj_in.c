/* Peer-RIB Adj-In handling -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_route.h"

#include "list_util.h"
#include "ihash.h"
#include "prefix_id.h"

/*==============================================================================
 * Each peer_rib has a rib_main adj-in and an optional rib_rs adj-in.
 *
 * The adj-in is an ihash table, by prefix_id.  Each entry in the table points
 * to a route_info object.  The route_info object may also be pointed to by
 * the respective bgp_rib_node (in the bgp RIB).
 *
 * All routes received from the peer are held in the rib_main adj-in, even if
 * the route is filtered out.  (So is always capable of "soft reconfig".)
 *
 * If there is at least one Route Server Client (in the bgp instance and
 * address family), then all routes which are not withdrawn or treated as
 * withdrawn will also have an entry in the rib_rs adj-in.
 *
 * There are small differences in the contents of the route_info objects in
 * the rib_main and rib_rs.  The entries in the rib_rs are dependent on the
 * rib_main entries, and rib_rs adj-in is always a subset of the rib_main one.
 *
 * The functions here are to do with walking the adj-in to update it and make
 * any consequent changes to the bgp RIB.
 */

/*------------------------------------------------------------------------------
 * Create new, empty adj_in.
 *
 *
 */
extern void
bgp_adj_in_init(peer_rib prib, rib_type_t rib_type)
{
  /* Set up an empty adj_out -- indexed by prefix_id
   */
  prib->adj_in[rib_type] = ihash_table_new(200, 50) ;
} ;

/*------------------------------------------------------------------------------
 * Empty out all adj_out elements in the given peer_rib.
 *
 *
 */
extern void
bgp_adj_in_reset(peer_rib prib)
{

} ;


/*==============================================================================
 * Route_Info operations.
 */
/*------------------------------------------------------------------------------
 *
 */
extern route_info
bgp_route_info_new(peer_rib prib, rib_type_t rib_type, prefix_id_entry pie,
                                                    bgp_route_type_t route_type)
{
  route_info ri ;

  ri = XCALLOC(MTYPE_BGP_ROUTE_INFO, sizeof(route_info_t)) ;

  /* Zeroising sets:
   *
   *    * prib               -- X         -- set below
   *
   *    * rn                 -- NULL      -- no associated bgp_rib_node, yet
   *    * route_list         -- NULLs     -- ditto
   *
   *    * pfx_id             -- X         -- set below and locked
   *    * tag                -- 0         -- none, yet
   *
   *    * med_as             -- BGP_ASN_NULL -- nothing yet
   *    * igp_metric         -- 0
   *
   *    * attr_recv          -- NULL      -- nothing, yet
   *    * attr               -- NULL      -- nothing, yet
   *
   *    * candidate_list     -- NULL      -- not yet a candidate
   *    * merit              -- 0         -- none, yet
   *
   *    * extra              -- NULL      -- no route-flap etc, yet
   *
   *    * uptime             -- 0         -- set below
   *
   *    * lock               -- 0         -- no locks
   *
   *    * flags              -- 0         -- nothing, yet
   *
   *    * rib_type           -- X         -- set below
   *    * qafx               -- X         -- set below
   *    * route_type         -- X         -- set below
   */
  ri->prib       = prib ;
  ri->pfx_id     = pie->id ;

  ri->rib_type   = rib_type ;
  ri->qafx       = prib->qafx ;
  ri->route_type = route_type ;

  prefix_id_entry_inc_ref(pie) ;
  ihash_set_item(prib->adj_in[rib_type], pie->id, ri) ;

  return ri ;
} ;

/*------------------------------------------------------------------------------
 * Free the given route_info object.
 *
 *
 *
 */
extern route_info
bgp_route_info_free(route_info ri, bool ream)
{
  peer_rib     prib ;
  bgp_rib_node rn ;

  prib = ri->prib ;

  /* When freeing rib_main entry, automatically free any related
   * rib_rs one.
   */
  if ((prib->adj_in[rib_rs] != NULL) && (ri->rib_type == rib_main))
    {
      route_info ri_rs ;

      ri_rs = ihash_del_item(prib->adj_in[rib_rs], ri->pfx_id, NULL) ;
      if (ri_rs != NULL)
        bgp_route_info_free(ri_rs, true /* not ream */) ;
    } ;

  /* Remove from the adj-in and reduce the reference count on the related
   * prefix-id.
   */
  if (!ream)
    ihash_del_item(prib->adj_in[ri->rib_type], ri->pfx_id, NULL) ;

  prefix_id_dec_ref(ri->pfx_id) ;

  /* If this is associated with the respective bgp_rib_node, now is the time
   * to disassociate.
   *
   * For rib_main, we need to reschedule if we are removing a current
   * candidate *and* is the current selection.  If the current selection is
   * not amongst the candidates, the will already be scheduled for processing.
   *
   * For rib_rs, we must always reschedule, because this may be the current
   * selection for some client.
   */
  rn = ri->rn ;
  if (rn != NULL)
    {
      bool reschedule ;                 /* for rib_main         */

      ddl_del(rn->routes, ri, route_list) ;

      reschedule = ssl_del(rn->candidates, ri, candidate_list) ;

      if (ri == rn->selected)
        rn->selected = NULL ;   /* no longer the last selected !        */
      else
        reschedule = false ;    /* no need to reschedule for rib_main   */

      if ((ri->rib_type == rib_rs) || reschedule)
        bgp_process_schedule(rn->it.rib, rn) ;
    } ;

  /* If this is a stale route, time to remove it from the list of stale
   * routes.
   */
  if (ri->flags & RINFO_STALE)
    ddl_del(prib->stale_routes, ri, stale_list) ;

  /* Discard any known attributes and any "extra" data
   */
  if (ri->attr != NULL)
    ri->attr = bgp_attr_unlock(ri->attr) ;
  if (ri->attr_rcv != NULL)
    ri->attr_rcv = bgp_attr_unlock(ri->attr_rcv) ;

  if (ri->extra != NULL)
    ri->extra = NULL ;                  // TODO !!

  /* Now we can free the object and return NULL.
   */
  XFREE(MTYPE_BGP_ROUTE_INFO, ri) ;

  return NULL ;
} ;

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * Discard contents of the given adj-in(s).
 *
 * Discarding the rib_main adj-in automatically discards the rib_rs one.
 */
extern void
bgp_adj_in_discard(peer_rib prib, rib_type_t rib_type)
{
  ihash_table adj_in ;
  route_info  ri ;

  if (rib_type == rib_main)
    bgp_adj_in_discard(prib, rib_rs) ;

  adj_in = prib->adj_in[rib_type] ;

  if (adj_in == NULL)
    return ;

  while ((ri = ihash_table_ream(adj_in, free_it)) != NULL)
    bgp_route_info_free(ri, true /* ream */);

  prib->adj_in[rib_type] = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set everything in the given adj-in "stale".
 *
 * By rule, anything which is already stale must be discarded (from both
 * rib_main and rib_rs).
 *
 * We only set the rib_main entries stale.
 */
extern void
bgp_adj_in_set_stale(peer_rib prib)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;

  /* Discard anything which is already stale
   */
  bgp_adj_in_discard_stale(prib) ;

  /* Walk the rib_main adj-in, mark everything stale and add to the list of
   * stale routes.
   */
  ihash_walk_start(prib->adj_in[rib_main], walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      ddl_append(prib->stale_routes, ri, stale_list) ;

      ri->flags |= RINFO_STALE ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Discard everything in the given adj-in which is "stale".
 */
extern void
bgp_adj_in_discard_stale(peer_rib prib)
{
  route_info  ri ;

  while ((ri = ddl_head(prib->stale_routes)) != NULL)
    bgp_route_info_free(ri, false /* not ream */) ;
} ;

/*------------------------------------------------------------------------------
 * Refresh everything in the given adj-in.
 *
 *   * discard anything which is "stale".
 *
 *   * discard anything which has been withdrawn.
 *
 *   * re-announce to self the current attr_rcv -- sets prib->refresh for the
 *     duration (to avoid complaints about repeated attributes).
 *
 * The purpose may be any one of:
 *
 *   * tidy up adj-in -- removing stale and withdrawn entries.
 *
 *   * re-process routes after change of filters and/or 'in' or 'rs-in'
 *     route-maps.
 *
 */
extern void
bgp_adj_in_refresh(peer_rib prib)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;

  /* Discard anything which is stale
   */
  bgp_adj_in_discard_stale(prib) ;

  /* Walk the rib_main adj-in.
   */
  prib->refresh = true ;

  ihash_walk_start(prib->adj_in[rib_main], walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if (ri->attr_rcv == NULL)
        bgp_route_info_free(ri, false /* not ream */) ;
      else if (!(ri->flags & RINFO_TREAT_AS_WITHDRAW))
        {
          route_in_parcel_t  parcel[1] ;

          parcel->attr       = ri->attr_rcv ;
          parcel->pfx_id     = ri->pfx_id ;
          parcel->tag        = ri->tag ;
          parcel->qafx       = ri->qafx ;
          parcel->action     = ra_in_update ;
          parcel->route_type = ri->route_type ;

          bgp_update_from_peer(prib->peer, parcel, false) ;
        } ;
    } ;

  prib->refresh = false ;
} ;

/*------------------------------------------------------------------------------
 * Enable the given prib for RS Routes -- if not already enabled.
 *
 * If required, creates an adj_in[rib_rs], and populates it from the rib_main,
 * scheduling any affected RS prefixes for processing.
 */
extern void
bgp_adj_in_rs_enable(peer_rib prib)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;

  if (prib->adj_in[rib_rs] != NULL)
    return ;

  /* Create a new, empty adj_in[rib_rs]
   */
  bgp_adj_in_init(prib, rib_rs) ;

  /* Walk the rib_main adj-in, and for all
   */
  ihash_walk_start(prib->adj_in[rib_main], walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if ((ri->attr_rcv != NULL) && !(ri->flags & RINFO_TREAT_AS_WITHDRAW))
        bgp_update_rs_from_peer(prib, ri, prefix_id_get_entry(ri->pfx_id),
                                                           true /* process */) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Disable the given prib for RS Routes -- if enabled.
 *
 * If there is an adj_in[rib_rs], discards the contents -- which will schedule
 * any affected RS prefixes for processing -- and then discards the
 * adj_in[rib_rs].
 */
extern void
bgp_adj_in_rs_disable(peer_rib prib)
{
  bgp_adj_in_discard(prib, rib_rs) ;
} ;

