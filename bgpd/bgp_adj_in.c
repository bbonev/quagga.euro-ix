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
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_nexthop.h"

#include "list_util.h"
#include "ihash.h"
#include "prefix_id.h"

/*==============================================================================
 * Each peer_rib has a rib_main adj-in and an optional rib_rs adj-in.
 *
 * The adj-in is an ihash table, by prefix_id.  Each entry in the table points
 * to a route_info object.
 *
 * All routes received from the peer are held in the rib_main adj-in, even if
 * the route is filtered out.  (So is always capable of "soft reconfig".)
 *
 * As routes arrive from the I/O (ring-buffer), the adj-in's pending state
 * is updated, and the route-info is added to the list of those to be
 * processed for the neighbor.  At this moment, the need for information
 * about the next-hop is registered.
 *
 * If the route has not been filtered out, it is known to the respective
 * rib-node, and has an entry in its 'avail' svec.
 *
 * For each route-context the adj-in has its own attributes and merit, which
 * comprise the 'iroute'.  The iroutes for a route-context are hung from the
 * rib-node's 'rroute' for that route-context -- ith the current selection
 * as the first entry.
 */

/*------------------------------------------------------------------------------
 * Create new, empty adj_in.
 *
 *
 */
extern void
bgp_adj_in_init(peer_rib prib)
{
  /* Set up an empty adj_out -- indexed by prefix_id
   */
  prib->adj_in = ihash_table_new(200, 50) ;
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
 * Create a new, empty, route-info and puts it into the adj-in for the given
 *                                                 prefix -- locking the prefix.
 *
 * The result is not attached to any rib-node, nor to any adj-in processing
 * list.
 *
 * Returns:  address of new route-info
 */
extern route_info
bgp_route_info_new(peer_rib prib, prefix_id_entry pie)
{
  route_info ri ;
  uint       context_count ;

  context_count = prib->rib->context_count ;

  ri = XCALLOC(MTYPE_BGP_ROUTE_INFO,
                               offsetof(route_info_t, iroutes[context_count])) ;

  /* Zeroising sets:
   *
   *    * prib          -- X            -- set below
   *
   *    * rn            -- NULL         -- no bgp_rib_node, yet
   *    * rlist         -- SVEC_NULL    -- ditto
   *    * rindex        -- SVEC_NULL    -- ditto
   *
   *    * pfx_id        -- X            -- set below and locked
   *
   *    * current.attr          -- NULL
   *             .tags          -- mpls_tags_null
   *             .flags         -- X         -- set RINFO_WITHDRAWN, below
   *             .qafx          -- X         -- set below
   *             .route_type    -- bgp_route_type_null
   *
   *    * current.attr          -- NULL
   *             .tags          -- mpls_tags_null
   *             .flags         -- RINFO_NULL
   *             .qafx          -- X         -- set below
   *             .route_type    -- bgp_route_type_null
   *
   *    * plist                 -- NULLs        -- not on any list, yet
   *
   *    * med_as                -- BGP_ASN_NULL -- nothing yet
   *    * igp_metric            -- 0
   *
   *    * extra                 -- NULL      -- no route-flap etc, yet
   *
   *    * uptime                -- 0         -- set below
   *
   *    * context_count         -- X         -- set below
   *    * iroutes.list          -- SVEC_NULLs
   *             .attr          -- NULL
   *             .merit         -- 0
   */
  confirm(SVEC_NULL           == 0) ;
  confirm(RINFO_NULL          == 0) ;
  confirm(bgp_route_type_null == 0) ;
  confirm(mpls_tags_null      == 0) ;

  ri->prib       = prib ;
  ri->pfx_id     = pie->id ;

  ri->current.flags = RINFO_WITHDRAWN ;
  ri->current.qafx  = prib->qafx ;
  ri->pending.qafx  = prib->qafx ;

  ri->context_count = context_count ;

  prefix_id_entry_inc_ref(pie) ;
  ihash_set_item(prib->adj_in, pie->id, ri) ;

  return ri ;
} ;

/*------------------------------------------------------------------------------
 * The given route-info needs to be extended to support more route-contexts
 * than it currently does.
 *
 * Adjusts:  any rib-node svec to point at the new route-info.
 *
 *           any list pointers for adj-in processing lists
 *
 * Inherits all the locks on anything the existing route-info has locked.
 *
 * Remains on any lists of routes for all current contexts known to the
 * rib-node (if any).
 *
 * Returns:  address of newly extended route-info
 */
extern route_info
bgp_route_info_extend(route_info ri)
{
  route_info ri_new ;
  uint       context_count ;

  context_count = ri->prib->rib->context_count ;

  if (ri->context_count >= context_count)
    return ri ;

  /* We do need a new route-info, so make one and copy the old route_info
   * to it.
   */
  ri_new = XCALLOC(MTYPE_BGP_ROUTE_INFO,
                               offsetof(route_info_t, iroutes[context_count])) ;

  memcpy(ri_new, ri, offsetof(route_info_t, iroutes[ri->context_count])) ;

  /* We now have:
   *
   *    * prib               -- copied
   *
   *    * rn                 ) if is known to rib-node, need to
   *    * rlist              ) update the pointer in the
   *    * rindex             ) rn->avail svec.
   *
   *    * pfx_id             -- copied, along with the lock
   *
   *    * current            -- copied, along with lock on any attr
   *    * pending            -- copied, along with lock on any attr
   *
   *    * plist              -- needs to be updated, see below.
   *
   *    * med_as             -- copied
   *    * extra              -- copied
   *    * uptime             -- copied
   *
   *    * context_count      -- needs to be set to new value, see below
   *
   *    * iroutes            -- existing contexts copied, rest:
   *             .list       -- SVEC_NULLs
   *             .attr       -- NULL
   *             .merit      -- 0
   */
  if (ri_new->rindex != SVEC_NULL)
    {
      qassert(ri_new->rn != NULL) ;
      qassert(svec_get(ri_new->rn->avail, ri_new->rindex) == ri) ;

      svec_set(ri_new->rn->avail, ri_new->rindex, ri_new) ;
    } ;

  ri_new->context_count = context_count ;

  if      (ri_new->pending.flags & RINFO_PENDING)
    {
      qassert(!(ri_new->current.flags & RINFO_STALE)) ;
      ddl_replace(ri_new->prib->pending_routes, ri, plist, ri_new) ;
    }
  else if (ri_new->current.flags & RINFO_STALE)
    {
      ddl_replace(ri_new->prib->stale_routes, ri, plist, ri_new) ;
    } ;

  return ri_new ;
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

  /* Remove from the adj-in and reduce the reference count on the related
   * prefix-id.
   */
  if (!ream)
    ihash_del_item(prib->adj_in, ri->pfx_id, NULL) ;

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

  /* If this is pending or stale, time to remove it from the respective list.
   */
  if      (ri->pending.flags & RINFO_PENDING)
    {
      qassert(!(ri->current.flags & RINFO_STALE)) ;
      ddl_del(ri->prib->pending_routes, ri, plist) ;
    }
  else if (ri->current.flags & RINFO_STALE)
    {
      ddl_del(ri->prib->stale_routes, ri, plist) ;
    } ;

  /* Discard any known attributes and any "extra" data
   */
  if (ri->current.attr != NULL)
    ri->current.attr = bgp_attr_unlock(ri->current.attr) ;

  if (ri->pending.attr != NULL)
    ri->pending.attr = bgp_attr_unlock(ri->pending.attr) ;

  if (ri->extra != NULL)
    ri->extra = NULL ;                  // TODO !!

  /* Now we can free the object and return NULL.
   */
  XFREE(MTYPE_BGP_ROUTE_INFO, ri) ;

  return NULL ;
} ;

/*==============================================================================
 * Incoming UPDATE processing.
 */

/*------------------------------------------------------------------------------
 * Process update into the adj-in -- checking for max-prefix.
 *
 *   1) create an adj-in entry for the prefix if none currently exists.
 *
 *   2) if the adj-in is currently marked as 'stale' it is now fresh, and
 *      can be removed from the stale list.
 *
 *   3) set the pending state of the adj-in
 *
 *   4) kick the Next-Hop resolver
 *
 *   5) queue the pending adj-in for the peer's work-queue.
 *
 * Note that even if what we receive is exactly the same as what we have, will
 * schedule the re-processing of the route -- except for withdraws.  This
 * is to allow for route-refresh and the like to be run through the full
 * filtering process.
 *
 * Where a set of attributes has been found wanting, but we have elected not
 * to drop the session, the route is accepted into the adj-in, and counted,
 * but will be filtered out and treated as withdraw when the route-info is
 * processed.
 */
extern void
bgp_adj_in_update(peer_rib prib, prefix_id_entry pie, iroute_state parcel)
{
  route_info      ri ;
  bool            was_counted ;

  qassert(prib->qafx == parcel->qafx) ;
  if (parcel->attr == NULL)
    qassert(parcel->flags == RINFO_WITHDRAWN) ;
  else
    qassert((parcel->flags == 0) || (parcel->flags == RINFO_REFUSED)) ;

  /* Lookup the route-info entry.
   */
  ri = ihash_get_item(prib->adj_in, pie->id, NULL) ;

  /* Worry about increasing the prefixes received count -- we do this very
   * early, because if we are going to stop receiving updates, want to do so
   * *before* we create an adj-in entry !
   *
   * Note that we count routes which we are "refused", even though we will
   * later treat those as withdrawn.
   *
   * If the count goes up, look out for max prefix.
   */
  if (ri == NULL)
    was_counted = false ;
  else if (ri->pending.flags & RINFO_PENDING)
    was_counted = !(ri->pending.flags & (RINFO_REFUSED | RINFO_WITHDRAWN)) ;
  else
    was_counted = !(ri->current.flags & (RINFO_REFUSED | RINFO_WITHDRAWN
                                                       | RINFO_STALE)) ;

  if (was_counted)
    {
      if ((parcel->flags & (RINFO_REFUSED | RINFO_WITHDRAWN)) &&
                                  (parcel->route_type == bgp_route_type_normal))
        {
          qassert(prib->pcount_recv != 0) ;
          prib->pcount_recv -= 1 ;
        } ;
    }
  else
    {
      if (!(parcel->flags & (RINFO_REFUSED | RINFO_WITHDRAWN)) &&
                                  (parcel->route_type == bgp_route_type_normal))
        {
          uint pcount ;

          prib->pcount_recv = pcount = prib->pcount_recv + 1 ;

          if (pcount > prib->pmax.trigger)
            {
              /* Have exceeded the current max-prefix trigger.
               *
               * If we are only warning, or if this is just the threshhold,
               * then we may continue.
               *
               * Adjusts the pmax.trigger so that we don't go through this
               * every time !
               */
              if (!bgp_peer_pmax_check(prib))
                return ;
            } ;
        } ;
    } ;

  /* If we don't have a route-info for this prefix, now is the time to
   * create one -- unless we have a withdraw on our hands.
   *
   * If we do have a route-info for this prefix, now is the time to clear
   * any stale flag
   */
  if (ri == NULL)
    {
      /* Route does not exist, so create route-info, except...
       *
       * ... if this is a withdraw, then we can give up now, because we
       * know nothing about the route.
       */
      if (parcel->flags & RINFO_WITHDRAWN)
        {
          /* The sender is withdrawing something we don't have a record of...
           * which is odd.
           *
           * But in any case there is nothing more to be done.
           */
          if (BGP_DEBUG (update, UPDATE_IN) &&
                                  (parcel->route_type == bgp_route_type_normal))
            zlog (prib->peer->log, LOG_DEBUG,
                       "%s withdraw for unknown route %s",
                                     prib->peer->host, spfxtoa(pie->pfx).str) ;

          return ;
        } ;

      /* We have received an UPDATE, even if that is refused (invalid
       * attributes) or later denied (unreachable or filtered out etc), we
       * still want to hold an adj_in entry for it.
       *
       * Marks the current as RINFO_WITHDRAWN.
       */
      ri = bgp_route_info_new(prib, pie) ;
    }
  else
    {
      /* This is an existing route_info -- if it is "stale" then we now have
       * a shiny new set of attributes for it, so remove from the stale
       * list and clear the state.
       */
      if (ri->current.flags & RINFO_STALE)
        {
          qassert(!(ri->current.flags & (RINFO_REFUSED | RINFO_WITHDRAWN))) ;
          qassert(ri->pending.flags == RINFO_NULL) ;
          qassert(ri->current.attr != NULL) ;

          ddl_del(prib->stale_routes, ri, plist) ;
          ri->current.flags ^= RINFO_STALE ;
        } ;
    } ;

  /* Check for withdraw of route which we already have withdrawn.
   *
   * NB: does not get here at all if there has never been a route and we
   *     are
   *
   * If there is a pending update, then we have received a withdraw before
   * we had time to process the update :-(
   *
   * If we don't have a pending update, then this is a route-info for something
   * which we used to have a route for, but which has been withdrawn by the
   * neighbor and is being withdrawn again
   *
   * In any case, we may as well leave the adj-in set to withdrawn, discard
   * any pending update and exit without scheduling any further work.  The
   * rib-node should have no record of this route-info !
   */
  if (ri->current.flags & parcel->flags & RINFO_WITHDRAWN)
    {
      /* We have a withdraw, but the adj-in is already withdrawn.
       */
      qassert(ri->rn == NULL) ;

      if (ri->pending.flags & RINFO_PENDING)
        {
          /* We have something pending, so we need to discard an earlier update
           * that has not been processed.
           */
          if (ri->pending.attr != NULL)
            ri->pending.attr = bgp_attr_unlock(ri->pending.attr) ;
          ri->pending.flags = RINFO_NULL ;

          ddl_del(prib->pending_routes, ri, plist) ;

          if (BGP_DEBUG (update, UPDATE_IN) &&
                                  (parcel->route_type == bgp_route_type_normal))
            zlog (prib->peer->log, LOG_DEBUG,
                 "%s route for %s withdrawn before previous update processed",
                                      prib->peer->host, spfxtoa(pie->pfx).str) ;
        }
      else
        {
          zlog (prib->peer->log, LOG_DEBUG,
                     "%s withdraw for already withdrawn route %s",
                                      prib->peer->host, spfxtoa(pie->pfx).str) ;
        } ;

      return ;
    } ;

  /* If there is something pending already, then we now displace it.
   *
   * Add to the pending queue -- sets RINFO_PENDING below.
   *
   * NB: does not reschedule an existing pending.
   */
  if (ri->pending.flags & RINFO_PENDING)
    {
      /* We have something pending, so we need to discard an earlier update
       * that has not been processed.
       */
      qassert((ri->pending.attr == NULL) ==
                                        (ri->pending.flags & RINFO_WITHDRAWN)) ;

      if (ri->pending.attr != NULL)
        ri->pending.attr = bgp_attr_unlock(ri->pending.attr) ;
    }
  else
    {
      ddl_append(prib->pending_routes, ri, plist) ;
    } ;

  /* Now we set the pending -- taking a lock on the attributes, if any.
   *
   * Whatever flags have been passed, make sure we keep only those which are
   * relevant, and set RINFO_PENDING.
   */
  ri->pending = *parcel ;

  if (ri->pending.attr != NULL)
    bgp_attr_lock(ri->pending.attr) ;

  ri->pending.flags = (parcel->flags & (RINFO_REFUSED | RINFO_WITHDRAWN))
                                                               | RINFO_PENDING ;

  qassert((ri->pending.attr == NULL) == (ri->pending.flags & RINFO_WITHDRAWN)) ;

  /* Boot the work queue for this adj-in/prib....
   *
   */

} ;


static bool bgp_adj_in_update_rc(bgp_rib_node rn, route_info ri, attr_set attr,
                                                     uint rc, bool tag_change) ;

static bool bgp_adj_in_withdraw_rc(bgp_rib_node rn, route_info ri, uint rc) ;

/*------------------------------------------------------------------------------
 * Work queue action for prib adj-in -- process route into RIB.
 *
 *
 * TODO aggregate stuff
 */
extern bool
bgp_adj_in_process(peer_rib prib)
{
  route_info      ri ;
  prefix_id_entry pie ;

  next_hop_state_t  nhs ;

  bool            withdraw, announce, must_change, process ;

  bgp_rib_node    rn ;
  uint  cc ;

  /* Establish where we were.
   */
  ri = ddl_head(prib->pending_routes) ;

  pie = NULL ;

  if (ri == NULL)
    qassert(prib->in_state == ai_next) ;
  else
    qassert(prib == ri->prib) ;

  switch (prib->in_state)
    {
      /* Completed the previous pending route, or never done any.
       *
       * Either way, if we have something to do, proceed, otherwise exit.
       */
      case ai_next:
        if (ri == NULL)
          return false ;                /* all done !   */

        qassert(ri->pending.flags & RINFO_PENDING) ;

        prib->in_attrs = NULL ;         /* none, yet    */

        if (ri->pending.flags & (RINFO_REFUSED | RINFO_WITHDRAWN))
          break ;

        qassert(ri->pending.attr != NULL) ;
        fall_through ;

      /* First step is to establish whether the next hop as it arrived is
       * valid or not.
       */
      case ai_next_hop_valid:
        nhs = bgp_next_hop_in_valid(ri->pending.attr) ;

        if (nhs != nhs_valid)
          {
            if (nhs == nhs_unknown)
              {
                prib->in_state = ai_next_hop_valid ;
                return true  ;              /* no answer, yet       */
              } ;

            qassert(nhs == nhs_invalid) ;

            ri->pending.flags |= RINFO_DENIED ;
            break ;
          } ;

        /* Run the 'in' "global" filter set, if required.
         *
         * Note that we store the result in the prib.  This is so that we do
         * not lose track of it if the bgp_next_hop_in_reachable() returns
         * not available and we exit and re-enter.
         *
         * Note that prib->in_attrs owns a lock on the result of the filtering.
         */
        if (pie == NULL)
          pie = prefix_id_get_entry(ri->pfx_id) ;

        prib->in_attrs = bgp_route_in_filter(prib, ri->pending.attr, pie) ;

        if (prib->in_attrs == NULL)
          {
            /* The route is denied by 'in' filtering.
             */
            ri->pending.flags |= RINFO_DENIED ;
            break ;
          } ;

        fall_through ;

        /* Worry about the reachability of the next-hop, if is not reachable
         * at all at all, then it is denied for all contexts.
         *
         * Also, at this point we make sure we have a set of metrics for the
         * next-hop for all route-contexts.
         */
        case ai_next_hop_reachable:
          nhs = bgp_next_hop_in_reachable(prib->in_attrs) ;

          if (nhs != nhs_reachable)
            {
              if (nhs == nhs_unknown)
                {
                  prib->in_state = ai_next_hop_reachable ;
                  return true  ;              /* no answer, yet       */
                } ;

              qassert((nhs == nhs_unreachable) || (nhs == nhs_invalid)) ;

              prib->in_attrs = bgp_attr_unlock(prib->in_attrs) ;
              ri->pending.flags |= RINFO_DENIED ;
            } ;

          break ;

      default:
        qassert(false) ;

        ri->pending.flags |= RINFO_DENIED ;

        break ;
    } ;

  /* We now have a decision which can be propagated to all route-contexts.
   *
   * Decide whether to withdraw/announce/neither and update pcount_accept.
   */
  withdraw    = ri->pending.flags &
                              (RINFO_DENIED | RINFO_REFUSED | RINFO_WITHDRAWN) ;
  announce    = !withdraw ;
  must_change = false ;

  if (ri->current.flags & (RINFO_DENIED | RINFO_REFUSED | RINFO_WITHDRAWN))
    {
      /* Was not previously accepted -- so is not known to the rib-node.
       *
       * If we are not about to announce, then we need do nothing, in
       * particular there is nothing to withdraw !
       */
      qassert((ri->rn == NULL) && (ri->rindex == SVEC_NULL)) ;

      if (announce)
        ri->prib->pcount_accept += 1 ;
      else
        withdraw    = false ;
    }
  else
    {
      /* Was previously accepted
       *
       * If we are announcing a replacement route, then set must_change if is
       * is_mpls and if the tag is changing -- this forces through a change of
       * current selected route, even if the attributes are unchanged.
       */
      if (withdraw)
        ri->prib->pcount_accept -= 1 ;
      else
        must_change = prib->is_mpls && (ri->current.tags != ri->pending.tags) ;
    } ;

  /* Whatever else happens, now we update the current attributes, and clear
   * down the pending state.
   */
  ri->pending.flags ^= RINFO_PENDING ;  /* prepare for copy to current  */
  ddl_del(prib->pending_routes, ri, plist) ;

  if (ri->current.attr != NULL)
    bgp_attr_unlock(ri->current.attr) ;

  ri->current = ri->pending ;

  memset(&ri->pending, 0, sizeof(iroute_state_t)) ;
  confirm(RINFO_NULL == 0)

  /* Deal with announcing or withdrawing
   *
   * So pick up the rib-node, if any.  Note that only attaches to the rib-node
   * when a route is added.  If we are withdrawing, and we are not attached to
   * a rib-node, then there is not much to be done !
   *
   * Note that when we get to here, we have prib->in_attrs iff we are going
   * to announce (even if that is filtered out).
   */
  rn = ri->rn ;

  if (rn == NULL)
    qassert(ri->rindex == SVEC_NULL) ;
  else
    qassert(ri == svec_get(rn->avail, ri->rindex)) ;

  qassert(announce == (prib->in_attrs != NULL)) ;

  cc = prib->rib->context_count ;
  process = false ;
  if      (announce)
    {
      /* For all current route-contexts, add/update route.
       *
       * The global context receives the current.attr.
       *
       * Other contexts receive
       *
       * If this changes the current selection in any route-context, then we
       * will have to set the rib-node to be processed, later.
       *
       * The route-info should not have more route-context than the rib-node,
       * since if we extend a route-info we extend any related rib-node.
       * However, since we are withdrawing, if the rib-node has no knowledge
       * of of a given context it matters not !
       */
      if (pie == NULL)
        pie = prefix_id_get_entry(ri->pfx_id) ;

      /* Worry about the med_as stuff.
       */
      if      (prib->rib->always_compare_med)
        ri->med_as = BGP_ASN_NULL ;
      else if (prib->rib->confed_compare_med)
        ri->med_as = as_path_left_most_asn(prib->in_attrs->asp) ;
      else
        ri->med_as = as_path_first_simple_asn(prib->in_attrs->asp) ;

      /* If we don't have a rib-node, now is an excellent time to go and
       * get same, and set rindex for this route-info.
       *
       * For both rib-node and route-info, make sure we have all the route
       * contexts we need.
       *
       * It is possible that no routes will actually be added here... if we
       * are (a) not maintaining the "global" table, and (b) all other
       * contexts are filtered out... but that is deemed a remote possibility,
       * and avoiding the creation of the rib-node a small win even in that
       * case.  Also, if this is effectively a withdraw, this does not remove
       * the route-info from the rib-node -- need to do a real withdraw to
       * achieve that.
       */
      if (rn == NULL)
        {
          rn = ri->rn = bgp_rib_node_get(prib->rib, pie) ;

          ri->rindex = svec_add(rn->avail, ri) ;
          svl_append(rn->avail->base, rn->avail, ri->rindex,
                                                          route_info_t, rlist) ;
        }
      else if (rn->context_count < cc)
        rn = ri->rn = bgp_rib_node_extend(rn) ;

      if (ri->context_count < cc)
        ri = bgp_route_info_extend(ri) ;

      /* Deal with the "global" route-context.
       */
      if (bgp_adj_in_update_rc(rn, ri, prib->in_attrs, 0, must_change))
         process = true ;

      /* Deal with any remaining contexts.
       */
      if (cc > 1)
        {
          attr_set rc_in_attrs ;
          uint rc ;

          rc_in_attrs = bgp_route_rc_in_filter(prib, prib->in_attrs, pie) ;

          for (rc = 1 ; rc < cc ; ++rc)
            {
              attr_set rc_attrs ;

              if (rc_in_attrs != NULL)
                rc_attrs = bgp_route_rc_from_to_filter(prib, rc_in_attrs, pie) ;
              else
                rc_attrs = NULL ;

              if (rc_attrs != NULL)
                {
                  if (bgp_adj_in_update_rc(rn, ri, rc_attrs, rc, must_change))
                    process = true ;
                }
              else
                {
                  if (bgp_adj_in_withdraw_rc(rn, ri, rc))
                    process = true ;
                } ;
            } ;

          bgp_attr_unlock(rc_in_attrs) ;
        } ;
    }
  else if (withdraw && (rn != NULL))
    {
      /* For all known route-contexts, remove the route, and detach the
       * route-info from the rib-node.
       *
       * If this changes the current selection in any route-context, then we
       * will have to set the rib-node to be processed, later.
       *
       * The route-info should not have more route-context than the rib-node,
       * since if we extend a route-info we extend any related rib-node.
       * However, since we are withdrawing, if the rib-node has no knowledge
       * of of a given context it matters not !
       */
      uint rc ;

      for (rc = 0 ; rc < cc ; ++rc)
        if (bgp_adj_in_withdraw_rc(rn, ri, rc))
          process = true ;
    } ;

  if (process)
    {
      ri->uptime = bgp_clock() ;
    } ;

  /* Done push state back to ai_next, and forget any in_attrs (to be tidy).
   *
   * If there were any, we transferred in_attrs to the "global" route-context,
   * complete with the lock -- so don't need to worry about that here.
   */
  prib->in_state = ai_next ;
  prib->in_attrs = NULL ;
  return true ;
} ;


static route_merit_t bgp_route_merit(bgp_rib rib, attr_set attr,
                                                                byte sub_type) ;





/*------------------------------------------------------------------------------
 * Update the given route-context's available routes.
 *
 * The available routes are semi-sorted.  The first route is the current
 * selection.  Routes with equal merit can only be distinguished by the
 * rib-node processing.
 *
 * The LS bits of the merit are reserved as markers -- dirty, but cheap.
 *
 * The first route may be marked as RMERIT_CHANGED.  If so, the rib-node
 * should be down-stream of the rib-walker, and the routes need to be
 * scanned to collect all those of equal or greater merit than the first.
 */
static bool
bgp_adj_in_update_rc(bgp_rib_node rn, route_info ri, attr_set attr, uint rc,
                                                               bool must_change)
{
  route_merit_t merit ;
  iroute        ir ;
  bool          add ;
  svs_base      base ;
  route_info    ri_head ;

  qassert(attr != NULL) ;               /* not a withdraw !     */

  /* The route merit may change even if the attributes do not, so we calculate
   * that now.
   */
  merit = bgp_route_merit(rn->it.rib, attr,
                                    bgp_route_subtype(ri->current.route_type)) ;

  /* Update the iroute, if required.
   *
   * If the attributes have changed, swap in the new attributes.
   *
   * If neither attributes nor merit have changed, we are done unless we
   * 'must_change' (eg MPLS tag has changed).
   */
  ir = &ri->iroutes[rc] ;

  add     = false ;
  if (ir->attr != attr)
    {
      /* Honest to god attribute change.
       */
      if (ir->attr != NULL)
        bgp_attr_unlock(ir->attr) ;
      else
        add = true ;                    /* no route before      */

      ir->attr = bgp_attr_lock(attr) ;
      must_change = true ;
    }
  else if ((merit == (ir->merit & route_merit_mask)) && !must_change)
    return false ;

  /* Special case: for the global context we allow the selection of routes
   * to be suppressed.
   */
  if ((rc == 0) && (false))
    {
      ir->merit = merit ;
      return false ;
    } ;

  /* Get the current selection -- if any.
   *
   * NB: need to look out for the base being SVEC_INDEX_MAX, which signals
   *     a list which is empty because the last available route has been
   *     withdrawn.
   */
  base = &rn->iroute_bases[rc] ;

  if (*base != SVEC_INDEX_MAX)
    ri_head = svs_head(base, rn->avail) ;
  else
    {
      /* Special case -- nothing on the list, which we can now normalise.
       */
      ri_head = NULL ;
      *base   = SVEC_NULL ;
    } ;

  /* If we are already the selected route, then worry about change of merit.
   *
   * If the merit has reduced, then need to re-scan for possible change of
   * selection.
   *
   * If the merit is unchanged, we may be here because MEDs or IGP have
   * changed, so need to rescan.
   *
   * If the merit has increased, then there is no need to worry !  But do
   * need to preserve RMERIT_CHANGED if was set, and need to set it if
   * 'must_change'.
   */
  if (ri == ri_head)
    {
      route_merit_t merit_was ;
      bool changed ;

      qassert(!add) ;

      merit_was = ir->merit ;

      changed = (merit <= (merit_was & route_merit_mask)) ||
                (merit_was & RMERIT_CHANGED) ||
                must_change ;

      if (changed)
        merit |= RMERIT_CHANGED ;

      ir->merit = merit ;

      return changed ;
    } ;

  /* We are not the selected route.
   *
   *
   *
   * If the list is not empty, worry about what impact this route has.
   */
  if (ri_head == NULL)
    qassert(add) ;
  else
    {
      iroute        ir_head ;
      route_merit_t merit_head ;

      ir_head    = &ri_head->iroutes[rc] ;
      merit_head = ir_head->merit ;

      if (merit <= (merit_head & route_merit_mask))
        {
          /* The new route has merit which is less than or equal to the current
           * anointed.
           *
           * Set the merit and if not already on the list, add it.
           *
           * Note that the current selection remains the first on the list,
           * where it will take priority if everything else is equal.
           */
          ir->merit = merit ;

          if (add)
            svs_in_after(ri_head->rindex, base, rn->avail, ri->rindex,
                                               route_info_t, iroutes[rc].list) ;

          /* If the new route has less merit than the current anointed, then
           * we are done, and no processing is required.
           */
          if (merit < (merit_head & route_merit_mask))
            return false ;

          /* Have added a route with merit equal to the current anointed,
           * so set it changed so that rib-node processing will sort it out.
           */
          ir_head->merit = merit_head | RMERIT_CHANGED ;
          return true ;
        } ;

      /* The new route has greater merit than the current anointed.
       *
       * Clear any CHANGED flag on on the current anointed, and if is not
       * already on the list, take it off so can become the anointed one.
       */
      if (merit_head & RMERIT_CHANGED)
        ir_head->merit = merit_head ^ RMERIT_CHANGED ;

      if (!add)
        svs_del(base, rn->avail, ri->rindex, route_info_t, iroutes[rc].list) ;
    } ;

  /* New selection.
   */
  ir->merit = merit | RMERIT_CHANGED ;

  svs_push(base, rn->avail, ri->rindex, route_info_t, iroutes[rc].list) ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Calculate the merit of the given route
 *
 * Merit is RFC4271's "Phase 1: Degree of Preference", plus the first two
 * steps of the "Phase 2: Breaking Ties".  It includes:
 *
 *    1. weight     -- "preconfigured system policy"
 *
 *    2. Local_Pref -- from iBGP/cBGP peer and/or "preconfigured system policy"
 *
 *    3. Local Routes (internally sourced) take precedence over Peer Routes
 *
 *    4. AS-Path length
 *
 *    5. ORIGIN Attribute
 *
 * NB: the merit depends mostly on the attributes, but also on:
 *
 *       * default local_pref
 *
 *       * BGP_FLAG_ASPATH_IGNORE and BGP_FLAG_ASPATH_CONFED
 */
static route_merit_t
bgp_route_merit(bgp_rib rib, attr_set attr, byte sub_type)
{
  route_merit_t merit, temp ;

#define ROUTE_MERIT_MASK(n) (((route_merit_t)1 << n) - 1)

  /* 1. attr->weight   -- RFC4271 9.1.1, "preconfigured policy".
   *
   *    By the time we get to here, the weight has either been set to some
   *    default (depending on Local Route-ness) or explicitly by route-map.
   *
   *    We mask this as a matter of form, the compiler should eliminate it.
   */
  temp  = attr->weight & ROUTE_MERIT_MASK(route_merit_weight_bits) ;
  merit = temp << route_merit_weight_shift ;

  /* 2. Local Preference -- RFC4271 9.1.1.
   *
   *    This is the LOCAL_PREF attribute from iBGP/cBGP peer and/or
   *    "preconfigured policy".
   *
   *    By the time we get to here, the Local Pref may have been set by
   *    Route-Map.
   *
   *    TODO... perhaps could set the default in the original attribute set...
   *                               ... but lots of work if default changes !!??
   */
  if (attr->have & atb_local_pref)
    temp = attr->local_pref & ROUTE_MERIT_MASK(route_merit_local_pref_bits) ;
  else
    temp = rib->default_local_pref
                            & ROUTE_MERIT_MASK(route_merit_local_pref_bits) ;

  merit |= temp << route_merit_local_pref_shift ;

  /* 3. Local Route State  -- RFC4271 9.1.1, "preconfigured policy"
   *
   *    All local routes have greater merit than normal routes (learned from
   *    peers.  They also have no path length and no origin.
   *
   *    Definitely "preconfigured policy".
   */
  if (sub_type != BGP_ROUTE_NORMAL)
    return merit | (route_merit_as_path_max << route_merit_as_path_shift) ;

  /* 4. ~AS-PATH Length   -- RFC4271 9.1.2.2 (a) -- Breaking Ties (Phase 2).
   *
   *    If, for some crazy reason, the AS-PATH is beyond what we have bits
   *    for, we leave the field as 0 -- least possible merit.
   */
  if (!rib->aspath_ignore)
    {
       if (rib->aspath_confed)
         temp = as_path_total_path_length (attr->asp);
       else
         temp = as_path_simple_path_length (attr->asp) ;

       if (temp < route_merit_as_path_max)
         merit |= (route_merit_as_path_max - 1 - temp)
                                                 << route_merit_as_path_shift ;
     } ;

  /* 5. ~Origin   -- RFC4271 9.1.2.2 (b) -- Breaking Ties (Phase 2).
   *
   *   The origin will fit, unless there is an invalid value -- which is
   *   treated as no merit !
   */
  confirm(BGP_ATT_ORG_MAX < ROUTE_MERIT_MASK(route_merit_origin_bits)) ;

  if (attr->origin < ROUTE_MERIT_MASK(route_merit_origin_bits))
    merit |= (attr->origin ^ ROUTE_MERIT_MASK(route_merit_origin_bits))
                                                   << route_merit_origin_shift ;

  return merit ;

#undef ROUTE_MERIT_MASK
} ;

/*------------------------------------------------------------------------------
 * Withdraw one of the given route-context's available routes, if any.
 */
static bool
bgp_adj_in_withdraw_rc(bgp_rib_node rn, route_info ri, uint rc)
{
  iroute     ir ;
  svs_base   base ;
  route_info ri_head ;

  ir = &ri->iroutes[rc] ;

  if (ir->attr == NULL)
    return false ;                      /* already withdrawn    */

  ir->attr  = bgp_attr_unlock(ir->attr) ;
  ir->merit = route_merit_none ;        /* tidy                 */

  if (rn->context_count <= rc)
    return false ;                      /* not know to rib-node */

  /* We are withdrawing a route which we believe to be known.
   *
   * If this is the "global" context it is possible that the route has not
   * been put into the RIB -- in which case the list of iroutes will, in fact,
   * be empty.
   */
  base    = &rn->iroute_bases[rc] ;
  ri_head = svs_head(base, rn->avail) ;

  if (ri_head != NULL)
    svs_del(base, rn->avail, ri->rindex, route_info_t, iroutes[rc].list) ;
  else
    qassert((rc == 0) && false) ;

  if (ri != ri_head)
    return false ;

  /* We have just removed the currently selected route for this context -- so
   * will need to re-process the rib-node.
   *
   * We mark the new head of the available routes with RMERIT_CHANGED.  But if
   * there are (now) no available routes, we have to set SVEC_INDEX_MAX to
   * signal the state.
   */
  ri_head = svs_head(base, rn->avail) ;

  if (ri_head != NULL)
    ri_head->iroutes[rc].merit |= RMERIT_CHANGED ;
  else
    *base = SVEC_INDEX_MAX ;

  return true ;
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
bgp_adj_in_discard(peer_rib prib, bgp_rib_type_t rib_type)
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

          bgp_adj_in_update(prib->peer, parcel, false) ;
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

  if (prib->adj_in != NULL)
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

