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
#include "bgpd/bgpd.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_rcontext.h"
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
 * Create new, empty adj_in, and initialise related fields:
 *
 *   * adj_in           -- set to a new, empty ihash.
 *   * stale_routes     -- NULLs        -- none, yet
 *   * pending_routes   -- NULLs        -- none, yet
 *   * in_state         -- ai_next
 *   * in_attrs         -- NULL         -- none, yet
 */
extern void
bgp_adj_in_init(bgp_prib prib)
{
  /* Set up an empty adj_in -- indexed by prefix_id
   */
  prib->adj_in = ihash_table_new(200, 50) ;

  /* For completeness, clear the related fields.
   */
  ddl_init(prib->stale_routes) ;
  ddl_init(prib->pending_routes) ;
  prib->in_state = ai_next ;
  prib->in_attrs = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Empty out all adj_out elements in the given peer_rib.
 *
 *
 */
extern void
bgp_adj_in_reset(bgp_prib prib)
{

} ;


/*==============================================================================
 * Route_Info operations.
 */
static void bgp_adj_in_withdraw_lc(bgp_rib_node rn, route_info ri,
                                                               bgp_lc_id_t lc) ;

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
bgp_route_info_new(bgp_prib prib, prefix_id_entry pie)
{
  route_info ri ;
  uint       lcc ;

  lcc = prib->rib->local_context_count ;

  ri = XCALLOC(MTYPE_BGP_ROUTE_INFO, offsetof(route_info_t, iroutes[lcc])) ;

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
   *    * local_context_count         -- X         -- set below
   *    * iroutes.list          -- SVEC_NULLs
   *             .attr          -- NULL                 -- signals no route
   *             .merit         -- route_merit_none     -- signals no route
   */
  confirm(SVEC_NULL           == 0) ;
  confirm(RINFO_NULL          == 0) ;
  confirm(bgp_route_type_null == 0) ;
  confirm(mpls_tags_null      == 0) ;
  confirm(route_merit_none    == 0) ;

  ri->prib       = prib ;
  ri->pfx_id     = pie->id ;

  ri->current.flags = RINFO_WITHDRAWN ;
  ri->current.qafx  = prib->qafx ;
  ri->pending.qafx  = prib->qafx ;

  ri->local_context_count = lcc ;

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
  uint       lcc ;

  lcc = ri->prib->rib->local_context_count ;

  if (ri->local_context_count >= lcc)
    return ri ;

  /* We do need a new route-info, so make one and copy the old route_info
   * to it.
   */
  ri_new = XCALLOC(MTYPE_BGP_ROUTE_INFO, offsetof(route_info_t, iroutes[lcc])) ;

  memcpy(ri_new, ri, offsetof(route_info_t, iroutes[ri->local_context_count])) ;

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
   *    * local_context_count      -- needs to be set to new value, see below
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

  ri_new->local_context_count = lcc ;

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
 * If this is called during a 'ream' of the adj-in, then the prefix has already
 * been removed from the adj-in.  Otherwise, need to remove it here.
 */
extern route_info
bgp_route_info_free(route_info ri, bool remove)
{
  bgp_prib     prib ;
  bgp_rib_node rn ;

  prib = ri->prib ;

  /* If required, remove from the adj-in.
   */
  if (remove)
    ihash_del_item(prib->adj_in, ri->pfx_id, NULL) ;

  /* If this is associated with the respective bgp_rib_node, now is the time
   * to disassociate and withdraw the route.
   */
  rn = ri->rn ;

  qassert((rn == NULL) == (ri->rindex == SVEC_NULL)) ;

  if (rn != NULL)
    {
      bgp_lc_id_t  lc ;

      rn->has_changed = false ;

      for (lc = lc_view_id ; lc < ri->local_context_count ; ++lc)
        bgp_adj_in_withdraw_lc(rn, ri, lc) ;

      svec_del(rn->avail, ri->rindex) ;

      if (rn->has_changed)
        bgp_rib_process_schedule(rn) ;
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

  /* Now we can reduce the reference count on the related prefix-id, free the
   * object and return NULL.
   */
  prefix_id_dec_ref(ri->pfx_id) ;
  XFREE(MTYPE_BGP_ROUTE_INFO, ri) ;

  return NULL ;
} ;

/*==============================================================================
 * Incoming UPDATE processing.
 */
static void bgp_adj_in_update_lc(bgp_rib_node rn, route_info ri, attr_set attr,
                                              bgp_lc_id_t lc, bool tag_change) ;
static void bgp_adj_in_changed_lc(bgp_rib_node rn, bgp_lc_id_t lc,
                                                                  bool change) ;
static route_merit_t bgp_route_merit(bgp_rib rib, attr_set attr,
                                                                byte sub_type) ;
static void bgp_route_info_process_schedule(route_info ri) ;

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
bgp_adj_in_update_prefix(bgp_prib prib, prefix_id_entry pie,
                                          iroute_state parcel, mpls_tags_t tags)
{
  route_info      ri ;

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
   * Note that we count routes which are "refused", even though we will later
   * treat those as withdrawn.
   *
   * If the count goes up, look out for max prefix.
   */
  if (parcel->route_type == bgp_route_type_normal)
    {
      bool  was_counted ;

      if (ri == NULL)
        was_counted = false ;
      else if (ri->pending.flags & RINFO_PENDING)
        was_counted = !(ri->pending.flags & RINFO_WITHDRAWN) ;
      else
        was_counted = !(ri->current.flags & (RINFO_WITHDRAWN | RINFO_STALE)) ;

      if (parcel->flags & RINFO_WITHDRAWN)
        {
          if (was_counted)
            {
              qassert(prib->pcount_recv != 0) ;
              prib->pcount_recv -= 1 ;
            } ;
        }
      else
        {
          if (!was_counted)
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
            zlog (prib->prun->log, LOG_DEBUG,
                       "%s withdraw for unknown route %s",
                                    prib->prun->name, spfxtoa(pie->pfx).str) ;

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
            zlog (prib->prun->log, LOG_DEBUG,
                 "%s route for %s withdrawn before previous update processed",
                                    prib->prun->name, spfxtoa(pie->pfx).str) ;
        }
      else
        {
          zlog (prib->prun->log, LOG_DEBUG,
                     "%s withdraw for already withdrawn route %s",
                                    prib->prun->name, spfxtoa(pie->pfx).str) ;
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
   * At this (final) moment we embed any tags required in the pending.attr,
   * so that from now on we don't worry about them.
   *
   * Whatever flags have been passed, make sure we keep only those which are
   * relevant, and set RINFO_PENDING.
   */
  ri->pending = *parcel ;

  if (ri->pending.attr != NULL)
    {
      if (ri->pending.attr->tags == tags)
        bgp_attr_lock(ri->pending.attr) ;
      else
        ri->pending.attr = bgp_attr_set_tags(ri->pending.attr, tags) ;
    } ;

  ri->pending.flags = (parcel->flags & (RINFO_REFUSED | RINFO_WITHDRAWN))
                                                               | RINFO_PENDING ;

  qassert((ri->pending.attr == NULL) == (ri->pending.flags & RINFO_WITHDRAWN)) ;

  /* Boot the work queue for this adj-in/prib....
   */
  bgp_route_info_process_schedule(ri) ;
} ;

/*------------------------------------------------------------------------------
 * Refresh the given adj-in entry.
 *
 * Do nothing if:
 *
 *   * there is a pending route change already.
 *
 *   * the current is RINFO_WITHDRAWN, RINFO_STALE or RINFO_REFUSED
 *
 * Otherwise, set the pending as copy of the current, and set the entry pending
 * processing.
 */
static void
bgp_adj_in_refresh_route(bgp_prib prib, route_info ri)
{
  if (ri->pending.flags & RINFO_PENDING)
    return ;

  if (ri->current.flags & (RINFO_STALE | RINFO_REFUSED | RINFO_WITHDRAWN))
    return ;

  /* Set the current as pending.
   */
  ri->pending       = ri->current ;
  ri->pending.flags = RINFO_PENDING ;

  qassert(ri->pending.attr != NULL) ;
  bgp_attr_lock(ri->pending.attr) ;

  ddl_append(prib->pending_routes, ri, plist) ;

  /* Boot the work queue for this adj-in/prib....
   */
  bgp_route_info_process_schedule(ri) ;
} ;

/*------------------------------------------------------------------------------
 * Schedule the given route-info for processing into the adj-in.
 */
static void
bgp_route_info_process_schedule(route_info ri)
{
  // TODO !!!;
} ;

/*------------------------------------------------------------------------------
 * Work queue action for prib adj-in -- process route into RIB.
 *
 * Processes the head of the prib->pending_routes.
 *
 * Returns:  true <=> successfully processed one pending route.
 *           false => no pending routes or waiting for some external event.
 *
 * TODO aggregate stuff
 */
static bool
bgp_adj_in_process(bgp_prib prib)
{
  route_info        ri ;
  prefix_id_entry   pie ;
  next_hop_state_t  nhs ;
  bool              withdraw, announce, must_change ;
  bgp_rib_node      rn ;
  bgp_lc_id_t       lcc ;

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

        /* Run the 'in' "view" filter set, if required.
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
   * Decide whether to withdraw/announce/neither and update pcount_in.
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
        ri->prib->pcount_in += 1 ;
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
        ri->prib->pcount_in -= 1 ;
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

  rn->has_changed = false ;
  lcc = prib->rib->local_context_count ;
  if      (announce)
    {
      /* For all current route-contexts, add/update route.
       *
       * The view context receives the prib->in_attrs, if any.
       *
       * Other contexts receive the prib->in_attrs after:
       *
       *   a) the rc_in filter -- extension to the "view" 'in' filter, common
       *      to all local contexts.
       *
       *   b) the rc_in_from and rc_in_to filters, as required for each
       *      local context.
       *
       * If this changes the current selection in any route-context, then we
       * will have to set the rib-node to be processed, later.
       *
       * The route-info should not have more route-context than the rib-node,
       * since if we extend a route-info we extend any related rib-node.
       * However, since we are withdrawing, if the rib-node has no knowledge
       * of of a given context it matters not !
       */
      svec4_t*  lc_map ;

      if (pie == NULL)
        pie = prefix_id_get_entry(ri->pfx_id) ;

      /* Worry about the med_as stuff.
       */
      if      (prib->rib->rp.do_always_compare_med)
        ri->med_as = BGP_ASN_NULL ;
      else if (prib->rib->rp.do_confed_compare_med)
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
       * are (a) not maintaining the "view" table, and (b) all other
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
      else if (rn->local_context_count < lcc)
        rn = ri->rn = bgp_rib_node_extend(rn) ;

      if (ri->local_context_count < lcc)
        ri = bgp_route_info_extend(ri) ;

      /* Deal with the "view" route-context, which receives all routes from
       * all contexts.
       */
      bgp_adj_in_update_lc(rn, ri, prib->in_attrs, lc_view_id, must_change) ;

      /* Deal with any remaining contexts -- note that if the source is
       * in the view context, its routes are not advertised to any other
       * context.
       */
      lc_map = prib->rib->lc_map ;

      if ((prib->lc_id != lc_view_id) && (lc_map->base->head != SVEC_NULL))
        {
          /* Process from the prib's local context to all other local
           * contexts.
           *
           * Noting that for a route-server client, we do not process into
           * its own context !
           */
          attr_set      rc_in_attrs ;
          bgp_lcontext  lc_to, lc_from ;

          rc_in_attrs = bgp_route_inx_filter(prib, prib->in_attrs, pie) ;

          lc_from = svec_get(lc_map, prib->lc_id) ;
          for (lc_to = svl_head(lc_map->base, prib->rib->lc_map) ;
               lc_to != NULL ;
               lc_to = svl_next(lc_to->lcs, lc_map))
            {
              attr_set rc_attrs ;

              if (prib->rp.is_route_server_client && (lc_from->id == lc_to->id))
                continue ;

              if (rc_in_attrs != NULL)
                rc_attrs = bgp_route_rc_to_from_filter(lc_from, rc_in_attrs,
                                                                   pie, lc_to) ;
              else
                rc_attrs = NULL ;

              if (rc_attrs != NULL)
                bgp_adj_in_update_lc(rn, ri, rc_attrs, lc_to->id, must_change) ;
              else
                bgp_adj_in_withdraw_lc(rn, ri, lc_to->id) ;
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
      bgp_lc_id_t lc ;

      for (lc = lc_view_id ; lc < lcc ; ++lc)
        bgp_adj_in_withdraw_lc(rn, ri, lc) ;
    } ;

  ri->uptime = bgp_clock() ;

  if (rn->has_changed)
    bgp_rib_process_schedule(rn) ;

  /* Done push state back to ai_next, and forget any in_attrs (to be tidy).
   *
   * If there were any, we transferred in_attrs to the "global" route-context,
   * complete with the lock -- so don't need to worry about that here.
   */
  prib->in_state = ai_next ;
  prib->in_attrs = NULL ;
  return true ;
} ;

/*------------------------------------------------------------------------------
 * Update the given route-context's available routes.
 *
 * The available routes are semi-sorted.  The first route is the current
 * selection unless that is to be replaced.  Routes with equal merit can only
 * be distinguished by the rib-node processing.
 *
 * The LS bits of the merit are reserved as markers -- dirty, but cheap.
 *
 * By semi-sorted we mean that any route which is not marked as RMERIT_UNSORTED
 * is definitely of greater or equal merit to any route after it -- whether
 * or not those routes are sorted or unsorted.  So, unless the first route
 * is UNSORTED, the first route has the greatest merit, and as routes arrive
 * the route with the greatest merit will occupy the first entry.
 *
 * We need to keep track of the current selection.  We need to do this while
 * routes are added, taken away and changed -- including the current
 * selection -- and this may happen many time before a new selection is
 * actually made.  The current selection is *always* the head of the list.
 * If the head of the list is not marked RMERIT_SELECTED, either there is
 * no selection, or the current selection has been withdrawn and its
 * replacement is yet to be installed.  This means that if the head is
 * selected, routes can only be added after it, even if that means they
 * are out of order.  This is a compromise, to avoid having to chase down
 * the list of routes to find (and clear) the current selection (if it has not
 * been withdrawn).
 *
 * If the rib_node candidates have changed such that the rib_node needs to be
 * processed, the rn->has_changed flag is set.
 */
static void
bgp_adj_in_update_lc(bgp_rib_node rn, route_info ri, attr_set attr,
                                               bgp_lc_id_t lc, bool must_change)
{
  route_merit_t merit, merit_was ;
  svs_base      base ;
  iroute        ir ;
  route_info    ri_head ;

  qassert(attr != NULL) ;               /* not a withdraw !     */

  /* The route merit may change even if the attributes do not, so we calculate
   * that now.
   */
  merit = bgp_route_merit(rn->it.rib, attr,
                                    bgp_route_subtype(ri->current.route_type)) ;
  qassert(merit != route_merit_none) ;

  /* Update the iroute, if required.
   *
   * If the attributes have changed, swap in the new attributes.
   *
   * Set the new merit -- assuming no flags are required.
   *
   * If neither attributes nor merit have changed, we are done unless we
   * 'must_change' (eg MPLS tag or IGP metric has changed) -- the MEDs are
   * part of the attributes.
   */
  ir = &ri->iroutes[lc] ;

  merit_was = ir->merit ;
  ir->merit = merit ;

  qassert((ir->attr == NULL) == (ir->merit == route_merit_none)) ;

  if (ir->attr != attr)
    {
      /* Honest to god attribute change.
       */
      if (ir->attr != NULL)
        bgp_attr_unlock(ir->attr) ;

      ir->attr = bgp_attr_lock(attr) ;
      must_change = true ;
    }
  else if ((merit == (merit_was & route_merit_mask)) && !must_change)
    return ;

  /* Set the new merit, preserving flags.
   */
  ir->merit = merit | (merit_was & ~route_merit_mask) ;

  /* Special case: for the global context we allow the selection of routes
   * to be suppressed.
   */
  if ((lc == 0) && (false))
    return ;

  /* Get the head of the list -- the current anointed -- if any.
   *
   * When the rib-node is processed, the anointed is also the currently
   * selected route.  In what follows, if it is RMERIT_SELECETED, the head
   * of the list remains the head.
   */
  base = rn->aroutes[lc].base ;

  ri_head = svs_head(base, rn->avail) ;

  /* If we are at the head we may be the selected and:
   *
   *   * if the merit has reduced, then may need to process the rib-node.
   *
   *   * if the merit is unchanged, we may be here because MEDs or IGP have
   *     changed, and for that reason process the rib-node.
   *
   *   * if the merit has increased, then nothing has changed unless
   *     'must_change'.
   *
   * Note that whatever happens, the head does not change, whether or not it is
   * RMERIT_SELECTED.
   */
  if (ri == ri_head)
    {
      svec_index_t  is_next ;
      route_info    ri_next ;
      iroute        ir_next ;
      route_merit_t merit_next ;

      qassert(merit_was != route_merit_none) ;

      /* If there are no more routes, then not much has changed !
       */
      is_next = ir->list->next ;

      if (is_next == SVEC_NULL)
        return bgp_adj_in_changed_lc(rn, lc, must_change) ;

      /* If was unsorted, it is still unsorted, and we signal change -- which
       * should be redundant !
       *
       * This is a special case... the rule is that a sorted route is greater
       * than or equal to any route which follows.  If the first route is
       * unsorted, there are no preceding routes to worry about, and it does
       * not matter how its merit compares to any routes which follow.
       */
      if (merit_was & RMERIT_UNSORTED)
        return bgp_adj_in_changed_lc(rn, lc, true) ;

      /* There is at least one other route.
       *
       * The current head is sorted, so all further routes were <= current head.
       * So, if the new merit is greater than the previous merit, then it is
       * now the greatest !
       */
      if (merit > (merit_was & route_merit_mask))
        return bgp_adj_in_changed_lc(rn, lc, must_change) ;

      /* The current head's merit is unchanged or less than it was.
       *
       * Consider the merit of the next route -- if that is UNSORTED, then
       * we do not know where we are any more, and must process the node.
       */
      ri_next = svec_get(rn->avail, is_next) ;
      ir_next = &ri_next->iroutes[lc] ;
      merit_next = ir_next->merit ;

      if (merit_next & RMERIT_UNSORTED)
        {
          ir->merit |= RMERIT_UNSORTED ;
          return bgp_adj_in_changed_lc(rn, lc, true) ;
        } ;

      /* The next route is not UNSORTED, so all further routes are <= next,
       * so:
       *
       *   if the new merit is greater than that, then nothing has changed.
       *
       *   if the new merit is less than that, the current is now unsorted (!)
       *   and we need to process the rib-node.
       *
       *   if the new merit is equal to that, need to process the rib-node to
       *   deal with possible MED changes.
       */
      if (merit > (merit_next & route_merit_mask))
        return bgp_adj_in_changed_lc(rn, lc, must_change) ;

      if (merit < (merit_next & route_merit_mask))
        ir->merit |= RMERIT_UNSORTED ;

      return bgp_adj_in_changed_lc(rn, lc, true) ;
    } ;

  /* We are not the head, and hence not the selected route.
   *
   * If the list is not empty, worry about what impact this route has.
   */
  if      (ri_head == NULL)
    qassert(merit_was == route_merit_none) ;
  else
    {
      /* The list is not currently empty.
       */
      iroute        ir_head ;
      route_merit_t merit_head ;

      ir_head    = &ri_head->iroutes[lc] ;
      merit_head = ir_head->merit ;

      if (merit_was != route_merit_none)
        {
          /* We are changing an existing route, but not the current selection.
           */
          if (merit < (merit_was & route_merit_mask))
            {
              /* Reducing the route's merit.
               *
               * If was UNSORTED, it still is UNSORTED and we are done.
               *
               * Otherwise, we consider the next route on the list, if any.
               */
              route_info    ri_next ;
              iroute        ir_next ;
              route_merit_t merit_next ;

              if (merit_was & RMERIT_UNSORTED)
                return ;

              /* If there is no next route, we have just reduced the merit of
               * the last route, so there is nothing more to be done.
               */
              ri_next = svs_next(ir->list, rn->avail) ;

              if (ri_next == NULL)
                return ;

              /* If the next route is UNSORTED, we have no information about
               * any subsequent routes, so we simply set this one UNSORTED
               * as well, and have done.
               *
               * Neither this nor the next are UNSORTED.  So, if this is
               * still greater than or equal to the next, we are done,
               * otherwise, we need to set this one UNSORTED and then we
               * are done.
               */
              ir_next    = &ri_next->iroutes[lc] ;
              merit_next = ir_next->merit ;

              if ((merit_next & RMERIT_UNSORTED) ||
                                      ((merit_next & route_merit_mask) > merit))
                ir->merit |= RMERIT_UNSORTED ;

              return ;
            }
          else if (merit == (merit_was & route_merit_mask))
            {
              /* We are not changing the route's merit, so not much is
               * happening.
               *
               * If was UNSORTED before, then it is still UNSORTED.
               *
               * If is same merit as the current selection, then need to
               * process the rib-node, in case MEDs have changed.
               */
              return bgp_adj_in_changed_lc(rn, lc,
                                   (merit == (merit_head & route_merit_mask))) ;
            }
          else
            {
              /* Increasing the route's merit, so we need to consider the
               * previous route on the list.
               */
              route_info    ri_prev ;
              iroute        ir_prev ;
              route_merit_t merit_prev ;

              ri_prev    = svs_prev(ir->list, rn->avail) ;
              ir_prev    = &ri_prev->iroutes[lc] ;
              merit_prev = ir_prev->merit ;

              qassert(ri_prev != NULL) ;

              if (merit <= (merit_prev & route_merit_mask))
                {
                  /* New merit does not exceed previous's merit.  So, nothing
                   * has changed unless the new merit is the same as the
                   * current selection.  Note:
                   *
                   *   * this route's merit has increased, so whether it
                   *     is sorted or not, it is still better than any
                   *     route which follows.
                   *
                   *   * if this and the previous are both sorted, then they
                   *     remain so.
                   *
                   *   * whether or not the previous route is sorted, it is
                   *     less than or equal to any preceding sorted routes,
                   *     so this (new) merit is also less than or equal to
                   *     any preceding sorted routes.
                   *
                   * If was UNSORTED then still is.
                   */
                  return bgp_adj_in_changed_lc(rn, lc,
                                   (merit == (merit_head & route_merit_mask))) ;
                } ;

              /* The new, greater, merit exceeds that of the previous.
               *
               * If the previous is the head, and is RMERIT_SELECTED, then we
               * are forced to leave the route where it is, but force the
               * head to RMERIT_UNSORTED, and set changed.
               *
               * Also, if the head is RMERIT_UNSORTED there is no point moving
               * the current
               *
               * This is where we preserve the rule that if there is a
               * selected route, it is the head of the list.
               */
              if ((ri_prev == ri_head) && (merit_head & RMERIT_SELECTED))
                {
                  ir_head->merit |= RMERIT_UNSORTED ;

                  return bgp_adj_in_changed_lc(rn, lc, true) ;
                } ;

              /* The new, greater, merit exceeds the previous, and may
               * exceed the head -- but we are not immediately after the
               * head.
               *
               * In this case we do not know whether there are any sorted
               * routes before the previous or how the new merit compares
               * with those -- so we have to promote this route.
               *
               * Note that it does not matter whether the previous is sorted
               * or not.
               */
              svs_del(base, rn->avail, ri->rindex, route_info_t,
                                                             iroutes[lc].list) ;
            } ;
        } ;

      /* We are adding a new route, or we are promoting an existing, one, which
       * has been removed from the list.
       *
       * There is at least one other route.
       *
       *   * if new route's merit is == current head, add after the
       *     current head, also not unsorted -- signal change.
       *
       *   * if new route's merit is < current head, consider the next
       *     after the current:
       *
       *       * if there is none, add after the current head, not
       *         UNSORTED and there is no change.
       *
       *       * if the next is unsorted, add after it, unsorted, but no
       *         change.
       *
       *       * if the next is <= new, add after the current head,
       *         not UNSORTED and no change.
       *
       *       * if the next is > new, add after it, UNSORTED unless is now the
       *         last (!).
       *
       *   * if new route's merit > current head, add at the front, also
       *     not unsorted -- signal change.
       */
      if (merit <= (merit_head & route_merit_mask))
        {
          /* The new route has merit which is less than or equal to the current
           * head -- so we are definitely adding it after the head, so need not
           * worry about RMERIT_SELECTED.
           */
          route_info    ri_next ;
          iroute        ir_next ;
          route_merit_t merit_next ;

          /* Add new route after the current head.
           *
           * Note that the current head remains the first on the list,
           * where it will take priority if everything else is equal.
           */
          svs_in_after(ri_head->rindex, base, rn->avail, ri->rindex,
                                               route_info_t, iroutes[lc].list) ;

          /* If this has same merit as current head, signal that rib-node
           * needs to be processed.
           */
          if (merit == (merit_head & route_merit_mask))
            return bgp_adj_in_changed_lc(rn, lc, true) ;

          /* If the new route has merit less than the current head, so
           * there is no change -- but we need to consider the next route.
           */
          ri_next = svs_next(ir->list, rn->avail) ;

          /* If there is no next route, we have just added a route of less
           * merit than the current head and it was the only route.
           */
          if (ri_next == NULL)
            return ;

          /* If the next route is UNSORTED, we have no information about
           * any subsequent routes, so we simply set this one UNSORTED
           * as well, and have done.
           *
           * Neither this nor the next are UNSORTED.  So, if this is greater
           * than or equal to the next, we are done.  Otherwise, we need to set
           * this one UNSORTED and then we are done.
           */
          ir_next    = &ri_next->iroutes[lc] ;
          merit_next = ir_next->merit ;

          if ((merit_next & RMERIT_UNSORTED) ||
                                  (merit < (merit_next & route_merit_mask)))
            ir->merit |= RMERIT_UNSORTED ;

          return ;
        } ;

      /* We have a new route with merit greater than the current head.
       *
       * If the current head is RMERIT_SELECTED, then we have no choice, and
       * must insert after it, setting the head RMERIT_UNSORTED.  If the
       * current head was already RMERIT_UNSORTED, then the new route is
       * too !
       *
       * If the current head is not RMERIT_SELECTED, then can insert in front
       * of it !
       */
     if (merit_head & RMERIT_SELECTED)
       {
         ir_head->merit |= RMERIT_UNSORTED ;
         if (merit_head & RMERIT_UNSORTED)
           ir->merit    |= RMERIT_UNSORTED ;

         svs_in_after(ri_head->rindex, base, rn->avail, ri->rindex,
                                             route_info_t, iroutes[lc].list) ;

         return bgp_adj_in_changed_lc(rn, lc, true) ;
                                       /* should be redundant  */
       } ;
    } ;

  /* New head -- insert at front, not UNSORTED and not SELECTED.
   */
  svs_push(base, rn->avail, ri->rindex, route_info_t, iroutes[lc].list) ;

  return bgp_adj_in_changed_lc(rn, lc, true) ;
} ;

/*------------------------------------------------------------------------------
 * Withdraw one of the given route-context's available routes, if any.
 *
 * If the rib-node changes, such that it should be processed, rn->has_changed
 * will be set.
 */
static void
bgp_adj_in_withdraw_lc(bgp_rib_node rn, route_info ri, bgp_lc_id_t lc)
{
  iroute     ir ;
  svs_base   base ;
  route_info ri_head ;

  ir = &ri->iroutes[lc] ;

  if (ir->attr == NULL)
    {
      qassert(ir->merit == route_merit_none) ;
      return ;                          /* already withdrawn for lc     */
    } ;

  ir->attr  = bgp_attr_unlock(ir->attr) ;
  ir->merit = route_merit_none ;        /* required                     */

  if (rn->local_context_count <= lc)
    return ;                            /* not known to rib-node        */

  /* We are withdrawing a route which we believe to be known.
   *
   * If this is the "global" context it is possible that the route has not
   * been put into the RIB -- in which case the list of aroutes will, in fact,
   * be empty.
   */
  base    = rn->aroutes[lc].base ;
  ri_head = svs_head(base, rn->avail) ;

  if (ri_head != NULL)
    svs_del(base, rn->avail, ri->rindex, route_info_t, iroutes[lc].list) ;
  else
    qassert((lc == 0) && false) ;

  /* If we are withdrawing the head of the routes, we are most likely
   * changing something !  It is possible that the head is already changed,
   * and possibly marked RMERIT_UNSORTED, but that will fall out in the wash.
   */
  return bgp_adj_in_changed_lc(rn, lc, (ri == ri_head)) ;
} ;

/*------------------------------------------------------------------------------
 * Set the given local-context as changed, if required and not already set.
 */
static void
bgp_adj_in_changed_lc(bgp_rib_node rn, bgp_lc_id_t lc, bool changed)
{
  if (changed && (rn->aroutes[lc_view_id].next == lc_id_null))
    {
      bgp_lc_id_t lc_head ;

      lc_head = rn->changed->head ;

      if      (lc_head == lc_end_id)
        {
          /* List is empty, so insert at head and set tail !
           */
          rn->changed->head         = lc ;
          rn->changed->tail         = lc ;
          rn->aroutes[lc_view_id].next = lc_end_id ;
        }
      else if (lc == lc_view_id)
        {
          /* We place the "view" at the head of the list, always.
           */
          rn->changed->head            = lc_view_id ;
          rn->aroutes[lc_view_id].next = lc_head;
        }
      else
        {
          /* All other Local Contexts are placed at the end of the list.
           */
          rn->aroutes[rn->changed->tail].next = lc ;
          rn->changed->tail                   = lc ;
          rn->aroutes[lc].next = lc_end_id ;
        } ;

      rn->has_changed = true ;
    } ;
} ;

/*==============================================================================
 * Route Selection support.
 */
static route_info bgp_route_deterministic_med(bgp_rib_node rn, route_info ris,
                                  bgp_lc_id_t lc, uint count, route_info ris_was) ;
static route_info bgp_tie_break(bgp_rib_node rn, route_info best,
                             route_info cand, bgp_lc_id_t lc, route_info ris_was) ;

/*------------------------------------------------------------------------------
 * Return selected route for given rib-node in the given context
 */
extern route_info
bgp_route_select_lc(bgp_rib_node rn, bgp_lc_id_t lc)
{
  route_info    ris, ris_was ;
  iroute        irs ;
  svs_base      base ;
  route_merit_t merit_best ;
  uint          count ;
  bool          simple, step ;

  /* See if we have any candidates at all.
   */
  base  = rn->aroutes[lc].base ;

  ris = svs_head(base, rn->avail) ;
  if (ris == NULL)
    return NULL ;

  /* If there is only 1 candidate, return it now !.
   */
  irs = &ris->iroutes[lc] ;

  if (irs->list->next == SVEC_NULL)
    {
      irs->merit |= RMERIT_SELECTED ;   /* now the select       */
      return ris ;
    } ;

  /* We need the full selection process.
   *
   * Scan for the greatest merit, find the first with that merit and
   * count the number of routes which share that merit.
   *
   * Start by selecting the first on the list -- hopefully that will be
   * that !  If comes out with simple == true, then all the selected
   * candidates are already at the front of the list.
   *
   * We assume that the current first on the list is the current selection.
   * This will be true unless:
   *
   *   * a route of greater merit than the current selection has been placed at
   *     the front of the list.
   *
   *   * or
   */
  merit_best = irs->merit & route_merit_mask ;
  count      = 1 ;

  if (irs->merit & RMERIT_SELECTED)
    ris_was = ris ;
  else
    ris_was = NULL ;

  step       = false ;
  simple     = true ;

  while (1)
    {
      route_merit_t merit, merit_masked  ;
      route_info    ri ;
      iroute        ir ;

      ri = svs_next(irs->list, rn->avail) ;

      if (ri == NULL)
        break ;                         /* we only have one route !     */

      ir = &ri->iroutes[lc] ;
      merit = ir->merit ;
      merit_masked = merit & route_merit_mask ;

      if (merit_masked < merit_best)
        {
          /* We have a route with a lesser merit.
           *
           * If that is an UNSORTED route, then we step past and continue.
           *
           * If that is a sorted route, then we know any routes which
           * follow are equal to or less than this one, so we can stop !
           */
          if (!(merit & RMERIT_UNSORTED))
            break ;

          step = simple ;           /* stepped past something       */
          continue ;
        } ;

      if (merit_masked > merit_best)
        {
          /* New best merit.
           */
          merit_best = merit_masked ;
          ris        = ri ;
          irs        = ir ;
          count      = 1 ;

          simple = false ;          /* first is not at head         */
          continue ;
        } ;

      count += 1 ;                  /* another of equal merit       */
      if (step)
        simple = false ;            /* not contiguous with previous */
    } ;

  /* We have: ris/irs = first best merit route.
   *
   * Clear any RMERIT_UNSORTED state -- which is all we need to do if is simple
   * simple or if count == 1 !
   *
   * Then, if the candidates are not already all at the head of the list,
   * collect them there.
   */
  if (irs->merit & RMERIT_UNSORTED)
    irs->merit ^= RMERIT_UNSORTED ;

  if (!simple)
    {
      /* Need to move candidates to the head of the list.
       *
       * Start with the first candidate, which we move if it is not already
       * at the head of the list.
       */
      route_info  ri, ri_last ;
      uint        i ;

      ri = svs_next(irs->list, rn->avail) ;

      if (*base != ris->rindex)
        {
          svs_del(base, rn->avail, ris->rindex, route_info_t,
                                                         iroutes[lc].list) ;
          svs_push(base, rn->avail, ris->rindex, route_info_t,
                                                         iroutes[lc].list) ;
        } ;

      /* Now append any other candidates.
       *
       * At the top of the loop we have:  ri_last = last candidate added
       *                                  ri      = next to consider
       */
      ri_last = ris ;
      for (i = 2 ; i <= count ; ++i)
        {
          /* We have two or more routes to consider.
           */
          route_info    ri_this ;
          iroute        ir_this ;
          route_merit_t merit_this ;
          bool          step ;

          /* Starting with ri, which is the first route after the last one we
           * moved, scan for another route with the best merit.
           *
           * Exits loop with: ri_this & ir_this pointing at next candidate
           *                  merit_this is next candidate merit & flags
           *                  step == true if had to step past something
           */
          ri_this = ri ;
          step    = false ;
          while (1)
            {
              ir_this = &ri_this->iroutes[lc] ;

              merit_this = ir_this->merit ;
              if ((merit_this & route_merit_mask) == merit_best)
                break ;

              ri_this = svs_next(ir_this->list, rn->avail) ;
              step = true ;
            } ;

          /* Clear any UNSORTED state and move, if required, making a note
           * of the next route, if any.
           */
          if (merit_this & RMERIT_UNSORTED)
            ir_this->merit = merit_this ^ RMERIT_UNSORTED ;

          ri = svs_next(ir_this->list, rn->avail) ;

          if (step)
            {
              svs_del(base, rn->avail, ri_this->rindex,
                                           route_info_t, iroutes[lc].list) ;
              svs_in_after(ri_last->rindex, base, rn->avail,
                          ri_this->rindex, route_info_t, iroutes[lc].list) ;
            } ;

          /* Advance the ri_last
           */
          ri_last = ri_this ;
        } ;
    } ;

  /* We now have all the candidates together at the head of the list, and we
   * have cleared RMERIT_UNSORTED on all of them:
   *
   *   * ris and irs -- point at the first candidate.
   *
   *   * count is the number of candidates.
   *
   *   * ris_was     -- points at the previous select, if any.
   */
  if (count > 1)
    {
      if (rn->it.rib->rp.do_deterministic_med && (count > 2))
        {
          /* Do the tie break, with Deterministic-MED.
           */
          ris = bgp_route_deterministic_med(rn, ris, lc, count, ris_was) ;
        }
      else
        {
          /* Do the tie break, without Deterministic-MED.
           *
           * First time around the loop we compare 2 candidates, so we can stop
           * when the count is 2 !
           */
          iroute ir ;

          ir = irs ;
          while (1)
            {
              route_info  ri ;

              ri = svs_next(ir->list, rn->avail) ;

              ris = bgp_tie_break(rn, ris, ri, lc, ris_was) ;

              if (count <= 2)
                break ;

              ir = &ri->iroutes[lc] ;
              count -= 1 ;
            } ;
        } ;

      /* If the selected candidate is not at the head of the list, now
       * is the time to move it there.
       */
      if (*base != ris->rindex)
        {
          svs_del(base, rn->avail, ris->rindex, route_info_t,
                                                            iroutes[lc].list) ;
          svs_push(base, rn->avail, ris->rindex, route_info_t,
                                                            iroutes[lc].list) ;
        } ;

      /* Set irs so that ris/irs both refer to the now selected route.
       */
      irs = &ris->iroutes[lc] ;
    } ;

  /* We have our new selection -- mark it and we are done.
   */
  irs->merit |= RMERIT_SELECTED ;
  return ris ;
} ;

/*------------------------------------------------------------------------------
 * Pre-process candidates to deal with any Deterministic-MED.
 *
 * When is not "always compare", the "Deterministic MED" option solves the
 * following problem.  Suppose we have 3 routes which are equal up to, but
 * excluding the MEDs.  Suppose those are:
 *
 *    a) NeighborAS=9, MED=X, Peer Type=eBGP, IGP Metric=4
 *    b) NeighborAS=1, MED=2, Peer Type=eBGP, IGP Metric=5
 *    c) NeighborAS=1, MED=5, Peer Type=eBGP, IGP Metric=3
 *
 * The MEDs say that (b) is better than (c), so we should not select (c).
 * However, if the best path selection starts with (a) and compares that with
 * (b), then (b) is eliminated.  The (a) will be compared with (c), and (c)
 * will be chosen !
 *
 * So... for "Deterministic MEDs" need to choose the best among those routes
 * with the same NeighborAS, and then compare those.
 *
 * Here we scan the candidates, looking for any with the same med-as, and
 * doing an immediate tie-break between them, then do tie-break between the
 * best in each cluster.
 *
 * The candidates with the same med-as are clustered together, in their
 * original order.  It is conceivable that at some point the candidates could
 * be permanently clustered... hence the logic here.
 *
 * NB: does nothing at all if there are 2 or fewer candidates.  With 2
 *     candidates the tie break will do meds as required !
 *
 * NB: the caller needs to worry about the possibility that the first route(s)
 *     on the list is(are) eliminated.
 */
static route_info
bgp_route_deterministic_med(bgp_rib_node rn, route_info ris, bgp_lc_id_t lc,
                                                 uint count, route_info ris_was)
{
  svs_base   base ;
  route_info ri_next ;
  iroute     ir ;
  uint       left ;

  /* The selection loop will cope with 2 or more routes, though there is no
   * point doing this with less than 3.
   */
  qassert(count > 2) ;

  if (count < 2)
    return ris ;

  /* We now scan the candidates, pulling all with equal med-as togther into
   * clusters.
   *
   * Note that within a cluster the routes remain in their original order, in
   * particular the head of the list of routes does not change.
   */
  base  = rn->aroutes[lc].base ;

  left    = count ;
  ri_next = ris ;
  while (1)
    {
      route_info ri_last ;
      iroute     ir_last ;
      uint       n ;

      /* Start a new cluster, containing the current route.
       */
      ri_last = ri_next ;
      ir_last = &ri_next->iroutes[lc] ;

      left -= 1 ;                       /* one less to consider         */

      /* Step forward looking for other routes to join the current cluster,
       * and select the best of same.
       *
       * At the top of the loop we always have ri_next as the next route to
       * consider in the scan.  We update that early in the scan loop, so that
       * can move the current scan route around, without affecting the progress
       * of the scan.
       */
      ri_next = svs_next(ir_last->list, rn->avail) ;

      for (n = left ; n > 0 ; --n)
        {
          route_info ri ;

          ri = ri_next ;
          ir = &ri->iroutes[lc] ;

          ri_next = svs_next(ir->list, rn->avail) ;

          if (ri_last->med_as == ri->med_as)
            {
              /* We have found a friend for our current route !
               *
               * Move it into place, if required, as the new last in cluster.
               */
              if (ir_last->list->next != ri->rindex)
                {
                  svs_del(base, rn->avail, ri->rindex,
                                               route_info_t, iroutes[lc].list) ;
                  svs_in_after(ri_last->rindex, base, rn->avail,
                                   ri->rindex, route_info_t, iroutes[lc].list) ;
                } ;

              ri_last = ri ;
              ir_last = ir ;

              /* We can reduce the number of left to consider
               */
              left -= 1 ;
            } ;
        } ;

      /* If 2 or fewer routes to consider, we can stop clustering.
       */
      if (left <= 2)
        break ;

      /* Set ri to the first route after the last cluster.
       */
      ri_next = svs_next(ir_last->list, rn->avail) ;
    } ;

  /* Do the tie break, without Deterministic-MED.
   *
   * We start with: ris == first route
   *                ir  == iroute for first route
   *
   * But as we step forward, ir becomes the iroute for the next candidate.
   *
   * First time around the loop we compare 2 candidates, so we can stop
   * when the count is 2 !
   */
  ir      = &ris->iroutes[lc] ;
  ri_next = svs_next(ir->list, rn->avail) ;
  while (1)
    {
      route_info ri ;

      /* If we are down to the last two candidates, can return the best of
       * those.
       */
      if (count == 2)
        return bgp_tie_break(rn, ris, ri_next, lc, ris_was) ;

      /* We have three or more candidates, so we need to worry about clusters.
       */
      ri      = ri_next ;

      ir      = &ri_next->iroutes[lc] ;
      ri_next = svs_next(ir->list, rn->avail) ;

      while (ri->med_as == ri_next->med_as)
        {
          ri = bgp_tie_break(rn, ri, ri_next, lc, ris_was) ;

          count -= 1 ;
          if (count == 2)
            return bgp_tie_break(rn, ris, ri, lc, ris_was) ;

          ir      = &ri_next->iroutes[lc] ;
          ri_next = svs_next(ir->list, rn->avail) ;
        } ;

      ris = bgp_tie_break(rn, ris, ri, lc, ris_was) ;

      count -= 1 ;
    } ;
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
   *    Route-Map.  But in any case, a default has been set as part of
   *    the 'in' filtering.
   */
  temp = attr->local_pref & ROUTE_MERIT_MASK(route_merit_local_pref_bits) ;

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
  if (!rib->rp.do_aspath_ignore)
    {
       if (rib->rp.do_aspath_confed)
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
 * Tie break -- between routes of equal merit -- see bgp_route_merit().
 *
 * The order and form of comparison are:
 *
 *    6. MEDs           (smaller) -- if applicable
 *    7. Peer Type      (external)
 *    8. IGP Metric     (smaller)
 *    9. Maximum Path Check -- dropped
 *   10. Current                  -- if eBGP, per RFC5004
 *   11. Router-ID      (smaller)
 *   12. Cluster Length (smaller) -- if any
 *   13. Peer IP        (smaller)
 *
 * NB: uses ris_was for RFC5004 selection.
 *
 * NB: does not change the bgp_rib_node or either of the given route_info.
 */
static route_info
bgp_tie_break (bgp_rib_node rn, route_info best, route_info cand, bgp_lc_id_t lc,
                                                             route_info ris_was)
{
  attr_set best_attr, cand_attr ;
  uint32_t best_igp_metric, cand_igp_metric ;
  bgp_id_t best_id, cand_id ;
  uint best_cluster, cand_cluster ;
  int ret;
  bgp_peer_sort_t best_sort, cand_sort ;

  best_attr = best->iroutes[lc].attr ;
  cand_attr = cand->iroutes[lc].attr ;

  /* 6. MED check -- RFC4271 9.1.2.2 (c), also RFC5065 for Confed.
   *
   *    RFC4271 says that MEDs are compared if the "neighborAS" of the two
   *    routes are the same.  The neighborAS is:
   *
   *      * if the AS_PATH is empty, the local AS
   *
   *      * if the AS_PATH starts with an AS_SET, the local AS
   *
   *      * if the AS_PATH starts with an AS_SEQUENCE, the first AS in that
   *
   *    Where confederations are involved, RFC5065 (section 5.3) basically
   *    says that the confederation stuff should be ignored.
   *
   *    But for confederations RFC5065 allows an option to treat the first
   *    ASN in either AS_SEQUENCE or AS_CONFED_SEQUENCE as the "neighborAS".
   *    That is the BGP_FLAG_MED_CONFED.
   *
   *    The BGP_FLAG_ALWAYS_COMPARE_MED forces MEDs to be compared for all
   *    routes, ignoring the "neighborAS".
   *
   *    The "neighborAS" is set in the ri->med_as, and is always BGP_ASN_NULL
   *    for BGP_FLAG_ALWAYS_COMPARE_MED.
   *
   *    Note that if we have deterministic MED (and not always compare MED)
   *    then that affects the order in which routes are considered for the
   *    tie-break, not how the tie-break is performed.
   *
   *    MED is a weight/cost... so we are looking for the smaller.
   */
  if (best->med_as == cand->med_as)
    {
      uint32_t best_med, cand_med ;

      best_med = best_attr->med;
      cand_med = cand_attr->med;

      if (best_med != cand_med)
        return (best_med < cand_med) ? best : cand ;
    } ;

  /* 7. Peer type check  -- RFC4271 9.1.2.2 (d), also RFC5065 for Confed.
   *
   *    CONFED and iBGP rank equal, "internal" (RFC5065).
   */
  best_sort = best->prib->prun->rp.sort ;
  cand_sort = cand->prib->prun->rp.sort ;

  if (best_sort != cand_sort)
    {
      if (best_sort == BGP_PEER_EBGP)
        return best ;
      if (cand_sort == BGP_PEER_EBGP)
        return cand ;
    } ;

  /* NB: from now on, if best_sort == BGP_PEER_EBGP then both == BGP_PEER_EBGP
   */

  /* 8. IGP metric check  -- RFC4271 9.1.2.2 (e).
   *
   * This is a weight/cost... so we are looking for the smaller.
   */
  best_igp_metric = best->igp_metric ;
  cand_igp_metric = cand->igp_metric ;

  if (best_igp_metric != cand_igp_metric)
    return (best_igp_metric < cand_igp_metric) ? best : cand ;

  /* 9. Maximum path check -- dropped.
   */

  /* 10, 11 and 12  -- RFC4271 9.1.2.2 (f) as modified by RFC4456 and RFC5004
   *
   * 10. For eBGP: prefer the current, or go by BGP Identifier -- RFC5004
   *
   *     For eBGP (NOT cBGP), prefer "the existing best path", except where
   *     the BGP Identifier is identical.  If neither is the existing best
   *     path, compare BGP Identifiers
   *
   *     NB: BGP_FLAG_COMPARE_ROUTER_ID overrides the RFC5004 recommendation.
   *
   * 11. For iBGP and cBGP -- BGP Identifier comparison RFC4271 and RFC4456
   *
   *     RFC4456 says to use ORIGINATOR_ID, if any, instead of the BGP
   *     Identifier.  (Step 10 deals with the eBGP case, where there cannot
   *     be an ORIGINATOR_ID in any case.)
   *
   * 12. For iBGP and cBGP -- Cluster length comparison -- RFC4456.
   *
   *     There is no cluster length for eBGP, so we skip this test in this
   *     case.
   */
  if (best_sort == BGP_PEER_EBGP)
    {
      qassert(cand_sort == BGP_PEER_EBGP) ;

      /* 10. for eBGP (and not cBGP) -- BGP Identifier or prefer current
       */
      best_id = best->prib->prun->session->sargs->remote_id ;
      cand_id = cand->prib->prun->session->sargs->remote_id ;

      if (best_id != cand_id)
        {
          if (rn->it.rib->rp.do_prefer_current)
            {
              if (best == ris_was)
                return best ;

              if (cand == ris_was)
                return cand ;
            } ;

          return (ntohl(best_id) < ntohl(cand_id)) ? best : cand ;
        } ;
    }
  else
    {
      /* 11. for iBGP and cBGP -- BGP Identifier or ORIGINATOR_ID
       */
      if (best_attr->have & atb_originator_id)
        best_id = best_attr->originator_id ;
      else
        best_id = best->prib->prun->session->sargs->remote_id ;

      if (cand_attr->have & atb_originator_id)
        cand_id = cand_attr->originator_id ;
      else
        cand_id = cand->prib->prun->session->sargs->remote_id ;

      if (best_id != cand_id)
        return (ntohl (best_id) < ntohl (cand_id)) ? best : cand ;

      /* 12. for iBGP and cBGP -- Cluster length comparison
       */
      best_cluster = attr_cluster_length(best_attr->cluster);
      cand_cluster = attr_cluster_length(cand_attr->cluster);

      if (best_cluster != cand_cluster)
        return (best_cluster < cand_cluster) ? best : cand ;
    } ;

  /* 13. Neighbor address comparison   -- RFC4271 9.1.2.2 (g)
   *
   *     NB: the addresses cannot be equal !
   */
  ret = sockunion_cmp (&best->prib->prun->session->cops->remote_su,
                       &cand->prib->prun->session->cops->remote_su);

  return (ret <= 0) ? best : cand ;
} ;

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * Discard contents of the given prib's adj-in, withdrawing all routes from
 * all local contexts.
 *
 * TODO ... break this up so can run in the background.
 */
extern void
bgp_adj_in_discard(bgp_prib prib)
{
  route_info  ri ;

  while ((ri = ihash_table_ream(prib->adj_in, free_it)) != NULL)
    bgp_route_info_free(ri, false /* no need to remove */);

  prib->adj_in = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set everything in the given adj-in "stale".
 *
 * By rule, anything which is already stale must be discarded.  HOWEVER, a
 * recent draft: draft-ietf-idr-gr-notification suggests that multiple
 * restarts SHOULD NOT discard already stale routes.  Certainly there seems
 * no particular reason to do so, PROVIDED that the stale timer is not
 * restarted until an EoR is received.
 *
 * NB: since we are setting stuff 'stale', we must be expecting a new set of
 *     routes, so we can dispense with any which are 'pending' !
 *
 * We only set the rib_main entries stale.
 */
extern void
bgp_adj_in_set_stale(bgp_prib prib)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;

  /* Walk the rib_main adj-in, mark everything stale and add to the list of
   * stale routes.
   *
   * NB: for routes which are already stale, we have little to do !
   */
  ihash_walk_start(prib->adj_in, walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if (ri->current.flags & RINFO_STALE)
        continue ;

      /* Forget any pending state
       */
      if (ri->pending.attr != NULL)
        ri->pending.attr = bgp_attr_unlock(ri->pending.attr) ;

      if (ri->pending.flags & RINFO_PENDING)
        {
          qassert(!(ri->current.flags & RINFO_STALE)) ;
          ddl_del(ri->prib->pending_routes, ri, plist) ;
        }

      memset(&ri->pending, 0, sizeof(ri->pending)) ;

      /* If we have any useful current state, set it stale.  Otherwise
       * discard the route altogether.
       */
      if (ri->current.flags & (RINFO_DENIED | RINFO_REFUSED | RINFO_WITHDRAWN))
        {
          /* The route we have in hand is of no use at all, so we may as well
           * discard it now.  (This removes the current adj-in entry, which we
           * may do during the walk.)
           */
          bgp_route_info_free(ri, true /* remove */) ;
        }
      else
        {
          /* Keeping the route, but stale.
           */
          ddl_append(prib->stale_routes, ri, plist) ;

          ri->current.flags |= RINFO_STALE ;
        } ;
    } ;

  qassert(ddl_head(ri->prib->pending_routes) == NULL) ;

  /* Back to square one with the received prefix count, and for good measure
   * we clear any max-prefix setting
   */
  prib->pcount_recv = 0 ;
  bgp_peer_pmax_clear(prib) ;
} ;

/*------------------------------------------------------------------------------
 * Discard everything in the given adj-in which is "stale".
 */
extern void
bgp_adj_in_discard_stale(bgp_prib prib)
{
  route_info  ri ;

  while ((ri = ddl_head(prib->stale_routes)) != NULL)
    bgp_route_info_free(ri, true /* remove */) ;
} ;

/*------------------------------------------------------------------------------
 * Refresh everything in the given adj-in.
 *
 * Used to re-process routes after change of filters and/or 'in' or 'rc-xx'
 * route-maps.
 */
extern void
bgp_adj_in_refresh(bgp_prib prib)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;

  ihash_walk_start(prib->adj_in, walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    bgp_adj_in_refresh_route(prib, ri) ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Enable the given prib for RS Routes -- if not already enabled.
 *
 * If required, creates an adj_in[rib_rs], and populates it from the rib_main,
 * scheduling any affected RS prefixes for processing.
 */
extern void
bgp_adj_in_rs_enable(bgp_prib prib)
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
bgp_adj_in_rs_disable(bgp_prib prib)
{
  bgp_adj_in_discard(prib) ;
} ;

#endif
