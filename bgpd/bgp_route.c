/* BGP routing information
   Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "filter.h"
#include "str.h"
#include "log.h"
#include "routemap.h"
#include "buffer.h"
#include "sockunion.h"
#include "plist.h"
#include "thread.h"
#include "workqueue.h"
#include "ihash.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgp_adj_out.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_names.h"

/*==============================================================================
 *
 */
enum { bgp_send_aspath_check
#ifdef BGP_SEND_ASPATH_CHECK
                              = true
#else
                              = false
#endif
} ;


/*==============================================================================
 * Incoming UPDATE processing.
 */
static bool bgp_update_filter_next_hop(peer_rib prib, route_in_parcel parcel,
                                                                 prefix_c pfx) ;
static attr_set bgp_update_filter_main(peer_rib prib, attr_set attr,
                                                                 prefix_c pfx) ;
static attr_set bgp_update_filter_rs_in(peer_rib prib, attr_set attr,
                                                                 prefix_c pfx) ;
static route_merit_t bgp_route_merit(bgp_inst bgp, attr_set attr,
                                                                byte sub_type) ;
static void bgp_candidate_add(bgp_rib_node rn, route_info ri) ;
static route_info bgp_candidates_cluster(bgp_rib_node rn) ;

inline static bool bgp_is_deterministic_med(bgp_inst bgp) ;
inline static bool bgp_rib_node_deterministic_med(bgp_rib_node rn,
                                                                 bgp_inst bgp) ;

/*------------------------------------------------------------------------------
 * Process update into the RIB -- for ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL.
 *
 * The route in the given parcel has arrived from the given peer.
 *
 * We first process the update into the peer's main adj_in.  We keep a
 * record of all routes received the peer.
 *
 * Note that we *always* run all the inbound filters and the 'in' route-map.
 * This includes checking the next-hop for reachability.  If the
 *
 *
 *
 *   If the state of the route has
 * changed, such that this could affect the selection of routes, the
 *
 *
 *
 * If this is a withdraw (and not a treat-as-withdraw), we
 *
 *
 *
 * If the route does not exist in the peer RIB's adj-in, then we create a
 * new route_info (ri).  Otherwise we update the existing route_info.  This
 * sets the ri->attr_rcv.  (Note that even if soft_reconfig is not configured,
 * we remember the attributes as they were received -- it seems almost
 * pointless not to.)
 *
 *
 *
 * We run the peer's 'in' routemap and other filters, and update the
 * ri->attr_main.
 *
 * We run the peer's 'rs-in' routemap (if any) and update the rnode->attr_rs.
 *
 *
 * For soft-reconfig the trick is to NULL out the attr...
 *
 *
 *
 * ******
 *
 * The 'refresh' argument signals that the update is, in fact, a soft-reconfig,
 * which may involve changes to the inbound filtering, so force through
 *
 * *****
 *
 *
 *
 * Returns:  true <=> OK, done
 *           false => the qafx is not activated, or
 *
 *
 * TODO max prefix stuff
 *
 * TODO prefix counting
 *
 * TODO aggregate stuff
 */
extern bool
bgp_update_from_peer(bgp_peer peer, route_in_parcel parcel, bool rs_reprocess)
{
  bgp_rib         rib ;
  peer_rib        prib ;
  bgp_rib_node    rn ;
  route_info      ri ;
  prefix_id_entry pie ;
  route_merit_t   merit ;
  attr_set        attr_rcv, attr_main ;
  bool            changed, process, tag_changed, med_as_changed ;

  /* Note that at this stage we expect the peer to be locked.
   *
   * We do not, however, touch the bgp_rib just yet.
   */

  /* Get the peer_rib and ensure is activated for this qafx.
   */
  prib = peer->prib[parcel->qafx] ;

  if (prib == NULL)
    return false ;

  qassert(prib->qafx == parcel->qafx) ;

  pie = prefix_id_get_entry(parcel->pfx_id) ;

  changed        = false ;
  process        = false ;
  tag_changed    = false ;
  med_as_changed = false ;

  /* Run the main RIB filters -- end up with:
   *
   *   attr_rcv    -- NULL iff is ra_in_withdraw
   *
   *   attr_main   -- NULL if ra_in_withdraw, ra_in_treat_as_withdraw or is
   *                          filtered out.
   */
  switch (parcel->action)
    {
      case ra_in_update:
        /* Update comes with a set of attributes, which we use unless the
         * next-hop is rejected.
         *
         * We run the filters here, so that ...
         */
        qassert(parcel->attr   != NULL) ;

        attr_rcv = parcel->attr ;

        if (bgp_update_filter_next_hop(prib, parcel, pie->pfx))
          attr_main = bgp_update_filter_main(prib, attr_rcv, pie->pfx) ;
        else
          {
            parcel->action = ra_in_treat_as_withdraw ;
            attr_main = NULL ;
          } ;

        break ;

      case ra_in_treat_as_withdraw:
        /* Treat as withdraw comes with a set of attributes, which we don't
         * use, nohow.
         */
        qassert(parcel->attr   != NULL) ;

        attr_rcv  = parcel->attr ;
        attr_main = NULL ;

        break ;

      case ra_in_withdraw:
        /* Explicit withdraw does not come with a set of attributes
         */
        qassert(parcel->attr   == NULL) ;

        attr_rcv  = NULL ;
        attr_main = NULL ;

        break ;

      default:
        qassert(false) ;
        return false ;
    } ;

  /*--------------------------------------------------------------------------
   * Process into the peer's main adj_in.
   *
   * If there is no route_info for this route, make one -- unless is withdraw.
   *
   * NB: for Route-Server, all routes appear in the main RIB.
   *
   * NB: we do not store NULL pointers in the adj_in
   */
  ri = ihash_get_item(prib->adj_in[rib_main], pie->id, NULL) ;

  if (ri == NULL)
    {
      /* Route does not exist, so create if this is an update, even if it is
       * treat-as-withdraw.
       *
       * But, if this is a withdraw, then we can give up now, because we
       * know nothing about the route.  The absence of an entry in the main
       * adj_in implies an absence of an entry in the RS adj_in.
       */
      if (attr_rcv == NULL)
        {
          /* The sender is withdrawing something we don't have a record of...
           * which is odd.
           *
           * But in any case there is nothing more to be done.
           */
          if (BGP_DEBUG (update, UPDATE_IN))
            zlog (peer->log, LOG_DEBUG,
              "%s Can't find the route %s", peer->host, spfxtoa(pie->pfx).str) ;

          if (qdebug && (prib->adj_in[rib_rs] != NULL))
            assert(ihash_get_item(prib->adj_in[rib_rs], parcel->pfx_id, NULL)
                                                                      == NULL) ;
          return true ;
        } ;

      /* We have received an UPDATE, even if that is treat-as-withdraw or
       * filtered out, we still want to hold an adj_in entry for it.
       *
       * We will set the ri->attr to NULL -- so if this is treat-as-withdraw
       * or is filtered out, then that will not look like a change, below.
       */
      ri = bgp_route_info_new(prib, rib_main, pie, parcel->route_type) ;
    }
  else
    {
      /* This is an existing route_info -- if it is "stale" then we now have
       * a shiny new set of attributes for it, so remove from the stale
       * list and clear the state.
       */
      if (ri->flags & RINFO_STALE)
        {
          ddl_del(prib->stale_routes, ri, stale_list) ;

          ri->flags ^= RINFO_STALE ;
        } ;
    } ;

  if (parcel->action == ra_in_treat_as_withdraw)
    ri->flags |=  RINFO_TREAT_AS_WITHDRAW ;
  else
    ri->flags &= ~RINFO_TREAT_AS_WITHDRAW ;

  /* Now update the adj_in entry to reflect the attr_rcv.
   *
   * Need now to lock the bgp_rib, because we are about to fiddle with one
   * of the routes attached to a bgp_rib_node.
   *
   * NB: at this point, if attr_rcv is NULL, then
   *
   * TODO Route Flap damping..................................................
   *
   * TODO Effect of change of med_as if is among the candidates
   */
  if (ri->attr_rcv != attr_rcv)
    {
      /* Change of received attributes -- may be:
       *
       *   1) a brand new route or one previously withdrawn.
       *
       *   2) replacing an existing route -- implicitly withdrawing current
       *
       *   3) explicitly withdrawing the current route
       *
       *   4) re-instating a route which was previously withdrawn, but
       *      for whom we have held on to the adj_in entry for route-flap
       *      damping reasons.
       */
      if (ri->attr_rcv != NULL)
        {
          /* Implicit or explicit withdraw of the previous route.
           */
          bgp_attr_unlock(ri->attr_rcv) ;
        } ;

      if (attr_rcv != NULL)
        {
          /* The sender has announced a replacement route
           *
           *
           * MED-AS change id this is amongst the select !!!!  XXX .........
           */
          as_t med_as ;

          qassert(parcel->action & ra_in_update) ;
          ri->attr_rcv = bgp_attr_lock(attr_rcv) ;

          med_as = (peer->bgp->flags & BGP_FLAG_MED_CONFED)
                                     ? as_path_left_most_asn(attr_rcv->asp)
                                     : as_path_first_simple_asn(attr_rcv->asp) ;
          if (med_as != ri->med_as)
            {
              ri->med_as = med_as ;
              med_as_changed = bgp_is_deterministic_med(peer->bgp) ;
            } ;

          if (prib->is_mpls)
            ri->tag      = parcel->tag ;
          else
            ri->tag      = mpls_tags_null ;
        }
      else
        {
          /* The sender has withdrawn the route.
           */
          ri->attr_rcv = NULL ;
          ri->med_as   = BGP_ASN_NULL ;
          ri->tag      = mpls_tags_null ;
        } ;
    }
  else
    {
      /* The incoming attributes are identical to the ones we have.
       *
       * If there is a change in the tag value, then this is still a change,
       * which we will deal with later if the effective attr are also
       * unchanged.
       */
      if ((prib->is_mpls) && (attr_rcv != NULL))
        {
          if (ri->tag != parcel->tag)
            {
              tag_changed = true ;
              ri->tag = parcel->tag ;
            } ;
        }
      else
        qassert(ri->tag == mpls_tags_null) ;

      if (BGP_DEBUG (update, UPDATE_IN) && !prib->refresh
                                        && !tag_changed
                                        && !(ri->flags & RINFO_HISTORY))
      {
        /* Log the fact that the sender has apparently spontaneously sent
         * an exact copy of something previously sent.
         *
         * Note that: changed => soft_reconfig or update with change of tag
         *
         *            RINFO_HISTORY means that the route we have has been
         *            saved for some reason, and we are not surprised if
         *            the sender resends it.
         */
        if (attr_rcv != NULL)
          zlog (peer->log, LOG_DEBUG,
              "%s Repeated update for route %s", peer->host,
                                                      spfxtoa(pie->pfx).str) ;
        else
          zlog (peer->log, LOG_DEBUG,
              "%s Repeated withdraw for route %s", peer->host,
                                                      spfxtoa(pie->pfx).str) ;
      } ;
    } ;

  ri->uptime = bgp_clock() ;

  /* Now update the adj_in to reflect the attr_main.
   */
  if (ri->attr != attr_main)
    {
      /* We are replacing whatever the attr_main were by a new set of
       * attributes.
       *
       * We mark the Route as having an attribute change, so that if this is
       * the currently selected route, and it remains the currently selected
       * route, then will still update peers and Zebra !
       *
       * Note that if this is not the current route, then if it is selected
       * at any time, then will want to update peers and Zebra in any case.
       *
       * NB: if not NULL, these attributes were locked when returned by
       *     bgp_update_filter_main(), and we are here bequeathing that
       *     lock to ri->attr_main.
       */
      if (ri->attr != NULL)
        bgp_attr_unlock(ri->attr) ;

      ri->attr = attr_main ;

      changed = true ;                  /* route changed -- attributes  */
    }
  else
    {
      /* The attr_main attributes were locked by bgp_update_filter_main(),
       * but we no longer have a need for them.
       */
      if (attr_main != NULL)
        bgp_attr_unlock(attr_main) ;

      changed = tag_changed ;           /* route changed -- tag, only   */
    } ;

  /* If there are attr_main, then we have something which could be announced.
   *
   * Otherwise, this is (effectively) a withdraw.
   *
   * NB: the rn->candidates list may be empty if all previous candidates have
   *     been withdrawn.
   */
  rn = ri->rn ;

  if (attr_main != NULL)
    merit = bgp_route_merit(peer->bgp, attr_main, ri->sub_type) ;
  else
    merit = route_merit_none ;

  rib = peer->bgp->rib[prib->qafx][rib_main] ;
  qassert(rib != NULL) ;

  if (merit != route_merit_none)
    {
      /* Have something that could be announced.
       */
      if (rn == NULL)
        {
          /* Get RIB Node for prefix -- creating same if required.
           */
          rn = ri->rn = bgp_rib_node_get(rib, pie) ;

          qassert(!(rn->flags & rnf_processed)) ;
          qassert(rn->candidates == NULL) ;

          ddl_push(rib->queue, &rn->it, queue) ;

          ddl_push(rn->routes, ri, route_list) ;
        } ;

      if (rn->candidates == NULL)
        {
          /* There are no current candidates, but we have something that could
           * be announced, so schedule processing.
           *
           * Update rnf_deterministic_med so that will apply when candidates
           * are collected.
           */
          qassert(rn->selected == NULL) ;

          bgp_rib_node_deterministic_med(rn, peer->bgp) ;
          process = true ;
        }
      else
        {
          route_merit_t merit_select ;
          merit_select = rn->candidates->merit ;
          qassert(merit_select != route_merit_none) ;

          if      (merit > merit_select)
            {
              /* The route has greater merit than the current candidate(s)
               *
               * We can replace them all.
               *
               * Unless is already the selected route (whose merit has
               * increased), need to schedule processing.
               */
              qassert(merit > ri->merit) ;

              rn->candidates     = ri ;
              ri->candidate_list = NULL ;

              if (ri != rn->selected)
                process = true ;

              /* We only have one candidate, so Deterministic MED is moot.
               *
               * But we update rnf_deterministic_med in any case.
               */
              bgp_rib_node_deterministic_med(rn, peer->bgp) ;
            }
          else if (merit == merit_select)
            {
              /* The route has merit equal to the current candidate(s)
               *
               * So, route must already be a candidate, or must join the
               * candidates.
               */
              if      (merit > ri->merit)
                {
                  /* The route needs to join the candidates.
                   *
                   * But first, update the RIB Node Deterministic MED state.
                   * If that changes *up* to Deterministic MED, better cluster
                   * together the existing candidates, before adding the new
                   * candidate.
                   */
                  if (bgp_rib_node_deterministic_med(rn, peer->bgp))
                    bgp_candidates_cluster(rn) ;

                  bgp_candidate_add(rn, ri) ;
                  process = true ;
                }
              else
                {
                  /* Route has the same merit as the current candidates, and
                   * the new merit is <= the old merit.
                   *
                   * The old merit cannot be greater than the current
                   * candidates (of which there is at least one) -- for if so,
                   * it would be a candidate !
                   */
                  qassert(merit == ri->merit) ;

                  /* Update the RIB Node Deterministic MED state.  If that
                   * changes *up* to Deterministic MED, better cluster together
                   * the existing candidates.
                   *
                   * It is possible (though extremely unlikely) that the med_as
                   * for this route has changed.  Since we are keeping the
                   * candidates list as-is, this is another reason for
                   * clustering the existing candidates.
                   */
                  if (bgp_rib_node_deterministic_med(rn, peer->bgp)
                                                              || med_as_changed)
                    {
                      bgp_candidates_cluster(rn) ;
                      process = true ;
                    } ;
                } ;
            }
          else      /* merit < merit_select */
            {
              /* The new form of the route has less merit than the current
               * candidate(s).
               *
               * If the old form of the route was amongst the candidates, then
               * it no longer qualifies.  If the old form of the route was the
               * selected route, then we need to schedule processing.
               *
               * This is similar to a withdraw, except that we do not remove
               * the route from the RIB-node.
               *
               * This may empty the list of candidates.  If does empty the
               * list, then this must be the selected candidate.
               */
              if (ri->merit == merit_select)
                {
                  ssl_del(rn->candidates, ri, candidate_list) ;
                  qassert((rn->candidates != NULL) || (rn->selected == ri)) ;
                } ;

              if (rn->selected == ri)
                {
                  rn->selected = NULL ;
                  process = true ;
                } ;

             /* Update the RIB Node Deterministic MED state. If that changes
              * *up* to Deterministic MED, better cluster together the existing
              * candidates and process.
              */
             if (bgp_rib_node_deterministic_med(rn, peer->bgp))
               {
                 bgp_candidates_cluster(rn) ;
                 process = true ;
               } ;
            } ;
        } ;
    }
  else
    {
      /* Effective withdraw: if is attached to a RIB-Node, then need to
       * detach.
       *
       * If is amongst the candidates, then need to withdraw.
       *
       * If is the current selected, then need to schedule processing.
       *
       * Note that if this makes no difference to the selected route, then
       * we don't need a RIB-node !
       */
      process = false ;                 /* may change nothing   */

      if (rn != NULL)
        {
          ri->rn = NULL ;               /* no longer attached   */
          ddl_del(rn->routes, ri, route_list) ;

          if ((rn->candidates != NULL) && (ri->merit == rn->candidates->merit))
            {
              /* The route is amongst the candidates, so need to remove.
               *
               * This may empty the list of candidates.  If does empty the
               * list, then this must be the selected candidate.
               */
              ssl_del(rn->candidates, ri, candidate_list) ;

              qassert((rn->candidates != NULL) || (rn->selected == ri)) ;
            } ;

          if (rn->selected == ri)
            {
              rn->selected = NULL ;
              process = true ;
            } ;

          /* Update the RIB Node Deterministic MED state.
           *
           * If that changes *up* to Deterministic MED, better cluster together
           * the existing candidates, and process
           */
          if (bgp_rib_node_deterministic_med(rn, peer->bgp))
            {
              bgp_candidates_cluster(rn) ;
              process = true ;
            } ;
        } ;
    } ;

  ri->merit = merit ;

  /* Schedule processing run as required.
   */
  if (process)
    {
      qassert(rn != NULL) ;

      /* If something about the route has changed, and it is the currently
       * selected route -- then mark it changed so that if after processing
       * this is still the selected route, then it will be announced in its
       * new form.
       */
      if (changed && (ri == rn->selected))
        ri->flags |= RINFO_ATTR_CHANGED ;

      /* If not already scheduled for processing, reschedule at the end of the
       * queue.
       */
      bgp_process_schedule(rib, rn) ;
    } ;

  /* If no RS RIB to worry about, can exit now.
   */
  if ((prib->adj_in[rib_rs] == NULL))
    {
      if (attr_rcv == NULL)
        {
          // xxx ......................................

        } ;

      return true ;
    } ;


  return bgp_update_rs_from_peer(prib, ri, pie,
                              rs_reprocess || tag_changed || med_as_changed) ;
} ;



/*--------------------------------------------------------------------------
 * Process into the peer's Route-Server adj_in.
 *
 *
 */
extern bool
bgp_update_rs_from_peer(peer_rib prib, route_info ri_main,
                                              prefix_id_entry pie, bool process)
{
  attr_set     attr_rcv, attr_rs ;
  route_info   ri ;
  bgp_rib_node rn ;
  bgp_rib      rib ;

  /* Run the RS RIB filters -- end up with:
   *
   *   attr_rcv  -- NULL, if withdraw or treat as withdraw
   *
   *   attr_rs   -- attributes after filtering received attributes (if any)
   *                                                            through 'rs-in'.
   *                NULL, if withdraw, treat_as_withdraw or is filtered out.
   */
  if (ri_main->flags & RINFO_TREAT_AS_WITHDRAW)
    attr_rcv = NULL ;
  else
    attr_rcv = ri_main->attr_rcv ;

  if (attr_rcv != NULL)
    attr_rs = bgp_update_filter_rs_in(prib, attr_rcv, pie->pfx) ;
  else
    attr_rs = NULL ;

  /* If there is no route_info for this route, make one -- unless is withdraw.
   *
   * NB: if the route was withdrawn, and we had no record of the route in the
   *     main RIB, then we will have no record of it in the adj_in_rs, and we
   *     exited some time ago.
   *
   * NB: we do not store NULL pointers in the adj_in_rs
   */
  ri = ihash_get_item(prib->adj_in[rib_rs], pie->id, NULL) ;

  if (ri == NULL)
    ri = bgp_route_info_new(prib, rib_rs, pie, ri_main->route_type) ;

  /* Copy stuff across from the Main RIB adj_in
   */
  ri->med_as   = ri_main->med_as ;
  ri->tag      = ri_main->tag ;
  ri->uptime   = ri_main->uptime ;

  /* Decide whether need to do anything about the RS
   */
  if (ri->attr_rcv != attr_rs)
    {
      /* We are replacing whatever the attr_rs were by a new set of
       * attributes.
       *
       * NB: if not NULL, these attributes were locked when returned by
       *     bgp_update_filter_rs_in(), and we are here bequeathing that
       *     lock to ri->attr_rs.
       */
      if (ri->attr_rcv != NULL)
        bgp_attr_unlock(ri->attr_rcv) ;

      ri->attr_rcv = attr_rs ;

      process = true ;                  /* route changed -- attributes  */
    }
  else
    {
      /* The attr_rs are unchanged.
       *
       * The attr_rs attributes were locked by bgp_update_filter_rs_in(),
       * but we no longer have a need for them.
       */
      if (attr_rs != NULL)
        bgp_attr_unlock(attr_rs) ;
    } ;

  /* If we have some attr_rs, we have something which could be announced.
   *
   * Otherwise, this is (effectively) a withdraw.
   *
   * Note that for the RS-RIB the candidates list and the route's merit are
   * possibly different for each route-server client, and all that is done
   * in the back-ground.
   */
  rn = ri->rn ;
  rib = prib->peer->bgp->rib[prib->qafx][rib_rs] ;

  qassert(rib != NULL) ;                /* since we got this far        */

  if (attr_rs != NULL)
    {
      /* Have something that could be announced.
       */
      if (rn == NULL)
        {
          /* We need a new RIB-node
           */
          rn = ri->rn = bgp_rib_node_get(rib, pie) ;

          qassert(!(rn->flags & rnf_processed)) ;

          ddl_push(rib->queue, &rn->it, queue) ;

          ddl_push(rn->routes, ri, route_list) ;

          process = true ;
        } ;
    }
  else
    {
      /* Effective withdraw: if is attached to a RIB-Node, then need to
       * detach.
       *
       * If there is no RIB-Node, then is not currently a route, so this
       * makes no difference and no processing is required.
       */
      if (rn != NULL)
        {
          ri->rn = NULL ;               /* no longer attached   */
          ddl_del(rn->routes, ri, route_list) ;

          process = true ;              /* need to reconsider   */
        }
      else
        process = false ;               /* nothing changed      */
    } ;

  /* Schedule processing run as required.
   */
  if (process)
    {
      qassert(rn != NULL) ;

      bgp_rib_node_deterministic_med(rn, prib->peer->bgp) ;

      /* If not already scheduled for processing, reschedule at the end of the
       * queue.
       */
      bgp_process_schedule(rib, rn) ;
    } ;

  /* Finally: if the route has been withdrawn, xxx ? discard the adj-in entry,
   *
   */
  if (attr_rcv == NULL)
    {


      // xxx ......................................


    } ;

  return true ;
} ;






#if 0












/*------------------------------------------------------------------------------
 * Deal with update for the given prefix.
 *
 * Returns:  true <=> OK, done
 *           false => the qafx is not activated, or hit max-prefix limit
 */
extern bool
bgp_update (bgp_peer peer, prefix p, attr_set attr, qafx_t qafx,
                    int type, int sub_type, const byte* tag, bool soft_reconfig)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;
  struct bgp *bgp;
  struct bgp_node* rn ;
  bool ok;

  /* For all neighbors, update the main RIB
   */
  bgp = peer->bgp;
  rn = bgp_afi_node_get (bgp->rib[qafx], qafx, p, prd);

  ok = bgp_update_main (peer, rn, attr, qafx, type, sub_type, prd, tag,
                                                                soft_reconfig) ;

  /* Update all Route-Server Client RIBs
   */
  bgp = peer->bgp;

  if (bgp->rsclient != NULL)
    {
      rs_route_t   rt[1] ;
      attr_pair_t  attrs[1] ;
      attr_set     rs_in ;

      /* Apply rs_in policy.
       */
      bgp_attr_pair_load(attrs, attr) ;

      if (bgp_rs_input_modifier(peer, p, attrs, qafx))
        {
          /* Loading the attribute pair took a lock on the original.
           *
           * If the attributes have been modified, storing the new attributes
           * unlocks the original and locks the new stored stuff.
           *
           * So we hold a lock on the rs_in, in the attr_pair.
           *
           * We store the result away in the adj_in for the source, so that
           * we don't have to do this again.
           */
          bgp_attr_pair_store(attrs) ;  /* make sure 'stored'   */
          rs_in = attrs->stored ;

          bgp_adj_rs_in_set(rn, peer, attr, rs_in) ;
        }
      else
        {
          /* The rs-in has denied this route.
           *
           * If the adj_in has an rs_in version of the route, we unset that
           * now.
           */
          rs_in = NULL ;                /* Filtered out         */
          bgp_adj_rs_in_unset(rn, peer) ;
        } ;

      /* Prepare the rs_route object, ready to update all rs clients active
       * in this q_afi/q_safi.
       */
      bgp_rs_route_init(rt, qafx, rs_in, peer, p, type, sub_type, prd, tag) ;

      /* Process the update for each RS-client.
       */
      for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
        if (rsclient->af_flags[rt->qafx] & PEER_AFF_RSERVER_CLIENT)
          bgp_update_rsclient (rsclient, rt) ;

      /* Release our lock on any stored attributes and discard any new stuff
       * which has not been stored.
       */
      bgp_attr_pair_unload(attrs) ;
    } ;

  /* Undo lock gained by bgp_afi_node_get() and return result
   */
  bgp_unlock_node (rn);

  return ok ;                   /* result of bgp_update_main()  */
} ;

/*------------------------------------------------------------------------------
 * Withdraw the given prefix
 */
extern bool
bgp_withdraw (bgp_peer peer, prefix p, qafx_t qafx, int type, int sub_type)
{
  bgp_peer rsclient;
  struct listnode *node, *nnode;

  /* Process the withdraw for each RS-client.
   */
  for (ALL_LIST_ELEMENTS (peer->bgp->rsclient, node, nnode, rsclient))
    {
      if (rsclient->af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)
        bgp_withdraw_rsclient (rsclient, peer, p, qafx, type, sub_type) ;
    } ;

  /* Withdraw specified route from routing table.
   */
  return bgp_withdraw_main(peer, p, qafx, type, sub_type) ;
}






/*------------------------------------------------------------------------------
 * Process update into the RIB.
 *
 * Need
 *
 *
 *
 * Returns:  true <=> OK, done
 *           false => the qafx is not activated, or
 */
static bool
bgp_update_main (bgp_peer peer, bgp_node rn, attr_set attr, qafx_t qafx,
                       int type, int sub_type,
                     struct prefix_rd *prd, const byte* tag, bool soft_reconfig)
{
  ;
  struct bgp *bgp;
  struct bgp_info *ri;
  const char *reason;
  prefix p ;
  bgp_peer_sort_t sort ;
  attr_pair_t  attrs[1] ;
  attr_set     working, stored ;
  bool  ok ;

  typedef enum
  {
    update_process               = BIT(0),
    update_aggregate_increment   = BIT(1),
    update_nexthop_reachability  = BIT(2),
    update_mpls_tag              = BIT(3),
  } update_actions_t ;

  update_actions_t  actions ;

  ok = true ;
  actions = 0 ;

  working = bgp_attr_pair_load(attrs, attr) ;

  bgp = peer->bgp;
  p   = &rn->p ;

  sort = peer->sort ;

  /* When peer's soft reconfiguration enabled.  Record input packet in
   * Adj-RIBs-In.
   */
  if ((peer->af_flags[qafx] & PEER_AFF_SOFT_RECONFIG)
                                 && (peer != bgp->peer_self) && ! soft_reconfig)
    bgp_adj_in_set (rn, peer, working);

  /* Look for previously received route, if any.
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* AS path change-local-as loop check.
   *
   * Note belt and braces test for change_local_as -- significant only for
   * eBGP peers.  Note also that change_local_as is ignored if it is the same
   * as the confed_id.
   */
  if ( (peer->change_local_as != BGP_ASN_NULL) && (sort == BGP_PEER_EBGP) &&
       (peer->change_local_as != bgp->cluster_id) )
    {
      uint loop_limit ;

      loop_limit = (peer->flags & PEER_FLAG_LOCAL_AS_NO_PREPEND) ? 0 : 1 ;

      if (!as_path_loop_check (working->asp, peer->change_local_as, loop_limit))
        {
          reason = "as-path contains our own (change-local) AS;";
          goto filtered;
        } ;
    } ;

  /* AS path local-as loop check.
   */
  if (!as_path_loop_check(working->asp, bgp->as, peer->allowas_in[qafx]))
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* AS path confed_id loop check.
   */
  if ((bgp->confed_id != BGP_ASN_NULL) &&
      !as_path_loop_check(working->asp, bgp->confed_id, peer->allowas_in[qafx]))
    {
      reason = "as-path contains our own (CONFED_ID) AS;";
      goto filtered;
    }

  /* Check that we are not the originator of this route
   */
  if ((bgp->router_id == working->originator_id)
                                         && (working->have & atb_originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    } ;

  /* Route Reflector Cluster List check
   */
  if (working->cluster != NULL)
    {
      /* Check that our cluster_id/router_id does not appear in the cluster
       * list.
       *
       * NB: we don't actually know whether we are a Route Reflector or not,
       *     so we here scan the CLUSTER_LIST in any case.
       */
     if (!attr_cluster_check (working->cluster, bgp->cluster_id))
        {
          reason = "reflected from the same cluster;";
          goto  filtered;
        } ;
    } ;

  /* Apply incoming filter.
   *
   * NB: this does not change the attributes.
   */
  if (bgp_input_filter (peer, p, working, qafx) == FILTER_DENY)
    {
      reason = "filter;";
      goto filtered;
    }

  /* Apply incoming route-map.
   *
   * NB: this may change the attributes.
   */
  if (bgp_input_modifier(peer, p, attrs, qafx))
    working = attrs->working ;
  else
    {
      reason = "route-map;";
      goto filtered;
    } ;

  /* IPv4 unicast next hop check.
   */
  if (qafx == qafx_ipv4_unicast)
    {
      qassert(working->next_hop.type == nh_ipv4) ;

      /* If the peer is EBGP and nexthop is not on connected route,
       * discard it.
       */
      if ( (sort == BGP_PEER_EBGP)
              && (peer->ttl == 1)
              && ! bgp_nexthop_onlink (qAFI_ipv4, &working->next_hop)
              && ! (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK) )
        {
          reason = "non-connected next-hop;";
          goto filtered;
        } ;

      /* Next hop must not be 0.0.0.0 nor Class D/E address.
       *
       * Next hop must not be my own address.
       */
      if ( bgp_nexthop_self (working->next_hop.ip.v4)
                               || (working->next_hop.ip.v4 == 0)
                               || IPV4_CLASS_DE(ntohl(working->next_hop.ip.v4)))
        {
          reason = "martian next-hop;";
          goto filtered;
        } ;
    } ;

  /* We are now ready to use this route -- so, if any changes have been made
   * to the attributes, we now need a stored version of the new ones.
   */
  stored = bgp_attr_pair_store(attrs) ;

  actions = 0 ;                 /* Nothing, yet */

  if (ri != NULL)
    {
      /* We have an existing route ---------------------------------------------
       */
      bool  damping ;
      bool  removed ;

      damping = (bgp->af_flags[qafx] & BGP_CONFIG_DAMPING)
                                                    && (sort == BGP_PEER_EBGP) ;

      removed = (ri->flags & BGP_INFO_REMOVED) ;

      ri->uptime = bgp_clock ();

      if ((ri->attr == stored) && !removed)
        {
          /* Same attribute as the current attribute rolls up.
           */
          bgp_info_unset_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          if (damping && (ri->flags & BGP_INFO_HISTORY))
            {
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (peer->log, LOG_DEBUG, "%s rcvd %s",
                                                   peer->host, spfxtoa(p).str) ;

              if (bgp_damp_update(ri, rn) != BGP_DAMP_SUPPRESSED)
                actions = update_process | update_aggregate_increment ;
            }
          else /* Duplicate - odd */
            {
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (peer->log, LOG_DEBUG, "%s rcvd %s...duplicate ignored",
                                                   peer->host, spfxtoa(p).str) ;

              /* graceful restart STALE flag unset.
               */
              if (ri->flags & BGP_INFO_STALE)
                {
                  bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);
                  actions = update_process ;
                }
            } ;
        }
      else
        {
          /* Either no current route, or previous route is still in the process
           * of being removed
           */
          if (removed)
            {
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (peer->log, LOG_DEBUG,
                        "%s rcvd %s, flapped quicker than processing",
                                                   peer->host, spfxtoa(p).str) ;
              bgp_info_restore (rn, ri);
            }
          else
            {
              /* Different attribute
               */
              if (BGP_DEBUG (update, UPDATE_IN))
                  zlog (peer->log, LOG_DEBUG, "%s rcvd %s",
                                                  peer->host, spfxtoa(p).str) ;
            } ;

          /* graceful restart STALE flag unset.
           */
          if (ri->flags & BGP_INFO_STALE)
            bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);

          /* The attribute is changed.
           */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* implicit withdraw, decrement aggregate and pcount here.
           * only if update is accepted, they'll increment below.
           */
          bgp_aggregate_decrement (bgp, p, ri, qafx);

          /* Update bgp route damping information if required.
           */
          if (damping && (ri->flags & BGP_INFO_HISTORY))
            bgp_damp_withdraw (ri, rn, qafx, true /* changed */);

          /* Update to new attribute.
           */
          bgp_attr_unlock(ri->attr) ;
          ri->attr = bgp_attr_lock(stored) ;

          actions = update_process | update_aggregate_increment
                                   | update_nexthop_reachability
                                   | update_mpls_tag ;

          /* Update bgp route damping information.
           */
          if (damping)
            {
              if (bgp_damp_update (ri, rn) == BGP_DAMP_SUPPRESSED)
                actions = update_mpls_tag ;
            } ;
        } ;
    }
  else
    {
      /* This is a new route ---------------------------------------------------
       */
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG, "%s rcvd %s", peer->host, spfxtoa(p).str) ;

      ri = bgp_info_new ();
      ri->type     = type;
      ri->sub_type = sub_type;
      ri->peer     = peer;
      ri->attr     = bgp_attr_lock(stored) ;
      ri->uptime   = bgp_clock ();

      /* Note that bgp_info_add() locks the rn -- so for each bgp_info that the
       * bgp_node points to, there is a lock on the rn (which corresponds to
       * the pointer from the bgp_info to the rn).
       */
      bgp_info_add (rn, ri);

      actions = update_process | update_aggregate_increment
                               | update_nexthop_reachability
                               | update_mpls_tag ;
    } ;

  /* Perform such actions as are required.
   */
  if (qafx_is_mpls_vpn(qafx) && (actions & update_mpls_tag))
    memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);

  if (actions & update_nexthop_reachability)
    {
      if (qafx_is_unicast(qafx)
          && (   (sort == BGP_PEER_IBGP)
              || (sort == BGP_PEER_CBGP)
              || ((sort == BGP_PEER_EBGP) && (peer->ttl != 1))
              || (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK)))
        {
          if (bgp_nexthop_lookup (get_qAFI(qafx), peer, ri, NULL, NULL))
            bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
          else
            bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
        }
      else
        bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
    } ;

  if (actions & update_aggregate_increment)
    bgp_aggregate_increment (bgp, p, ri, qafx);

  if (actions & update_process)
    bgp_process_dispatch (bgp, rn) ;

  ok = !bgp_maximum_prefix_overflow (peer, qafx, false /* not always */) ;

  /* Deal with locks and then we are done.
   */
 bgp_update_main_exit:

  bgp_attr_pair_unload(attrs) ;

  return ok ;

  /* This BGP update is filtered.  Log the reason then update BGP
   * entry.
   */
 filtered:
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
            "%s rcvd UPDATE about %s -- DENIED due to: %s",
                                           peer->host, spfxtoa(p).str, reason);

  if (ri != NULL)
    bgp_rib_remove (rn, ri, peer, qafx) ;

  goto bgp_update_main_exit ;
} ;

/*------------------------------------------------------------------------------
 * Withdraw the given prefix from main RIB
 */
static bool
bgp_withdraw_main(bgp_peer peer, prefix p, qafx_t qafx, int type, int sub_type)
{
  pnode pn ;
  rnode rn ;

  /* Logging
   */
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG, "%s rcvd UPDATE about %s -- withdrawn",
                                                   peer->host, spfxtoa(p).str) ;

  /* Find the peer-node.
   */
  rn = bgp_afi_node_get (peer->bgp->rib[qafx], qafx, p, prd);

  /* If we have an adj_in entry, time to remove it.
   */
  bgp_adj_in_unset (rn, peer);

  /* Lookup withdrawn route.
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* Withdraw route from main RIB -- applying damping if required.
   */
  if ((ri != NULL) && !(ri->flags & BGP_INFO_HISTORY))
    {
      /* apply damping, if result is suppressed, we'll be retaining
       * the bgp_info in the RIB for historical reference.
       */
      int status ;

      if ((peer->bgp->af_flags[qafx] & BGP_CONFIG_DAMPING)
                                         && (peer->sort == BGP_PEER_EBGP))
        status = bgp_damp_withdraw (ri, rn, qafx, false /* not changed */) ;
      else
        status = BGP_DAMP_NONE ;

        bgp_aggregate_decrement (peer->bgp, &rn->p, ri, qafx) ;

        if (status != BGP_DAMP_SUPPRESSED)
          {
            if (!(ri->flags & BGP_INFO_HISTORY))
              bgp_info_delete (rn, ri) ;

            bgp_process_dispatch (peer->bgp, rn);
          } ;
      }
  else
    {
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG,
                     "%s Can't find the route %s", peer->host, spfxtoa(p).str);
    } ;

  /* Unlock bgp_node_get() lock.
   */
  bgp_unlock_node (rn);

  return true ;
}

/*------------------------------------------------------------------------------
 * Update the given RS Client's RIB with the given route from the given peer.
 *
 * The peer's rs-in route-map once for all the rsclients who are to receive
 * the route.
 *
 * Then export and import route-maps for the peer and the rsclient respectively.
 */
static void
bgp_update_rsclient (bgp_peer rsclient, rs_route rt)
{
  attr_pair_t attrs[1] ;
  attr_set    working, stored ;
  bgp_node    rn;
  struct bgp_info *ri;
  const char *reason;

  typedef enum
  {
    update_process   = BIT(0),
    update_mpls_tag  = BIT(1),
  } update_actions_t ;

  update_actions_t  actions ;

  /* Do not insert announces from a rsclient into its own 'bgp_table'.
   */
  if (rt->peer == rsclient)
    return;

  /* Find node for this route in the RS Client RIB
   */
  rn = bgp_afi_node_get (rsclient->prib[rt->qafx], rt->qafx, rt->p, rt->prd) ;

  /* Find any previously received route.
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if (ri->peer == rt->peer && ri->type     == rt->type
                             && ri->sub_type == rt->sub_type)
      break;

  /* If rs-in denies the route, stop now
   */
  if (rt->rs_in == NULL)
    {
      bgp_attr_pair_load_new(attrs) ;   /* empty the pair       */

      reason = "rs-in-policy;";
      goto filtered;
    } ;

  /* Load the attribute pair so can do route-maps etc.
   */
  working = bgp_attr_pair_load(attrs, rt->rs_in) ;

  /* AS path loop check.
   */
  if (!as_path_loop_check (working->asp, rsclient->as,
                                               rt->peer->allowas_in[rt->qafx]))
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.
   */
  if ( (working->have & atb_originator_id) &&
                        (rsclient->remote_id == working->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }

  /* Apply export policy.
   *
   * The export policy belongs to the source peer (which may not be an
   * RS-Client).  The route-map is run with the destination peer (which is an
   * RS-Client) as the peer-as.
   *
   * So the export policy may do things depending on the destination peer, and
   * stands in for the 'out' filter which would (absent the route-server) be
   * the source peer's 'out' route-map facing the destination peer.
   */
  if (rt->peer->af_flags[rt->qafx] & PEER_AFF_RSERVER_CLIENT)
    {
      if (bgp_export_modifier (rsclient, rt, attrs))
        working = attrs->working ;
      else
        {
          reason = "export-policy;";
          goto filtered;
        } ;
    } ;

  /* Apply import policy.
   *
   * The import policy belongs to the destination peer (which is an RS-Client).
   * The route-map is run with the source peer (which may not be an RS-Client)
   * as the peer-as.
   *
   * So the import policy may do things depending on the source peer, and
   * stands in for the 'in' filter which would (absent the route-server) be
   * the destination peer's 'in' route-map facing the source peer.
   */
  if (bgp_import_modifier (rsclient, rt, attrs, BGP_RMAP_TYPE_IMPORT))
    working = attrs->working ;
  else
    {
      reason = "import-policy;";
      goto filtered;
    }

  /* IPv4 unicast next hop check.
   */
  if (rt->qafx == qafx_ipv4_unicast)
    {
      /* Next hop must not be 0.0.0.0 nor Class D/E address.
       */
      qassert(working->next_hop.type == nh_ipv4) ;

      if ( (working->next_hop.ip.v4 == 0) ||
                                 IPV4_CLASS_DE(ntohl(working->next_hop.ip.v4)))
        {
          reason = "martian next-hop;";
          goto filtered;
        } ;
    } ;

  /* We are now ready to use this route -- so, if any changes have been made
   * to the attributes, we now need a stored version of the new ones.
   */
  stored = bgp_attr_pair_store(attrs) ;

  actions = 0 ;                 /* Nothing, yet */

  if (ri != NULL)
    {
      /* We have an existing route ---------------------------------------------
       *
       * Note that we don't do any damping for RS Client RIB
       */
      bool  removed ;

      ri->uptime = bgp_clock ();

      removed = (ri->flags & BGP_INFO_REMOVED) ;

      ri->uptime = bgp_clock ();

      if ((ri->attr == stored) && !removed)
        {
          /* Same attribute as the current attribute rolls up.
           */
          bgp_info_unset_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          if (BGP_DEBUG (update, UPDATE_IN))
            zlog (rt->peer->log, LOG_DEBUG,
                    "%s rcvd %s for RS-client %s...duplicate ignored",
                           rt->peer->host, spfxtoa(rt->p).str, rsclient->host) ;
        }
      else
        {
          /* Either no current route, or previous route is still in the
           * process of being removed
           */
          if (removed)
            {
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (rt->peer->log, LOG_DEBUG,
                 "%s rcvd %s for RS-client %s, flapped quicker than processing",
                           rt->peer->host, spfxtoa(rt->p).str, rsclient->host) ;

              bgp_info_restore (rn, ri);
            }
          else
            {
              /* Different attribute
               */
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (rt->peer->log, LOG_DEBUG, "%s rcvd %s for RS-client %s",
                           rt->peer->host, spfxtoa(rt->p).str, rsclient->host) ;
            } ;

          /* The attribute is changed.
           */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Update to new attribute.
           */
          bgp_attr_unlock(ri->attr) ;
          ri->attr = bgp_attr_lock(stored) ;

          actions = update_process | update_mpls_tag ;
        } ;
    }
  else
    {
      /* This is a new route ---------------------------------------------------
       */
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (rt->peer->log, LOG_DEBUG, "%s rcvd %s for RS-client %s",
                           rt->peer->host, spfxtoa(rt->p).str, rsclient->host) ;

      ri = bgp_info_new ();
      ri->type     = rt->type;
      ri->sub_type = rt->sub_type;
      ri->peer     = rt->peer;
      ri->attr     = bgp_attr_lock(stored) ;
      ri->uptime   = bgp_clock ();

      bgp_info_add (rn, ri);

      actions = update_process | update_mpls_tag ;
    } ;

  /* Perform such actions as are required.
   */
  if ((rt->q_safi == qSAFI_MPLS_VPN) && (actions & update_mpls_tag))
    memcpy ((bgp_info_extra_get (ri))->tag, rt->tag, 3);

  if (actions & update_process)
    {
      bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
      bgp_process_dispatch (rsclient->bgp, rn) ;
    } ;

  /* Deal with locks and then we are done.
   */
 bgp_update_rsclient_exit:

  bgp_unlock_node (rn);
  bgp_attr_pair_unload(attrs) ;

  return ;

  /* Deal with route which has been filtered out.
   *
   * If there was a previous route, then remove it.
   *
   * If have an interned client attributes, then discard those.
   */
  filtered:

  /* This BGP update is filtered.  Log the reason then update BGP entry.  */
  if (BGP_DEBUG (update, UPDATE_IN))
        zlog (rt->peer->log, LOG_DEBUG,
        "%s rcvd UPDATE about %s -- DENIED for RS-client %s due to: %s",
                   rt->peer->host, spfxtoa(rt->p).str, rsclient->host, reason) ;

  if (ri != NULL)
    {
      /* Kill off existing route.
       *
       * Note that we don't do any damping for RS Client RIB
       */
      bgp_info_delete (rn, ri);
      bgp_process_dispatch (rsclient->bgp, rn);
    } ;

  goto bgp_update_rsclient_exit ;
}

/*------------------------------------------------------------------------------
 * Withdraw route from RS Client, where route came from given peer
 */
static void
bgp_withdraw_rsclient (bgp_peer rsclient, bgp_peer peer, prefix p, qafx_t qafx,
                                  int type, int sub_type, struct prefix_rd *prd)
{
  bgp_node rn ;
  struct bgp_info *ri;

  if (rsclient == peer)
    return;

  rn = bgp_afi_node_get (rsclient->prib[qafx], qafx, p, prd);

  /* Lookup withdrawn route
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* Withdraw specified route from routing table
   *
   * NB: no damping performed for RS Client stuff !
   */
  if (ri != NULL)
    {
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG,
                  "%s rcvd %s for RS-client %s -- withdrawn",
                                   peer->host, spfxtoa(p).str, rsclient->host) ;
      bgp_info_delete (rn, ri) ;
      bgp_process_dispatch (rsclient->bgp, rn) ;
    }
  else
    {
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG,
             "%s rcvd %s for RS-client %s -- withdrawn, but cannot find route",
                                   peer->host, spfxtoa(p).str, rsclient->host) ;
    } ;

  /* Unlock bgp_node_get() lock.
   */
  bgp_unlock_node (rn);
} ;

/*------------------------------------------------------------------------------
 * Unconditionally remove the route from the RIB, without taking
 * damping into consideration (eg, because the session went down)
 */
static void
bgp_rib_remove (bgp_node rn, struct bgp_info *ri, bgp_peer peer, qafx_t qafx)
{
  bgp_aggregate_decrement (peer->bgp, &rn->p, ri, qafx);

  if (!CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    bgp_info_delete (rn, ri); /* keep historical info */

  bgp_process_dispatch (peer->bgp, rn);
}

#endif


/*------------------------------------------------------------------------------
 * Do we need to worry about Determinstic MEDs ?
 */
inline static bool
bgp_is_deterministic_med(bgp_inst bgp)
{
  return ( bgp->flags &
                 (BGP_FLAG_ALWAYS_COMPARE_MED | BGP_FLAG_DETERMINISTIC_MED) )
                                             == BGP_FLAG_DETERMINISTIC_MED ;
} ;

/*------------------------------------------------------------------------------
 * Set the rn->flags rnf_deterministic_med to reflect the current state of the
 * parent bgp.
 *
 * This can be done when a RIB Node is about to be processed or scheduled for
 * processing, so that a change in the state of the parent bgp is taken into
 * account the next time routes are selected.
 *
 * Returns:  true <=> is now rnf_deterministic_med AND was not before.
 */
inline static bool
bgp_rib_node_deterministic_med(bgp_rib_node rn, bgp_inst bgp)
{
  bool deterministic_med ;

  deterministic_med = bgp_is_deterministic_med(bgp) ;

  if (deterministic_med == (rn->flags & rnf_deterministic_med))
    return false ;

  rn->flags ^= rnf_deterministic_med ;

  return deterministic_med ;
} ;

/*==============================================================================
 * Inbound update filtering.
 *
 */


/*------------------------------------------------------------------------------
 * Issue UPDATE_IN debug message as required.
 */
inline static void
bgp_update_filter_in_log(bgp_peer peer, prefix_c pfx, const char* reason)
{
  if (BGP_DEBUG (update, UPDATE_IN) && (reason != NULL))
    zlog (peer->log, LOG_DEBUG,
             "%s rcvd UPDATE about %s -- DENIED due to: %s",
                                         peer->host, spfxtoa(pfx).str, reason) ;
} ;


#define FILTER_EXIST_WARN(type, is_set, name) \
  if (BGP_DEBUG (update, UPDATE_IN) && !(is_set)) \
    plog_warn (peer->log, "%s: %s %s not set", peer->host, type, name)

/*------------------------------------------------------------------------------
 * Process the given parcel to construct the attr_main set.
 *
 * Performs the following checks and filters:
 *
 *   * AS-PATH loop checks: 1) change_local_as -- if implemented
 *                          2) our AS
 *                          3) confed_id -- if required
 *
 *   * originator_id -- if any
 *
 *   * route-reflector cluster -- if any
 *
 *   * IPv4 Unicast next hop checks -- if nexthop is IPv4 Unicast
 *
 *   * distribute-list aaaa in -- if any
 *
 *   * 'prefix-list aaaa in' -- if any
 *
 *   * 'filter-list aaaa in' -- if any
 *
 *   * set the peer->weight -- if any
 *
 *   * change_local-as prepend -- as required
 *
 *   * 'route-map aaaa in' -- if any
 *
 * NB: expects the parcel->attr to be stored, and to have been created from a
 *     set of attributes from a message.
 *
 *     In particular:  parcel->attr->weight  == 0
 *                     parcel->attr->tag     == 0
 *
 * From bgp_inst requires:
 *
 *   bgp->as
 *   bgp->ebgp_as
 *   bgp->confed_id
 *   bgp->router_id
 *   bgp->cluster_id
 */
static attr_set
bgp_update_filter_main(peer_rib prib, attr_set attr, prefix_c pfx)
{
  bgp_peer    peer ;
  bgp_inst    bgp ;
  attr_pair_t pair[1] ;
  as_path     asp ;
  access_list dlist ;
  prefix_list plist ;
  as_list     aslist ;
  route_map   rmap ;
  bool        change_local_as_prepend ;
  const char* reason;
  bgp_peer_sort_t sort ;
  qafx_t  qafx ;

  qafx = prib->qafx ;
  peer = prib->peer ;
  bgp  = peer->bgp;
  sort = peer->sort ;

  /* Load attribute pair in preparation for any changes later on.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* AS path loop and Next-Hop checks.
   *
   * For eBGP: if directly connected, check that the nexthop is "onlink".
   *
   *           if there is a change_local_as, look for that unless it is the
   *           same as the ebgp_as.
   *
   *           look for the ebgp_as -- with allow_as_in.
   *
   *           if confed_id is defined, check for bgp->as as well.
   *
   * For other peers:
   *
   *           no check for directly connected next hop.
   *
   *           look for the bgp->as -- with allow_as_in.
   *
   *           if confed_id is defined, check for that as well.
   */
  change_local_as_prepend = false ;
  asp = pair->working->asp ;

  if (sort == BGP_PEER_EBGP)
    {
      /* If the peer is EBGP and nexthop is not on connected route,
       * discard it.
       *
       * TODO nexthop check for IPv6 ????..............................................
       */
      if ( (peer->ttl == 1)
              && ! bgp_nexthop_onlink (qAFI_ipv4, &attr->next_hop)
              && ! (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK) )
        {
          reason = "non-connected next-hop;";
          goto filtered;
        } ;

      /* If we have a change_local_as which is not the same as the as the
       * bgp->ebgp_as, then need to check for that.
       *
       * Note that the 'allowas_in' does not apply to this check.
       */
      if ( (peer->change_local_as != BGP_ASN_NULL) &&
           (peer->change_local_as != bgp->ebgp_as) )
        {
          if (!as_path_loop_check (asp, peer->change_local_as, 0))
            {
              reason = "as-path contains our own (change-local) AS;";
              goto filtered;
            } ;

          change_local_as_prepend =
                                !(peer->flags & PEER_FLAG_LOCAL_AS_NO_PREPEND) ;
        } ;

      /* AS path eBGP loop check -- this is the standard check for loop.
       */
      if (!as_path_loop_check(asp, bgp->ebgp_as, prib->allowas_in))
        {
          if (bgp->confed_id == BGP_ASN_NULL)
            reason = "as-path contains our own AS;";
          else
            reason = "as-path contains our own (Confed_ID) AS;";
          goto filtered;
        } ;

      /* Final check, if there is a confed_id which is not the same as the
       * bgp->as, then we check for the bgp->as too.
       *
       * This is a belt-and-braces thing.  If confed_id != bgp->as, then the
       * bgp->as is the Confederation Member AS, which should not have leaked
       * out to the outside world.
       *
       * The AS-PATH really should not contain any of the Confederation Member
       * ASes (the confed_peers) -- but we do not check for that.
       */
      if (bgp->check_confed_id && !as_path_loop_check(asp, bgp->as, 0))
        {
          reason = "as-path contains our own (Confed Member) AS;";
          goto filtered;
        } ;
    }
  else
    {
      /* AS path our AS loop check for all but eBGP
       *
       * For iBGP this will jump on any AS_PATHs which for some unknown reason
       * an internal peer is sending with our AS in it.
       *
       * For Confed -- that is a peer in the same confederation, but in a
       * different member AS -- this traps route loops within the confederation.
       * (In this case the bgp->as ought to be in Confed segments -- but we
       * don't actually worry about that !)
       */
      if (!as_path_loop_check(asp, bgp->as, prib->allowas_in))
        {
          reason = "as-path contains our own AS;";
          goto filtered;
        } ;

      /* Final check, if there is a confed_id which is not the same as the
       * bgp->as, then we check for that too.
       *
       * This is a belt-and-braces thing.  The confed_id should not appear in
       * the AS-PATH, unless it is a Member AS, in which case it should not
       * appear in any not-confederation segment.
       */
      if (bgp->check_confed_id)
        {
          if (bgp->check_confed_id_all)
            {
              if (!as_path_loop_check(asp, bgp->confed_id, 0))
                {
                  reason = "as-path contains our own (Confed_ID) AS;";
                  goto filtered ;
                } ;
            }
          else
            {
              if (!as_path_loop_check_not_confed(asp, bgp->confed_id, 0))
                {
                  reason = "as-path contains our own (Confed_ID) AS;";
                  goto filtered;
                } ;
            } ;
        } ;
    } ;

  /* Check that we are not the originator of this route
   */
  if ((bgp->router_id == pair->working->originator_id)
                                   && (pair->working->have & atb_originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    } ;

  /* Route Reflector Cluster List check
   */
  if (pair->working->cluster != NULL)
    {
      /* Check that our cluster_id does not appear in the cluster list.
       *
       * NB: all bgp instances have a default cluster_id, which is the
       *     instance's router-id.
       *
       * NB: we don't actually know whether we are a Route Reflector or not,
       *     so we here scan the CLUSTER_LIST in any case.
       */
      if (!attr_cluster_check (pair->working->cluster, bgp->cluster_id))
        {
          reason = "reflected from the same cluster;";
          goto  filtered;
        } ;
    } ;

  /* Apply incoming filter(s):
   *
   *   * 'distribute-list in'
   *
   *   * 'prefix-list in'
   *
   *   * 'filter-list in'
   *
   * Noting that none of these change the given set of attributes.
   */
  dlist = prib->dlist[FILTER_IN] ;
  if (dlist != NULL)
    {
      FILTER_EXIST_WARN("distribute-list in", access_list_is_set(dlist),
                                              access_list_get_name(dlist)) ;

      if (access_list_apply (dlist, pfx) == FILTER_DENY)
        {
          reason = "distribute-list in;";
          goto filtered;
        } ;
    } ;

  plist = prib->plist[FILTER_IN] ;
  if (plist != NULL)
    {
      FILTER_EXIST_WARN("prefix-list in", prefix_list_is_set(plist),
                                          prefix_list_get_name(plist)) ;

      if (prefix_list_apply (plist, pfx) == PREFIX_DENY)
        {
          reason = "prefix-list in;";
          goto  filtered;
        } ;
    } ;

  aslist = prib->flist[FILTER_IN] ;
  if (aslist != NULL)
    {
      FILTER_EXIST_WARN("filter-list", as_list_is_set(aslist),
                                       as_list_get_name(aslist)) ;

      if (as_list_apply (aslist, asp) == AS_FILTER_DENY)
        {
          reason = "filter-list;";
          goto  filtered;
        } ;
    }

  /* Set 'weight' if required.
   */
  qassert(pair->working->weight == 0) ;

  if (peer->weight != 0)
    bgp_attr_pair_set_weight(pair, peer->weight) ;

  /* change_local-as prepend
   *
   * Where we are inserting the "phantom" change_local_as at the head of
   * the AS_PATH on output to the peer, we do the same on input from that
   * peer -- unless PEER_FLAG_LOCAL_AS_NO_PREPEND.
   *
   * The effect of this is as if the "phantom" ASN still existed, between
   * us and the peer.
   *
   * Except: if the "phantom" ASN is the same as the current bgp->ebp_as,
   *         then the change_local_as is ignored.
   */
  if (change_local_as_prepend)
    bgp_attr_pair_set_as_path(pair,
                                as_path_add_seq (asp, peer->change_local_as)) ;

  /* Process prefix and attributes against any 'in' route-map.
   */
  rmap = prib->rmap[RMAP_IN] ;

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      FILTER_EXIST_WARN("route-map in", route_map_is_set(rmap),
                                        route_map_get_name(rmap)) ;

      brm->peer      = peer ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_IN ;

      if (route_map_apply(rmap, pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          reason = "route-map in;";
          goto  filtered ;
        } ;
    } ;

  /* Deal with locks and then we are done.
   */
  return bgp_attr_pair_store(pair) ;

  /* This BGP update is filtered.  Log the reason then update BGP
   * entry.
   */
 filtered:
  bgp_update_filter_in_log(peer, pfx, reason) ;

  bgp_attr_pair_unload(pair) ;
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Process the given parcel to construct the attr_rs set.
 *
 * Performs the following checks and filters:
 *
 *   * AS-PATH loop checks: our AS
 *
 *   * originator_id        -- if any
 *
 *   * set the peer->weight -- if any
 *
 *   * 'route-map rs-in'    -- if any
 *
 * From bgp_inst requires:
 *
 *   bgp->as
 *   bgp->router_id
 */
static attr_set
bgp_update_filter_rs_in(peer_rib prib, attr_set attr, prefix_c pfx)
{
  bgp_peer    peer ;
  bgp_inst    bgp ;
  attr_pair_t pair[1] ;
  route_map rmap ;
  const char *reason;
  qafx_t  qafx ;

  qafx = prib->qafx ;
  peer = prib->peer ;
  bgp  = peer->bgp;

  /* Load attribute pair in preparation for any changes later on.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* AS path loop check
   *
   * This is a duplicate of the Main RIB check -- so no need to log.
   */
  if (!as_path_loop_check(pair->working->asp, bgp->as, 0))
    {
      reason = NULL ;
      goto filtered ;
    } ;

  /* Check that we are not the originator of this route
   *
   * This is a duplicate of the Main RIB check -- so no need to log.
   */
  if ((bgp->router_id == pair->working->originator_id)
                                   && (pair->working->have & atb_originator_id))
    {
      reason = NULL ;
      goto filtered ;
    } ;

  /* Set 'weight' if required.
   */
  qassert(pair->working->weight == 0) ;

  if (peer->weight != 0)
    bgp_attr_pair_set_weight(pair, peer->weight) ;

  /* Process prefix and attributes against any 'in' route-map.
   */
  rmap = prib->rmap[RMAP_RS_IN] ;

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      FILTER_EXIST_WARN("route-map rs-in", route_map_is_set(rmap),
                                           route_map_get_name(rmap)) ;

      brm->peer      = peer ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_RS_IN ;

      if (route_map_apply(rmap, pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          reason = "route-map rs-in;";
          goto filtered;
        } ;
    } ;

  /* Deal with locks and then we are done.
   */
  return bgp_attr_pair_store(pair) ;

  /* This BGP update is filtered.  Log the reason then update BGP
   * entry.
   */
 filtered:
  bgp_update_filter_in_log(peer, pfx, reason) ;

  return bgp_attr_pair_unload(pair) ;
} ;

/*------------------------------------------------------------------------------
 * Process the given route_info to construct the attributes for the given
 * RS-Client.
 *
 * Starts from the ri->attr_rcv -- which, for RS RIB route_info is the
 * attributes after processing by 'rs_in' route-map etc.
 *
 * Returns:  NULL <=> the route has been filtered out.
 *           attributes after export and import route-maps, if any -- stored
 *           and locked.
 *
 * NB: any attribute set returned has been locked by this function.
 *
 *     If the route-maps did not change the attributes, then returns the
 *     given ri->attr_rcv *with* an extra lock.
 *
 *     If the route-maps did change the attributes, then returns the new
 *     attributes, stored with one level of lock.
 */
static route_merit_t
bgp_update_filter_rs_use(route_info ri, peer_rib crib, prefix_c pfx)
{
  attr_pair_t pair[1] ;
  attr_set    attr ;
  route_map   rmap ;

  if (ri->attr_rcv == NULL)
    {
      ri->flags |= RINFO_RS_DENIED ;
      return route_merit_none ;
    } ;

  /* Load attribute pair in preparation for any changes later on.
   */
  bgp_attr_pair_load(pair, ri->attr_rcv) ;

  /* Apply the export route-map for the given source peer.
   *
   * Route map apply.
   *
   * Note that the peer for relevant matches is the client which is the
   * *destination* for the route.  (The route-map itself belongs to the peer
   * which is the *source* of the route.)
   */
  rmap = ri->prib->rmap[RMAP_EXPORT] ;

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->peer      = crib->peer ;
      brm->attrs     = pair ;
      brm->qafx      = ri->qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_EXPORT ;

      if (route_map_apply(rmap, pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          bgp_attr_pair_unload(pair) ;
          ri->flags |= RINFO_RS_DENIED ;
          return route_merit_none ;
        } ;
    } ;

  /* Apply the import route-map for the given destination rsclient
   *
   * Note that the peer for relevant matches is the peer which is the
   * *source* of the route.  (The route-map itself belongs to the client
   * which is the *destination* of the route.)
   */
  rmap = crib->rmap[RMAP_IMPORT];

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->peer      = ri->prib->peer ;
      brm->attrs     = pair ;
      brm->qafx      = ri->qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_IMPORT ;

      if (route_map_apply(rmap, pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          bgp_attr_pair_unload(pair) ;
          ri->flags |= RINFO_RS_DENIED ;
          return route_merit_none ;
        } ;
    } ;

  ri->flags &= ~RINFO_RS_DENIED ;

  /* Need a stored version of the attributes -- if anything has changed.
   *
   * If this is the same result as the last time, then we discard the result
   * and we can re-use the existing merit.
   */
  attr = bgp_attr_pair_store(pair) ;

  if (ri->attr == attr)
    {
      /* If the attr for this client are the same as the current attr,
       * then we don't need the extra lock on the attr, and we can use the
       * stored merit to decide whether this route is a candidate.
       *
       * This works nicely where the export and import route-maps do not
       * change the attributes.
       */
      bgp_attr_unlock(attr) ;

      return ri->merit ;
    }

  /* We have a different set of attributes than we had before, so we need to
   * store the attributes and merit in the route_info, for use in
   * tie break and possibly for future use.
   */
  if (ri->attr != NULL)
    bgp_attr_unlock(ri->attr) ;

  ri->attr = attr ;

  return ri->merit = bgp_route_merit(crib->peer->bgp, attr, ri->sub_type) ;
} ;

#undef FILTER_EXIST_WARN

/*------------------------------------------------------------------------------
 * next-hop check.
 *
 *
 */
static bool
bgp_update_filter_next_hop(peer_rib prib, route_in_parcel parcel, prefix_c pfx)
{
  attr_next_hop next_hop ;
  const char* reason ;

  qassert(parcel->action == ra_in_update) ;

  switch (parcel->qafx)
    {
      case qafx_ipv4_unicast:
        /* Next hop must not be 0.0.0.0/8 nor 127.0.0.0/8 nor
         * Class D/E address.
         *
         * RFC 4271 means all or some of these when it requires the address
         * to be "syntactically" correct (and hence be the cause of a
         * NOTIFICATION).  But, Cisco does not treat these as session-reset,
         * and neither do we.
         */
        if (IPV4_N_NET0(next_hop->ip.v4) || IPV4_N_NET127(next_hop->ip.v4)
                                         || IPV4_N_CLASS_DE(next_hop->ip.v4))
          {
            reason = "martian next-hop;";
            goto filtered;
          } ;

        /* Next hop must not be my own address.
         *
         * RFC 4271 requires this, without session-reset.
         */
        if (bgp_nexthop_self (next_hop->ip.v4))
          {
            reason = "next-hop is us;";
            goto filtered;
          } ;

        return true ;

      default:
        return true ;
    } ;

  /* Reject next-hop -- the sender has no business sending it.
   */
 filtered:
  zlog(prib->peer->log, LOG_INFO,
            "%s rcvd UPDATE about %s -- DENIED due to: %s",
                                  prib->peer->host, spfxtoa(pfx).str, reason) ;

   return false ;
} ;

/*==============================================================================
 * Processing of rib_node to update current selection, and announce as required.
 *
 * This is the background stuff...
 */
static wq_ret_code_t bgp_process_walker(void* data, qtime_mono_t yield_time) ;
static void bgp_process_main(bgp_rib rib, bgp_rib_walker rw, bgp_rib_node rn) ;
static void bgp_process_rs(bgp_rib rib, bgp_rib_walker rw, bgp_rib_node rn) ;

static route_info bgp_main_candidates(bgp_rib_node rn) ;
static route_info bgp_rs_candidates(bgp_rib_node rn, prefix_id_entry pie,
                                                                peer_rib crib) ;
static route_info bgp_best_selection (bgp_rib_node rn, route_info ris) ;
static void bgp_process_announce_selected (peer_rib prib, prefix_id_entry pie,
                                                               route_info ris) ;
static void bgp_announce_selected (peer_rib prib, prefix_id_entry pie,
                                                               route_info ris) ;
static void bgp_announce_rs_selected (peer_rib crib, prefix_id_entry pie,
                                                              bgp_rib_node rn) ;

/*------------------------------------------------------------------------------
 * Schedule the given route_node for "update" processing in the given bgp_rib,
 *                                                                  if required.
 *
 * Starts the rib's walker going, if required.
 */
extern void
bgp_process_schedule(bgp_rib rib, bgp_rib_node rn)
{
  qassert(rib == rn->it.rib) ;

  /* If not already scheduled for processing, reschedule at the end of the
   * queue.
   */
  if (rn->flags & rnf_processed)
    {
      rn->flags ^= rnf_processed ;

      ddl_del(rib->queue, &rn->it, queue) ;
      ddl_append(rib->queue, &rn->it, queue) ;
    } ;

  /* In any case, if the walker does not have an active work queue item,
   * now is the time to kick it.
   */
  if (!(rib->walker->it.flags & rib_itf_wq_queue))
    bgp_rib_walker_start(rib->walker, bgp_process_walker) ;
} ;

/*------------------------------------------------------------------------------
 * Work queue function for BGP RIB Walker
 *
 */
static wq_ret_code_t
bgp_process_walker(void* data, qtime_mono_t yield_time)
{
  bgp_rib_walker  rw ;
  bgp_rib         rib ;
  bgp_rib_item    item ;
  peer_rib        prib ;

  rw = data ;

  qassert(rw->it.type == rib_it_walker) ;
  qassert( (rw->it.flags & (rib_itf_rib_queue | rib_itf_wq_queue))
                        == (rib_itf_rib_queue | rib_itf_wq_queue) );

  /* Start by removing the walker from the RIB queue
   */
  rib = rw->it.rib ;

  item = rw->it.queue.next ;
  ddl_del(rib->queue, &rw->it, queue) ;
  rw->it.flags &= ~rib_itf_rib_queue ;

  /* If there is something ahead of the walker, and that is not a rib node,
   * then we need to sort that out.
   */
  if ((item != NULL) && (item->type == rib_it_walker))
    {
      /* We have found another walker -- so merge the walkers together.
       *
       * NB: The rib's update walker starts at the front of the queue, and
       *     remains on the queue forever.
       *
       *     All initial walkers start at the front of the queue.  If the
       *     update walker is at the front of the queue, the initial walker is
       *     merged with it (no initial walker is actually created in this
       *     case).
       *
       *     The upshot of all this is that no initial walker can appear after
       *     an update one.
       *
       * So, the walker we have in our hands cannot be the rib's update walker.
       *
       * We merge the "initial" list from the walker we have, with the walker
       * in front, and then exit, discarding the walker we have and its
       * work queue item.
       */
      bgp_rib_walker rwx ;

      rwx = (bgp_rib_walker)item ;
      confirm(offsetof(bgp_rib_walker_t, it) == 0) ;

      qassert(rw != rib->walker) ;
      qassert(ddl_head(rw->peers[prib_update]) == NULL) ;

      qassert(rwx->it.type == rib_it_walker) ;
      qassert(rwx->it.flags & rib_itf_rib_queue) ;

      for (prib = ddl_head(rw->peers[prib_initial]) ;
                                            prib != NULL ;
                                            prib = ddl_next(prib, walk_list))
        {
          qassert((prib->walker == rw)
                                     && (prib->update_state == prib_initial)) ;
          prib->walker = rwx ;
        } ;

      ddl_prepend_list(rwx->peers[prib_initial], rw->peers[prib_initial],
                                                                    walk_list) ;

      /* We need to make sure that the rwx is active.
       *
       * The rib_main walker, may not be active... if it is at the end of the
       * queue or has no pribs (for example)
       */
      if (!(rwx->it.flags & rib_itf_wq_queue))
        bgp_rib_walker_start(rwx, bgp_process_walker) ;

      /* Can now discard rw.
       *
       * The walker was removed from the rib->queue above.  The peers lists
       * are empty or the contents moved elsewhere.  So we can simply free it,
       * undoing the association between the walker and the work queue item.
       *
       * We return wqrc_release, which takes the work queue item off the
       * work queue and frees it.
       */
      bgp_rib_walker_free(rw) ;

      return wqrc_something | wqrc_release ;
    } ;

  /* If we have a RIB Node to process, do that
   */
  if (item != NULL)
    {
      bgp_rib_node rn ;

      qassert(rw->it.type == rib_it_node) ;

      rn = (bgp_rib_node)item ;
      confirm(offsetof(bgp_rib_node_t, it) == 0) ;

      if (rib->rib_type == rib_main)
        bgp_process_main(rib, rw, rn) ;
      else
        bgp_process_rs(rib, rw, rn) ;

      rn->flags |= rnf_processed ;

      /* If something follows the item we have just processed, then put the
       * walker back on the queue after the item, and return.
       *
       * If this is an initial run for any peers, return wqrc_rerun, so that
       * is time runs out, this will retain its place in the work queue.
       *
       * Otherwise, return qrc_rerun_reschedule, so that will use up the
       * current time-slot, but round-robin between time-slots.
       */
      if (item->queue.next != NULL)
        {
          ddl_in_after(item, rib->queue, &rw->it, queue) ;
          rw->it.flags |= rib_itf_rib_queue ;

          if (ddl_head(rw->peers[prib_initial]) != NULL)
            return wqrc_something | wqrc_rerun ;
          else
            return wqrc_something | wqrc_rerun_reschedule ;
        } ;
    } ;

  /* We have processed the last item in the queue of nodes to process
   *
   * Send EoR to all initial peers, and rehoming them on the "update" list
   * for the bgp_rib walker.
   *
   * Note that we clear the prib->walker pointer in all those initial peers,
   * so if this is an initial walker, we need to discard that
   */
  prib = ddl_head(rw->peers[prib_initial]) ;

  if (prib != NULL)
    {
      /* We want to transfer the initial list to the update list of the bgp_rib
       * walker, and send EoR as required.
       */
      do
        {
          qassert((prib->walker == rw)
                                     && (prib->update_state == prib_initial)) ;

          if (prib->eor_required)
            bgp_adj_out_eor(prib) ;     // TODO when negotiated !!

          prib->walker = rib->walker ;
          prib = ddl_next(prib, walk_list) ;
        }
      while (prib != NULL) ;

      ddl_append_list(rib->walker->peers[prib_update], rw->peers[prib_initial],
                                                                    walk_list) ;
      ddl_init(rw->peers[prib_initial]) ;
    } ;

  /* Can now stop the walker.
   */
  if (rw == rib->walker)
    {
      /* We have completely processed the queue with the "update" walker,
       * which we leave at the end of the queue.
       *
       * We return wqrc_remove, signalling the work queue stuff to remove the
       * work queue item from the work queue.
       */
      ddl_append(rib->queue, &rw->it, queue) ;
      rw->it.flags = (rw->it.flags & ~rib_itf_wq_queue) | rib_itf_rib_queue ;

      return wqrc_something | wqrc_remove ;
    }
  else
    {
      /* We are done with the "initial" rib walker and it's work queue item.
       *
       * The walker is no longer associated with any pribs, and is not on
       * the queue, so we can simply free it, undoing the association between
       * the walker and the work queue item.
       *
       * We return wqrc_release, which takes the work queue item off the
       * work queue and frees it.
       */
      qassert(ddl_head(rw->peers[prib_initial]) == NULL) ;
      qassert(ddl_head(rw->peers[prib_update])  == NULL) ;
      qassert(!(rw->it.flags & rib_itf_rib_queue)) ;

      bgp_rib_walker_free(rw) ;

      return wqrc_something | wqrc_release ;
    } ;
} ;






/*------------------------------------------------------------------------------
 * Work queue process for a Main RIB Node.
 *
 * If there is a candidates list, then we need to re-run the best path
 * selection across that.  The candidates list will contain all possible routes
 * of the same merit, greater than the merit of all other available routes.
 * The currently selected route may be on that list.
 *
 * If the candidates list is empty, then we need to run along the available
 * routes, and create a new candidates list, and then run the best path
 * selection on that.
 */
static void
bgp_process_main(bgp_rib rib, bgp_rib_walker rw, bgp_rib_node rn)
{
  route_info      ris ;
  bool            fib_update ;
  peer_rib        update_run, initial_run ;

  qassert(rib->rib_type == rib_main) ;
  qassert(rw->it.type == rib_it_walker) ;
  qassert(rw->it.rib == rib) ;

  /* Initial state for whether to update peers and/or the fib.
   */
  initial_run = ddl_head(rw->peers[prib_initial]) ;
  update_run  = ddl_head(rw->peers[prib_update]) ;

  if (rw == rib->walker)
    {
      /* For the update walker, we update the FIB if we are the main (unnamed)
       * bgp instance and the FIB is not suppressed.
       *
       * We update the current known peers, as well as any which are in initial
       * state (if any) -- hung off the walker.
       */
      bgp_rib_node_flags_t flags ;

      fib_update  = (rib->bgp->name == NULL) &&
                                          ! bgp_option_check (BGP_OPT_NO_FIB) ;

      /* Pick up and clear the routing information changed flags.
       */
      flags = ris->flags & (RINFO_ATTR_CHANGED | RINFO_IGP_CHANGED) ;
      ris->flags ^= flags ;

      /* We need to run the selection process.
       *
       * If rn->candidates is empty, then we fill it by selecting the route(s)
       * with the highest merit from the available routes.
       *
       * Then perform any tie-break required to finally select a route.
       */
      ris = rn->candidates ;

      if (ris == NULL)
        {
          /* Set candidates to best currently available -- excluding no merit
           * at all.
           */
          qassert(rn->selected == NULL) ;
          ris = bgp_main_candidates(rn) ;
        } ;

      if (ris != NULL)
        {
          /* Have at least one candidate, so will select one -- possibly the
           * same as the current selection.
           *
           * NB: rn->selected == NULL may mean:
           *
           *       1) nothing has ever been selected
           *
           *       2) the last route that was selected has been withdrawn
           *
           *     in both cases ris != rn->selected, and we have a new selection
           *     on our hands.
           */
          ris = bgp_best_selection (rn, ris) ;

          qassert(ris != NULL) ;

          if (ris != rn->selected)
            {
              /* New selection -- will update peers and fib (if required)
               */
              rn->selected = ris ;
              rn->flags   |= rnf_selected ;
            }
          else
            {
              /* Selection is unchanged:
               *
               * Suppress update of peers, unless the attribute value has
               * changed.
               *
               * Suppress FIB update unless the attribute value or IGP metric
               * has changed.
               *
               * Note that will update any initial peers which are attached
               * to the update walker.
               */
              if (!(flags & RINFO_ATTR_CHANGED))
                update_run  = NULL ;

              if (!(flags & (RINFO_ATTR_CHANGED | RINFO_IGP_CHANGED)))
                fib_update  = false ;
            } ;
        }
      else
        {
          /* Have no candidates, so nothing to select.
           *
           * NB: rn->selected must be NULL -- because either we have never
           *     selected anything, or the previously selected route has
           *     been withdrawn.
           *
           * If there was no previous selection, then nothing has changed !
           */
          qassert(rn->selected == NULL) ;

          if (rn->flags & rnf_selected)
            {
              /* There was something selected before, so we now clear the
               * flag and proceed to update peers (including initial peers)
               * and the FIB.
               */
              rn->flags ^= rnf_selected ;
            }
          else
            {
              /* There was nothing selected before, and there is now nothing
               * to select from... so need do nothing at all.
               */
              fib_update  = false ;
              update_run  = NULL ;
              initial_run = NULL ;
            } ;
        } ;
    }
  else
    {
      /* For an initial walker, we don't update the FIB.
       *
       * NB: the first thing that runs when a RIB is started up is an update
       *     walker -- which will update the FIB as required.
       *
       *     Any change to a RIB entry will trigger another update walker.
       *
       *     So, an initial walker should not affect the FIB.
       *
       * Nor do we update the current known peers, only those which are in
       * initial state (if any) -- hung off the walker.
       */
      fib_update  = false ;
      qassert(update_run == NULL) ;

      /* An initial walker uses the current selection.
       *
       * Everything ahead of an initial walker has been visited by an update
       * one -- since cannot start an initial walker ahead of an update one,
       * and cannot overtake an update one.  (Changes to routes already
       * processed by an initial walker will be placed ahead of an update
       * walker, ahead of all initial walkers.)
       *
       * So, if the current selection is NULL, that means the route has been
       * withdrawn -- will be !rnf_selected.
       *
       * NB: the initial walker cannot tell whether it has previously announced
       *     the route or not... so must go ahead and withdraw (which will be
       *     debounced in the adj_out).
       */
      ris = rn->selected ;

      qassert((ris == NULL) == ((rn->flags & rnf_selected) == 0)) ;
    } ;

  /* Update peers and FIB as required.
   */
  if (!(DISABLE_BGP_ANNOUNCE))
    {
      prefix_id_entry pie ;

      pie = prefix_id_get_entry(rn->pfx_id) ;

      while (initial_run != NULL)
        {
          bgp_announce_selected (initial_run, pie, ris) ;
          initial_run = ddl_next(initial_run, walk_list) ;
        } ;

      while (update_run != NULL)
        {
          bgp_announce_selected (update_run, pie, ris) ;
          update_run = ddl_next(update_run, walk_list) ;
        } ;

      /* FIB update if Attributes and/or IGP Metric changed.
       *
       * TODO ... sort out state of rn->zebra after withdraw.
       */
      if (fib_update)
        {
          if ((ris != NULL) && (ris->route_type ==
                             bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL)))
            rn->zebra = bgp_zebra_announce (rn->zebra, rn, pie->pfx) ;
          else
            bgp_zebra_withdraw (rn->zebra, pie->pfx);
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Work queue process for a RS RIB
 */
static void
bgp_process_rs(bgp_rib rib, bgp_rib_walker rw, bgp_rib_node rn)
{
  qassert(rib->rib_type == rib_rs) ;
  qassert(rw->it.type == rib_it_walker) ;
  qassert(rw->it.rib  == rib) ;

  if (!(DISABLE_BGP_ANNOUNCE))
    {
      /* Best path selection and then dispatch update.
       *
       * For RS Clients we run through this once per Client, scanning the
       * available routes, running export/import filters and constructing the
       * candidates list each time, afresh.
       */
      peer_rib        crib ;
      prefix_id_entry pie ;

      pie = prefix_id_get_entry(rn->pfx_id) ;

      /* For update walker, we update all the known peers.
       */
      crib  = ddl_head(rw->peers[prib_update]) ;

      while (crib != NULL)
        {
          bgp_announce_rs_selected (crib, pie, rn) ;
          crib = ddl_next(crib, walk_list) ;
        } ;

      /* For update and for initial walker, we update the (initial) peers
       * attached to the walker.
       */
      crib  = ddl_head(rw->peers[prib_initial]) ;

      while (crib != NULL)
        {
          bgp_announce_rs_selected (crib, pie, rn) ;
          crib = ddl_next(crib, walk_list) ;
        } ;
    } ;
} ;

/*==============================================================================
 * Best Path Selection
 */

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
 */
static route_merit_t
bgp_route_merit(bgp_inst bgp, attr_set attr, byte sub_type)
{
  route_merit_t merit, temp ;

#define ROUTE_MERIT_MASK(n) (((route_merit_t)1 << n) - 1)

  /* 1. ~attr->weight   -- RFC4271 9.1.1, "preconfigured policy".
   *
   *    By the time we get to here, the weight has either been set to some
   *    default (depending on Local Route-ness) or explicitly by route-map.
   *
   *    We mask this as a matter of form, the compiler should eliminate it.
   */
  temp  = ~attr->weight & ROUTE_MERIT_MASK(route_merit_weight_bits) ;
  merit = temp << route_merit_weight_shift ;

#if 0
  route_merit_weight_shift      = 2 + 13 + 1 + 32,
  route_merit_local_pref_shift  = 2 + 13 + 1,
  route_merit_local_shift       = 2 + 13,
  route_merit_as_path_shift     = 2,
#endif

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
    temp = bgp->default_local_pref
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
    return merit | ((route_merit_t)1 << route_merit_local_shift) ;

  /* 4. ~AS-PATH Length   -- RFC4271 9.1.2.2 (a) -- Breaking Ties (Phase 2).
   *
   *    If, for some crazy reason, the AS-PATH is beyond what we have bits
   *    for, we leave the field as 0 -- least possible merit.
   */
  if (! (bgp->flags & BGP_FLAG_ASPATH_IGNORE))
    {
       if (bgp->flags & BGP_FLAG_ASPATH_CONFED)
         temp = as_path_total_path_length (attr->asp);
       else
         temp = as_path_simple_path_length (attr->asp) ;

       if (temp < ROUTE_MERIT_MASK(route_merit_as_path_bits))
         merit |= (temp ^ ROUTE_MERIT_MASK(route_merit_as_path_bits))
                                              << route_merit_local_pref_shift ;
     } ;

   /* 5. ~Origin   -- RFC4271 9.1.2.2 (b) -- Breaking Ties (Phase 2).
    *
    *   The origin will fit, unless there is an invalid value -- which is
    *   treated as no merit !
    */
  confirm(BGP_ATT_ORG_MAX < ROUTE_MERIT_MASK(route_merit_origin_bits)) ;
  confirm(route_merit_origin_shift == 0) ;

  if (attr->origin < ROUTE_MERIT_MASK(route_merit_origin_bits))
    merit |= (attr->origin ^ ROUTE_MERIT_MASK(route_merit_origin_bits)) ;

  return merit ;

#undef ROUTE_MERIT_MASK
} ;

/*------------------------------------------------------------------------------
 * Get MED value.  If MED value is missing, use the default.
 */
inline static uint32_t
bgp_med_value (attr_set attr, uint32_t default_med)
{
  if (attr->have & atb_med)
    return attr->med;
  else
    return default_med ;
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
 * NB: uses rn->selected for RFC5004 selection.
 *
 * NB: does not change the bgp_rib_node or either of the given route_info.
 */
static route_info
bgp_tie_break (bgp_rib_node rn, route_info best, route_info cand)
{
  attr_set best_attr, cand_attr ;
  uint32_t best_igp_metric, cand_igp_metric ;
  bgp_id_t best_id, cand_id ;
  uint best_cluster, cand_cluster ;
  int ret;
  bgp_peer_sort_t best_sort, cand_sort ;
  bgp_inst bgp ;

  best_attr = best->attr ;
  cand_attr = cand->attr ;

  /* 6. MED check -- RFC4271 9.1.2.2 (c), also RFC5065 for Confed.
   *
   * XXX I believe there was a long time bug here... Cisco documentation says
   *     that the default is not to consider MED when choosing paths from
   *     confederation peers.
   *
   *     MEDs are compared without reference to the source if the
   *     BGP_FLAG_ALWAYS_COMPARE_MED is set.
   *
   *     RFC4271 says that MEDs are compared if the "neighborAS" of the two
   *     routes are the same.  The neighborAS is:
   *
   *       * if the AS_PATH is empty, the local AS
   *
   *       * if the AS_PATH starts with an AS_SET, the local AS
   *
   *       * if the AS_PATH starts with an AS_SEQUENCE, the first AS in that
   *
   *     Where confederations are involved, RFC5065 (section 5.3) basically
   *     says that the confederation stuff should be ignored.
   *
   *     But for confederations RFC5065 allows an option to treat the first
   *     ASN in either AS_SEQUENCE or AS_CONFED_SEQUENCE as the "neighborAS".
   *     That is the BGP_FLAG_MED_CONFED.
   *
   * MED is a weight/cost... so we are looking for the smaller.
   *
   * Note that if we have deterministic MED (and not always compare MED) then
   * have already done the MED thing, and don't need to do it here.
   */
  bgp = rn->it.rib->bgp ;
  if ( (bgp->flags & BGP_FLAG_ALWAYS_COMPARE_MED) ||
                                                (best->med_as == cand->med_as) )
    {
      uint32_t best_med, cand_med, default_med ;

      default_med = bgp->default_med ;
      best_med    = bgp_med_value (best_attr, default_med);
      cand_med    = bgp_med_value (cand_attr, default_med);

      if (best_med != cand_med)
        return (best_med < cand_med) ? best : cand ;
    } ;

  /* 7. Peer type check  -- RFC4271 9.1.2.2 (d), also RFC5065 for Confed.
   *
   *    CONFED and iBGP rank equal, "internal" (RFC5065).
   */
  best_sort = best->prib->peer->sort ;
  cand_sort = cand->prib->peer->sort ;

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
  cand_igp_metric = cand->igp_metric  ;

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
      best_id = best->prib->peer->remote_id ;
      cand_id = cand->prib->peer->remote_id ;

      if (best_id != cand_id)
        {
          if (!(bgp->flags & BGP_FLAG_COMPARE_ROUTER_ID))
            {
              if (best == rn->selected)
                return best ;

              if (cand == rn->selected)
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
        best_id = best->prib->peer->remote_id ;

      if (cand_attr->have & atb_originator_id)
        cand_id = cand_attr->originator_id ;
      else
        cand_id = cand->prib->peer->remote_id ;

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
  ret = sockunion_cmp (best->prib->peer->su_remote,
                       cand->prib->peer->su_remote);

  return (ret <= 0) ? best : cand ;
} ;

/*------------------------------------------------------------------------------
 * Add the given route_info to the main_list of the given rn.
 *
 * If required by deterministic_med, keep entries with the same med_as
 * together.
 */
static void
bgp_candidate_add(bgp_rib_node rn, route_info ri)
{
  route_info rs ;

  rs = rn->candidates ;

  if (rn->flags & rnf_deterministic_med)
    {
      /* For deterministic MED, search for another entry with same med_as,
       * and insert after it.
       */
      route_info rp ;

      rp = rs ;
      while (rp != NULL)
        {
          if (rp->med_as == ri->med_as)
            {
              ri->candidate_list = rp->candidate_list ;
              rp->candidate_list = ri ;

              return ;
            } ;

          rp = rp->candidate_list ;
        } ;
    } ;

  ri->candidate_list = rs ;
  rn->candidates     = ri ;
} ;

/*------------------------------------------------------------------------------
 * Scan all known routes for given bgp_rib_node and construct the list of
 * candidates.
 *
 * The list of candidates are all those routes with the greatest merit, in
 * some random order -- except that if Deterministic MED is in force, all
 * candidates with the same med_as are clustered together.
 *
 * Returns:  address of first candidate (if any) == rn->candidates
 */
static route_info
bgp_main_candidates(bgp_rib_node rn)
{
  route_info rh, ri ;
  route_merit_t merit ;

  /* Run through all the available routes, and pull onto the rh list all the
   * entries with the highest available merit.
   *
   * We expect all available routes to have some merit, but do not require
   * that to be the case.
   */
  rh = ddl_head(rn->routes) ;

  if (rh == NULL)
    return rn->candidates = rh ;

  merit = rh->merit ;

  while (merit == route_merit_none)     /* Skip no merit routes         */
    {
      rh = ddl_next(rh, route_list) ;

      if (rh == NULL)
        return rn->candidates = rh ;

      merit = rh->merit ;
    }

  for (ri = ddl_next(rh, route_list) ; ri != NULL ;
                                                 ri = ddl_next(ri, route_list))
    {
      if (ri->merit < merit)
        continue ;

      if (ri->merit == merit)
        ri->candidate_list = rh ;       /* add at start of list */
      else
        {
          merit = ri->merit ;           /* update merit         */
          ri->candidate_list = NULL ;   /* new end of list      */
        } ;

        rh = ri ;                       /* new start of list    */
    } ;

  /* Set the candidates and return first of same.
   *
   * If deterministic med and at least two candidates, rearrange the candidates
   * so that any equal med_as appear together
   */
  rn->candidates = rh ;

  if (rn->flags & rnf_deterministic_med)
    return bgp_candidates_cluster(rn) ;

  return rh ;
} ;

/*------------------------------------------------------------------------------
 * Scan all known routes for given bgp_rib_node and construct the candidates
 * list -- where these are Route Server Client Routes.
 *
 * For the Main RIB the route_info reflects the selection made by this router,
 * for itself, and hence what should be announced to others.
 *
 * For the RS RIB the route_info reflects only the routes which have not been
 * filtered out by the 'rs-in' route-map.  This selection process has to be
 * run for each peer, running the export and import filters for each available
 * route.  So we have:
 *
 *   * ri->attr_rcv    -- attributes as received and processed by 'rs-in' etc.
 *
 *   * ri->attr        -- attributes after last run of 'export'/'import'
 *                        which returned a not NULL result.
 *
 *                        this function runs 'export'/'import' on the
 *                        ri->attr_rcv:
 *
 *                          if the result is NULL, sets RINFO_RS_DENIED, but
 *                          leaves ri->attr and ri->merit.  Does not consider
 *                          the route as a possible candidate.
 *
 *                          otherwise, clears RINFO_RS_DENIED and sets ri->attr
 *                          and ri->merit, if required.
 *
 *   * ri->merit       -- the merit for ri->attr
 *
 *   * ri->flags & RINFO_RS_DENIED
 *
 *                     -- set or cleared as above.  Caller can run along the
 *                        rn->routes list and pick out the not-denied ones.
 *
 * NB: this means that the selection process is relatively expensive.  The
 *     assumptions are:
 *
 *       a) that for a Route Server there will generally *not* be many routes
 *          per prefix.  eg. where a Route Server is taking the place of
 *          multiple *peering* sessions.
 *
 *       b) that the export/import filters are generally simple or absent.
 *
 *       c) multiple CPU can compensate.
 *
 *       d) that during the start-up of a Route Server that all routes will
 *          be received quickly, so that the selection process actually only
 *          happens once -- when all available routes are in place.
 *
 *     But... if any of these are not true, then the solution is likely to be
 *     to store the result of the export/import filtering on a per-client
 *     basis -- rather than having a complete RIB for every client.
 *
 * Returns:  address of first candidate (if any) == rn->candidates
 */
static route_info
bgp_rs_candidates(bgp_rib_node rn, prefix_id_entry pie, peer_rib crib)
{
  route_info    rh, ri ;
  route_merit_t merit_select ;

  /* Run along the available routes and build the rh list of routes with the
   * highest merit.
   */
  merit_select = route_merit_none ;

  for (ri = ddl_head(rn->routes) ; ri != NULL ;
                                   ri = ddl_next(ri, route_list))
    {
      route_merit_t merit ;

      merit = bgp_update_filter_rs_use(ri, crib, pie->pfx) ;

      if (merit >= merit_select)
        {
          /* This route is at least as good as the current candidates.
           */
          if (merit > merit_select)
            {
              merit_select       = merit ;
              ri->candidate_list = NULL ;
            }
          else
            ri->candidate_list = rh ;

          rh = ri ;
        } ;
    } ;

  /* Set the candidates and return first of same.
   *
   * If deterministic med and at least two candidates, rearrange the candidates
   * so that any equal med_as appear together
   */
  if (merit_select == route_merit_none)
    rh = NULL ;

  rn->candidates = rh ;
  rn->selected   = NULL ;

  if (rn->flags & rnf_deterministic_med)
    return bgp_candidates_cluster(rn) ;

  return rh ;
} ;

/*------------------------------------------------------------------------------
 * Rearrange candidates list for deterministic MED -- if required.
 *
 * Collect all candidates with the same med_as together.
 */
static route_info
bgp_candidates_cluster(bgp_rib_node rn)
{
  route_info rh ;

  qassert(rn->flags & rnf_deterministic_med) ;

  rh = rn->candidates ;
  if (rh != NULL)
    {
      route_info ri ;

      ri = rh->candidate_list ;
      if (ri != NULL)
        {
          /* Rearrange candidates list for deterministic MED, collecting the
           * ones with equal med_as together.
           *
           * We have ri   -- second, not NULL candidate
           *
           * Returns:  address of first candidate (if any) == rn->candidates
           */
          rh = ri->candidate_list ;     /* third entry (if any)         */
          ri->candidate_list = NULL ;   /* cut at second entry          */

          while (rh != NULL)
            {
              ri = rh ;                 /* next to add to list          */
              rh = rh->candidate_list ; /* next after that              */

              bgp_candidate_add(rn, ri) ;
            } ;

          rh = rn->candidates ;         /* return the candidates        */
        } ;
    } ;

  return rh ;
} ;

/*------------------------------------------------------------------------------
 * Run Best Path Selection on the given candidates.
 *
 * MEDs are compared if the NeighborASes of the two routes are the same, or
 * if the "always compare" option is set.
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
 * The rn->selected is used for RFC5004 tie break.  For RS this is set to NULL
 * during the selection of candidates.
 *
 * Requires: ris == first candidate -- NOT NULL !
 *
 * Returns:  the new best candidate
 *
 * NB: uses rn->selection for RFC5004 selection.
 *
 *     Does not change rn->selection -- so caller can see if the selection
 *     has changed (at least for Main RIB).
 */
static route_info
bgp_best_selection (bgp_rib_node rn, route_info ris)
{
  route_info rp ;

  qassert(ris != NULL) ;

  rp = ris->candidate_list ;

  if (!(rn->flags & rnf_deterministic_med))
    {
      /* Simple -- no deterministic MED
       */
      while (rp != NULL)
        {
          ris = bgp_tie_break(rn, ris, rp) ;
          rp = rp->candidate_list ;
        } ;
    }
  else
    {
      /* Deterministic MED
       *
       * Before doing tie break against current selection, need to treat routes
       * with the same med_as as a group.
       *
       * Note that we start with the first candidate as the selection.  If it
       * is, in fact, the first of a group with the same med_as, then will
       * first choose the best of the rest of the group, and then compare that
       * with the first in the group -- which comes up with the right answer.
       */
      while (rp != NULL)
        {
          route_info ri ;

          ri = rp ;             /* next to consider     */

          while (1)
            {
              rp = rp->candidate_list ;

              if ((rp == NULL) || (rp->med_as != ri->med_as))
                break ;

              ri = bgp_tie_break(rn, ri, rp) ;
            } ;

          ris = bgp_tie_break(rn, ris, ri) ;
        } ;
    } ;

  return ris ;
} ;

/*------------------------------------------------------------------------------
 * Runs the selection process for the given bgp_rib_node, but does not
 * actually select, and does not send any updates.
 *
 * This is for use when showing the current state of a bgp_rib_node, or what
 * the state will be when it is processed (if processing is pending).
 *
 * For Main RIB:
 *
 *   * if an update is pending, do the route selection, so that we know
 *     what the selected route will be.
 *
 *   * if no update is pending, the RIB entry and routes are all up to date,
 *     so no need to do anything.
 *
 * For RS RIB:
 *
 *   * run the 'export' and 'import' filters across all routes, so that we
 *     have the attributes etc. for the given peer.
 *
 *   * do the route selection, so that we know what the selected route is or
 *     should be.
 *
 * NB: does not change rn->selected -- since is not actually selecting,
 *     and is not updating kernel or peers.
 *
 * Returns:  address of selection -- NULL if nothing available.
 */
static route_info
bgp_pseudo_selection (bgp_rib_node rn, peer_rib crib)
{
  route_info       ris ;

  switch (rn->it.type)
    {
      case rib_main:
        qassert(crib == NULL) ;

        if (rn->flags & rnf_processed)
          {
            ris = rn->selected ;

            if (ris == NULL)
              qassert(rn->candidates == NULL) ;
            else
              qassert(rn->candidates != NULL) ;
          }
        else
          {
            ris = rn->candidates ;

            if (ris == NULL)
              {
                qassert(rn->selected == NULL) ;
                ris = bgp_main_candidates(rn) ;
              } ;

            if (ris != NULL)
              ris = bgp_best_selection (rn, ris) ;
          } ;

        break ;

      case rib_rs:
        qassert(crib != NULL) ;

        ris = bgp_rs_candidates(rn, prefix_id_get_entry(rn->pfx_id), crib) ;

        if (ris != NULL)
          ris = bgp_best_selection (rn, ris) ;

        break ;

      default:
        qassert(false) ;
        return NULL ;
    } ;

  return ris ;
} ;

/*==============================================================================
 * Making and sending new announcements
 */
static attr_set bgp_announce_check_main (peer_rib prib, prefix_id_entry pie,
                                                               route_info ris) ;
static attr_set bgp_announce_check_rs (peer_rib crib, prefix_id_entry pie,
                                                               route_info ris) ;
static bool bgp_community_filter_out (bgp_peer peer, attr_set attr) ;
static bool bgp_output_filter (peer_rib prib, prefix pfx, attr_set attr) ;

/*------------------------------------------------------------------------------
 * Announce given route if possible -- either as an update or as a withdraw.
 *
 * If update, then runs filters, out route-map, etc. etc. which may either
 * modify the attributes for the update, or deny the route.
 */
static void
bgp_process_announce_selected (peer_rib prib, prefix_id_entry pie,
                                                                 route_info ris)
{
  bgp_peer    peer ;

  /* Reasons not to announce the route:
   *
   *   * not pEstablished
   *
   *   * not a negotiated AFI/SAFI
   *
   *   * waiting for ORF or ROUTE-REFRESH.
   */
  peer = prib->peer ;

  qassert(prib == peer->prib[prib->qafx]) ;

  if (peer->state != bgp_pEstablished)
    return ;

  if (!(peer->af_running & qafx_bit(prib->qafx)))
    return ;

  if (prib->af_status & PEER_STATUS_ORF_WAIT_REFRESH)
    return ;

  bgp_announce_selected (prib, pie, ris) ;
} ;

/*------------------------------------------------------------------------------
 * Announce given route if possible -- either as an update or as a withdraw.
 *
 * If update, then runs filters, out route-map, etc. etc. which may either
 * modify the attributes for the update, or deny the route.
 */
static void
bgp_announce_selected (peer_rib prib, prefix_id_entry pie, route_info ris)
{
  attr_set    attr ;
  mpls_tags_t tag ;

  /* Perform the final announcement checks, and then either update or
   * withdraw.
   */
      if (ris == NULL)
        {
          attr = NULL ;             /* withdraw     */
          tag  = 0 ;                /* tidy         */
        }
      else
        {
          /* If any changes have been made to the attributes, then we now need
           * a stored copy of the new ones.
           *
           * We then set the stored attributes into the adj_out (for this peer)
           * and trigger any update message processing.
           *
           * Whatever may have happened to the attributes, we now remove this
           * prefix from the adj_out for the peer and trigger any update
           * message processing.
           *
           * NB: where bgp_announce_check_main() and bgp_announce_check_rs() return
           *     a set of attributes, those are locked.
           */
          if (prib->rib_type == rib_main)
            attr = bgp_announce_check_main (prib, pie, ris) ;
          else
            attr = bgp_announce_check_rs (prib, pie, ris) ;

          tag = ris->tag ;          /* ignored if attr == NULL      */
        } ;

      bgp_adj_out_update (prib, pie, attr, tag) ;

      if (attr != NULL)
        bgp_attr_unlock(attr) ;
} ;

/*------------------------------------------------------------------------------
 * Announce given route if possible -- either as an update or as a withdraw.
 *
 * If update, then runs filters, out route-map, etc. etc. which may either
 * modify the attributes for the update, or deny the route.
 */
static void
bgp_announce_rs_selected (peer_rib crib, prefix_id_entry pie, bgp_rib_node rn)
{
  route_info ris ;

  ris = bgp_rs_candidates(rn, pie, crib) ;

  if (ris != NULL)
    ris = bgp_best_selection (rn, ris) ;

  bgp_process_announce_selected (crib, pie, ris) ;
} ;

/*------------------------------------------------------------------------------
 * Decide whether to announce the given route to the given peer (not RS Client)
 *
 * Applies the route-map out, amongst other things.
 *
 * Note that this may modify the attributes.
 *
 * Note that:
 *
 *   * for iBGP and cBGP, sets the default LocalPref before the route-map
 *
 *   * for eBGP, clears the MED, if required, before the route-map
 *
 *   * for eBGP, removes private ASN from the path, if required, before the
 *     route-map
 *
 *   * sets next-hop (if required) before the route-map
 *
 *   *
 *
 * Returns:  NULL <=> do not announce -- withdraw instead.
 *           attribute set to be announced -- with one level of lock
 */
static attr_set
bgp_announce_check_main (peer_rib prib, prefix_id_entry pie, route_info ris)
{
  bgp_inst bgp ;
  bgp_peer from_peer, to_peer ;
  attr_set  attr ;
  attr_pair pair ;
  route_map rmap ;
  bool reflecting, set_next_hop ;
  qafx_t    qafx ;

  qassert(!(prib->af_flags & PEER_AFF_RSERVER_CLIENT)) ;

  qafx = ris->qafx ;

  from_peer = ris->prib->peer ;
  to_peer   = prib->peer ;

  if (from_peer == to_peer)
    return NULL ;               /* Do not send routes back to sender    */

  attr = ris->attr ;            /* NB: unchanged until loaded           */

  /* XXX the checks here do not seem complete.
   *
   * This is copied from the existing code, except that have dropped the
   * invalid IPV6_ADDR_SAME() comparison of two IPv4 addresses !!
   *
   * Should this be checking the to_peer->su_remote ????
   */
  switch (pie->pfx->family) /* Do not send routes with nexthop which
                             * is an address of the destination peer    */
    {
      case AF_INET:
        if (to_peer->remote_id == attr->next_hop.ip.v4)
          return NULL ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
#if 0
        if (to_peer->remote_id == attr->next_hop.ip.v4)
          return NULL ;
#endif
        break ;
#endif

      default:
        break ;
    } ;

  /* Prepare for filtering etc.
   *
   * If this route is suppressed by aggregation, then it is not to be announced,
   * unless the unsuppress map says that it is.
   *
   * If this is an ordinary route, pick up the RMAP_OUT, if any
   */
#if 0           // TODO reinstate Aggregation
  if (ri->extra && ri->extra->suppress)
    {
      rmap = to_peer->filter[qafx].us_rmap ;
      if (rmap == NULL)
        return NULL ;
    }
  else
#endif
    rmap = prib->rmap[RMAP_OUT] ;

  /* Default route check -- if we have sent a default, do not send another.
   */
  if (prib->af_status & PEER_STATUS_DEFAULT_ORIGINATE)
    {
      switch (pie->pfx->family)
        {
          case AF_INET:
            if (pie->pfx->u.prefix4.s_addr == INADDR_ANY)
              return NULL ;
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            if (pie->pfx->prefixlen == 0)
              return NULL ;
            break ;
#endif

          default:
            break ;
        } ;
    } ;

  /* If community is not disabled check the no-export and local.
   */
  if (bgp_community_filter_out (to_peer, attr))
    return NULL ;

  /* If the attribute has originator-id and it is same as remote to_peer's id.
   *
   * If the attribute has no originator-id, then it will be zero, which is
   * unlikely to be the same as the remote to_peer's id -- but for completeness
   * we check for the existence of an originator-id *after* find equality.
   */
  if ((to_peer->remote_id == attr->originator_id) &&
                                            (attr->have & atb_originator_id))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (to_peer->log, LOG_DEBUG,
               "%s [Update:SEND] %s originator-id is same as remote router-id",
                                         to_peer->host, spfxtoa(pie->pfx).str) ;
      return NULL ;
    } ;

  /* ORF prefix-list filter check
   */
  if ((prib->af_caps_use & PEER_AF_CAP_ORF_PFX_RECV) &&
                                                     (prib->orf_plist != NULL))
    {
      if (prefix_list_apply (prib->orf_plist, pie->pfx) == PREFIX_DENY)
        {
          if (BGP_DEBUG (filter, FILTER))
           zlog (to_peer->log, LOG_DEBUG,
                 "%s [Update:SEND] %s/ is filtered by ORF",
                                         to_peer->host, spfxtoa(pie->pfx).str) ;
          return NULL ;
        } ;
    } ;

  /* Output filter check.
   *
   * NB: does not change the attributes.
   */
  if (!bgp_output_filter (prib, pie->pfx, attr))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (to_peer->log, LOG_DEBUG, "%s [Update:SEND] %s is filtered",
                                         to_peer->host, spfxtoa(pie->pfx).str) ;
      return NULL ;
    } ;

  /* Outgoing AS path loop check, if required.
   */
  bgp = to_peer->bgp;

  if (bgp_send_aspath_check)
    {
      /* AS path loop check.
       */
      if (as_path_loop_check (attr->asp, to_peer->as, 0))
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (to_peer->log, LOG_DEBUG,
                  "%s [Update:SEND] suppress announcement to to_peer AS %u"
                                                                " is AS path.",
                  to_peer->host, to_peer->as);
          return NULL ;
        }

      /* If we're a CONFED we need to loop check the CONFED ID too
       */
      if (bgp->confed_id != BGP_ASN_NULL)
        {
          if (as_path_loop_check(attr->asp, bgp->confed_id, 0))
            {
              if (BGP_DEBUG (filter, FILTER))
                zlog (to_peer->log, LOG_DEBUG,
                      "%s [Update:SEND] suppress announcement to to_peer AS %u"
                                                                " is AS path.",
                      to_peer->host,
                      bgp->confed_id);
              return NULL ;
            }
        }
    } ;

  /* From this point on, we construct a new set of attributes for the
   * destination to_peer, as required.
   *
   * Loading the pair adds a lock to the attributes.
   *
   * Unloading the pair removes the lock.  From now on, to return NULL and
   * deny the announcement, we must unload the pair.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* Things which depend on the sort of peer, and or the sort of source peer.
   *
   *   * iBGP-iBGP     -- invalid except for Route-Reflection
   *
   *   * iBGP and cBGP -- need at least the default local_pref
   *
   *   * eBGP          -- no MED, unless
   */
  reflecting   = false ;
  set_next_hop = true ;

  switch (to_peer->sort)
    {
      /* For iBGP destination, worry about iBGP source.
       */
      case BGP_PEER_IBGP:
        if (from_peer->sort == BGP_PEER_IBGP)
          {
            /* Both source and destination peers are iBGP.
             *
             * If we are not reflecting between these peers, we do not
             * announce the route.
             */
            if (from_peer->prib[qafx]->af_flags & PEER_AFF_REFLECTOR_CLIENT)
              {
                /* A route from a Route-Reflector Client.
                 *
                 * Reflect to all iBGP peers (Client and Non-Client), other
                 * other than the originator.  Have already checked the
                 * originator.  So there is nothing to do...
                 *
                 * ...except for the "no bgp client-to-client" option.
                 */
                if ( (bgp->flags & BGP_FLAG_NO_CLIENT_TO_CLIENT) &&
                     (prib->af_flags & PEER_AFF_REFLECTOR_CLIENT) )
                  return bgp_attr_pair_unload(pair) ;
              }
            else
              {
                /* A route from a Non-client.  Reflect only to clients.
                 */
                if (!(prib->af_flags & PEER_AFF_REFLECTOR_CLIENT))
                  return bgp_attr_pair_unload(pair) ;
              } ;

            reflecting   = true ;
            set_next_hop = false ;

            /* If we don't have an ORIGINATOR-ID, we now set the default.
             */
            if (!(attr->have & atb_originator_id))
              attr = bgp_attr_pair_set_originator_id(pair,
                                                         from_peer->remote_id) ;
          } ;

        fall_through ;

        /* For iBGP and cBGP destination, worry about local pref
         */
      case BGP_PEER_CBGP:
        if (!(attr->have & atb_local_pref))
          attr = bgp_attr_pair_set_local_pref(pair, bgp->default_local_pref) ;
        break ;

      /* For eBGP destination:
       *
       *   * clear the MED, unless required to keep it, or unless the source is
       *     ourselves -- may be overwritten by route-maps
       *
       *   * remove private ASN, if required
       *
       *     Cisco documentation says that:
       *
       *       * if the AS_PATH contains both public and private ASN, that is a
       *         configuration error, and the private ASN are not removed
       *
       *         XXX ought to log an error for this !
       *
       *       * if the AS_PATH contains the ASN of the destination, the
       *         private ASN will not be removed (the destination must have a
       *         private ASN !)
       *
       *       * with a confederation, this will work as long as the private
       *         ASN follow the confederation portion of the AS_PATH.
       *
       *     Now... where the to_peer is an eBGP peer, the confed stuff will be
       *     dropped in any case.  Plus, it is likely that the confed stuff is
       *     all private ASN, anyway.
       */
      case BGP_PEER_EBGP:
        if (attr->have & atb_med)
          {
            if ((from_peer != bgp->peer_self)
                        && ! (prib->af_flags & PEER_AFF_MED_UNCHANGED))
              attr = bgp_attr_pair_clear_med(pair) ;
          } ;

        if (prib->af_flags & PEER_AFF_REMOVE_PRIVATE_AS)
          {
            if (as_path_private_as_check (attr->asp))
              attr = bgp_attr_pair_set_as_path(pair, as_path_empty_asp) ;
          } ;

        break ;

      /* Don't crash !
       */
      default:
        qassert(false) ;
        break ;
    } ;

  attr = bgp_attr_pair_set_reflected(pair, reflecting) ;

  /* next-hop-set
   */
  if (set_next_hop)
    {
      bool have_next_hop ;

      switch (pie->pfx->family)
        {
          case AF_INET:
            if (attr->next_hop.type != nh_none)
              qassert(attr->next_hop.type == nh_ipv4) ;

            have_next_hop = (attr->next_hop.type == nh_ipv4) &&
                                       (attr->next_hop.ip.v4 != INADDR_ANY) ;
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            if (attr->next_hop.type != nh_none)
              qassert( (attr->next_hop.type == nh_ipv6_1) ||
                       (attr->next_hop.type == nh_ipv6_2) );

            have_next_hop = ( (attr->next_hop.type == nh_ipv6_1) ||
                              (attr->next_hop.type == nh_ipv6_2)
                            ) && ! IN6_IS_ADDR_UNSPECIFIED(
                                        &attr->next_hop.ip.v6[in6_global]) ;
            break ;
#endif

          default:
            have_next_hop = false ;
            break ;
        } ;

      if (prib->af_flags & PEER_AFF_NEXTHOP_UNCHANGED)
        set_next_hop = !have_next_hop ;
      else if (prib->af_flags & PEER_AFF_NEXTHOP_SELF)
        set_next_hop = true ;
      else if (!have_next_hop)
        set_next_hop = true ;
      else if ((to_peer->sort == BGP_PEER_EBGP)
                                            && (attr->next_hop.type == nh_ipv4))
        set_next_hop = (bgp_multiaccess_check_v4 (attr->next_hop.ip.v4,
                                                      &to_peer->su_name) == 0) ;
      else
        set_next_hop = false ;
    } ;

  if (set_next_hop)
    {
      switch (pie->pfx->family)
        {
          case AF_INET:
            attr = bgp_attr_pair_set_next_hop(pair, nh_ipv4,
                                                  &to_peer->nexthop.v4.s_addr) ;
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_1,
                                                  &to_peer->nexthop.v6_global) ;
            break ;
#endif
          default:
            break ;
        } ;
    } ;

#ifdef HAVE_IPV6
  if ((pie->pfx->family == AF_INET6) && (attr->next_hop.type != nh_none))
    {
      /* If PEER_AFF_NEXTHOP_LOCAL_UNCHANGED
       *
       *     we preserve the link-local address, provided it is a link-local
       *     address.
       *
       * Otherwise: if to_peer is on a shared network
       *               AND we are not reflecting the route
       *
       *     set or replace the link-local address by the one we use for the
       *     to_peer, if we have one.
       *
       * Otherwise:
       *
       *   * wipe out the link-local address, if any.
       */
      bool have_link_local ;
      bool keep_link_local ;

      qassert( (attr->next_hop.type == nh_ipv6_1) ||
               (attr->next_hop.type == nh_ipv6_2) );

      if (attr->next_hop.type == nh_ipv6_2)
        {
          /* Have a link-local BUT we cannot keep it if it is not a link-local
           * IP -- don't know why that should occur, this is defensive.
           */
          have_link_local = true ;

          keep_link_local = IN6_IS_ADDR_LINKLOCAL(
                                &attr->next_hop.ip.v6[in6_link_local]) ;
        }
      else
        {
          have_link_local = false ;
          keep_link_local = false ;
        } ;

      if (!(prib->af_flags & PEER_AFF_NEXTHOP_LOCAL_UNCHANGED))
        {
          /* We are not required to preserve the existing link-local address.
           *
           * We will wipe any link-local unless we set a new one here.
           *
           * We set a new link-local if we are on a shared_network with the
           * to_peer, and we are not reflecting a route and we actually have
           * a link-local address we can use.
           */
          keep_link_local = false ;

          if (to_peer->shared_network && !reflecting
                      && ! IN6_IS_ADDR_UNSPECIFIED (&to_peer->nexthop.v6_local))
            {
              attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_2,
                                                   &to_peer->nexthop.v6_local) ;
              have_link_local = true ;
              keep_link_local = true ;
            } ;
        } ;

      if (have_link_local && !keep_link_local)
        {
          qassert(attr->next_hop.type == nh_ipv6_2) ;
          attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_2, NULL) ;
        } ;
    } ;
#endif /* HAVE_IPV6 */

  /* Route map or unsuppress-map apply.
   */
  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->peer      = to_peer ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_OUT ;

      if (route_map_apply(rmap, pie->pfx,
                           RMAP_BGP | (reflecting ? RMAP_NO_SET : 0), brm)
                                                             == RMAP_DENY_MATCH)
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (to_peer->log, LOG_DEBUG,
                 "%s [Update:SEND] %s is filtered by %s route-map",
                                           to_peer->host, spfxtoa(pie->pfx).str,
// TODO             (ri->extra && ri->extra->suppress) ? "Unsuppress" : "Out") ;
                                                                        "Out") ;

          return bgp_attr_pair_unload(pair) ;
        } ;
    } ;

  /* Finally: we like this announcement -- so we store any changes made to
   * the pair and return the stored attribute set.
   *
   * Storing the pair does not affect the lock if the attributes are unchanged,
   * but if they are changed, the attributes returned have been locked.  (The
   * effect is that the stored half of the pair has a lock on it by virtue of
   * being the stored half of the pair.)
   *
   * By returning the result of bgp_attr_pair_store() we are returning the
   * attributes with "our" lock on them -- so we are passing upwards one level
   * of locking.
   */
  return bgp_attr_pair_store(pair) ;
} ;

/*------------------------------------------------------------------------------
 * Decide whether to announce the given route to the given RS Client.
 *
 * Applies the route-map out, amongst other things.
 *
 * Note that this may modify the attributes.
 *
 * Returns:  NULL <=> do not announce -- withdraw instead.
 *           attribute set to be announced -- with one level of lock
 */
static attr_set
bgp_announce_check_rs (peer_rib crib, prefix_id_entry pie, route_info ris)
{
  route_map rmap_out ;
  bgp_peer  from_peer, client ;
  attr_set  attr ;
  attr_pair pair ;
  qafx_t    qafx ;

  /* Quick reasons for not doing anything with the route
   */
  from_peer = ris->prib->peer;
  client    = crib->peer;

  if (from_peer == client)
    return NULL ;               /* Do not send routes back to sender    */

  attr = ris->attr ;            /* NB: unchanged until loaded           */

  /* Default route check -- if we have sent a default, do not send another.
   */
  qafx = ris->qafx ;

  if (crib->af_status & PEER_STATUS_DEFAULT_ORIGINATE)
    {
      switch (pie->pfx->family)
        {
          case AF_INET:
            if (pie->pfx->u.prefix4.s_addr == INADDR_ANY)
              return NULL ;
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            if (pie->pfx->prefixlen == 0)
              return NULL ;
            break ;
#endif

          default:
            break ;
        } ;
    } ;

  /* If the attribute has originator-id and it is same as remote
   * client's id.
   */
  if (attr->have & atb_originator_id)
    {
      if (client->remote_id == attr->originator_id)
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (client->log, LOG_DEBUG,
               "%s [Update:SEND] %s originator-id is same as remote router-id",
                                       client->host, spfxtoa(pie->pfx).str) ;
          return NULL ;
        } ;
    } ;

  /* ORF prefix-list filter check
   */
  if ((crib->af_caps_use & PEER_AF_CAP_ORF_PFX_RECV) &&
                                                      (crib->orf_plist != NULL))
    {
      if (prefix_list_apply (crib->orf_plist, pie->pfx) == PREFIX_DENY)
        {
          if (BGP_DEBUG (filter, FILTER))
           zlog (client->log, LOG_DEBUG,
                 "%s [Update:SEND] %s/ is filtered by ORF",
                                       client->host, spfxtoa(pie->pfx).str) ;
          return NULL ;
        } ;
    } ;

  /* Output filter check.
   */
  if (!bgp_output_filter (crib, pie->pfx, attr))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (client->log, LOG_DEBUG, "%s [Update:SEND] %s is filtered",
                                       client->host, spfxtoa(pie->pfx).str) ;
      return NULL ;
    } ;

  /* Outgoing AS path loop check, if required.
   */
  if (bgp_send_aspath_check)
    {
      /* AS path loop check.
       */
      if (as_path_loop_check (attr->asp, client->as, 0))
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (client->log, LOG_DEBUG,
                  "%s [Update:SEND] suppress announcement to rsclient AS %u"
                                                                " is AS path.",
                  client->host, client->as);
          return NULL ;
        }
    } ;

  /* From this point on, we construct a new set of attributes for the
   * destination peer, as required.
   *
   * Loading the pair adds a lock to the attributes.
   *
   * Unloading the pair removes the lock.  From now on, to return NULL and
   * deny the announcement, we must unload the pair.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* The next-hop should be transparent for RS, but must send a next-hop, so
   * if there is no next-hop, we set one up here !!
   *
   * This can really only happen if the RS itself is originating routes !
   *
   * TODO .... leave this to the last possible moment ??? ...........................
   *           or make a function for this ???
   */
  switch (pie->pfx->family)
    {
      case AF_INET:
        if (attr->next_hop.type != nh_none)
          qassert(attr->next_hop.type == nh_ipv4) ;

        if ((attr->next_hop.type != nh_ipv4) ||
                                        (attr->next_hop.ip.v4 == INADDR_ANY))
          attr = bgp_attr_pair_set_next_hop(pair, nh_ipv4,
                                                &client->nexthop.v4.s_addr) ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
        if (attr->next_hop.type != nh_none)
          qassert( (attr->next_hop.type == nh_ipv6_1) ||
                   (attr->next_hop.type == nh_ipv6_2) ) ;

        if ( ( (attr->next_hop.type != nh_ipv6_1) &&
               (attr->next_hop.type != nh_ipv6_2)
             ) || IN6_IS_ADDR_UNSPECIFIED(&attr->next_hop.ip.v6[in6_global]))
          attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_1,
                                                &client->nexthop.v6_global) ;
        break ;
#endif

      default:
        break ;
    } ;

#ifdef HAVE_IPV6
  if ((pie->pfx->family == AF_INET6) && (attr->next_hop.type != nh_none))
    {
      qassert( (attr->next_hop.type == nh_ipv6_1) ||
               (attr->next_hop.type == nh_ipv6_2) ) ;

      /* If PEER_AFF_NEXTHOP_LOCAL_UNCHANGED
       *
       *     we preserve the link-local address, provided it is a link-local
       *     address.
       *
       * Otherwise: if destination client is on a shared network
       *           AND source peer is on a shared network
       *           AND they are on the same interface
       *
       *     we preserve the link-local address, provided it is a link-local
       *     address.
       *
       * Otherwise: if destination client is on a shared network
       *
       *     set or replace the link-local address by the one we use for the
       *     client, if we have one.
       *
       * Otherwise:
       *
       *     wipe out the link-local address, if any.
       */
      bool have_link_local ;
      bool keep_link_local ;

      if (attr->next_hop.type == nh_ipv6_2)
        {
          /* Have a link-local BUT we cannot keep it if it is not a link-local
           * IP -- don't know why that should occur, this is defensive.
           */
          have_link_local = true ;
          keep_link_local = IN6_IS_ADDR_LINKLOCAL(
                                &attr->next_hop.ip.v6[in6_link_local]) ;
        }
      else
        {

          have_link_local = false ;
          keep_link_local = false ;
        } ;

      if (!(crib->af_flags & PEER_AFF_NEXTHOP_LOCAL_UNCHANGED))
        {
          /* We are not required to preserve the existing link-local address.
           *
           * If the client and the source of the route are on the same
           * shared network, then we keep the link-local address if it was
           * valid.
           *
           * If the client is on a shared network, and we have a link-local
           * address for it,
           *
           */
          if (client->shared_network)
            {
              if (from_peer->shared_network
                                  && (client->ifindex == from_peer->ifindex))
                {
                  keep_link_local = have_link_local ;
                }
              else if (! IN6_IS_ADDR_UNSPECIFIED (&client->nexthop.v6_local))
                {
                  attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_2,
                                                 &client->nexthop.v6_local) ;
                  have_link_local = true ;
                  keep_link_local = true ;
                }
              else
                keep_link_local = false ;
            }
          else
            keep_link_local = false ;
        } ;

      if (have_link_local && !keep_link_local)
        {
          qassert(attr->next_hop.type == nh_ipv6_2) ;
          attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_2, NULL) ;
        } ;
    } ;
#endif

  /* If this is eBGP client and remove-private-AS is set.
   *
   * Cisco documentation says that:
   *
   *   * if the AS_PATH contains both public and private ASN, that is a
   *     configuration error, and the private ASN are not removed
   *
   *     XXX ought to log an error for this !
   *
   *   * if the AS_PATH contains the ASN of the destination, the private ASN
   *     will not be removed (the destination must have a private ASN !)
   *
   *   * with a confederation, this will work as long as the private ASN follow
   *     the confederation portion of the AS_PATH.
   *
   *     Now... where the client is an eBGP client, the confed stuff will
   *     be dropped in any case.  Plus, it is likely that the confed stuff is
   *     all private ASN, anyway.
   */
  if ((crib->af_flags & PEER_AFF_REMOVE_PRIVATE_AS)
                                          && (client->sort == BGP_PEER_EBGP))
    {
      if (as_path_private_as_check (attr->asp))
        attr = bgp_attr_pair_set_as_path(pair, as_path_empty_asp) ;
    } ;

  /* Output Route-Map -- don't do aggregation for RS Client !
   *
   * Also, don't do Route Reflection for RS Client.
   */
  rmap_out = crib->rmap[RMAP_OUT] ;

  if (rmap_out != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->peer      = client ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_OUT ;

      if (route_map_apply(rmap_out, pie->pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (client->log, LOG_DEBUG,
                 "%s [Update:SEND] %s is filtered by Out route-map",
                                       client->host, spfxtoa(pie->pfx).str) ;

          return bgp_attr_pair_unload(pair) ;
        } ;
    } ;

  /* Finally: we like this announcement -- so we store any changes made to
   * the pair and return the stored attribute set.
   *
   * Storing the pair does not affect the lock if the attributes are unchanged,
   * but if they are changed, the attributes returned have been locked.  (The
   * effect is that the stored half of the pair has a lock on it by virtue of
   * being the stored half of the pair.)
   *
   * By returning the result of bgp_attr_pair_store() we are returning the
   * attributes with "our" lock on them -- so we are passing upwards one level
   * of locking.
   */
  return bgp_attr_pair_store(pair) ;
} ;

/*------------------------------------------------------------------------------
 * If community attribute includes no_advertise or no_export then return true.
 *
 * Looks for no-export and/or no-export-subconfed, depending on the sort of
 * peer.
 *
 * Returns:  true <=> community attribute => do NOT announce
 *
 * NB: does not change the attribute set.
 */
static bool
bgp_community_filter_out (bgp_peer peer, attr_set attr)
{
  if (attr->community != NULL)
    {
      attr_community_state_t known ;

      /* Pick up the state of the known communities, and exit immediately if
       * none of no-advertise, no-export or no-export-subconfed are set.
       */
      known = attr_community_known (attr->community) ;

      if ((known & (cms_no_advertise | cms_no_export | cms_local_as)) == 0)
        return false ;

      /* no-advertise -- applies no matter what sort of peer it is
       */
      if (known & cms_no_advertise)
        return true ;

      /* We have one or both of no-export or no-export-subconfed.
       *
       * For eBGP either of these => do not export.  For confed peers in a
       * different member-AS, no-export-subconfed => do not export.
       */
      qassert(known & (cms_no_export | cms_local_as)) ;

      switch (peer->sort)
        {
          case BGP_PEER_EBGP:
            return true ;

          case BGP_PEER_CBGP:
            return known & cms_local_as ;

          default:
            break ;
        } ;
    } ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Apply any and all of the:
 *
 *   * 'distribute-list out'
 *
 *   * 'filter-list out'
 *
 *   * 'prefix-list out'
 *
 * Returns:  true <=> OK as far as filters are concerned
 *           false => filter out
 *
 * NB: does not change the given set of attributes.
 */
static bool
bgp_output_filter (peer_rib prib, prefix pfx, attr_set attr)
{
  access_list dlist ;
  prefix_list plist ;
  as_list     aslist ;

#define FILTER_EXIST_WARN(type, is_set, name) \
  if (BGP_DEBUG (update, UPDATE_OUT) && !(is_set)) \
    plog_warn (prib->peer->log, "%s: output %s-list %s not set", \
                                                 prib->peer->host, type, (name))

  dlist = prib->dlist[FILTER_OUT] ;
  if (dlist != NULL)
    {
      FILTER_EXIST_WARN("distribute", access_list_is_set(dlist),
                                      access_list_get_name(dlist)) ;

      if (access_list_apply (dlist, pfx) == FILTER_DENY)
        return false ;
    }

  plist = prib->plist[FILTER_OUT] ;
  if (plist != NULL)
    {
      FILTER_EXIST_WARN("prefix", prefix_list_is_set(plist),
                                  prefix_list_get_name(plist)) ;

      if (prefix_list_apply (plist, pfx) == PREFIX_DENY)
        return false ;
    }

  aslist = prib->flist[FILTER_OUT] ;
  if (aslist != NULL)
    {
      FILTER_EXIST_WARN("as", as_list_is_set(aslist),
                              as_list_get_name(aslist)) ;

      if (as_list_apply (aslist, attr->asp) == AS_FILTER_DENY)
        return false ;
    }

  return true;

#undef FILTER_EXIST_WARN
} ;

/*============================================================================*/

/*------------------------------------------------------------------------------
 * Max Prefix Overflow timer expired -- turn off overflow status and enable.
 */
static int
bgp_maximum_prefix_restart_timer (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_pmax_restart = NULL;

  assert(CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW)) ;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s Maximum-prefix restart timer expired, restore peering",
                peer->host);

  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);

  bgp_peer_enable(peer);

  return 0;
}

/*------------------------------------------------------------------------------
 * If there is an active max prefix restart timer, cancel it now.
 *
 * NB: clears PEER_STATUS_PREFIX_OVERFLOW, but does NOT enable the peer.
 */
void
bgp_maximum_prefix_cancel_timer (struct peer *peer)
{
  if (peer->t_pmax_restart)
    {
      assert(CHECK_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW)) ;

      BGP_TIMER_OFF (peer->t_pmax_restart);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s Maximum-prefix restart timer cancelled", peer->host) ;
    } ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW) ;
} ;

/*------------------------------------------------------------------------------
 * See if number of prefixes has overflowed.
 *
 * Returns:  true <=> have changed to overflowed state, and closed session
 *                    (if any) with suitable NOTIFICATION.
 */
extern bool
bgp_maximum_prefix_overflow (peer_rib prib, bool always)
{
  if (!prib->pmax.set)
    return false ;

  if (prib->pcount > prib->pmax.limit)
    {
      u_int8_t ndata[7] ;

      if ((prib->af_status & PEER_STATUS_PREFIX_LIMIT) && !always)
        return false ;          /* reported already     */

      zlog (prib->peer->log, LOG_INFO,
          "%%MAXPFXEXCEED: No. of %s prefix received from %s %u exceed, "
          "limit %u", get_qafx_name(prib->qafx), prib->peer->host,
                                              prib->pcount, prib->pmax.limit);

      prib->af_status |= PEER_STATUS_PREFIX_LIMIT ;

      if (prib->pmax.warning)
        return false ;

      /* Disable the peer, the timer routine will reenable.
       */
      store_ns(&ndata[0], get_iAFI(prib->qafx)) ;
      ndata[2] = get_iSAFI(prib->qafx) ;
      store_nl(&ndata[3], prib->pmax.limit) ;

      bgp_peer_down_error_with_data(prib->peer, BGP_NOMC_CEASE,
                                                BGP_NOMS_C_MAX_PREF, ndata, 7) ;

      /* restart timer start
       */
      if (prib->pmax.restart)
        {
          bgp_peer peer = prib->peer ;

          peer->v_pmax_restart = prib->pmax.restart * 60;

          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
                                             peer->host, peer->v_pmax_restart);

          BGP_TIMER_ON (peer->t_pmax_restart, bgp_maximum_prefix_restart_timer,
                        peer->v_pmax_restart);
        }

      prib->peer->sflags |= PEER_STATUS_PREFIX_OVERFLOW ;

      return true ;
    }
  else
    prib->af_status &= ~PEER_STATUS_PREFIX_LIMIT ;

  if (prib->pcount > prib->pmax.threshold)
    {
      if ((prib->af_status & PEER_STATUS_PREFIX_THRESHOLD) && ! always)
       return false ;

      zlog (prib->peer->log, LOG_INFO,
            "%%MAXPFX: No. of %s prefix received from %s reaches %u, max %u",
            get_qafx_name(prib->qafx), prib->peer->host, prib->pcount,
                                                             prib->pmax.limit);

      prib->af_status |= PEER_STATUS_PREFIX_THRESHOLD ;
    }
  else
    prib->af_status &= ~PEER_STATUS_PREFIX_THRESHOLD ;

  return false ;
}














/*==============================================================================
 * Inbound and Outbound reconfiguration
 *
 * Inbound reconfiguration runs down the Peer's adj_in and re-issues the
 * current route for each known prefix.  What this does is:
 *
 *   * for Main RIB: forces the inbound filters to be re-run, and if the
 *     result is not the same as before, will update the RIB etc. as required.
 *
 *   * for RS RIB: forces the rs-in filter to be re-run, and then pushes
 *     through a processing run for the prefix -- which will cause the peer's
 *     export filter to be re-run (also the destination peer's import filter,
 *     but that's another story).
 *
 * ...so the effect is to refresh the RIBs, and possibly generate announcements,
 * to reflect the new state of the inbound processing for the peer's routes.
 *
 * Outbound reconfiguration runs through the RIB, and re-announces routes to
 * the Peer:
 *
 *   * for Main RIB Peer: runs the current selected route for each prefix
 *     through the peer's outbound filters, and re-announce or withdraw as
 *     required.
 *
 *   * for RS RIB Peer: runs the route selection for each prefix, and then
 *     runs the selected route through the peer's outbound filters, and
 *     re-announce or withdraw as required.
 *
 * ...so the effect is to refresh the peer and its adj-out, and possibly
 * generate announcements to reflect the new state of the outbound processing
 * for the peer.  When a peer session is established, this operation is
 * required to fill in the peer's empty adj-out, and send the initial
 * announcements.
 *
 * Note XXX other mechanism(s) required to empty out an adj-out (for refresh)
 *      XXX to hold up announcements until entire table has been processed
 *      XXX to deal with stale routes
 *      XXX to send End-of-RIB when required.
 */

/*------------------------------------------------------------------------------
 * Do soft reconfiguration of the inbound side of the given peer and given
 * AFI/SAFI
 */
extern void
bgp_soft_reconfig_in (bgp_peer peer, qafx_t qafx)
{
  peer_rib       prib ;
  route_info     ri ;
  ihash_walker_t walk[1] ;
  route_in_parcel_t parcel[1] ;

  if (peer->state != bgp_pEstablished)
    return;

  prib = peer->prib[qafx] ;
  qassert(prib != NULL) ;

  if (prib == NULL)
    return ;

  qassert((peer == prib->peer) && (qafx == prib->qafx)) ;

  /* We walk the peer's Main RIB adj-in, which contains all the peer's incoming
   * routes, and run through bgp_update_from_peer().
   *
   * This will update any RS RIB adj-in.
   */
  memset(parcel, 0, sizeof(route_in_parcel_t)) ;

  parcel->qafx   = qafx ;
  parcel->action = ra_in_update ;
  if (bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) != 0)
    parcel->route_type = bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) ;

  ihash_walk_start(prib->adj_in[rib_main], walk) ;

  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if (ri->attr_rcv != NULL)
        {
          parcel->attr   = ri->attr_rcv ;
          parcel->pfx_id = ri->pfx_id ;
          parcel->tag    = ri->tag ;

          bgp_update_from_peer(peer, parcel, true /* refresh */) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Do soft reconfiguration of the given RS Client's routes and route-selection.
 *
 * This sets a rib-walker going for the bgp instances RS RIB, for the
 * client.  This will consider all prefixes, re-run the export and import
 * route-maps (for the client) and re-run the route selection (for the
 * client).
 */
extern void
bgp_soft_reconfig_rsclient_in (bgp_peer rsclient, qafx_t qafx)
{
} ;

/*------------------------------------------------------------------------------
 * Announce all AFI/SAFI to peer
 *
 * Used (eg) when peer becomes established.
 */
extern void
bgp_announce_all_families (bgp_peer peer, uint delay)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    bgp_announce_family (peer, qafx, delay) ;
} ;

/*------------------------------------------------------------------------------
 * Announce entirety of given AFI/SAFI to peer
 *
 * Mark all the adj_out for this peer and family as "stale".  Which means
 * that will send an update or a withdraw for every prefix which the peer
 * currently has a route for, and an update for any which we have, but the
 * peer does not.
 *
 * For an ordinary peer:
 *
 *  will announce the current selected routes, re-running the output
 *  route-map and orf etc.
 *
 * For a RS Client:
 *
 *  will run everything from the export route-map onwards.
 *
 * Used (eg) when peer becomes established or when a route-refresh is required.
 */
extern void
bgp_announce_family (bgp_peer peer, qafx_t qafx, uint delay)
{
  peer_rib     prib ;

  /* Reasons not to announce the given family to the given peer
   */
  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (peer->state != bgp_pEstablished)
    return;

  if (!(peer->af_running & qafx_bit(qafx)))
    return ;

  prib = peer->prib[qafx] ;
  qassert((peer == prib->peer) && (qafx == prib->qafx)) ;

  if (prib->af_status & PEER_STATUS_ORF_WAIT_REFRESH)
    return ;

  /* If there is anything in the given peer's adj-out, then we set it "stale",
   * and we set the required delay before any further announcements are made.
   */
  bgp_adj_out_set_stale(prib, delay) ;

  /* Start a rib walker for the peer, so that all the prefixes are reconsidered
   * and re-announced.
   *
   * Note that an EoR must be sent once all prefixes have been announced.
   */
  prib->eor_required = true ;
  prib->walker = bgp_rib_walker_start_initial(prib, bgp_process_walker) ;
} ;

/*==============================================================================
 * Clearing.
 *
 * There are two (quite different) forms of clearing:
 *
 *   1. Normal clearing    -- mass withdraw of given peer's routes for all
 *                            or individual AFI/SAFI.
 *
 *      This is clears the routes *from* the given peer.
 *
 *      Note that normal clearing deals with the main RIB and any RS Client
 *      RIBs that may also contain routes.
 *
 *   2. RS Client clearing -- dismantling of RS Client RIB for an AFI/SAFI.
 *
 *      This clears out the routes *for* the given RS Client.
 *
 *------------------------------------------------------------------------------
 * Normal clearing
 *
 * This is used in two ways:
 *
 *   1. when a peer falls out of Established state.
 *
 *      See: bgp_clear_route_all().
 *
 *      All the peer's routes in all AFI/SAFI are withdrawn, but may be subject
 *      to NSF.
 *
 *   2. when an individual AFI/SAFI is disabled.
 *
 *      See: bgp_clear_route().
 *
 *      [This appears to be for Dynamic Capabilities only.]
 *      TODO: discover whether NSF affects Dynamic Capability route clear.
 *
 *      All the peer's routes in the AFI/SAFI are withdrawn.  (NSF ??).
 *
 * Normal clearing affects:
 *
 *   1. the main RIB in all relevant AFI/SAFI.
 *
 *   2. all RS Client RIBs in all relevant AFI/SAFI
 *
 * Any routes (ie bgp_info objects) in the affected tables are either marked
 * stale or are removed all together.
 *
 * Any adj_in (soft reconfig) and adj_out (announcement state) objects are
 * removed.
 *
 * The peer's:
 *
 *   struct bgp_info*    routes_head[AFI_MAX][SAFI_MAX] ;
 *
 *     This list threads through every use of all routes which belong to
 *     the peer, in all RIBs.
 *
 *   struct bgp_adj_in*  adj_in_head[AFI_MAX][SAFI_MAX] ;
 *
 *     This list threads through every copy of all routes which belong to the
 *     peer and which have been preserved for soft reconfiguration, in all RIBs.
 *
 *   struct bgp_adj_out* adj_out_head[AFI_MAX][SAFI_MAX] ;
 *
 *     This list threads through every route which has been selected for the
 *     peer, in all RIBs.
 *
 * Are maintained for exactly this purpose.
 *
 * NB: this is now a linear process, because the lists identify the stuff to
 *     be processed.
 *
 *     Not much work is required to remove a route -- the consequences are
 *     dealt with by the relevant processing work queue.
 *
 *     In theory it would be better to break up the work.  A peer who announces
 *     500,000 prefixes has a fair amount to do here.  A peer who announces
 *     10,000 prefixes to 1,000 RS Clients has 10,000,000 routes to withdraw.
 *
 *     Nevertheless, a really hard case looks like less than 10secs work...
 *     For the time being, the simplicity of living without a clearing work
 *     queue task is preferred -- and the
 *
 * [The old code walked the main RIB, and then every RS Client RIB, searching
 *  for bgp_node objects which had bgp_info from the given peer.  It then issued
 *  a work queue task to do the actual change (which was probably more work than
 *  doing the change straight away).]
 *
 * [The MPLS VPN stuff has a two level RIB, which the above probably doesn't
 *  work for...  more work required, here.]
 *
 * TODO: fix bgp_clear_route() and MPLS VPN !!
 *
 *------------------------------------------------------------------------------
 * RS Client Clearing
 *
 * This is done when a given RS Client RIB is about to be dismantled.
 *
 * This walks the RS Client RIB and discards all bgp_info, adj_in and adj_out.
 * (This is unconditional -- no NSF gets in the way.)
 *
 */

/*------------------------------------------------------------------------------
 * Normal clearing of given peer for all AFI/SAFI -- in and out.
 */
extern void
bgp_clear_all_routes (bgp_peer peer, bool nsf)
{
  qafx_t qafx ;

  assert(peer->state == bgp_pDown) ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT) ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    bgp_clear_routes(peer, qafx, nsf) ;
} ;

/*------------------------------------------------------------------------------
 * Normal clearing of given peer's routes for given AFI/SAFI -- in and out.
 *
 * 'nsf' means that the peer's adj_in is marked "stale" (discarding any entries
 * which are already stale.  Stale routes continue to be used.
 *
 * If not 'nsf', then the adj_in is emptied out, and all routes are immediately
 * discarded -- which may force reprocessing of routes.
 *
 * NB: in the latest scheme of things this is completed immediately...
 *
 *     ...however, retain the ability to run this in the background with the
 *        peer in bgp_peer_pClearing.
 */
extern void
bgp_clear_routes(bgp_peer peer, qafx_t qafx, bool nsf)
{
  peer_rib   prib ;
  ihash_walker_t walk[1] ;
  route_info ri ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return true ;

  /* If NSF requested and nsf configured for this q_afi/q_safi, do nsf and
   * set flag to indicate that at least one q_afi/q_safi may have stale routes.
   *
   * Walk the main adj-in and either mark stale or discard.
   */
  nsf = nsf && prib->nsf ;
  if (nsf)
    SET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT) ;

  ihash_walk_start(prib->adj_in[rib_main], walk) ;

  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if (nsf && (ri->attr_rcv != NULL) && !(ri->flags & BGP_INFO_STALE))
       ri->flags |= BGP_INFO_STALE ;
      else
        bgp_route_info_free(ri, false /* not "ream" */) ;
    } ;

  /* Clear out the contents of the adj-out, completely.
   */
  bgp_adj_out_discard(prib) ;
} ;

/*------------------------------------------------------------------------------
 * Clear Route Server RIB for given AFI/SAFI -- unconditionally
 *
 * This is used to dismantle a Route Server Client's RIB -- this is removing
 * all the routes from all *other* Route Server Clients that have been placed
 * in this Clients RIB.
 *
 * Walks all the nodes in the table and discards all routes, all adj_in and
 * all adj_out.
 *
 * Does nothing if there is no RIB for that AFI/SAFI.
 */
extern void
bgp_clear_rsclient_rib(bgp_peer rsclient, qafx_t qafx)
{
  bgp_node  rn ;
  bgp_table table ;

  table = rsclient->prib[qafx] ;

  if (table == NULL)
    return ;            /* Ignore unconfigured q_afi/q_safi or similar      */

  /* TODO: fix bgp_clear_rsclient_rib() so that will clear an MPLS VPN table.
   */
  passert(get_qSAFI(table->qafx) != qSAFI_MPLS_VPN) ;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_info    *ri;
      struct bgp_info    *next_ri ;
      bgp_adj_in  ai;
      bgp_adj_out ao;

      next_ri = rn->info ;
      while(next_ri != NULL)
        {
          /* Kill off existing route
           *
           * Note that we don't do any damping for RS Client RIB
           */
          ri = next_ri ;
          next_ri = ri->info.next ;     /* bank this    */

          bgp_info_delete (rn, ri);
          bgp_process_dispatch (rsclient->bgp, rn);
        } ;

      while ((ai = rn->adj_in) != NULL)
        {
          qassert(ai->adj.prev == NULL) ;
          bgp_adj_in_remove (rn, ai);
          qassert(ai != rn->adj_in) ;
        } ;

      while ((ao = rn->adj_out) != NULL)
        {
          qassert(ao->adj.prev == NULL) ;
          bgp_adj_out_delete (ao) ;
          qassert(ao != rn->adj_out) ;
        } ;
    }
  return ;
}

/*------------------------------------------------------------------------------
 * Walk main RIB and remove any adj_in for given peer.
 *
 * TODO: walk peer->bgp_adj_in_head[q_afi][q_safi] -- but check which table ?
 */
extern void
bgp_clear_adj_in (bgp_peer peer, qafx_t qafx)
{
  bgp_table  table;
  bgp_node   rn;
  bgp_adj_in ai;

  table = peer->bgp->rib[qafx][rib_main];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ai = rn->adj_in; ai ; ai = ai->adj.next)
      if (ai->peer == peer)
        {
          bgp_adj_in_remove (rn, ai);
          break;
        }
} ;

/*------------------------------------------------------------------------------
 * Walk main RIB and remove all stale routes for the given peer.
 *
 * NB: is required to complete immediately !
 *
 * TODO: walk peer->routes_head[q_afi][q_safi]
 */
extern void
bgp_clear_stale_route (bgp_peer peer, qafx_t qafx)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = peer->bgp->rib[qafx][rib_main];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->info.next)
        if (ri->peer == peer)
          {
            if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
              bgp_rib_remove (rn, ri, peer, qafx);
            break;
          }
    }
}





















/*==============================================================================
 *
 */




/*------------------------------------------------------------------------------
 * Originate a default route from us.
 *
 * Cannot, and does not, announce a default route for MPLS VPN.
 */
extern void
bgp_default_originate (bgp_peer peer, qafx_t qafx, bool withdraw)
{
  peer_rib     prib ;
  attr_pair_t  attrs[1] ;
  prefix_t     p[1] ;

  prib = peer_family_prib(peer, qafx) ;
  qassert(prib != NULL) ;
  if (prib == NULL)
    return ;

  switch (qafx)
    {
      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        prefix_default(p, AF_INET) ;
        break ;

#ifdef HAVE_IPV6
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        prefix_default(p, AF_INET6) ;
        break ;
#endif

      case qafx_ipv4_mpls_vpn:
      case qafx_ipv6_mpls_vpn:
      default:
        return ;
    } ;

  if (!withdraw)
    {
      struct bgp *bgp;
      route_map  default_rmap ;

      bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP);

      default_rmap = prib->default_rmap ;

      bgp = peer->bgp;

      bgp_attr_pair_set_local_pref(attrs, bgp->default_local_pref) ;

// TODO .......... either set self as next hop at the last moment, or  ...............
//                 have a common function for doing this ??

      switch (qafx)
        {
          case qafx_ipv4_unicast:
          case qafx_ipv4_multicast:
            bgp_attr_pair_set_next_hop(attrs, nh_ipv4,
                                                    &peer->nexthop.v4.s_addr) ;
            break ;

#ifdef HAVE_IPV6
          case qafx_ipv6_unicast:
          case qafx_ipv6_multicast:
            bgp_attr_pair_set_next_hop(attrs, nh_ipv6_1,
                                                     &peer->nexthop.v6_global) ;

            if (peer->shared_network
                         && !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
              bgp_attr_pair_set_next_hop(attrs, nh_ipv6_2,
                                                      &peer->nexthop.v6_local) ;
            else
              bgp_attr_pair_set_next_hop(attrs, nh_ipv6_2, NULL) ;

            break ;
#endif /* HAVE_IPV6 */

          default:
            withdraw     = true ;
            default_rmap = NULL ;
            break ;
        } ;

      if ((default_rmap != NULL) && !withdraw)
        {
          bgp_route_map_t  brm[1] ;

          brm->peer      = bgp->peer_self ;
          brm->attrs     = attrs ;
          brm->qafx      = qafx ;
          brm->rmap_type = BGP_RMAP_TYPE_DEFAULT ;

          withdraw = route_map_apply(default_rmap, p, RMAP_BGP, brm)
                                                            == RMAP_DENY_MATCH ;
        } ;
    } ;

  if (withdraw)
    {
      if (prib->af_status & PEER_STATUS_DEFAULT_ORIGINATE)
        {
          bgp_default_withdraw_send (peer, p, qafx) ;
          prib->af_status &= ~PEER_STATUS_DEFAULT_ORIGINATE ;
        } ;
    }
  else
    {
      attr_set  stored ;

      stored = bgp_attr_pair_store(attrs) ;

      prib->af_status |= PEER_STATUS_DEFAULT_ORIGINATE ;
      bgp_default_update_send (peer, p, stored, qafx, peer->bgp->peer_self);
    } ;

  bgp_attr_pair_unload(attrs) ;
} ;





























/*==============================================================================
 *
 */
static struct bgp_node *
bgp_afi_node_get (bgp_table table, qafx_t qafx, prefix p, struct prefix_rd *prd)
{
  bgp_node rn ;
  bgp_node prn ;

  if (!qafx_is_mpls_vpn(qafx))
    return bgp_node_get (table, p) ;

  prn = bgp_node_get (table, (struct prefix *) prd);

  if (prn->info == NULL)
    prn->info = bgp_table_init (qafx);
  else
    bgp_unlock_node (prn);

  rn = bgp_node_get (prn->info, p);

  rn->prn = prn;

  return rn ;
} ;

/* Allocate bgp_info_extra */
static struct bgp_info_extra *
bgp_info_extra_new (void)
{
  struct bgp_info_extra *new;
  new = XCALLOC (MTYPE_BGP_ROUTE_EXTRA, sizeof (struct bgp_info_extra));
  return new;
}

static void
bgp_info_extra_free (struct bgp_info_extra **extra)
{
  if (extra && *extra)
    {
      if ((*extra)->damp_info)
        bgp_damp_info_free ((*extra)->damp_info, 0);

      (*extra)->damp_info = NULL;

      XFREE (MTYPE_BGP_ROUTE_EXTRA, *extra);

      *extra = NULL;
    }
}

/* Get bgp_info extra information for the given bgp_info, lazy allocated
 * if required.
 */
struct bgp_info_extra *
bgp_info_extra_get (struct bgp_info *ri)
{
  if (!ri->extra)
    ri->extra = bgp_info_extra_new();
  return ri->extra;
}

/* Allocate new bgp info structure. */
static bgp_info
bgp_info_new (void)
{
  return XCALLOC (MTYPE_BGP_ROUTE, sizeof (bgp_info_t));
}

/* Free bgp route information. */
static bgp_info
bgp_info_free (bgp_info binfo)
{
  if (binfo->attr != NULL)
    bgp_attr_unlock(binfo->attr) ;

  bgp_info_extra_free (&binfo->extra);

  XFREE (MTYPE_BGP_ROUTE, binfo);

  return NULL ;
}

extern bgp_info
bgp_info_lock (bgp_info binfo)
{
  binfo->lock++;
  return binfo;
}

extern bgp_info
bgp_info_unlock (bgp_info binfo)
{
  assert ((binfo != NULL) && (binfo->lock > 0)) ;

  if (binfo->lock == 1)
    {
#if 0
      zlog_debug ("%s: unlocked and freeing", __func__);
      zlog_backtrace (LOG_DEBUG);
#endif
      return bgp_info_free (binfo);
    } ;

  binfo->lock -= 1 ;

#if 0
  if (binfo->lock == 1)
    {
      zlog_debug ("%s: unlocked to 1", __func__);
      zlog_backtrace (LOG_DEBUG);
    }
#endif

  return NULL ;
}

void
bgp_info_add (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_peer          peer = ri->peer ;
  struct bgp_info** routes_head ;

  /* add to list of routes for this bgp_node
   */
  ri->rn        = rn ;
  ri->info.next = rn->info;
  ri->info.prev = NULL;
  if (rn->info != NULL)
    ((struct bgp_info*)rn->info)->info.prev = ri;
  rn->info      = ri;

  /* add to list of routes for this peer
   */
  routes_head = &(peer->routes_head[rn->qafx]) ;
  ri->routes.next = *routes_head ;
  ri->routes.prev = NULL ;
  if (*routes_head != NULL)
    (*routes_head)->routes.prev = ri ;
  *routes_head = ri ;

  bgp_info_lock (ri);
  bgp_lock_node (rn);
  bgp_peer_lock (peer);     /* bgp_info peer reference */
}

/* Do the actual removal of info from RIB, for use by bgp_process_dispatch
   completion callback *only* */
static void
bgp_info_reap (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_peer          peer = ri->peer ;
  struct bgp_info** routes_head ;

  assert(ri->rn == rn) ;

  /* remove from list of routes for the bgp_node
   */
  if (ri->info.next)
    ri->info.next->info.prev = ri->info.prev;
  if (ri->info.prev)
    ri->info.prev->info.next = ri->info.next;
  else
    rn->info = ri->info.next;

  /* remove from list of routes for the peer
   */
  routes_head = &(peer->routes_head[rn->qafx]) ;
  if (ri->routes.next != NULL)
    ri->routes.next->routes.prev = ri->routes.prev ;
  if (ri->routes.prev != NULL)
    ri->routes.prev->routes.next = ri->routes.next ;
  else
    *routes_head = ri->routes.next ;

  bgp_info_unlock (ri);         /* fewer references to bgp_info */
  bgp_unlock_node (rn);         /* fewer references to bgp_node */
  bgp_peer_unlock (peer);       /* fewer references to peer     */
}

void
bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_set_flag (rn, ri, BGP_INFO_REMOVED);
  /* set of previous already took care of pcount */
  UNSET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* undo the effects of a previous call to bgp_info_delete; typically
   called when a route is deleted and then quickly re-added before the
   deletion has been processed */
static void
bgp_info_restore (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_unset_flag (rn, ri, BGP_INFO_REMOVED);
  /* unset of previous already took care of pcount */
  SET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* Adjust pcount as required */
static void
bgp_pcount_adjust (bgp_rib_node rn, route_info ri)
{
  assert (rn && rn->table);
  assert (ri && ri->peer && ri->peer->bgp);

  /* Ignore 'pcount' for RS-client tables */
  if (rn->table->type != BGP_TABLE_MAIN
      || ri->peer == ri->peer->bgp->peer_self)
    return;

  if (BGP_INFO_HOLDDOWN (ri)
      && CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {

      UNSET_FLAG (ri->flags, BGP_INFO_COUNTED);

      /* slight hack, but more robust against errors. */
      if (ri->prib->pcount != 0)
        ri->prib->pcount -= 1 ;
      else
        {
          zlog_warn ("%s: Asked to decrement 0 prefix count for peer %s",
                     __func__, ri->prib->peer->host);
          zlog_backtrace (LOG_WARNING);
          zlog_warn ("%s: Please report to Quagga bugzilla", __func__);
        }
    }
  else if (!BGP_INFO_HOLDDOWN (ri)
           && !CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
    {
      SET_FLAG (ri->flags, BGP_INFO_COUNTED);
      ri->prib->pcount += 1 ;
    }
}


/*------------------------------------------------------------------------------
 * Set/unset bgp_info flags, adjusting any other state as needed.
 * This is here primarily to keep prefix-count in check.
 */
void
bgp_info_set_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  SET_FLAG (ri->flags, flag);

  /* early bath if we know it's not a flag that changes useability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_UNUSEABLE))
    return;

  bgp_pcount_adjust (rn, ri);
}

void
bgp_info_unset_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  UNSET_FLAG (ri->flags, flag);

  /* early bath if we know it's not a flag that changes useability state */
  if (!CHECK_FLAG (flag, BGP_INFO_VALID|BGP_INFO_UNUSEABLE))
    return;

  bgp_pcount_adjust (rn, ri);
}




/*============================================================================*/

/*------------------------------------------------------------------------------
 * Reset state during SIGHUP, prior to rereading the configuration file.
 */
void
bgp_reset (void)
{
  /* TODO: community-list and extcommunity-list ??
   * TODO: route-maps ??
   */
  bgp_zclient_reset ();
  access_list_reset (keep_it);
  prefix_list_reset (keep_it);
}

/*==============================================================================
 * Static Route Stuff
 */
static void bgp_static_withdraw_main (struct bgp *bgp, prefix p, qafx_t qafx) ;
static void bgp_static_withdraw_rsclient (struct bgp *bgp, bgp_peer rsclient,
                                                        prefix p, qafx_t qafx) ;
static bool bgp_static_make_attributes(struct bgp* bgp, prefix p,
                  attr_pair attrs, qafx_t qafx, struct bgp_static *bgp_static,
                                                bgp_peer peer, uint rmap_type) ;

/*------------------------------------------------------------------------------
 * Create new bgp_static object
 */
static struct bgp_static *
bgp_static_new (void)
{
  return XCALLOC (MTYPE_BGP_STATIC, sizeof (struct bgp_static));
}

/*------------------------------------------------------------------------------
 * Free given bgp_static object and any remaining sub-objects
 */
static void
bgp_static_free (struct bgp_static *bgp_static)
{
  if (bgp_static->rmap.name)
    free (bgp_static->rmap.name);
  XFREE (MTYPE_BGP_STATIC, bgp_static);
}

/*------------------------------------------------------------------------------
 * For the given static route:
 *
 *   * construct a set of attributes -- running the static route's route-map.
 *
 *   * if the result is that the route is denied, withdraw it.
 *
 *   * if the route is allowed:
 *
 *       if there is an existing route in the main table, update it
 *
 *       otherwise install the new route.
 */
static void
bgp_static_update_main (struct bgp *bgp, prefix p,
                                    struct bgp_static *bgp_static, qafx_t qafx)
{
  attr_pair_t  attrs[1] ;

  qassert(bgp_static != NULL) ;
  if (bgp_static == NULL)
    return ;

  if (bgp_static_make_attributes(bgp, p, attrs, qafx, bgp_static,
                                         bgp->peer_self, BGP_RMAP_TYPE_NETWORK))
    {
      /* We have made a nice new set of attributes, which we are permitted to
       * now use.
       */
      bgp_node rn ;
      struct bgp_info *ri;
      attr_set stored ;
      bool process ;

      stored = bgp_attr_pair_store(attrs) ;

      rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, NULL);

      for (ri = rn->info; ri; ri = ri->info.next)
        if ((ri->peer == bgp->peer_self)
                                      && (ri->type == ZEBRA_ROUTE_BGP)
                                      && (ri->sub_type == BGP_ROUTE_STATIC))
          break;

      process = false ;

      if (ri != NULL)
        {
          /* The static route is in the RIB already.
           */
          if ((ri->attr != stored) || (ri->flags & BGP_INFO_REMOVED))
            {
              /* The attribute is changed or was being removed.
               */
              bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

              /* Rewrite BGP route information
               */
              if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
                bgp_info_restore(rn, ri);
              else
                bgp_aggregate_decrement (bgp, p, ri, qafx);

              bgp_attr_unlock(ri->attr) ;
              ri->attr   = bgp_attr_lock(stored) ;
              ri->uptime = bgp_clock ();

              process = true ;
            }
        }
      else
        {
          /* Static route needs to be inserted in the RIB.
           */
          ri = bgp_info_new ();
          ri->type     = ZEBRA_ROUTE_BGP ;
          ri->sub_type = BGP_ROUTE_STATIC ;
          ri->peer     = bgp->peer_self ;
          ri->attr     = bgp_attr_lock(stored) ;
          ri->uptime   = bgp_clock ();
          ri->flags   |= BGP_INFO_VALID ;

          /* Note that bgp_info_add() locks the rn -- so for each bgp_info that
           * the bgp_node points to, there is a lock on the rn (which
           * corresponds to the pointer from the bgp_info to the rn).
           */
          bgp_info_add (rn, ri);

          process = true ;
        } ;

      /* Process if required
       */
      if (process)
        {
          bgp_aggregate_increment (bgp, p, ri, qafx);
          bgp_process_dispatch (bgp, rn);
        } ;

      /* undo the bgp_afi_node_get() lock
       */
      bgp_unlock_node (rn);
    }
  else
    {
      /* We made a new set of attributes, but the route-map said no
       */
      bgp_static_withdraw_main(bgp, p, qafx) ;
    }

  bgp_attr_pair_unload(attrs) ;         /* finished     */
} ;

/*------------------------------------------------------------------------------
 * Withdraw any static route there is for the given prefix & AFI/SAFI in the
 * main RIB.
 */
static void
bgp_static_withdraw_main (struct bgp *bgp, prefix p, qafx_t qafx)
{
  bgp_node  rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, NULL);

  /* Check selected route and self inserted route.
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == bgp->peer_self)
                            && (ri->type == ZEBRA_ROUTE_BGP)
                            && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  /* Withdraw static BGP route from routing table.
   *
   * Note that there is no damping going on here.
   */
  if (ri != NULL)
    {
      bgp_aggregate_decrement (bgp, p, ri, qafx);
      bgp_info_delete (rn, ri);
      bgp_process_dispatch (bgp, rn);
    } ;

  /* undo the bgp_afi_node_get() lock
   */
  bgp_unlock_node (rn);
} ;

/*------------------------------------------------------------------------------
 * For the given static route:
 *
 *   * construct a set of attributes -- running the static route's route-map.
 *
 *   * if the result is that the route is denied, withdraw it.
 *
 *   * if the route is allowed:
 *
 *       run it against the RS Client's import route-map.
 *
 *       if the route is still allowed:
 *
 *         if there is an existing route in the RS Client's table, update it
 *
 *         otherwise install the new route.
 *
 *   * if the route is not allowed for any reason
 *
 *       withdraw it from the RS Client's table -- if it is there
 */
static void
bgp_static_update_rsclient (struct bgp *bgp, bgp_peer rsclient, prefix p,
                                    struct bgp_static *bgp_static, qafx_t qafx)
{
  attr_pair_t  attrs[1] ;
  rs_route_t   rt[1] ;
  bool permitted ;

  qassert(bgp_static != NULL) ;
  if (bgp_static == NULL)
    return ;

  bgp_rs_route_init(rt, qafx, NULL, bgp->peer_self, p,
                                ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, NULL, NULL) ;

  permitted = false ;           /* assume 'no'  */

  if (bgp_static_make_attributes(bgp, p, attrs, qafx, bgp_static, rsclient,
                                BGP_RMAP_TYPE_EXPORT | BGP_RMAP_TYPE_NETWORK))
    {
      /* We have made a nice new set of attributes, which we are permitted to
       * now use.
       *
       * Next step is to push those past the RS Client's 'import' route-map,
       * to see what that says.
       */
      permitted = bgp_import_modifier (rsclient, rt, attrs,
                               BGP_RMAP_TYPE_IMPORT | BGP_RMAP_TYPE_NETWORK) ;

      if (!permitted)
        {
          /* This BGP update is filtered.  Log the reason then update BGP entry.
           */
          if (BGP_DEBUG (update, UPDATE_IN))
                zlog (rsclient->log, LOG_DEBUG,
                "Static UPDATE about %s -- DENIED for RS-client %s due to: "
                                                                "import-policy",
                                               spfxtoa(p).str, rsclient->host);
        } ;
    } ;

  if (permitted)
    {
      /* We have made a nice new set of attributes, which we are still
       * permitted to use after running the RS Client's import route-map.
       *
       * So, time to find any existing route, update or install.
       */
      bgp_node rn ;
      struct bgp_info *ri;
      attr_set stored ;
      bool process ;

      stored = bgp_attr_pair_store(attrs) ;

      rn = bgp_afi_node_get (rsclient->rib[qafx], qafx, p, NULL);

      for (ri = rn->info; ri; ri = ri->info.next)
        if ((ri->peer == bgp->peer_self)
                                      && (ri->type == ZEBRA_ROUTE_BGP)
                                      && (ri->sub_type == BGP_ROUTE_STATIC))
          break;

      process = false ;

      if (ri != NULL)
        {
          /* The static route is in the RIB already.
           */
          if ((ri->attr != stored) || (ri->flags & BGP_INFO_REMOVED))
            {
              /* The attribute is changed or was being removed.
               */
              bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

              if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
                bgp_info_restore(rn, ri);

              bgp_attr_unlock(ri->attr) ;
              ri->attr   = bgp_attr_lock(stored) ;
              ri->uptime = bgp_clock ();

              process = true ;
            }
        }
      else
        {
          /* Static route needs to be inserted in the RIB.
           */
          ri = bgp_info_new ();
          ri->type     = ZEBRA_ROUTE_BGP ;
          ri->sub_type = BGP_ROUTE_STATIC ;
          ri->peer     = bgp->peer_self ;
          ri->attr     = bgp_attr_lock(stored) ;
          ri->uptime   = bgp_clock ();
          ri->flags   |= BGP_INFO_VALID ;

          /* Note that bgp_info_add() locks the rn -- so for each bgp_info that
           * the bgp_node points to, there is a lock on the rn (which
           * corresponds to the pointer from the bgp_info to the rn).
           */
          bgp_info_add (rn, ri);

          process = true ;
        } ;

      /* Process if required
       */
      if (process)
        {
          bgp_aggregate_increment (bgp, p, ri, qafx);
          bgp_process_dispatch (bgp, rn);
        } ;

      /* undo the bgp_afi_node_get() lock
       */
      bgp_unlock_node (rn);

    }
  else
    {
      bgp_static_withdraw_rsclient (bgp, rsclient, p, qafx);
    } ;

  bgp_attr_pair_unload(attrs) ;         /* finished     */
}

/*------------------------------------------------------------------------------
 * Withdraw any static route for the given prefix from the given RS Client
 */
static void
bgp_static_withdraw_rsclient (struct bgp *bgp, bgp_peer rsclient, prefix p,
                                                                    qafx_t qafx)
{
  bgp_node  rn ;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (rsclient->prib[qafx], qafx, p, NULL);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->info.next)
    if (ri->peer == bgp->peer_self
       && ri->type == ZEBRA_ROUTE_BGP
       && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table.
   */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process_dispatch (bgp, rn);
    }

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (rn);
}

/*------------------------------------------------------------------------------
 * Update main RIB *only* with given MPLS VPN static route.
 *
 * Note that the 'bgp import' process does not touch these -- so these are
 * updated directly when the test route is configured.
 *
 * There is no route-map associated with MPLS VPN statics.
 */
static void
bgp_static_update_vpnv4 (struct bgp *bgp, prefix p, qafx_t qafx,
                                            struct prefix_rd *prd, u_char *tag)
{
  bgp_node rn ;
  attr_pair_t  attrs[1] ;
  attr_set     stored ;
  struct bgp_info* ri ;
  bool process ;

  qassert(qafx_is_mpls_vpn(qafx)) ;
  if (!qafx_is_mpls_vpn(qafx))
    return ;

  /* Construct the static route attributes.
   *
   * Starts with: the given ORIGIN, an empty AS_PATH and the default weight.
   */
  bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP) ;
  stored = bgp_attr_pair_store(attrs) ;

  /* Find bgp_node and then look for route
   */
  rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, prd);

  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == bgp->peer_self)
                                  && (ri->type == ZEBRA_ROUTE_BGP)
                                  && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  /* Really do not expect to find this route, but we cope ....
   */
  process = false ;

  if (ri != NULL)
    {
      /* The static route is in the RIB already.
       */
      if ((ri->attr != stored) || (ri->flags & BGP_INFO_REMOVED))
        {
          /* The attribute is changed or was being removed.
           */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information
           */
          if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
            bgp_info_restore(rn, ri);

          bgp_attr_unlock(ri->attr) ;
          ri->attr   = bgp_attr_lock(stored) ;
          ri->uptime = bgp_clock ();

          process = true ;
        }
    }
  else
    {
      /* Static route needs to be inserted in the RIB.
       */
      ri = bgp_info_new ();
      ri->type     = ZEBRA_ROUTE_BGP ;
      ri->sub_type = BGP_ROUTE_STATIC ;
      ri->peer     = bgp->peer_self ;
      ri->attr     = bgp_attr_lock(stored) ;
      ri->uptime   = bgp_clock ();
      ri->flags   |= BGP_INFO_VALID ;

      /* Note that bgp_info_add() locks the rn -- so for each bgp_info that
       * the bgp_node points to, there is a lock on the rn (which
       * corresponds to the pointer from the bgp_info to the rn).
       */
      bgp_info_add (rn, ri);

      process = true ;
    } ;

  /* Process if required
   */
  if (process)
    bgp_process_dispatch (bgp, rn);

  /* undo the bgp_afi_node_get() lock
   */
  bgp_unlock_node (rn);
} ;

/*------------------------------------------------------------------------------
 * Withdraw from main RIB *only* any MPLS VPN static route with given prefix.
 */
static void
bgp_static_withdraw_vpnv4 (struct bgp *bgp, prefix p, qafx_t qafx,
                                             struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, prd);

  /* Check selected route and self inserted route. */
  for (ri = rn->info; ri; ri = ri->info.next)
    if (ri->peer == bgp->peer_self
        && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process_dispatch (bgp, rn);
    }

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (rn);
} ;

/*------------------------------------------------------------------------------
 * Update with given static route
 *
 * This withdraws stuff from main and RS RIBs
 *
 * NB: this will not cope with VPN static routes !!
 */
extern void
bgp_static_update (bgp_inst bgp, prefix p,
                                    struct bgp_static *bgp_static, qafx_t qafx)
{
  bgp_peer peer ;
  struct listnode *node, *nnode;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    return ;

  bgp_static_update_main (bgp, p, bgp_static, qafx);

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;

      if ((prib == NULL) || !(prib->af_flags & PEER_AFF_RSERVER_CLIENT))
        continue ;

      bgp_static_update_rsclient (bgp, peer, p, bgp_static, qafx);
    } ;
} ;

/*------------------------------------------------------------------------------
 * Withdraw any static route there is for the given prefix & AFI/SAFI
 *
 * This withdraws stuff from main and RS RIBs
 *
 * NB: this will not cope with VPN static routes !!
 */
extern void
bgp_static_withdraw (bgp_inst bgp, prefix p, qafx_t qafx)
{
  bgp_peer peer;
  struct listnode *node, *nnode;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    return ;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;

      if ((prib == NULL) || !(prib->af_flags & PEER_AFF_RSERVER_CLIENT))
        continue ;

      bgp_static_withdraw_rsclient (bgp, peer, p, qafx);
    }

  bgp_static_withdraw_main (bgp, p, qafx);
} ;

/*------------------------------------------------------------------------------
 * Send static routes to the given RS Client.
 */
extern void
bgp_check_local_routes_rsclient (bgp_peer rsclient, qafx_t qafx)
{
  struct bgp_static *bgp_static;
  struct bgp *bgp;
  struct bgp_node *rn;
  struct prefix *p;

  bgp = rsclient->bgp ;

  for (rn = bgp_table_top (bgp->route[qafx]); rn != NULL ;
                                                       rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        bgp_static_update_rsclient (bgp, rsclient, p, bgp_static, qafx) ;
      }
} ;

/*------------------------------------------------------------------------------
 * Configure static BGP network.  When user don't run zebra, static
 * route should be installed as valid.
 *
 * Takes:  ip_str    -- string specifying prefix.
 *
 *         qafx      -- AFI/SAFI
 *
 *         rmap      -- optional: name of route-map to apply when constructing
 *                                route.
 *
 *         backdoor  -- true <=> 'backdoor' route
 *
 * NB: this will not cope with VPN static routes !!
 */
static int
bgp_static_set (struct vty *vty, struct bgp *bgp, const char *ip_str,
                                   qafx_t qafx, const char *rmap, bool backdoor)
{
  int ret;
  prefix_t  p[1] ;
  struct bgp_static* bgp_static;
  bgp_node  rn;
  bool   need_withdraw ;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    {
      vty_out (vty, "%% %s() cannot do MPLS VPN -- BUG\n", __func__);
      return CMD_ERROR ;
    } ;

  /* Convert IP prefix string to struct prefix.
   */
  ret = str2prefix (ip_str, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix\n");
      return CMD_WARNING;
    } ;

#ifdef HAVE_IPV6
  if (qafx_is_ipv6(qafx) && IN6_IS_ADDR_LINKLOCAL (&p->u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)\n") ;
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (p);

  /* Set BGP static route configuration.
   *
   * Creates a node entry in the bgp instance's table of static routes,
   * if there isn't one there already.
   *
   * bgp_node_get() locks the node.
   */
  rn = bgp_node_get (bgp_table_get(&bgp->route[qafx], qafx), p) ;

  if (rn->info != NULL)
    {
      /* The static route exists already
       */
      bool new_rmap ;

      bgp_static = rn->info;

      if (bgp_static->backdoor != backdoor)
        {
          need_withdraw  = true ;
          bgp_static->valid = false ;

          bgp_static->backdoor = backdoor;
        } ;

      new_rmap = false ;

      if (bgp_static->rmap.name != NULL)
        new_rmap = (rmap == NULL) || (strcmp(rmap, bgp_static->rmap.name) != 0);
      else
        new_rmap = (rmap != NULL) ;

      if (new_rmap)
        {
          if (bgp_static->rmap.name != NULL)
            free (bgp_static->rmap.name);

          if (rmap != NULL)
            {
              bgp_static->rmap.name = strdup (rmap);
              bgp_static->rmap.map  = route_map_lookup (rmap);
            }
          else
            {
              bgp_static->rmap.name = NULL;
              bgp_static->rmap.map = NULL;
            } ;

          bgp_static->valid = false ;
          need_withdraw = true ;
        } ;

      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration.
       *
       * NB: the node is locked by bgp_node_get(), and we leave that lock in
       *     place.  When bgp_static_unset() is called, the lock is removed.
       */
      need_withdraw = false ;

      bgp_static = bgp_static_new ();
      bgp_static->backdoor = backdoor;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;

      if (rmap)
        {
          bgp_static->rmap.name = strdup (rmap);
          bgp_static->rmap.map  = route_map_lookup (rmap);
        } ;

      rn->info = bgp_static;
    } ;

  /* If BGP scan is not enabled, we should install this route here.
   */
  if (! bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK) && !bgp_static->valid)
    {
      bgp_static->valid = true ;

      if (need_withdraw)
        bgp_static_withdraw (bgp, p, qafx);

      if (! bgp_static->backdoor)
        bgp_static_update (bgp, p, bgp_static, qafx);
    } ;

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * De-configure static BGP network.
 *
 * NB: will not cope with MPLS VPN
 */
static int
bgp_static_unset (struct vty *vty, struct bgp *bgp, const char *ip_str,
                                                                   qafx_t qafx)
{
  int ret;
  struct bgp_static *bgp_static;
  prefix_t p[1] ;
  bgp_node rn ;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    {
      vty_out (vty, "%% %s() cannot do MPLS VPN -- BUG\n", __func__);
      return CMD_ERROR ;
    } ;

  /* Convert IP prefix string to struct prefix. */
  ret = str2prefix (ip_str, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    } ;

#ifdef HAVE_IPV6
  if (qafx_is_ipv6(qafx) && IN6_IS_ADDR_LINKLOCAL (&p->u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)\n") ;
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (p);

  rn = bgp_node_lookup (bgp->route[qafx], p);
  if (rn == NULL)
    {
      vty_out (vty, "%% Can't find specified static route configuration.\n");
      return CMD_WARNING;
    }

  /* Update BGP RIB.
   */
  bgp_static = rn->info;

  if (! bgp_static->backdoor)
    bgp_static_withdraw (bgp, p, qafx);

  /* Clear configuration.
   *
   * Removes the lock set in bgp_static_set().
   */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  bgp_unlock_node (rn);         /* removes bgp_node_lookup() lock       */
  bgp_unlock_node (rn);         /* removes bgp_static_set() lock        */

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * For test purposes, can construct MPLS VPN static routes
 */
extern int
bgp_static_set_vpnv4 (struct vty *vty, const char *ip_str, const char *rd_str,
                      const char *tag_str)
{
  int ret;
  prefix_t p[1] ;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  mpls_tags_t tag ;

  bgp = vty->index;

  ret = str2prefix (ip_str, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    } ;

  apply_mask (p);

  if (!str2prefix_rd_vty (vty, &prd, rd_str))
    return CMD_WARNING;

  tag = str2tag (tag_str);
  if (tag == mpls_tags_invalid)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp_table_get(&bgp->route[qafx_ipv4_mpls_vpn],
                                   qafx_ipv4_mpls_vpn), (struct prefix *)&prd) ;
  if (prn->info == NULL)
    prn->info = bgp_table_init(qafx_ipv4_mpls_vpn);
  else
    bgp_unlock_node (prn);

  table = prn->info;

  rn = bgp_node_get(table, p);

  if (rn->info)
    {
      vty_out (vty, "%% Same network configuration exists\n") ;
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration.
       *
       * NB: the node is locked by bgp_node_get(), and we leave that lock in
       *     place.  When bgp_static_unset_vpn4() is called, the lock is
       *     removed.
       */
      bgp_static = bgp_static_new ();
      bgp_static->backdoor  = false ;
      bgp_static->valid     = 1;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;

      memcpy (bgp_static->tag, tag, 3);

      rn->info = bgp_static;

      bgp_static_update_vpnv4 (bgp, p, qafx_ipv4_mpls_vpn, &prd, tag);
    }

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * De-configure test static MPLS VPN Route.
 */
extern int
bgp_static_unset_vpnv4 (struct vty *vty, const char *ip_str,
                        const char *rd_str, const char *tag_str)
{
  int ret;
  struct bgp *bgp;
  prefix_t   p[1];
  struct prefix_rd prd;
  bgp_node  prn;
  bgp_node  rn;
  bgp_table table;
  struct bgp_static *bgp_static;
  mpls_tags_t tag ;

  bgp = vty->index;

  /* Convert IP prefix string to struct prefix.
   */
  ret = str2prefix (ip_str, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (p);

  if (!str2prefix_rd_vty (vty, &prd, rd_str))
    return CMD_WARNING;

  tag = str2tag (tag_str);
  if (tag == mpls_tags_invalid)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp_table_get(&bgp->route[qafx_ipv4_mpls_vpn],
                                   qafx_ipv4_mpls_vpn), (struct prefix *)&prd) ;
  if (prn->info == NULL)
    prn->info = bgp_table_init (qafx_ipv4_mpls_vpn);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_lookup (table, p);

  if (rn)
    {
      bgp_static_withdraw_vpnv4 (bgp, p, qafx_ipv4_mpls_vpn, &prd, tag);

      bgp_static = rn->info;
      bgp_static_free (bgp_static);
      rn->info = NULL;
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
  else
    vty_out (vty, "%% Can't find the route%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Called from bgp_delete().  Delete all static routes from the BGP instance.
 */
extern void
bgp_static_delete (struct bgp *bgp)
{
  bgp_node  rn;
  bgp_node  rm;
  bgp_table table;
  qafx_t    qafx ;
  struct bgp_static* bgp_static;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      for (rn = bgp_table_top (bgp->route[qafx]) ; rn ;
                                                      rn = bgp_route_next (rn))
        if (rn->info != NULL)
          {
            if (qafx_is_mpls_vpn(qafx))
              {
                table = rn->info;

                for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
                  {
                    bgp_static = rm->info;
                    bgp_static_withdraw_vpnv4 (bgp, &rm->p,
                                               qafx_ipv4_mpls_vpn,
                                               (struct prefix_rd *)&rn->p,
                                               bgp_static->tag);
                    bgp_static_free (bgp_static);
                    rm->info = NULL;
                    bgp_unlock_node (rm);
                  } ;
              }
            else
              {
                bgp_static = rn->info;
                bgp_static_withdraw (bgp, &rn->p, qafx);
                bgp_static_free (bgp_static);
                rn->info = NULL;
                bgp_unlock_node (rn);
              } ;
         } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Make a set of attributes for the given static route.
 *
 * Expects an uninitialised attribute pair, and returns result as the working
 * set in there.
 *
 * For main RIB statics, the given peer is the peer_self, and the rmap_type
 * is PEER_RMAP_TYPE_NETWORK.
 *
 * For RS Client statics, the given peer is the destination RS Client, and the
 * rmap_type is PEER_RMAP_TYPE_EXPORT | PEER_RMAP_TYPE_NETWORK.
 *
 * Returns:  true <=> have attributes ready to use -- but not stored
 *           false => the route-map says no
 */
static bool
bgp_static_make_attributes(struct bgp* bgp, prefix p, attr_pair attrs,
                                 qafx_t qafx, struct bgp_static *bgp_static,
                                                  bgp_peer peer, uint rmap_type)
{
  /* Construct the static route attributes.
   *
   * Starts with: the given ORIGIN, an empty AS_PATH and the default weight.
   */
  bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP) ;

  bgp_attr_pair_set_next_hop(attrs, nh_ipv4, &bgp_static->igpnexthop.s_addr) ;
  bgp_attr_pair_set_med(attrs, bgp_static->igpmetric) ;

  if (bgp_static->atomic)
    bgp_attr_pair_set_atomic_aggregate(attrs, true) ;

  /* Apply network route-map for export to the given peer.
   *
   * Create interned attributes client_attr, either from route-map result, or
   * from the static_attr.
   */
  if (bgp_static->rmap.name)
    {
      bgp_route_map_t  brm[1] ;

      brm->peer      = peer ;
      brm->attrs     = attrs ;
      brm->qafx      = qafx ;
      brm->rmap_type = rmap_type ;

      if (route_map_apply(bgp_static->rmap.map, p, RMAP_BGP, brm)
                                                            == RMAP_DENY_MATCH)
        return false ;
    } ;

  return true ;
} ;


DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
                         qafx_from_q(qAFI_IP, bgp_node_safi(vty)), NULL, 0);
}

DEFUN (bgp_network_route_map,
       bgp_network_route_map_cmd,
       "network A.B.C.D/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
                          qafx_from_q(qAFI_IP, bgp_node_safi(vty)), argv[1], 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_set (vty, vty->index, argv[0], qafx_ipv4_unicast,
                                                                   NULL, 1);
}

DEFUN (bgp_network_mask,
       bgp_network_mask_cmd,
       "network A.B.C.D mask A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
                            qafx_from_q(qAFI_IP, bgp_node_safi(vty)), NULL, 0);
}

DEFUN (bgp_network_mask_route_map,
       bgp_network_mask_route_map_cmd,
       "network A.B.C.D mask A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
                         qafx_from_q(qAFI_IP, bgp_node_safi(vty)), argv[2], 0);
}

DEFUN (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_cmd,
       "network A.B.C.D mask A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, qafx_ipv4_unicast,
                                                                       NULL, 1);
}

DEFUN (bgp_network_mask_natural,
       bgp_network_mask_natural_cmd,
       "network A.B.C.D",
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
                             qafx_from_q(qAFI_IP, bgp_node_safi(vty)), NULL, 0);
}

DEFUN (bgp_network_mask_natural_route_map,
       bgp_network_mask_natural_route_map_cmd,
       "network A.B.C.D route-map WORD",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str,
                         qafx_from_q(qAFI_IP, bgp_node_safi(vty)), argv[1], 0);
}

DEFUN (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_cmd,
       "network A.B.C.D backdoor",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_set (vty, vty->index, prefix_str, qafx_ipv4_unicast,
                                                                       NULL, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_unset (vty, vty->index, argv[0],
                                   qafx_from_q(qAFI_IP, bgp_node_safi(vty)));
}

ALIAS (no_bgp_network,
       no_bgp_network_route_map_cmd,
       "no network A.B.C.D/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network,
       no_bgp_network_backdoor_cmd,
       "no network A.B.C.D/M backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask,
       no_bgp_network_mask_cmd,
       "no network A.B.C.D mask A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str,
                                      qafx_from_q(qAFI_IP, bgp_node_safi(vty)));
}

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_route_map_cmd,
       "no network A.B.C.D mask A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_cmd,
       "no network A.B.C.D mask A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n")

DEFUN (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_cmd,
       "no network A.B.C.D",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], NULL, prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_static_unset (vty, vty->index, prefix_str,
                                     qafx_from_q(qAFI_IP, bgp_node_safi(vty)));
}

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_route_map_cmd,
       "no network A.B.C.D route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_cmd,
       "no network A.B.C.D backdoor",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_bgp_network,
       ipv6_bgp_network_cmd,
       "network X:X::X:X/M",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
                          qafx_from_q(qAFI_ipv6, bgp_node_safi(vty)), NULL, 0);
}

DEFUN (ipv6_bgp_network_route_map,
       ipv6_bgp_network_route_map_cmd,
       "network X:X::X:X/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
                       qafx_from_q(qAFI_ipv6, bgp_node_safi(vty)), argv[1], 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_unset (vty, vty->index, argv[0],
                                   qafx_from_q(qAFI_ipv6, bgp_node_safi(vty)));
}

ALIAS (no_ipv6_bgp_network,
       no_ipv6_bgp_network_route_map_cmd,
       "no network X:X::X:X/M route-map WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")

ALIAS (ipv6_bgp_network,
       old_ipv6_bgp_network_cmd,
       "ipv6 bgp network X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

ALIAS (no_ipv6_bgp_network,
       old_no_ipv6_bgp_network_cmd,
       "no ipv6 bgp network X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
#endif /* HAVE_IPV6 */

/* stubs for removed AS-Pathlimit commands, kept for config compatibility */
ALIAS_DEPRECATED (bgp_network,
       bgp_network_ttl_cmd,
       "network A.B.C.D/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (bgp_network_backdoor,
       bgp_network_backdoor_ttl_cmd,
       "network A.B.C.D/M backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (bgp_network_mask,
       bgp_network_mask_ttl_cmd,
       "network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (bgp_network_mask_backdoor,
       bgp_network_mask_backdoor_ttl_cmd,
       "network A.B.C.D mask A.B.C.D backdoor pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (bgp_network_mask_natural,
       bgp_network_mask_natural_ttl_cmd,
       "network A.B.C.D pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (bgp_network_mask_natural_backdoor,
       bgp_network_mask_natural_backdoor_ttl_cmd,
       "network A.B.C.D backdoor pathlimit <1-255>",
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_ttl_cmd,
       "no network A.B.C.D/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_backdoor_ttl_cmd,
       "no network A.B.C.D/M backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network,
       no_bgp_network_mask_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network_mask,
       no_bgp_network_mask_backdoor_ttl_cmd,
       "no network A.B.C.D mask A.B.C.D  backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Network mask\n"
       "Network mask\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_ttl_cmd,
       "no network A.B.C.D pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_bgp_network_mask_natural,
       no_bgp_network_mask_natural_backdoor_ttl_cmd,
       "no network A.B.C.D backdoor pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "Network number\n"
       "Specify a BGP backdoor route\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

#ifdef HAVE_IPV6
ALIAS_DEPRECATED (ipv6_bgp_network,
       ipv6_bgp_network_ttl_cmd,
       "network X:X::X:X/M pathlimit <0-255>",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")

ALIAS_DEPRECATED (no_ipv6_bgp_network,
       no_ipv6_bgp_network_ttl_cmd,
       "no network X:X::X:X/M pathlimit <0-255>",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "AS-Path hopcount limit attribute\n"
       "AS-Pathlimit TTL, in number of AS-Path hops\n")
#endif /* HAVE_IPV6 */


/*==============================================================================
 * Aggregate address:
 *
 *   advertise-map  Set condition to advertise attribute
 *   as-set         Generate AS set path information
 *   attribute-map  Set attributes of aggregate
 *   route-map      Set parameters of aggregate
 *   summary-only   Filter more specific routes from updates
 *   suppress-map   Conditionally filter more specific routes from updates
 *   <cr>
 */
struct bgp_aggregate
{
  bool  summary_only;
  bool  as_set;

  struct route_map *map;

  urlong count;

  qafx_t  qafx ;
};

static void bgp_aggregate_route (struct bgp *bgp, prefix p,
                                 struct bgp_info *rinew, struct bgp_info *del,
                                               struct bgp_aggregate *aggregate);
static bool bgp_aggregate_merge(struct bgp_aggregate* aggregate,
                                         attr_pair attrs, struct bgp_info* ri) ;
static void bgp_aggregate_delete (struct bgp* bgp, prefix p,
                                               struct bgp_aggregate* aggregate);
static cmd_ret_t bgp_aggregate_unset (struct vty *vty, const char *prefix_str,
                                                                  qafx_t qafx) ;

static struct bgp_aggregate *
bgp_aggregate_new (void)
{
  return XCALLOC (MTYPE_BGP_AGGREGATE, sizeof (struct bgp_aggregate));
}

static void
bgp_aggregate_free (struct bgp_aggregate *aggregate)
{
  XFREE (MTYPE_BGP_AGGREGATE, aggregate);
}


/*------------------------------------------------------------------------------
 * See if the given new or changed route should be aggregated.
 *
 * If so, update (or create) aggregate to include state of the new or changed
 * route.
 *
 * This is done after the route has been installed in the RIB -- so the given
 * bgp_info is sitting on the relevant bgp_node's list.
 *
 * NB: this is for main RIB *only* -- not RS Client RIBs
 */
extern void
bgp_aggregate_increment (struct bgp *bgp, prefix p,
                                               struct bgp_info *ri, qafx_t qafx)
{
  bgp_table aggregate_table ;
  bgp_node ag_rn ;

  aggregate_table = bgp->aggregate[qafx] ;
  if (aggregate_table == NULL)
    return ;

  if (qafx_is_mpls_vpn(qafx))
    return;             /* MPLS-VPN aggregation is not yet supported.   */

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  /* In the bgp->aggregate[] table we keep all the aggregate addresses.
   *
   * If we find that the current prefix is more-specific than the most-specific
   * aggregate address, then we have to do something with it.
   */
  ag_rn = bgp_node_lookup_parent(aggregate_table, p);

  if (ag_rn == NULL)
    return ;            /* prefix is not subject to aggregation         */

  qassert(ag_rn->info != NULL) ;

  /* We are updating a route which is more specific than an aggregate.
   *
   * First we delete the aggregate, then reconstruct it, to include all
   * other existing more specifics, plus the new one.
   */
  bgp_aggregate_delete (bgp, &ag_rn->p, ag_rn->info);
  bgp_aggregate_route (bgp, &ag_rn->p, ri, NULL, ag_rn->info);

  bgp_unlock_node (ag_rn) ;
} ;

/*------------------------------------------------------------------------------
 * See if the given route which is being removed was aggregated.
 *
 * If so, update (or remove) aggregate to remove the previously included route.
 *
 * NB: this is for main RIB *only* -- not RS Client RIBs
 */
extern void
bgp_aggregate_decrement (struct bgp *bgp, prefix p,
                                              struct bgp_info *del, qafx_t qafx)
{
  bgp_table aggregate_table ;
  bgp_node ag_rn ;

  aggregate_table = bgp->aggregate[qafx] ;
  if (aggregate_table == NULL)
    return ;

  if (qafx_is_mpls_vpn(qafx))
    return;             /* MPLS-VPN aggregation is not yet supported.   */

  /* In the bgp->aggregate[] table we keep all the aggregate addresses.
   *
   * If we find that the current prefix is more-specific than the most-specific
   * aggregate address, then we have to do something with it.
   */
  ag_rn = bgp_node_lookup_parent(aggregate_table, p);

  if (ag_rn == NULL)
    return ;            /* prefix is not subject to aggregation         */

  qassert(ag_rn->info != NULL) ;

  /* We are updating a route which is more specific than an aggregate.
   *
   * First we delete the aggregate, then reconstruct it, to include all
   * other existing more specifics, less the one being deleted.
   */
  bgp_aggregate_delete (bgp, &ag_rn->p, ag_rn->info);
  bgp_aggregate_route (bgp, &ag_rn->p, NULL, del, ag_rn->info);

  bgp_unlock_node (ag_rn) ;
} ;

/*------------------------------------------------------------------------------
 * Update aggregate route
 *
 * The aggregate exists in the aggregate table,
 */
static void
bgp_aggregate_route (struct bgp *bgp, prefix p, struct bgp_info *rinew,
                          struct bgp_info *del, struct bgp_aggregate *aggregate)
{
  bgp_table table ;
  bgp_node ag_rn, rn ;
  attr_pair_t attrs[1] ;

  /* Start with a working set of attributes, set to default:
   *
   *   * ORIGIN IGP
   *
   *   * empty AS_PATH
   *
   *   * weight = BGP_ATTR_DEFAULT_WEIGHT
   *
   * Then merge in the attributes for the new bgp_info (if any).
   */
  bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP) ;

  if (rinew != NULL)
    bgp_aggregate_merge(aggregate, attrs, rinew) ;

  /* Walk all the more-specific routes for the aggregate, and merge them in.
   *
   * Skips any bgp_info which is about to be withdrawn.
   */
  table = bgp->rib[aggregate->qafx][rib_main];

  ag_rn = bgp_node_get (table, p);
  rn  = bgp_lock_node(ag_rn) ;
  while ((rn = bgp_route_next_until (rn, ag_rn)) != NULL)
    {
      struct bgp_info* ri ;
      bool match ;

      qassert(rn->p.prefixlen > p->prefixlen) ;

      match = false;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          if (BGP_INFO_HOLDDOWN (ri))
            continue ;                  /* skip invalid, removed etc.   */

          if (ri == del)
            continue ;                  /* skip to be deleted bgp_info  */

          if (ri->sub_type == BGP_ROUTE_AGGREGATE)
            continue ;                  /* skip other aggregates        */

          if (ri != rinew)              /* already done this            */
            if (!bgp_aggregate_merge(aggregate, attrs, ri))
              {
                /* TODO -- need to break out of the loop, not create the
                 *         aggregate and (presumably) undo
                 */
#ifdef AGGREGATE_NEXTHOP_CHECK
#warning AGGREGATE_NEXTHOP_CHECK is not completely implemented !!
#endif
              } ;

          if (aggregate->summary_only)
            {
              (bgp_info_extra_get (ri))->suppress++;
              bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
              match = true ;
            } ;
        } ;

      if (match)
        bgp_process_dispatch  (bgp, rn);
    } ;

  /* If the aggregate has at least one less specific, then create the
   * aggregate route and dispatch it for processing.
   */
  if (aggregate->count > 0)
    {
      struct bgp_info* ag_ri ;

      /* Next hop attribute -- TODO ????     ........................................
       *
       * As it stands, no next_hop has been set... so will send next hop self
       */

      /* Setting of Atomic Aggregate
       *
       * If we haven't made an AS_PATH from all the more specifics' AS_PATHs,
       * then we set ATOMIC_AGGREGATE.
       *
       * TODO -- if all the more specifics' AS_PATHs were empty, then we
       *         don't really need to do this ?
       *
       * TODO -- this uses the confed_id if there is one....
       */
      if (! aggregate->as_set)
        bgp_attr_pair_set_atomic_aggregate(attrs, true) ;

      /* RFC4271: Any AGGREGATOR attributes from the routes to be aggregated
       *          MUST NOT be included in the agggregated route.  The BGP
       *          speaker performing the aggregation MAY attach a new
       *          AGGREGATOR attribute.
       */
      bgp_attr_pair_set_aggregator(attrs,
                    (bgp->confed_id != BGP_ASN_NULL) ? bgp->confed_id
                                                     : bgp->as,
                                                              bgp->router_id) ;

      /* RFC4271: If the aggregated route has an AS_SET as the first element
       *          in its AS_PATH attribute, then the router that originates
       *          the route SHOULD NOT advertise the MED attribute with this
       *          route.
       *
       * TODO as it stands, no MED is set in any case !
       */

      /* Now construct bgp_info and set its attributes.
       */
      ag_ri = bgp_info_new ();
      ag_ri->type     = ZEBRA_ROUTE_BGP;
      ag_ri->sub_type = BGP_ROUTE_AGGREGATE;
      ag_ri->peer     = bgp->peer_self;
      ag_ri->flags   |= BGP_INFO_VALID ;

      ag_ri->attr   = bgp_attr_pair_assign(attrs) ;
      ag_ri->uptime = bgp_clock ();

      /* Add route (bgp_info) to the bgp_node and dispatch for processing.
       */
      bgp_info_add (ag_rn, ag_ri);
      bgp_process_dispatch (bgp, ag_rn);
    } ;

  /* Done: undo the lock acquired by bgp_node_get() -- which will destroy the
   *       node if it is redundant.
   *
   *       discard any unstored attributes, or unlock the stored ones.
   */;
  bgp_unlock_node (ag_rn);
  bgp_attr_pair_unload(attrs) ;
} ;

/*------------------------------------------------------------------------------
 * Merge the given bgp_info into the working attributes, if required.
 *
 * Picks up the next_hop and med if not already picked up.  Otherwise, if is
 * required, run the next hop and med check.
 *
 * Counts another route which has been aggregated.
 *
 * Returns:  true <=> OK
 *           false -> failed the next_hop/med check
 */
static bool
bgp_aggregate_merge(struct bgp_aggregate* aggregate, attr_pair attrs,
                                                            struct bgp_info* ri)
{
#ifdef AGGREGATE_NEXTHOP_CHECK
#warning AGGREGATE_NEXTHOP_CHECK
  enum { aggregate_next_hop_check  = true   } ;
#else
  enum { aggregate_next_hop_check  = false  } ;
#endif

  if (attrs->working->next_hop.type == nh_none)
    {
      /* TODO .... non IPv4 aggregation ???
       */
      bgp_attr_pair_set_next_hop(attrs, nh_ipv4,
                                                    &ri->attr->next_hop.ip.v4) ;
      bgp_attr_pair_set_med(attrs, ri->attr->med) ;
    }
  else if (aggregate_next_hop_check)
    {
      /* RFC4271: When aggregating routes which have different NEXT_HOP
       *          attributes, the NEXT_HOP attribute of the aggregated route
       *          SHALL identify an interface on the BGP speaker that performs
       *          the aggregation.
       *
       * RFC4721: Route that have different MED attributes SHALL NOT be
       *          aggregated.
       *
       * TODO ..... checking of IPv4 next hop ??? ........................................
       */
      if ( (ri->attr->next_hop.ip.v4 != attrs->working->next_hop.ip.v4) ||
           (ri->attr->med            != attrs->working->med) )
        return false ;
    } ;

  aggregate->count++;

  if (aggregate->as_set)
    {
      /* RFC4271: any one INCOMPLETE -> INCOMPLETE,
       *          otherwise any one EGP -> EGP
       *          otherwise IGP
       */
      confirm((BGP_ATT_ORG_INCOMP > BGP_ATT_ORG_EGP) &&
                                   (BGP_ATT_ORG_EGP > BGP_ATT_ORG_IGP)) ;

      if (attrs->working->origin < ri->attr->origin)
        bgp_attr_pair_set_origin(attrs, ri->attr->origin) ;

      /* RFC4271: If at least one of the routes to be aggregated has
       *          ATOMIC_AGGREGATE path attribute, then the aggregated route
       *          SHALL have this attribute as well.
       */
      if (ri->attr->have & atb_atomic_aggregate)
        bgp_attr_pair_set_atomic_aggregate(attrs, true) ;

      /* as_path_aggregate() performs minimal RFC4271 operation.
       */
      if (ri->attr->asp != NULL)
        {
          as_path asp ;

          asp = as_path_aggregate (attrs->working->asp, ri->attr->asp) ;
          bgp_attr_pair_set_as_path(attrs, asp) ;
        } ;

      /* Lump all communities together
       */
      if (ri->attr->community != NULL)
        {
          attr_community comm ;

          comm = attr_community_add_list(attrs->working->community,
                                                          ri->attr->community) ;
          bgp_attr_pair_set_community(attrs, comm) ;
        }
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given aggregate prefix from the main table.
 *
 * Adjust the state of any more specific routes of that aggregate.
 */
static void
bgp_aggregate_delete (struct bgp *bgp, prefix p,
                                                struct bgp_aggregate *aggregate)
{
  bgp_table table;
  bgp_node ag_rn, rn ;
  struct bgp_info* ag_ri;

  if (qafx_is_ipv4(aggregate->qafx) && (p->prefixlen == IPV4_MAX_BITLEN))
    return;
  if (qafx_is_ipv6(aggregate->qafx) && (p->prefixlen == IPV6_MAX_BITLEN))
    return;

  /* See if we have the aggregate in the main RIB
   */
  table = bgp->rib[aggregate->qafx][rib_main];

  ag_rn = bgp_node_lookup(table, p) ;
  if (ag_rn == NULL)
    return ;                    /* no aggregate in the table            */

  for (ag_ri = ag_rn->info; ag_ri; ag_ri = ag_ri->info.next)
    if ((ag_ri->peer == bgp->peer_self)
                                 && (ag_ri->type == ZEBRA_ROUTE_BGP)
                                 && (ag_ri->sub_type == BGP_ROUTE_AGGREGATE))
      break;

  if (ag_ri == NULL)
    {
      bgp_unlock_node (ag_rn) ;
      return ;                  /* no aggregate route in the table      */
    } ;

  /* About to withdraw aggregate BGP route from routing table.
   *
   * If routes exists below this node, modify as required to reflect the fact
   * that the parent is about to be removed.
   *
   * Note that bgp_route_next_until() starts by moveing down to the left, and
   * unlocks the node it is on while locking the node it returns (if any).
   */
  rn  = bgp_lock_node(ag_rn) ;
  while ((rn = bgp_route_next_until (rn, ag_rn)) != NULL)
    {
      struct bgp_info *ri;
      bool match ;

      assert(rn->p.prefixlen > p->prefixlen) ;

      match = false ;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          if (BGP_INFO_HOLDDOWN (ri))
            continue;

          if (ri->sub_type != BGP_ROUTE_AGGREGATE)
            {
              if (aggregate->summary_only && (ri->extra != NULL))
                {
                  ri->extra->suppress--;

                  if (ri->extra->suppress == 0)
                    {
                      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
                      match = true ;
                    }
                } ;

              aggregate->count--;
            } ;
          } ;

        /* If this node was suppressed, process the change.
         */
        if (match)
          bgp_process_dispatch (bgp, rn);
      } ;

  /* Withdraw aggregate BGP route from routing table.
   */
  bgp_info_delete (ag_rn, ag_ri);
  bgp_process_dispatch (bgp, ag_rn);

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (ag_rn);
}

/*------------------------------------------------------------------------------
 * Set an aggregate prefix
 */
static cmd_ret_t
bgp_aggregate_set (struct vty *vty, const char *prefix_str, qafx_t qafx,
                                                 bool summary_only, bool as_set)
{
  prefix_t p[1] ;
  bgp_node ag_rn ;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;
  bgp_table aggregate_table ;

  bgp = vty->index;
  aggregate_table = bgp_table_get(&bgp->aggregate[qafx], qafx) ;

  /* Convert string to prefix structure. */
  if (!str2prefix (prefix_str, p))
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask (p);

  /* Get BGP structure.
   */
  bgp = vty->index;

  /* Old configuration check -- creates bgp_node in the aggregate table.
   */
  ag_rn = bgp_node_get (aggregate_table, p);

  if (ag_rn->info)
    {
      cmd_ret_t ret ;

      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);

      ret = bgp_aggregate_unset (vty, prefix_str, qafx);
      if (ret != CMD_SUCCESS)
        {
          vty_out (vty, "Error deleting aggregate.%s", VTY_NEWLINE);
          bgp_unlock_node (ag_rn);
          return CMD_WARNING;
        }
    }

  /* Make aggregate address structure.
   *
   * Note that bgp_node_get() has locked the node, and we retain that lock.
   */
  aggregate = bgp_aggregate_new () ;

  aggregate->summary_only = summary_only;
  aggregate->as_set       = as_set;
  aggregate->qafx         = qafx;

  ag_rn->info = aggregate;

  bgp_aggregate_route(bgp, p, NULL, NULL, ag_rn->info);

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Unet an aggregate prefix
 */
static cmd_ret_t
bgp_aggregate_unset (struct vty *vty, const char *prefix_str, qafx_t qafx)
{
  prefix_t  p[1] ;
  bgp_node  ag_rn;
  bgp_inst  bgp;

  bgp = vty->index;

  /* Convert string to prefix structure. */
  if (!str2prefix (prefix_str, p))
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  ;
  apply_mask (p);

  /* Get BGP structure.
   */
  bgp = vty->index;

  /* Old configuration check.
   */
  ag_rn = bgp_node_lookup (bgp->aggregate[qafx], p);

  if (ag_rn == NULL)
    {
      vty_out (vty, "%% There is no aggregate-address configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  qassert(((struct bgp_aggregate*)ag_rn->info)->qafx == qafx) ;

  bgp_aggregate_delete (bgp, p, ag_rn->info);

  /* Discard aggregate address configuration.
   *
   * Note that bgp_node_lookup() has locked the bgp_node, and when the node was
   * created, it was locked and left locked.
   */
  bgp_aggregate_free (ag_rn->info);
  ag_rn->info = NULL;

  bgp_unlock_node (ag_rn) ;             /* undo bgp_node_lookup()       */

  bgp_unlock_node (ag_rn) ;             /* discard node                 */

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Aggregate route commands.
 */
#define AGGREGATE_SUMMARY_ONLY true
#define AGGREGATE_AS_SET       true

#define NOT_AGGREGATE_SUMMARY_ONLY false
#define NOT_AGGREGATE_AS_SET       false

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask,
       aggregate_address_mask_cmd,
       "aggregate-address A.B.C.D A.B.C.D",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_summary_only,
       aggregate_address_mask_summary_only_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_as_set,
       aggregate_address_as_set_cmd,
       "aggregate-address A.B.C.D/M as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                  NOT_AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_as_set,
       aggregate_address_mask_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                 NOT_AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}


DEFUN (aggregate_address_as_set_summary,
       aggregate_address_as_set_summary_cmd,
       "aggregate-address A.B.C.D/M as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                      AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_as_set_summary,
       aggregate_address_summary_as_set_cmd,
       "aggregate-address A.B.C.D/M summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_as_set_summary_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                      AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_summary_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], bgp_node_qafx(vty));
}

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_only_cmd,
       "no aggregate-address A.B.C.D/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_cmd,
       "no aggregate-address A.B.C.D/M as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_summary_cmd,
       "no aggregate-address A.B.C.D/M as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_as_set_cmd,
       "no aggregate-address A.B.C.D/M summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address_mask,
       no_aggregate_address_mask_cmd,
       "no aggregate-address A.B.C.D A.B.C.D",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_unset (vty, prefix_str, bgp_node_qafx(vty));
}

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_only_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_summary_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], qafx_ipv6_unicast,
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "aggregate-address X:X::X:X/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], qafx_ipv6_unicast,
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], qafx_ipv6_unicast);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no aggregate-address X:X::X:X/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (ipv6_aggregate_address,
       old_ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (ipv6_aggregate_address_summary_only,
       old_ipv6_aggregate_address_summary_only_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_ipv6_aggregate_address,
       old_no_ipv6_aggregate_address_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (no_ipv6_aggregate_address_summary_only,
       old_no_ipv6_aggregate_address_summary_only_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Redistribution of routes from Zebra
 */
static void bgp_redistribute_update(struct bgp* bgp, prefix p, attr_pair attrs,
                                                       qafx_t qafx, byte type) ;
static void bgp_redistribute_withdraw(struct bgp* bgp, prefix p,
                                                       qafx_t qafx, byte type) ;

/*------------------------------------------------------------------------------
 * Redistribute route treatment.
 */
extern void
bgp_redistribute_add (prefix p, ip_union next_hop, uint32_t metric, byte type)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  qAFI_t q_afi ;
  qafx_t qafx ;
  attr_pair_t base_attrs[1] ;

  q_afi = family2afi(p->family) ;
  qafx  = qafx_from_q(q_afi, qSAFI_Unicast) ;

  /* Make default attribute set.
   */
  bgp_attr_pair_load_default(base_attrs, BGP_ATT_ORG_INCOMP);

  switch (q_afi)
    {
      case qAFI_IP:
        bgp_attr_pair_set_next_hop(base_attrs, nh_ipv4, next_hop) ;
        break ;

#ifdef HAVE_IPV6
      case qAFI_IP6:
        bgp_attr_pair_set_next_hop(base_attrs, nh_ipv6_1, next_hop) ;
        break ;
#endif

      default:
        return ;                /* get out now if the AFI is a mystery  */
    } ;

  bgp_attr_pair_set_med(base_attrs, metric) ;
  bgp_attr_pair_store(base_attrs) ;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      attr_pair_t attrs[1] ;
      bool denied ;

      if (!bgp->redist[q_afi][type])
        continue ;

      bgp_attr_pair_load(attrs, base_attrs->stored) ;

      if (bgp->redist_metric_set[q_afi][type])
        bgp_attr_pair_set_med(attrs, bgp->redist_metric[q_afi][type]) ;

      /* Apply route-map if required.
       */
      denied = false ;
      if (bgp->rmap[q_afi][type].map != NULL)
        {
          bgp_route_map_t  brm[1] ;

          brm->peer      = bgp->peer_self ;
          brm->attrs     = attrs ;
          brm->qafx      = qafx ;
          brm->rmap_type = BGP_RMAP_TYPE_REDISTRIBUTE ;

          if (route_map_apply(bgp->rmap[q_afi][type].map, p, RMAP_BGP, brm)
                                                             == RMAP_DENY_MATCH)
            denied = true ;
        } ;

      if (denied)
        bgp_redistribute_withdraw(bgp, p, qafx, type) ;
      else
        bgp_redistribute_update(bgp, p, attrs, qafx, type) ;

      bgp_attr_pair_unload(attrs) ;
    } ;

  bgp_attr_pair_unload(base_attrs) ;
}

void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      qafx_t qafx ;
      qAFI_t q_afi ;

      q_afi = family2afi(p->family) ;
      qafx  = qafx_from_q(q_afi, qSAFI_Unicast) ;

      if (bgp->redist[q_afi][type])
        {
          struct bgp_node *rn;
          struct bgp_info *ri;

          rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, NULL);

          for (ri = rn->info; ri; ri = ri->info.next)
            if ((ri->peer == bgp->peer_self) && (ri->type == type))
              break;

          if (ri)
            {
              bgp_aggregate_decrement (bgp, p, ri, qafx);
              bgp_info_delete (rn, ri);
              bgp_process_dispatch (bgp, rn);
            } ;

          bgp_unlock_node (rn);
        }
    }
}

/*------------------------------------------------------------------------------
 * Withdraw all specified route type's routes.
 */
extern void
bgp_redistribute_withdraw_all(struct bgp *bgp, qAFI_t q_afi, int type)
{
  bgp_table table;
  bgp_node  rn;
  struct bgp_info *ri;
  qafx_t qafx ;

  qafx = qafx_from_q(q_afi, qSAFI_Unicast) ;

  table = bgp->rib[qafx][rib_main];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->info.next)
        if ((ri->peer == bgp->peer_self) && (ri->type == type))
          break;

      if (ri != NULL)
        {
          bgp_aggregate_decrement (bgp, &rn->p, ri, qafx);
          bgp_info_delete (rn, ri);
          bgp_process_dispatch (bgp, rn);
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Update given bgp instance with given redistributed route.
 */
static void
bgp_redistribute_update(struct bgp* bgp, prefix p, attr_pair attrs,
                                                       qafx_t qafx, byte type)
{
  attr_set    stored ;
  struct bgp_info *ri;
  bgp_node  rn ;
  bool update ;

  stored = bgp_attr_pair_store(attrs) ;

  rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, NULL);

  /* TODO -- note that does not check for route type
   */
  for (ri = rn->info; ri; ri = ri->info.next)
     if ((ri->peer == bgp->peer_self)
                           && (ri->sub_type == BGP_ROUTE_REDISTRIBUTE))
       break;

  update = true ;

  if (ri != NULL)
    {
      if ((ri->attr == stored) && !(ri->flags & BGP_INFO_REMOVED))
        update = false ;
      else
        {
          /* The attribute is changed.                  */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information.             */
          if (ri->flags & BGP_INFO_REMOVED)
            bgp_info_restore(rn, ri);
          else
            bgp_aggregate_decrement (bgp, p, ri, qafx);

          ri->attr = bgp_attr_unlock(ri->attr) ;
        } ;
    }
  else
    {
      ri = bgp_info_new ();
      bgp_info_add (rn, ri);

      ri->type     = type;
      ri->sub_type = BGP_ROUTE_REDISTRIBUTE;
      ri->peer     = bgp->peer_self;
      ri->flags   |= BGP_INFO_VALID ;
    } ;

  if (update)
    {
      ri->attr   = bgp_attr_lock(stored) ;
      ri->uptime = bgp_clock ();

      bgp_aggregate_increment (bgp, p, ri, qafx);
      bgp_process_dispatch (bgp, rn);
    } ;

  bgp_unlock_node (rn) ;
} ;

/*------------------------------------------------------------------------------
 * Update given bgp instance withdrawing the given redistributed route, if any.
 */
static void
bgp_redistribute_withdraw(struct bgp* bgp, prefix p, qafx_t qafx, byte type)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[qafx][rib_main], qafx, p, NULL);

  /* TODO -- note that does not check for route sub-type
   */
  for (ri = rn->info; ri; ri = ri->info.next)
    if ((ri->peer == bgp->peer_self) && (ri->type == type))
      break;

  if (ri != NULL)
    {
      bgp_aggregate_decrement (bgp, p, ri, qafx);
      bgp_info_delete (rn, ri);
      bgp_process_dispatch (bgp, rn);
    } ;

  bgp_unlock_node (rn);
} ;

/*==============================================================================
 */

static bgp_peer
peer_lookup_in_view (vty vty, const char* view_name, const char* peer_str)
{
  bgp_inst bgp;

  bgp = bgp_lookup_vty(vty, view_name) ;
  if (bgp == NULL)
    return NULL ;

  return peer_lookup_vty (vty, bgp, peer_str, qafx_undef) ;
} ;

/* Static function to display route. */
static void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  u_int32_t destination;

  if (p->family == AF_INET)
    {
      len = vty_out (vty, "%s", siptoa(p->family, &p->u.prefix).str);
      destination = ntohl (p->u.prefix4.s_addr);

      if ((IN_CLASSC (destination) && p->prefixlen == 24)
          || (IN_CLASSB (destination) && p->prefixlen == 16)
          || (IN_CLASSA (destination) && p->prefixlen == 8)
          || p->u.prefix4.s_addr == 0)
        {
          /* When mask is natural, mask is not displayed. */
        }
      else
        len += vty_out (vty, "/%d", p->prefixlen);
    }
  else
    len = vty_out (vty, "%s/%d", siptoa(p->family, &p->u.prefix).str,
                   p->prefixlen);

  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 20, " ");
  else
    vty_out (vty, "%*s", len, " ");
}

enum bgp_display_type
{
  normal_list,
};

/* Print the short form route status for a bgp_info */
static void
route_vty_short_status_out (vty vty, route_info ri)
{
 /* Route status display.
  */
  if (ri->flags & BGP_INFO_REMOVED)
    vty_out (vty, "R");
  else if (ri->flags & BGP_INFO_STALE)
    vty_out (vty, "S");
  else if (false)               /* suppressed   */
    vty_out (vty, "s");
  else if (! (ri->flags & BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected
   */
  if (ri->flags & BGP_INFO_HISTORY)
    vty_out (vty, "h");
  else if (ri->flags & BGP_INFO_DAMPED)
    vty_out (vty, "d");
  else if (ri->flags & BGP_INFO_SELECTED)
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route.
   */
  if (ri->prib->peer->sort == BGP_PEER_IBGP)
    vty_out (vty, "i");
  else
    vty_out (vty, " ");
}

/*------------------------------------------------------------------------------
 * If the as_path is not NULL and not empty, output it using the given
 * format.  Otherwise, output the alternative string.
 */
static void
route_vty_out_as_path(struct vty *vty, const char* format, as_path asp,
                                                              const char * alt)
{
  const char* str ;

  if (asp == NULL)
    str = "" ;
  else
    str = as_path_str(asp) ;

  if (*str != '\0')
    vty_out(vty, format, str) ;
  else if ((alt != NULL) & (*alt != '\0'))
    vty_out(vty, "%s", alt) ;
} ;

/*------------------------------------------------------------------------------
 * called from terminal list command
 */
extern void
route_vty_out (vty vty, prefix p, route_info ri, bool display)
{
  attr_set attr;

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute
   */
  attr = ri->attr ;
  if (attr != NULL)
    {
      if (p->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          int len;

          len = vty_out(vty, "%s",
                 siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "\n%*s", 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->have & atb_med)
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->have & atb_local_pref)
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", attr->weight);

      /* Print aspath */
      route_vty_out_as_path (vty, "%s", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str) ;
    } ;

  vty_out (vty, "%s", VTY_NEWLINE);
}

/* called from terminal list command */
extern void
route_vty_out_tmp (vty vty, prefix p, attr_set attr, qafx_t qafx)
{
  /* Route status display. */
  vty_out (vty, "*");
  vty_out (vty, ">");
  vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (p, vty);

  /* Print attribute */
  if (attr)
    {
      if (p->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          int len;

          len = vty_out(vty, "%s",
                siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "\n%*s", 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->have & atb_med)
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->have & atb_local_pref)
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", attr->weight);

      /* Print aspath   */
      route_vty_out_as_path (vty, "%s ", attr->asp, "");

      /* Print origin   */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

extern void
route_vty_out_tag (vty vty, prefix p, route_info ri, bool display)
{
  attr_set attr;
  uint32_t label = 0;

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute
   */
  attr = ri->attr ;

  if (attr != NULL)
    {
      if (p->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          vty_out(vty, "%s", siptoa(AF_INET6,
                                  &attr->next_hop.ip.v6[in6_global]).str) ;

          if (attr->next_hop.type == nh_ipv6_2)
            vty_out(vty, "(%s)", siptoa(AF_INET6,
                              &attr->next_hop.ip.v6[in6_link_local]).str) ;
        }
#endif /* HAVE_IPV6 */
    }

  label = mpls_label_decode (ri->tag);

  vty_out (vty, "notag/%d", label);

  vty_out (vty, "%s", VTY_NEWLINE);
}

/* damping route */
static void
damp_route_vty_out (vty vty, prefix p, route_info ri, bool display)
{
  attr_set attr;
  int len;
  char timebuf[BGP_UPTIME_LEN];

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", ri->prib->peer->host);
  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 34, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf,
                                                               BGP_UPTIME_LEN));
  /* Print attribute
   */
  attr = ri->attr;
  if (attr != NULL)
    {
      /* Print aspath */
      route_vty_out_as_path (vty, "%s ", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    } ;

  vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (vty vty, prefix p, route_info ri, bool display)
{
  attr_set attr;
  struct bgp_damp_info *bdi;
  char timebuf[BGP_UPTIME_LEN];
  int len;

  if (ri->extra == NULL)
    return;

  bdi = ri->extra->damp_info;

  /* short status lead text
   */
  route_vty_short_status_out (vty,ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", ri->prib->peer->host);
  len = 16 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 33, " ");
  else
    vty_out (vty, "%*s", len, " ");

  len = vty_out (vty, "%d", bdi->flap);
  len = 5 - len;
  if (len < 1)
    vty_out (vty, " ");
  else
    vty_out (vty, "%*s ", len, " ");

  vty_out (vty, "%s ", peer_uptime (bdi->start_time,
           timebuf, BGP_UPTIME_LEN));

  if (CHECK_FLAG (ri->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, ri,
                                                      timebuf, BGP_UPTIME_LEN));
  else
    vty_out (vty, "%*s ", 8, " ");

  /* Print attribute
   */
  attr = ri->attr;
  if (attr != NULL)
    {
      /* Print aspath */
      route_vty_out_as_path (vty, "%s", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    } ;

  vty_out (vty, "%s", VTY_NEWLINE);
}


#define BGP_SHOW_SCODE_HEADER \
  "Status codes: s suppressed, d damped, h history, * valid, > best, "\
  "i - internal,\n"\
  "              r RIB-failure, S Stale, R Removed\n"
#define BGP_SHOW_OCODE_HEADER \
  "Origin codes: i - IGP, e - EGP, ? - incomplete\n"
#define BGP_SHOW_HEADER \
  "   Network          Next Hop            Metric LocPrf Weight Path\n"
#define BGP_SHOW_DAMP_HEADER \
  "   Network          From             Reuse    Path\n"
#define BGP_SHOW_FLAP_HEADER \
  "   Network          From            Flaps Duration Reuse    Path\n"

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_route_map,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_flap_statistics,
  bgp_show_type_flap_address,
  bgp_show_type_flap_prefix,
  bgp_show_type_flap_cidr_only,
  bgp_show_type_flap_regexp,
  bgp_show_type_flap_filter_list,
  bgp_show_type_flap_prefix_list,
  bgp_show_type_flap_prefix_longer,
  bgp_show_type_flap_route_map,
  bgp_show_type_flap_neighbor,
  bgp_show_type_damped_paths,
  bgp_show_type_damp_neighbor
};

static int
bgp_show_table (vty vty, bgp_rib rib, in_addr_t router_id,
                                      enum bgp_show_type type, void *output_arg)
{
  vector         rv ;
  vector_index_t i ;
  bool   header ;
  urlong output_count;

  /* This is first entry point, so reset total line.
   */
  output_count = 0 ;
  header       = false ;

  /* Start processing of routes.
   */
  rv = bgp_rib_extract(rib, NULL) ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;
      prefix       pfx ;

      bool display ;

      display = true ;

      rn  = vector_get_item(rv, i) ;
      pfx = prefix_id_get_prefix(rn->pfx_id) ;

      for (ri = ddl_head(rn->routes) ; ri != NULL ;
                                       ri = ddl_next(ri, route_list))
        {
          if ( (type == bgp_show_type_flap_statistics)    ||
               (type == bgp_show_type_flap_address)       ||
               (type == bgp_show_type_flap_prefix)        ||
               (type == bgp_show_type_flap_cidr_only)     ||
               (type == bgp_show_type_flap_regexp)        ||
               (type == bgp_show_type_flap_filter_list)   ||
               (type == bgp_show_type_flap_prefix_list)   ||
               (type == bgp_show_type_flap_prefix_longer) ||
               (type == bgp_show_type_flap_route_map)     ||
               (type == bgp_show_type_flap_neighbor)      ||
               (type == bgp_show_type_damped_paths)      ||
               (type == bgp_show_type_damp_neighbor) )
            {
              if (!(ri->extra && ri->extra->damp_info))
                continue;
            }
          if (type == bgp_show_type_regexp
              || type == bgp_show_type_flap_regexp)
            {
              regex_t *regex = output_arg;

              if (bgp_regexec_asp (regex, ri->attr->asp) == REG_NOMATCH)
                continue;
            }
          if (type == bgp_show_type_prefix_list
              || type == bgp_show_type_flap_prefix_list)
            {
              struct prefix_list *plist = output_arg;

              if (prefix_list_apply (plist, pfx) != PREFIX_PERMIT)
                continue;
            }
          if ( (type == bgp_show_type_filter_list)  ||
               (type == bgp_show_type_flap_filter_list) )
            {
              struct as_list *as_list = output_arg;

              if (as_list_apply (as_list, ri->attr->asp) != AS_FILTER_PERMIT)
                continue;
            }
          if ( (type == bgp_show_type_route_map) ||
               (type == bgp_show_type_flap_route_map) )
            {
              bgp_route_map_t  brm[1] ;
              attr_pair_t      attrs[1] ;
              route_map_result_t ret;

              bgp_attr_pair_load(attrs, ri->attr) ;

              brm->peer      = ri->prib->peer ;
              brm->attrs     = attrs ;
              brm->qafx      = ri->qafx ;
              brm->rmap_type = BGP_RMAP_TYPE_NONE ;

              ret = route_map_apply((route_map)output_arg, pfx,
                                                  RMAP_BGP | RMAP_NO_SET, brm) ;
              bgp_attr_pair_unload(attrs) ;

              if (ret == RMAP_DENY_MATCH)
                continue ;
            }
          if ( (type == bgp_show_type_neighbor)      ||
               (type == bgp_show_type_flap_neighbor) ||
               (type == bgp_show_type_damp_neighbor) )
            {
              sockunion su = ri->prib->peer->su_remote ;

              if ((su == NULL) || ! sockunion_same(su, (sockunion)output_arg))
                continue;
            }
          if ( (type == bgp_show_type_cidr_only)     ||
               (type == bgp_show_type_flap_cidr_only) )
            {
              u_int32_t destination;

              destination = ntohl (rn->p.u.prefix4.s_addr);
              if (IN_CLASSC (destination) && rn->p.prefixlen == 24)
                continue;
              if (IN_CLASSB (destination) && rn->p.prefixlen == 16)
                continue;
              if (IN_CLASSA (destination) && rn->p.prefixlen == 8)
                continue;
            }
          if ( (type == bgp_show_type_prefix_longer) ||
               (type == bgp_show_type_flap_prefix_longer) )
            {
              if (! prefix_match ((prefix)output_arg, pfx))
                continue;
            }
          if (type == bgp_show_type_community_all)
            {
              if (! ri->attr->community)
                continue;
            }
          if (type == bgp_show_type_community)
            {
              if ((ri->attr->community == NULL) ||
                  ! attr_community_match(ri->attr->community,
                                                  (attr_community)output_arg))
                continue;
            }
          if (type == bgp_show_type_community_exact)
            {
              if ((ri->attr->community == NULL) ||
                  ! attr_community_equal(ri->attr->community,
                                                  (attr_community)output_arg))
                continue ;
            }
          if (type == bgp_show_type_community_list)
            {
              struct community_list *list = output_arg;

              if (! community_list_match (ri->attr->community, list))
                continue;
            }
          if (type == bgp_show_type_community_list_exact)
            {
              struct community_list *list = output_arg;

              if (! community_list_exact_match (ri->attr->community, list))
                continue;
            }
          if ( (type == bgp_show_type_flap_address) ||
               (type == bgp_show_type_flap_prefix) )
            {
              struct prefix *p = output_arg;

              if (! prefix_match (pfx, p))
                continue;

              if (type == bgp_show_type_flap_prefix)
                if (p->prefixlen != pfx->prefixlen)
                  continue;
            }
          if ( (type == bgp_show_type_damped_paths) ||
               (type == bgp_show_type_damp_neighbor) )
            {
              if (! (ri->flags & BGP_INFO_DAMPED) ||
                    (ri->flags & BGP_INFO_HISTORY) )
                continue;
            }

          /* If we get this far, then we want to output the route.
           */
          if (header)
            {
              vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                               siptoa(AF_INET, &router_id).str, VTY_NEWLINE);
              vty_out (vty, BGP_SHOW_SCODE_HEADER);
              vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");

              if (   (type == bgp_show_type_damped_paths)
                  || (type == bgp_show_type_damp_neighbor) )
                vty_out (vty, BGP_SHOW_DAMP_HEADER);
              else if (   (type == bgp_show_type_flap_statistics)
                       || (type == bgp_show_type_flap_address)
                       || (type == bgp_show_type_flap_prefix)
                       || (type == bgp_show_type_flap_cidr_only)
                       || (type == bgp_show_type_flap_regexp)
                       || (type == bgp_show_type_flap_filter_list)
                       || (type == bgp_show_type_flap_prefix_list)
                       || (type == bgp_show_type_flap_prefix_longer)
                       || (type == bgp_show_type_flap_route_map)
                       || (type == bgp_show_type_flap_neighbor) )
                vty_out (vty, BGP_SHOW_FLAP_HEADER);
              else
                vty_out (vty, BGP_SHOW_HEADER);

              header = false ;
            }

          if ( (type == bgp_show_type_damped_paths) ||
               (type == bgp_show_type_damp_neighbor) )
            damp_route_vty_out (vty, pfx, ri, display);
          else if ((type == bgp_show_type_flap_statistics)    ||
                   (type == bgp_show_type_flap_address)       ||
                   (type == bgp_show_type_flap_prefix)        ||
                   (type == bgp_show_type_flap_cidr_only)     ||
                   (type == bgp_show_type_flap_regexp)        ||
                   (type == bgp_show_type_flap_filter_list)   ||
                   (type == bgp_show_type_flap_prefix_list)   ||
                   (type == bgp_show_type_flap_prefix_longer) ||
                   (type == bgp_show_type_flap_route_map)     ||
                   (type == bgp_show_type_flap_neighbor) )
            flap_route_vty_out (vty, pfx, ri, display);
          else
            route_vty_out (vty, pfx, ri, display);

          if (display)
            {
              output_count++;
              display = false ;
            } ;
        } ;
    } ;

  /* No route is displayed */
  if (output_count == 0)
    {
      if (type == bgp_show_type_normal)
        vty_out (vty, "No BGP network exists%s", VTY_NEWLINE);
    }
  else
    vty_out (vty, "\nTotal number of prefixes %" fRL "u\n", output_count);

  return CMD_SUCCESS;
}

static int
bgp_show (struct vty *vty, struct bgp *bgp, qafx_t qafx,
                                      enum bgp_show_type type, void *output_arg)
{
  struct bgp_table *table;

  if (bgp == NULL) {
    bgp = bgp_get_default ();
  }

  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = bgp->rib[qafx][rib_main];

  return bgp_show_table (vty, table, &bgp->router_id, type, output_arg);
}


/*==============================================================================
 * Showing entire RIB for given address family
 */

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, qafx_ipv4_unicast, bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show ip bgp ipv4 (unicast|multicast)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show (vty, NULL, qafx, bgp_show_type_normal, NULL);
}

ALIAS (show_ip_bgp_ipv4,
       show_bgp_ipv4_safi_cmd,
       "show bgp ipv4 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")

DEFUN (show_ip_bgp_view,
       show_ip_bgp_view_cmd,
       "show ip bgp view WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n")
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, qafx_ipv4_unicast, bgp_show_type_normal, NULL);
}

#ifdef HAVE_IPV6

DEFUN (show_bgp,
       show_bgp_cmd,
       "show bgp",
       SHOW_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, qafx_ipv6_unicast, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp,
       show_bgp_ipv6_cmd,
       "show bgp ipv6",
       SHOW_STR
       BGP_STR
       "Address family\n")

DEFUN (show_bgp_ipv6_safi,
       show_bgp_ipv6_safi_cmd,
       "show bgp ipv6 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show (vty, NULL, qafx, bgp_show_type_normal, NULL);
}

/* old command */
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, qafx_ipv6_unicast, bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_view,
       show_bgp_view_cmd,
       "show bgp view WORD",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n")
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }

  return bgp_show (vty, bgp, qafx_ipv6_unicast, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view,
       show_bgp_view_ipv6_cmd,
       "show bgp view WORD ipv6",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n")

/* old command */
DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp",
       SHOW_STR
       IP_STR
       MBGP_STR)
{
  return bgp_show (vty, NULL, qafx_ipv6_multicast, bgp_show_type_normal, NULL);
}

#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_rsclient,
       show_ip_bgp_view_rsclient_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;
  peer_rib   prib ;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  prib = peer_family_prib(peer, qafx_ipv4_unicast) ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! (prib->af_flags & PEER_AFF_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->prib[qafx_ipv4_unicast];

  return bgp_show_table (vty, table, peer->remote_id, bgp_show_type_normal, NULL);
}

ALIAS (show_ip_bgp_view_rsclient,
       show_ip_bgp_rsclient_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_view_ipv4_safi_rsclient_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                                 "rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table ;
  struct peer *peer ;
  const char* um_arg ;
  qafx_t  qafx ;
  peer_rib prib ;

  if (argc == 3)
    {
      peer = peer_lookup_in_view (vty, argv[0], argv[2]);
      um_arg = argv[1] ;
    }
  else
    {
      peer = peer_lookup_in_view (vty, NULL, argv[1]);
      um_arg = argv[0] ;
    }

  if (peer == NULL)
    return CMD_WARNING;

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
   {
      vty_out (vty, "%% Activate the neighbor for the address family first\n");
      return CMD_WARNING;
    }

  if ( ! (prib->af_flags & PEER_AFF_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->prib[qafx];

  return bgp_show_table (vty, table, peer->remote_id, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_ipv4_safi_rsclient_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

/*==============================================================================
 * Showing all entries in table where route has AS Path which matches the given
 * regex.
 */
static int
bgp_show_regexp (struct vty *vty, int argc, argv_t argv, qafx_t qafx,
                                                       enum bgp_show_type type)
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;
  regex_t *regex;
  int rc;

  first = 0;
  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
        {
          if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
            continue;
          first = 1;
        }

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  regex = bgp_regcomp (regstr);
  XFREE(MTYPE_TMP, regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", argv[0],
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  rc = bgp_show (vty, NULL, qafx, type, regex);
  bgp_regex_free (regex);
  return rc;
}

DEFUN (show_ip_bgp_regexp,
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv4_unicast,
                          bgp_show_type_regexp);
}

DEFUN (show_ip_bgp_flap_regexp,
       show_ip_bgp_flap_regexp_cmd,
       "show ip bgp flap-statistics regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv4_unicast,
                          bgp_show_type_flap_regexp);
}

DEFUN (show_ip_bgp_ipv4_regexp,
       show_ip_bgp_ipv4_regexp_cmd,
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_regexp (vty, argc, argv, qafx, bgp_show_type_regexp);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_regexp,
       show_bgp_regexp_cmd,
       "show bgp regexp .LINE",
       SHOW_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_unicast,
                          bgp_show_type_regexp);
}

ALIAS (show_bgp_regexp,
       show_bgp_ipv6_regexp_cmd,
       "show bgp ipv6 regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

/* old command */
DEFUN (show_ipv6_bgp_regexp,
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_unicast,
                          bgp_show_type_regexp);
}

/* old command */
DEFUN (show_ipv6_mbgp_regexp,
       show_ipv6_mbgp_regexp_cmd,
       "show ipv6 mbgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_multicast,
                          bgp_show_type_regexp);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given prefix list.
 */
static int
bgp_show_prefix_list (struct vty *vty, const char *prefix_list_str, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (get_qAFI(qafx), prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, qafx, type, plist);
}

DEFUN (show_ip_bgp_prefix_list,
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_prefix_list);
}

DEFUN (show_ip_bgp_flap_prefix_list,
       show_ip_bgp_flap_prefix_list_cmd,
       "show ip bgp flap-statistics prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_flap_prefix_list);
}

DEFUN (show_ip_bgp_ipv4_prefix_list,
       show_ip_bgp_ipv4_prefix_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_prefix_list (vty, argv[1], qafx, bgp_show_type_prefix_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_list,
       show_bgp_prefix_list_cmd,
       "show bgp prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_prefix_list);
}

ALIAS (show_bgp_prefix_list,
       show_bgp_ipv6_prefix_list_cmd,
       "show bgp ipv6 prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_list,
       show_ipv6_bgp_prefix_list_cmd,
       "show ipv6 bgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_prefix_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_list,
       show_ipv6_mbgp_prefix_list_cmd,
       "show ipv6 mbgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_multicast,
                               bgp_show_type_prefix_list);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given filter list.
 */
static int
bgp_show_filter_list (struct vty *vty, const char *filter, qafx_t qafx,
                                                       enum bgp_show_type type)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name\n", filter);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, qafx, type, as_list);
}

DEFUN (show_ip_bgp_filter_list,
       show_ip_bgp_filter_list_cmd,
       "show ip bgp filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_flap_filter_list,
       show_ip_bgp_flap_filter_list_cmd,
       "show ip bgp flap-statistics filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_flap_filter_list);
}

DEFUN (show_ip_bgp_ipv4_filter_list,
       show_ip_bgp_ipv4_filter_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_filter_list (vty, argv[1], qafx, bgp_show_type_filter_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_filter_list,
       show_bgp_filter_list_cmd,
       "show bgp filter-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_filter_list);
}

ALIAS (show_bgp_filter_list,
       show_bgp_ipv6_filter_list_cmd,
       "show bgp ipv6 filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

/* old command */
DEFUN (show_ipv6_bgp_filter_list,
       show_ipv6_bgp_filter_list_cmd,
       "show ipv6 bgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_filter_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_filter_list,
       show_ipv6_mbgp_filter_list_cmd,
       "show ipv6 mbgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_multicast,
                               bgp_show_type_filter_list);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given route-map.
 */
static int
bgp_show_route_map (struct vty *vty, const char *rmap_str, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  struct route_map *rmap;

  rmap = route_map_lookup (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name%s",
               rmap_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, qafx, type, rmap);
}

DEFUN (show_ip_bgp_route_map,
       show_ip_bgp_route_map_cmd,
       "show ip bgp route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv4_unicast,
                             bgp_show_type_route_map);
}

DEFUN (show_ip_bgp_flap_route_map,
       show_ip_bgp_flap_route_map_cmd,
       "show ip bgp flap-statistics route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv4_unicast,
                             bgp_show_type_flap_route_map);
}

DEFUN (show_ip_bgp_ipv4_route_map,
       show_ip_bgp_ipv4_route_map_cmd,
       "show ip bgp ipv4 (unicast|multicast) route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route_map (vty, argv[1], qafx, bgp_show_type_route_map);
}

DEFUN (show_bgp_route_map,
       show_bgp_route_map_cmd,
       "show bgp route-map WORD",
       SHOW_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv6_unicast,
                                                       bgp_show_type_route_map);
}

ALIAS (show_bgp_route_map,
       show_bgp_ipv6_route_map_cmd,
       "show bgp ipv6 route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

/*==============================================================================
 * Showing all entries in table where routes are "cidr-only".
 */
DEFUN (show_ip_bgp_cidr_only,
       show_ip_bgp_cidr_only_cmd,
       "show ip bgp cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show (vty, NULL, qafx_ipv4_unicast,
                                                 bgp_show_type_cidr_only, NULL);
}

DEFUN (show_ip_bgp_flap_cidr_only,
       show_ip_bgp_flap_cidr_only_cmd,
       "show ip bgp flap-statistics cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")
{
  return bgp_show (vty, NULL, qafx_ipv4_unicast,
                                           bgp_show_type_flap_cidr_only, NULL);
}

DEFUN (show_ip_bgp_ipv4_cidr_only,
       show_ip_bgp_ipv4_cidr_only_cmd,
       "show ip bgp ipv4 (unicast|multicast) cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show (vty, NULL, qafx, bgp_show_type_cidr_only, NULL);
}

/*==============================================================================
 * Showing all entries in table where route matches the given community.
 */
DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, qafx_ipv4_unicast,
                     bgp_show_type_community_all, NULL);
}

DEFUN (show_ip_bgp_ipv4_community_all,
       show_ip_bgp_ipv4_community_all_cmd,
       "show ip bgp ipv4 (unicast|multicast) community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show (vty, NULL, qafx, bgp_show_type_community_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_all,
       show_bgp_community_all_cmd,
       "show bgp community",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, qafx_ipv6_unicast,
                                            bgp_show_type_community_all, NULL);
}

ALIAS (show_bgp_community_all,
       show_bgp_ipv6_community_all_cmd,
       "show bgp ipv6 community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_all,
       show_ipv6_bgp_community_all_cmd,
       "show ipv6 bgp community",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, qafx_ipv6_unicast,
                   bgp_show_type_community_all, NULL);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_all,
       show_ipv6_mbgp_community_all_cmd,
       "show ipv6 mbgp community",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, qafx_ipv6_multicast,
                   bgp_show_type_community_all, NULL);
}
#endif /* HAVE_IPV6 */

static cmd_ret_t
bgp_show_community (struct vty *vty, const char *view_name,
                                            uint argf, uint argc, argv_t argv,
                                                        bool exact, qafx_t qafx)
{
  cmd_ret_t ret ;
  attr_community comm ;
  struct bgp *bgp ;
  char *str ;
  attr_community_type_t act ;

  /* BGP structure lookup */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  str = argv_concat(argv, argf, argc) ;
  comm = attr_community_from_str (str, &act);

  if (act == act_simple)
    {
      ret = bgp_show (vty, bgp, qafx, (exact ? bgp_show_type_community_exact
                                             : bgp_show_type_community), comm);
    }
  else
    {
      vty_out (vty, "%% Community malformed\n");
      ret = CMD_WARNING;
    } ;

  attr_community_free(comm);
  XFREE (MTYPE_TMP, str);

  return ret ;
}

DEFUN (show_ip_bgp_community,
       show_ip_bgp_community_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv, false /* not exact */,
                                                            qafx_ipv4_unicast) ;
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community3_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community4_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community (vty, NULL, 1, argc, argv, false /* not exact */,
                                                                          qafx);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community3_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community4_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes containing communities\n")
#else
DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes containing communities\n")
#endif
{
  struct bgp *bgp;
  qafx_t qafx ;
  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

#ifdef HAVE_IPV6
  if (strncmp (argv[1], "ipv6", 4) == 0)
    qafx = (argv[2][0] == 'm') ? qafx_ipv6_multicast
                               : qafx_ipv6_unicast ;
  else
    qafx = (argv[2][0] == 'm') ? qafx_ipv4_multicast
                               : qafx_ipv4_unicast ;
#else
  qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;
#endif

  return bgp_show (vty, bgp, qafx, bgp_show_type_community_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif
{
  qafx_t qafx ;
  uint   argf ;

#ifdef HAVE_IPV6
  if (strncmp (argv[1], "ipv6", 4) == 0)
    qafx = (argv[2][0] == 'm') ? qafx_ipv6_multicast
                               : qafx_ipv6_unicast ;
  else
    qafx = (argv[2][0] == 'm') ? qafx_ipv4_multicast
                               : qafx_ipv4_unicast ;
  argf = 3 ;
#else
  qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;
  argf = 2 ;
#endif

  return bgp_show_community (vty, argv[0], argf, argc, argv,
                                                   false /* not exact */, qafx);
}

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                  "(AA:NN|local-AS|no-advertise|no-export) "
                                  "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n") ;
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n") ;
#endif

DEFUN (show_ip_bgp_community_exact,
       show_ip_bgp_community_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv4_unicast);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community3_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community4_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community (vty, NULL, 1, argc, argv, true /* exact */, qafx);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community3_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community4_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

#ifdef HAVE_IPV6
DEFUN (show_bgp_community,
       show_bgp_community_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                      false /* not exact */, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community,
       show_bgp_ipv6_community_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community2_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community2_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community3_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community3_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community4_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community4_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_bgp_community,
       show_ipv6_bgp_community_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                      false /* not exact */, qafx_ipv6_unicast);
}

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community3_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community4_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_community_exact,
       show_bgp_community_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community2_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community2_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community3_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community3_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community4_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community4_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv6_unicast);
}

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community3_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community4_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                    false /* not exact */, qafx_ipv6_multicast);
}

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community3_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community4_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                        true /* exact */, qafx_ipv6_multicast);
}

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community3_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community4_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given community-list.
 */
static int
bgp_show_community_list (struct vty *vty, const char *com, bool exact,
                                                                   qafx_t qafx)
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, COMMUNITY_LIST, com);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, qafx, exact ? bgp_show_type_community_list_exact
                                          : bgp_show_type_community_list, list);
}

DEFUN (show_ip_bgp_community_list,
       show_ip_bgp_community_list_cmd,
       "show ip bgp community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_community_list,
       show_ip_bgp_ipv4_community_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community_list (vty, argv[1], 0, qafx);
}

DEFUN (show_ip_bgp_community_list_exact,
       show_ip_bgp_community_list_exact_cmd,
       "show ip bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) "
                                                                 "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community_list (vty, argv[1], true /* exact */, qafx);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_list,
       show_bgp_ipv6_community_list_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list,
       show_ipv6_bgp_community_list_cmd,
       "show ipv6 bgp community-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list,
       show_ipv6_mbgp_community_list_cmd,
       "show ipv6 mbgp community-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_multicast);
}

DEFUN (show_bgp_community_list_exact,
       show_bgp_community_list_exact_cmd,
       "show bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_list_exact,
       show_bgp_ipv6_community_list_exact_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list_exact,
       show_ipv6_bgp_community_list_exact_cmd,
       "show ipv6 bgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list_exact,
       show_ipv6_mbgp_community_list_exact_cmd,
       "show ipv6 mbgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_multicast);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table for route and any more specifics.
 */
static int
bgp_show_prefix_longer (struct vty *vty, const char *prefix, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  int ret;
  struct prefix *p;

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show (vty, NULL, qafx, type, p);
  prefix_free(p);
  return ret;
}

DEFUN (show_ip_bgp_prefix_longer,
       show_ip_bgp_prefix_longer_cmd,
       "show ip bgp A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_prefix_longer,
       show_ip_bgp_flap_prefix_longer_cmd,
       "show ip bgp flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_flap_prefix_longer);
}

DEFUN (show_ip_bgp_ipv4_prefix_longer,
       show_ip_bgp_ipv4_prefix_longer_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_prefix_longer (vty, argv[1], qafx,
                                                   bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_address,
       show_ip_bgp_flap_address_cmd,
       "show ip bgp flap-statistics A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                                    bgp_show_type_flap_address);
}

DEFUN (show_ip_bgp_flap_prefix,
       show_ip_bgp_flap_prefix_cmd,
       "show ip bgp flap-statistics A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_flap_prefix);
}
#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_longer,
       show_bgp_prefix_longer_cmd,
       "show bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_unicast,
                                 bgp_show_type_prefix_longer);
}

ALIAS (show_bgp_prefix_longer,
       show_bgp_ipv6_prefix_longer_cmd,
       "show bgp ipv6 X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_longer,
       show_ipv6_bgp_prefix_longer_cmd,
       "show ipv6 bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_unicast,
                                 bgp_show_type_prefix_longer);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_longer,
       show_ipv6_mbgp_prefix_longer_cmd,
       "show ipv6 mbgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_multicast,
                                 bgp_show_type_prefix_longer);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Display routes for given prefix/address.
 *
 */
static void bgp_show_route_header (vty vty, bgp_rib rib, bgp_rib_node rn,
             prefix_id_entry pie, vector rv, route_info ris, bgp_peer client) ;

static void bgp_show_route_detail (vty vty, bgp_rib rib,
                          prefix_id_entry pie, route_info ri, route_info ris) ;


#if 0


static int
bgp_show_route_in_table (vty vty, bgp_inst bgp, bgp_rib rib,
                         const char *ip_str,
                         qafx_t qafx, struct prefix_rd *prd,
                         bool prefix_check)
{
  bgp_inst       bgp ;
  vector         rv ;
  vector_index_t i, l ;
  bool header ;

  prefix_t  match;

  int ret;
  int header;
  int display = 0;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_table *table;

  /* Check IP address argument.
   */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (qafx_is_mpls_vpn(qafx))
    {
      for (rn = bgp_table_top (rib); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            {
              header = 1;

              if ((rm = bgp_node_match (table, &match)) != NULL)
                {
                  if (prefix_check && rm->p.prefixlen == match.prefixlen)
                    {
                      for (ri = rm->info; ri; ri = ri->info.next)
                        {
                          if (header)
                            {
                              bgp_show_route_header (vty, bgp, rm,
                                                  (struct prefix_rd *)&rn->p,
                                                                         qafx);

                              header = 0;
                            }
                          display++;
                          bgp_show_route_detail (vty, bgp, &rm->p, ri, qafx);
                        }
                    }

                  bgp_unlock_node (rm);
                }
            }
        }
    }
  else
    {
      header = 1;

      if ((rn = bgp_node_match (rib, &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              for (ri = rn->info; ri; ri = ri->info.next)
                {
                  if (header)
                    {
                      bgp_show_route_header (vty, bgp, rn, NULL, qafx);
                      header = 0;
                    }
                  display++;
                  bgp_show_route_detail (vty, bgp, &rn->p, ri, qafx);
                }
            }

          bgp_unlock_node (rn);
        }
    }

  if (! display)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}
#endif

/*------------------------------------------------------------------------------
 * Display routes for given prefix/address.
 *
 *   1) prefix/address is:
 *
 *       a) prefix -- which requires an exact match
 *
 *          Except for (2b), this is a straight look-up.
 *
 *       b) address -- which requires longest prefix match
 *
 *          Except for (2b), this is a repeated look-up, for reducing prefix
 *          length -- looking for prefix with at least one route.
 *
 *   2) for MPLS prefix/address:
 *
 *       a) with the given Route Discriminator
 *
 *          Which can be done by direct lookup as in (1).
 *
 *       b) for all Route Discriminators
 *
 *          Which requires a scan of the RIB to extract all routes which match
 *          the required route.  With (1b) the scan needs to generate a list
 *          of matches, in descending prefix length order.
 *
 *   3) from given RIB:
 *
 *       a) Main RIB -- which requires the routes after 'in' filtering.
 *
 *          So can simply lookup in the Main RIB.
 *
 *       b) RS RIB, for the given RS Client -- which requires the routes
 *          after 'rs-in' and 'export' and 'import' filtering.
 *
 *          Can lookup in the RS RIB, but must then run the filters to
 *          get the available routes for the given Client.
 *
 *          For (1b) it is possible that the longest prefix has no available
 *          routes after the filtering.
 *
 * Requires: view_name:    name of BGP instance -- NULL => "default"
 *           client_str:   NULL => Main RIB, otherwise "name" of RS Client
 *           qafx:         what sort of address/prefix
 *           ip_str:       address/prefix in question
 *           prefix:       true <=> ip_str is prefix, false <=> is address
 *           prd:          if MPLS qafx: NULL => all RD, otherwise RD.
 */
static cmd_ret_t
bgp_show_route (vty vty, const char* view_name, const char* client_str,
                           qafx_t qafx, const char *ip_str, bool prefix,
                                                             const char* rd_str)
{
  bgp_inst    bgp ;
  bgp_rib     rib ;
  bgp_peer    client ;
  prefix_t    pfx[1] ;
  prefix_rd_t prd[1] ;
  bool        is_mpls ;
  vector      rdv, rv ;
  vector_index_t  i ;

  /* BGP structure lookup.
   */
  bgp = bgp_lookup_vty(vty, view_name) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  /* Peer Lookup -- if any -- implies rib_rs if have client
   */
  if (client_str == NULL)
    {
      client = NULL ;
      rib = bgp->rib[qafx][rib_main] ;
    }
  else
    {
      client = peer_lookup_vty (vty, bgp, client_str, qafx) ;
      if (client == NULL)
        return CMD_WARNING;

      if ( ! (client->prib[qafx]->af_flags & PEER_AFF_RSERVER_CLIENT))
        {
          vty_out (vty, "%% Neighbor is not a Route-Server client\n") ;
          return CMD_WARNING;
        } ;

      rib = bgp->rib[qafx][rib_rs] ;
    } ;

  /* Worry about no RIB for given qafx
   */
  if (rib == NULL)
    {
      vty_out (vty, "%% No RIB for address family\n") ;
      return CMD_WARNING;
    } ;

  /* Convert rd_str (if any) to prefix_rd.
   *
   * NB: expect that for non-mpls qafx that no rd_str will be presented, but
   *     if one is presented, it will be checked.
   */
  if (rd_str != NULL)
    {
      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING ;
    } ;

  /* Fill in prefix, checking the IP address/prefix argument.
   */
  if (!str2prefix (ip_str, pfx))
    {
      vty_out (vty, "%% address is malformed\n") ;
      return CMD_WARNING;
    }

  /* Worry about the Route Discriminator, if any
   *
   * Constructs the vector rdv:
   *
   *   * if not mpls: contains one entry == NULL <=> no RD
   *
   *   * if mpls and want all RDs:  contains the prefix_rd_id_entry for each RD
   *                                known to exist in the RIB.
   *
   *                                May be empty !
   *
   *   * if mpls and want given RD: contains the prefix_rd_id_entry for the
   *                                given RD, iff it is known to exist in the
   *                                RIB.
   *
   *                                May be empty !
   */
  is_mpls = qafx_is_mpls_vpn(qafx) ;

  if (is_mpls)
    {
      if (rd_str == NULL)
        {
          /* Get list of prefix_rd_id_entry known to this RIB, in RD order.
           */
          rdv = bgp_rib_rd_extract(rib) ;
        }
      else
        {
          /* If the given RD is known to the RIB, get its prefix_rd_id_entry
           * and create one entry list.
           *
           * Otherwise, create an empty list.
           */
          prefix_rd_id_entry rdie ;

          rdie = bgp_rib_rd_seek(rib, prd) ;

          if (rdie == NULL)
            rdv = vector_new(0) ;
          else
            {
              rdv = vector_new(1) ;
              vector_push_item(rdv, rdie) ;
            } ;
        } ;
    }
  else
    {
      rdv = vector_new(1) ;
      vector_push_item(rdv, NULL) ;
    } ;

  /* So, now we run all the Route Discriminators, and for each one, extract
   * a list of available routes, which are sorted into order and then output.
   */
  rv = NULL ;           /* no routes, yet       */

  for (i = 0 ; i < vector_length(rdv) ; ++i)
    {
      prefix_rd_id_entry rdie ;
      prefix_t        find[1] ;
      bgp_rib_node    rn ;
      route_info      ris, ri ;
      prefix_id_entry pie ;
      vector_index_t  j ;

      /* Prepare 'find' to search for the given prefix or for the longest match
       * for the given address.
       *
       * If we have more than one RD, we start the process afresh for each one.
       */
      rdie = vector_get_item(rdv, i) ;

      *find = *pfx ;
      if (rdie != NULL)
        find->rd_id = rdie->id ;
      else
        find->rd_id = prefix_rd_id_null ;

      /* This loops (if not prefix) in order to find longest match which
       * provides at least one route.
       *
       * The RIB can only be looked up for an exact prefix match, for an exact
       * RD.  This is why we arrange to try only the RD which we know are
       * present in the RIB.  To find the longest match for an address, we
       * try the maximum length prefix first, and then reduce to 0 !
       */
      while (1)
        {
          apply_mask(find) ;

          pie = prefix_id_seek_entry(find) ;

          if (pie == NULL)
            {
              rn  = NULL ;
              ris = NULL ;
            }
          else
            {
              rn = ihash_get_item(rib->nodes_table, pie->id, NULL) ;

              if (rn != NULL)
                ris = bgp_pseudo_selection (rn, client->prib[qafx]) ;
              else
                ris = NULL ;
            } ;

          if (prefix || (find->prefixlen == 0))
            break ;

          find->prefixlen -= 1 ;
        } ;

      if (ris == NULL)
        continue ;              /* nothing for this RD (if any) */

      /* We have at least one route for this RD.
       *
       * Collect the routes and sort into...
       */
      rv = vector_re_init(rv, 12) ;

      for (ri = ddl_head(rn->routes) ; ri != NULL ;
                                       ri = ddl_next(ri, route_list))
        {
          if (ri->attr == NULL)
            continue ;          /* withdrawn or filtered        */
          if (ri->flags & RINFO_RS_DENIED)
            continue ;          /* denied by filter             */

          vector_push_item(rv, ri) ;
        } ;

      vector_sort(rv, bgp_show_route_sort) ;

      qassert(vector_length(rv) != 0) ;

      /* Now output the header which describes the prefix, followed by all the
       * available routes.
       */
      bgp_show_route_header (vty, rib, rn, pie, rv, ris, client) ;

      for (j = 0 ; j < vector_length(rv) ; ++j)
        {
          ri = vector_get_item(rv, j) ;

          bgp_show_route_detail (vty, rib, pie, ri, ris) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Header of detailed BGP route information -- one per Route Discriminator
 */
static void
bgp_show_route_header (vty vty, bgp_rib rib, bgp_rib_node rn,
                prefix_id_entry pie, vector rv, route_info ris, bgp_peer client)
{
  peer_rib prib ;
  bool announced ;

  vty_out (vty, "BGP routing table entry for ") ;
  if (qafx_is_mpls_vpn(rib->qafx))
    vty_out (vty, "%s:", srdtoa(prefix_rd_id_get_val(pie->pfx->rd_id)).str) ;
  vty_out(vty, "%s\n", spfxtoa(pie->pfx).str) ;

  vty_out (vty, "Paths: (%u available", vector_length(rv)) ;

  if (ris != NULL)
    {
      vector_index_t i ;
      uint best ;
      bool suppress ;
      attr_community_state_t known ;

      suppress = false ;
      known    = 0 ;
      best     = 0 ;

      best = 0 ;
      for (i = 0 ; i < vector_length(rv) ; ++i)
        {
          if (ris == vector_get_item(rv, i))
            {
              best = i + 1 ;
              break ;
            } ;
        } ;

      if (best == 0)
        ris = NULL ;
      else
        {
          vty_out (vty, ", best #%u", best) ;

          if (qafx_is_unicast(rib->qafx))
            vty_out (vty, ", table Default-IP-Routing-Table");

          known = attr_community_known (ris->attr->community) ;

          if (known & cms_no_advertise)
            vty_out (vty, ", not advertised to any peer");
          else if (known & cms_no_export)
            vty_out (vty, ", not advertised to EBGP peer");
          else if (known & cms_local_as)
            vty_out (vty, ", not advertised outside local AS");

          if (suppress)
            vty_out (vty, ", Advertisements suppressed by an aggregate.");
        } ;
    } ;

  if (ris == NULL)
    vty_out (vty, ", no best path") ;

  vty_out (vty, ")\n");

  /* Advertised to Peer(s) or Client(s)
   */
  announced = false ;

  if (client != NULL)
    prib = client->prib[rib->qafx] ;
  else
    prib = ddl_head(rib->peers) ;       // TODO sort rib->peers !

  while (prib != NULL)
    {
      if (bgp_adj_out_lookup (prib, pie))
        {
          if (! announced)
            {
              vty_out (vty, "  Advertised to non peer-group peers:\n ") ;
              announced = true ;
            } ;

          vty_out (vty, " %s", sutoa(prib->peer->su_name).str);
        } ;

      if (client != NULL)
        break ;

      prib = ddl_next(prib, peers) ;
    } ;

  if (announced)
    vty_out (vty, "\n");
  else
    vty_out (vty, "  Not advertised to any peer\n") ;
} ;

/*------------------------------------------------------------------------------
 * Body of detailed BGP route information -- one per route
 */
static void
bgp_show_route_detail (vty vty, bgp_rib rib,
                            prefix_id_entry pie, route_info ri, route_info ris)
{
  attr_set attr ;
  time_t tbuf ;

  attr = ri->attr ;
  if (attr == NULL)
    return ;

  /* Line1 display AS-path, Aggregator
   */
  route_vty_out_as_path (vty, "  %s", attr->asp, "  Local");

  if (ri->flags & RINFO_REMOVED)
    vty_out (vty, ", (removed)");
  if (ri->flags & RINFO_STALE)
    vty_out (vty, ", (stale)");

  if (attr->aggregator_as != BGP_ASN_NULL)
    vty_out (vty, ", (aggregated by %u %s)", attr->aggregator_as,
                                siptoa(AF_INET, &attr->aggregator_ip).str);

  if (ri->prib->af_flags & PEER_AFF_REFLECTOR_CLIENT)
    vty_out (vty, ", (Received from a RR-client)");

  if (ri->prib->af_flags & PEER_AFF_RSERVER_CLIENT)
    vty_out (vty, ", (Received from a RS-client)");

  if (ri->flags & RINFO_HISTORY)
    vty_out (vty, ", (history entry)");
  else if (ri->flags & RINFO_DAMPED)
    vty_out (vty, ", (suppressed due to damping)");

  vty_out (vty, "\n");

  /* Line2 display Next-hop, Neighbor, Router-id
   */
  if (pie->pfx->family == AF_INET)
    {
      vty_out (vty, "    %s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
    }
#ifdef HAVE_IPV6
  else
    {
       vty_out (vty, "    %s",
             siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
    }
#endif /* HAVE_IPV6 */

  if (ri->prib->peer == rib->bgp->peer_self)
    {
      vty_out (vty, " from %s (%s)",
                        pie->pfx->family == AF_INET ? "0.0.0.0" : "::",
                                     siptoa(AF_INET, &rib->bgp->router_id).str);
    }
  else
    {
      in_addr_t  originator ;

      if (! (ri->flags & RINFO_VALID))
        vty_out (vty, " (inaccessible)");
      else if ((ri->extra != NULL) && (ri->extra->igpmetric))
        vty_out (vty, " (metric %d)", ri->extra->igpmetric);

      if (attr->have & atb_originator_id)
        originator = attr->originator_id ;
      else
        originator = ri->prib->peer->remote_id ;

      vty_out (vty, " from %s (%s)", ri->prib->peer->host,
                                        siptoa(AF_INET, &originator).str) ;
    }
  vty_out (vty, "\n");

#ifdef HAVE_IPV6
  /* display nexthop local */
  if (attr->next_hop.type == nh_ipv6_2)
    {
      vty_out (vty, "    (%s)\n",
             siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_link_local]).str) ;
    }
#endif /* HAVE_IPV6 */

  /* Line 3 display:
   *  Origin, Med, Locpref, Weight, valid, Int/Ext/Local, Atomic, best
   */
  vty_out (vty, "      Origin %s",
                        map_direct(bgp_origin_long_map, attr->origin).str) ;

  if (attr->have & atb_med)
    vty_out (vty, ", metric %u", attr->med);

  if (attr->have & atb_local_pref)
    vty_out (vty, ", localpref %u", attr->local_pref);
  else
    vty_out (vty, ", localpref %u", rib->bgp->default_local_pref);

  if (attr->weight != 0)
    vty_out (vty, ", weight %u", attr->weight);

  if (! (ri->flags & RINFO_HISTORY))
    vty_out (vty, ", valid");

  if (ri->prib->peer != rib->bgp->peer_self)
    {
      const char* sort_str ;

      switch (ri->prib->peer->sort)
      {
        case BGP_PEER_IBGP:
          sort_str = "internal" ;
          break ;

        case BGP_PEER_CBGP:
          sort_str = "confed-external" ;
          break ;

        case BGP_PEER_EBGP:
          sort_str = "external" ;
          break ;

        case BGP_PEER_UNSPECIFIED:
        default:
          sort_str = "*unknown-sort:BUG*" ;
          break ;
      } ;

      vty_out (vty, ", %s", sort_str) ;
    }
  else if (bgp_route_subtype(ri->route_type) == BGP_ROUTE_AGGREGATE)
    vty_out (vty, ", aggregated, local");
  else if (bgp_zebra_route(ri->route_type) != ZEBRA_ROUTE_BGP)
    vty_out (vty, ", sourced");
  else
    vty_out (vty, ", sourced, local");

  if (attr->have & atb_atomic_aggregate)
    vty_out (vty, ", atomic-aggregate");

  if (ri == ris)
    vty_out (vty, ", best");

  vty_out (vty, "\n");

  /* Line 4 display Community
   */
  if (attr->community != NULL)
    vty_out (vty, "      Community: %s\n",
                                     attr_community_str(attr->community)) ;

  /* Line 5 display Extended-community
   */
  if (attr->ecommunity != NULL)
    vty_out (vty, "      Extended Community: %s\n",
                                    attr_ecommunity_str(attr->ecommunity));

  /* Line 6 display Originator, Cluster-id
   */
  if ((attr->have & atb_originator_id) || (attr->cluster != NULL))
    {
      const char* str ;

      vty_out (vty, "      Originator: %s",
                  (attr->have & atb_originator_id)
                             ? siptoa(AF_INET, &attr->originator_id).str
                             : "-none-") ;

      str = attr_cluster_str(attr->cluster) ;

      if (*str != '\0')
        vty_out (vty, ", Cluster list: %s", str);

      vty_out (vty, "\n");
    } ;

  /* Line ? Route Flap damping
   */
  if ((ri->extra != NULL) && (ri->extra->damp_info))
    bgp_damp_info_vty (vty, ri);

  /* Line 7 display Uptime
   */
  tbuf = bgp_wall_clock(ri->uptime);
  vty_out (vty, "      Last update: %s\n", ctime(&tbuf));
} ;

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_ipv4_route,
       show_ip_bgp_ipv4_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_ipv4_route,
       show_bgp_ipv4_safi_route_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_vpnv4_all_route,
       show_ip_bgp_vpnv4_all_route_cmd,
       "show ip bgp vpnv4 all A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_vpnv4_rd_route,
       show_ip_bgp_vpnv4_rd_route_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             argv[0]) ;         /* Route Disc.          */
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_ipv4_prefix,
       show_ip_bgp_ipv4_prefix_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_ipv4_prefix,
       show_bgp_ipv4_safi_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_ip_bgp_vpnv4_all_prefix,
       show_ip_bgp_vpnv4_all_prefix_cmd,
       "show ip bgp vpnv4 all A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_vpnv4_rd_prefix,
       show_ip_bgp_vpnv4_rd_prefix_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             argv[0]) ;         /* Route Disc.          */
}

DEFUN (show_ip_bgp_view_route,
       show_ip_bgp_view_route_cmd,
       "show ip bgp view WORD A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_view_prefix,
       show_ip_bgp_view_prefix_cmd,
       "show ip bgp view WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

#ifdef HAVE_IPV6

DEFUN (show_bgp_route,
       show_bgp_route_cmd,
       "show bgp X:X::X:X",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_route,
       show_bgp_ipv6_route_cmd,
       "show bgp ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_ipv6_safi_route,
       show_bgp_ipv6_safi_route_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_bgp_route,
       show_ipv6_bgp_route_cmd,
       "show ipv6 bgp X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_bgp_prefix,
       show_bgp_prefix_cmd,
       "show bgp X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_prefix,
       show_bgp_ipv6_prefix_cmd,
       "show bgp ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n")

DEFUN (show_bgp_ipv6_safi_prefix,
       show_bgp_ipv6_safi_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_bgp_prefix,
       show_ipv6_bgp_prefix_cmd,
       "show ipv6 bgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_bgp_view_route,
       show_bgp_view_route_cmd,
       "show bgp view WORD X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_route,
       show_bgp_view_ipv6_route_cmd,
       "show bgp view WORD ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_prefix,
       show_bgp_view_prefix_cmd,
       "show bgp view WORD X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_prefix,
       show_bgp_view_ipv6_prefix_cmd,
       "show bgp view WORD ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "IPv6 prefix <network>/<length>\n")

/* old command */
DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_multicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix,
       show_ipv6_mbgp_prefix_cmd,
       "show ipv6 mbgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_multicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_view_rsclient_route_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  const char* view_name, * client_str, * ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv4_unicast,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_rsclient_route_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_view_ipv4_safi_rsclient_route_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                          "rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  const char* view_name, * um_arg, * client_str, * ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_ipv4_safi_rsclient_route_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_view_rsclient_prefix_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  const char* view_name, * client_str, * ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv4_unicast,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_rsclient_prefix_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_view_ipv4_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  const char* view_name, * um_arg, * client_str, * ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_ipv4_safi_rsclient_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) "
                                        "rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

#ifdef HAVE_IPV6

DEFUN (show_bgp_view_rsclient_route,
       show_bgp_view_rsclient_route_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  const char* view_name, * client_str, * ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv6_unicast,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_rsclient_route,
       show_bgp_rsclient_route_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_view_ipv6_safi_rsclient_route_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) "
                                         "rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  const char* view_name, * um_arg, * client_str, * ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_ipv6_safi_rsclient_route_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_rsclient_prefix,
       show_bgp_view_rsclient_prefix_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  const char* view_name, * client_str, * ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv6_unicast,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_rsclient_prefix,
       show_bgp_rsclient_prefix_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_view_ipv6_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  const char* view_name, * um_arg, * client_str, * ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_ipv6_safi_rsclient_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")

#endif /* HAVE_IPV6 */

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 *
 */
static void
show_adj_route (struct vty *vty, struct peer *peer, qafx_t qafx, bool in)
{
  bgp_table   table;
  peer_rib    prib ;
  bgp_node    rn;
  urlong      output_count;
  int header1 = 1;
  struct bgp *bgp;
  int header2 = 1;

  bgp = peer->bgp;

  if (! bgp)
    return;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return ;

  table = bgp->rib[qafx][rib_main];

  output_count = 0;

  if (! in && prib->af_status & PEER_STATUS_DEFAULT_ORIGINATE)
    {
      vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                             siptoa(AF_INET, &bgp->router_id).str, VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_SCODE_HEADER);
      vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");

      vty_out (vty, "Originating default network 0.0.0.0%s%s",
               VTY_NEWLINE, VTY_NEWLINE);
      header1 = 0;
    }

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (in)
      {
        bgp_adj_in  ai;

        for (ai = rn->adj_in; ai; ai = ai->adj.next)
          if (ai->peer == peer)
            {
              if (header1)
                {
                  vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                            siptoa(AF_INET, &bgp->router_id).str, VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_SCODE_HEADER);
                  vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");
                  header1 = 0;
                }
              if (header2)
                {
                  vty_out (vty, BGP_SHOW_HEADER);
                  header2 = 0;
                }
              if (ai->attr)
                {
                  route_vty_out_tmp (vty, &rn->p, ai->attr, rn->qafx);
                  output_count++;
                }
            }
      }
    else
      {
        bgp_adj_out ao;

        for (ao = rn->adj_out; ao; ao = ao->adj.next)
          if (ao->peer == peer)
            {
              if (header1)
                {
                  vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                            siptoa(AF_INET, &bgp->router_id).str, VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_SCODE_HEADER);
                  vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");
                  header1 = 0;
                }
              if (header2)
                {
                  vty_out (vty, BGP_SHOW_HEADER);
                  header2 = 0;
                }
              if (ao->attr_sent)
                {
                  route_vty_out_tmp (vty, &rn->p, ao->attr_sent, rn->qafx);
                  output_count++;
                }
            }
      }

  if (output_count != 0)
    vty_out (vty, "\nTotal number of prefixes %"fRL"u\n", output_count);
}

static int
peer_adj_routes (struct vty *vty, struct peer *peer, qafx_t qafx, int in)
{
  peer_rib prib ;

  if (peer != NULL)
    prib = peer_family_prib(peer, qafx) ;
  else
    prib = NULL ;

  if (prib == NULL)
    {
      vty_out (vty, "%% No such neighbor or address family\n");
      return CMD_WARNING;
    }

  if (in && ! (prib->af_flags & PEER_AFF_SOFT_RECONFIG))
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled\n");
      return CMD_WARNING;
    }

  show_adj_route (vty, peer, qafx, in);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_view_neighbor_advertised_route_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv4_unicast, 0);
}

ALIAS (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_neighbor_advertised_route_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_advertised_route,
       show_ip_bgp_ipv4_neighbor_advertised_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;
  qafx_t qafx ;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return peer_adj_routes (vty, peer, qafx, 0);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_neighbor_advertised_route_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv6_unicast, 0);
}

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_ipv6_neighbor_advertised_route_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_bgp_view_neighbor_received_routes,
       show_bgp_view_neighbor_received_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv6_unicast, 1);
}

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_view_ipv6_neighbor_received_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_neighbor_advertised_route_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_ipv6_neighbor_advertised_route_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_advertised_route,
       ipv6_bgp_neighbor_advertised_route_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_advertised_route,
       ipv6_mbgp_neighbor_advertised_route_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv6_multicast, 0);
}
#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_view_neighbor_received_routes_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv4_unicast, 1);
}

ALIAS (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_neighbor_received_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_received_routes,
       show_ip_bgp_ipv4_neighbor_received_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;
  qafx_t qafx ;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return peer_adj_routes (vty, peer, qafx, true /* in */);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) "
            "neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
#else
DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
            "neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
#endif
{
  struct peer *peer;
  bool in;
  qafx_t qafx ;

#ifdef HAVE_IPV6
    peer = peer_lookup_in_view (vty, argv[0], argv[3]);
#else
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
#endif

  if (! peer)
    return CMD_WARNING;

#ifdef HAVE_IPV6
  if (strncmp (argv[1], "ipv6", 4) == 0)
    qafx = (argv[2][0] == 'm') ? qafx_ipv6_multicast
                               : qafx_ipv6_unicast ;
  else
    qafx = (argv[2][0] == 'm') ? qafx_ipv4_multicast
                               : qafx_ipv4_unicast ;
  in = (argv[4][0] == 'r') ;
#else
  qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;
  in = (argv[3][0] == 'r') ;
#endif

  return peer_adj_routes (vty, peer, qafx, in);
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  sockunion_t su[1] ;
  bgp_peer    peer;
  int count;

  if (! sockunion_str2su (su, argv[0])) ;
    {
      vty_out (vty, "Malformed address: %s\n", argv[0]);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || !peer_family_is_active(peer, qafx_ipv4_unicast))
    {
      vty_out (vty, "%% No such neighbor in address family\n");
      return CMD_WARNING;
    }

  prefix_bgp_orf_name_set(name, &peer->su_name, qafx_ipv4_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv4 Unicast\n");
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_neighbor_received_prefix_filter,
       show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd,
       "show ip bgp ipv4 (unicast|multicast) "
                          "neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  sockunion_t su[1] ;
  bgp_peer    peer;
  int count;

  if (! sockunion_str2su (su, argv[1])) ;
    {
      vty_out (vty, "Malformed address: %s\n", argv[1]);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || !peer_family_is_active(peer, qafx_ipv4_unicast))
    {
      vty_out (vty, "%% No such neighbor in address family\n");
      return CMD_WARNING;
    }

  if (argv[0][0] == 'm')
    {
      prefix_bgp_orf_name_set(name, &peer->su_name, qafx_ipv4_multicast) ;

      count =  prefix_bgp_show_prefix_list (NULL, name);
      if (count)
        {
          vty_out (vty, "Address family: IPv4 Multicast\n");
          prefix_bgp_show_prefix_list (vty, name);
        }
    }
  else
    {
      prefix_bgp_orf_name_set(name, &peer->su_name, qafx_ipv4_unicast) ;

      count =  prefix_bgp_show_prefix_list (NULL, name);
      if (count)
        {
          vty_out (vty, "Address family: IPv4 Unicast\n");
          prefix_bgp_show_prefix_list (vty, name);
        }
    }

  return CMD_SUCCESS;
}


#ifdef HAVE_IPV6
ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_neighbor_received_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_ipv6_neighbor_received_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_neighbor_received_prefix_filter,
       show_bgp_neighbor_received_prefix_filter_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  sockunion_t su[1] ;
  bgp_peer    peer;
  int count;

  if (! sockunion_str2su (su, argv[0])) ;
    {
      vty_out (vty, "Malformed address: %s\n", argv[0]);
      return CMD_WARNING;
    }

  peer = peer_lookup (NULL, su);
  if (! peer || !peer_family_is_active(peer, qafx_ipv6_unicast))
    {
      vty_out (vty, "%% No such neighbor in address family\n");
      return CMD_WARNING;
    }

  prefix_bgp_orf_name_set(name, &peer->su_name, qafx_ipv6_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast\n");
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_neighbor_received_prefix_filter,
       show_bgp_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")

/* old command */
ALIAS (show_bgp_view_neighbor_received_routes,
       ipv6_bgp_neighbor_received_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_received_routes,
       ipv6_mbgp_neighbor_received_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_adj_routes (vty, peer, qafx_ipv6_multicast, 1);
}

DEFUN (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_inst     bgp;
  bgp_orf_name name ;
  sockunion_t  su[1] ;
  bgp_peer     peer;
  int count;

  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    } ;

  if (! sockunion_str2su (su, argv[1]))
    {
      vty_out (vty, "Malformed address: %s\n", argv[1]);
      return CMD_WARNING;
    }

  peer = peer_lookup (bgp, su);
  if (! peer || !peer_family_is_active(peer, qafx_ipv6_unicast))
    {
      vty_out (vty, "%% No such neighbor in address family\n");
      return CMD_WARNING;
    } ;

  prefix_bgp_orf_name_set(name, &peer->su_name, qafx_ipv6_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
#endif /* HAVE_IPV6 */

static int
bgp_show_neighbor_route (struct vty *vty, struct peer *peer, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  if (! peer || !peer_family_is_active(peer, qafx))
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, peer->bgp, qafx, type, &peer->su_name);
}

DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv4_unicast,
                                  bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_neighbor_flap,
       show_ip_bgp_neighbor_flap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv4_unicast,
                                  bgp_show_type_flap_neighbor);
}

DEFUN (show_ip_bgp_neighbor_damp,
       show_ip_bgp_neighbor_damp_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv4_unicast,
                                  bgp_show_type_damp_neighbor);
}

DEFUN (show_ip_bgp_ipv4_neighbor_routes,
       show_ip_bgp_ipv4_neighbor_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;
  qafx_t qafx ;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return bgp_show_neighbor_route (vty, peer, qafx, bgp_show_type_neighbor);
}

#ifdef HAVE_IPV6

DEFUN (show_bgp_view_neighbor_routes,
       show_bgp_view_neighbor_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv6_unicast,
                                  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_view_ipv6_neighbor_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFUN (show_bgp_view_neighbor_damp,
       show_bgp_view_neighbor_damp_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv6_unicast,
                                  bgp_show_type_damp_neighbor);
}

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_view_ipv6_neighbor_damp_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_neighbor_flap,
       show_bgp_view_neighbor_flap_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv6_unicast,
                                  bgp_show_type_flap_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_view_ipv6_neighbor_flap_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_neighbor_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")


ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_ipv6_neighbor_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_routes,
       ipv6_bgp_neighbor_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_routes,
       ipv6_mbgp_neighbor_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_show_neighbor_route (vty, peer, qafx_ipv6_multicast,
                                  bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_neighbor_flap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_ipv6_neighbor_flap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_neighbor_damp_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_ipv6_neighbor_damp_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")


DEFUN (show_bgp_view_rsclient,
       show_bgp_view_rsclient_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  bgp_peer peer ;
  peer_rib prib ;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  prib = peer_family_prib(peer, qafx_ipv6_unicast) ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! (prib->af_flags & PEER_AFF_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->prib[qafx_ipv6_unicast];

  return bgp_show_table (vty, table, peer->remote_id, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view_rsclient,
       show_bgp_rsclient_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_view_ipv6_safi_rsclient_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  struct bgp_table *table;
  struct peer *peer;
  const char* um_arg ;
  qafx_t  qafx ;
  peer_rib prib ;

  if (argc == 3)
    {
      peer = peer_lookup_in_view (vty, argv[0], argv[2]);
      um_arg = argv[1] ;
    }
  else
    {
      peer = peer_lookup_in_view (vty, NULL, argv[1]);
      um_arg = argv[0] ;
    }

  if (! peer)
    return CMD_WARNING;

  qafx = qafx_from_q(qAFI_IP6, (*um_arg == 'm') ? qSAFI_Multicast
                                                : qSAFI_Unicast) ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! (prib->af_flags & PEER_AFF_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client\n");
      return CMD_WARNING;
    }

  table = peer->prib[qafx];

  return bgp_show_table (vty, table, peer->remote_id, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_ipv6_safi_rsclient_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

#endif

/*==============================================================================
 *
 */
enum bgp_stats
{
  BGP_STATS_MAXBITLEN = 0,
  BGP_STATS_RIB,
  BGP_STATS_PREFIXES,
  BGP_STATS_TOTPLEN,
  BGP_STATS_UNAGGREGATEABLE,
  BGP_STATS_MAX_AGGREGATEABLE,
  BGP_STATS_AGGREGATES,
  BGP_STATS_SPACE,
  BGP_STATS_ASPATH_COUNT,
  BGP_STATS_ASPATH_MAXHOPS,
  BGP_STATS_ASPATH_TOTHOPS,
  BGP_STATS_ASPATH_MAXSIZE,
  BGP_STATS_ASPATH_TOTSIZE,
  BGP_STATS_ASN_HIGHEST,
  BGP_STATS_MAX,
};

static const char *table_stats_strs[] =
{
  [BGP_STATS_PREFIXES]            = "Total Prefixes",
  [BGP_STATS_TOTPLEN]             = "Average prefix length",
  [BGP_STATS_RIB]                 = "Total Advertisements",
  [BGP_STATS_UNAGGREGATEABLE]     = "Unaggregateable prefixes",
  [BGP_STATS_MAX_AGGREGATEABLE]   = "Maximum aggregateable prefixes",
  [BGP_STATS_AGGREGATES]          = "BGP Aggregate advertisements",
  [BGP_STATS_SPACE]               = "Address space advertised",
  [BGP_STATS_ASPATH_COUNT]        = "Advertisements with paths",
  [BGP_STATS_ASPATH_MAXHOPS]      = "Longest AS-Path (hops)",
  [BGP_STATS_ASPATH_MAXSIZE]      = "Largest AS-Path (bytes)",
  [BGP_STATS_ASPATH_TOTHOPS]      = "Average AS-Path length (hops)",
  [BGP_STATS_ASPATH_TOTSIZE]      = "Average AS-Path size (bytes)",
  [BGP_STATS_ASN_HIGHEST]         = "Highest public ASN",
  [BGP_STATS_MAX] = NULL,
};

struct bgp_table_stats
{
  struct bgp_table *table;
  urlong counts[BGP_STATS_MAX];
};

#if 0
#define TALLY_SIGFIG 100000
static unsigned long
ravg_tally (unsigned long count, unsigned long oldavg, unsigned long newval)
{
  unsigned long newtot = (count-1) * oldavg + (newval * TALLY_SIGFIG);
  unsigned long res = (newtot * TALLY_SIGFIG) / count;
  unsigned long ret = newtot / count;

  if ((res % TALLY_SIGFIG) > (TALLY_SIGFIG/2))
    return ret + 1;
  else
    return ret;
}
#endif

static int
bgp_table_stats_walker (struct thread *t)
{
  struct bgp_node *rn;
  struct bgp_node *top;
  struct bgp_table_stats *ts = THREAD_ARG (t);
  unsigned int space = 0;

  if (!(top = bgp_table_top (ts->table)))
    return 0;

  switch (top->p.family)
    {
      case AF_INET:
        space = IPV4_MAX_BITLEN;
        break;

      case AF_INET6:
        space = IPV6_MAX_BITLEN;
        break;

      default:
        return 0 ;
    }

  ts->counts[BGP_STATS_MAXBITLEN] = space;

  for (rn = top; rn; rn = bgp_route_next (rn))
    {
      struct bgp_info *ri;
      struct bgp_node *prn = rn->parent;
      unsigned int rinum = 0;

      if (rn == top)
        continue;

      if (!rn->info)
        continue;

      ts->counts[BGP_STATS_PREFIXES]++;
      ts->counts[BGP_STATS_TOTPLEN] += rn->p.prefixlen;

#if 0
      ts->counts[BGP_STATS_AVGPLEN]
        = ravg_tally (ts->counts[BGP_STATS_PREFIXES],
                      ts->counts[BGP_STATS_AVGPLEN],
                      rn->p.prefixlen);
#endif

      /* check if the prefix is included by any other announcements */
      while (prn && !prn->info)
        prn = prn->parent;

      if (prn == NULL || prn == top)
        {
          ts->counts[BGP_STATS_UNAGGREGATEABLE]++;
          /* announced address space */
          if (space)
            ts->counts[BGP_STATS_SPACE] += 1 << (space - rn->p.prefixlen);
        }
      else if (prn->info)
        ts->counts[BGP_STATS_MAX_AGGREGATEABLE]++;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          rinum++;
          ts->counts[BGP_STATS_RIB]++;

          if ((ri->attr != NULL) && (ri->attr->have & atb_atomic_aggregate))
            ts->counts[BGP_STATS_AGGREGATES]++;

          /* as-path stats */
          if ((ri->attr != NULL) && (ri->attr->asp != NULL))
            {
              uint hops = as_path_simple_path_length (ri->attr->asp);
              uint size = as_path_size (ri->attr->asp);
              as_t highest = as_path_highest (ri->attr->asp);

              ts->counts[BGP_STATS_ASPATH_COUNT]++;

              if (hops > ts->counts[BGP_STATS_ASPATH_MAXHOPS])
                ts->counts[BGP_STATS_ASPATH_MAXHOPS] = hops;

              if (size > ts->counts[BGP_STATS_ASPATH_MAXSIZE])
                ts->counts[BGP_STATS_ASPATH_MAXSIZE] = size;

              ts->counts[BGP_STATS_ASPATH_TOTHOPS] += hops;
              ts->counts[BGP_STATS_ASPATH_TOTSIZE] += size;
#if 0
              ts->counts[BGP_STATS_ASPATH_AVGHOPS]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGHOPS],
                              hops);
              ts->counts[BGP_STATS_ASPATH_AVGSIZE]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGSIZE],
                              size);
#endif
              if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
                ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
            }
        }
    }
  return 0;
}

static int
bgp_table_stats (struct vty *vty, struct bgp *bgp, qafx_t qafx)
{
  struct bgp_table_stats ts;
  unsigned int i;

  if (!bgp->rib[qafx][rib_main])
    {
      vty_out (vty, "%% No RIB exist for the AFI/SAFI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&ts, 0, sizeof (ts));
  ts.table = bgp->rib[qafx][rib_main];
  thread_execute (bm->master, bgp_table_stats_walker, &ts, 0);

  vty_out (vty, "BGP %s RIB statistics\n\n", get_qafx_name(qafx));

  for (i = 0; i < BGP_STATS_MAX; i++)
    {
      if (!table_stats_strs[i])
        continue;

      switch (i)
        {
#if 0
          case BGP_STATS_ASPATH_AVGHOPS:
          case BGP_STATS_ASPATH_AVGSIZE:
          case BGP_STATS_AVGPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     (float)ts.counts[i] / (float)TALLY_SIGFIG);
            break;
#endif
          case BGP_STATS_ASPATH_TOTHOPS:
          case BGP_STATS_ASPATH_TOTSIZE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] /
                      (float)ts.counts[BGP_STATS_ASPATH_COUNT]
                     : 0);
            break;
          case BGP_STATS_TOTPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] /
                      (float)ts.counts[BGP_STATS_PREFIXES]
                     : 0);
            break;
          case BGP_STATS_SPACE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12llu%s", ts.counts[i], VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 9)
              break;
            vty_out (vty, "%30s: ", "%% announced ");
            vty_out (vty, "%12.2f%s",
                     100 * (float)ts.counts[BGP_STATS_SPACE] /
                       (float)((uint64_t)1UL << ts.counts[BGP_STATS_MAXBITLEN]),
                       VTY_NEWLINE);
            vty_out (vty, "%30s: ", "/8 equivalent ");
            vty_out (vty, "%12.2f%s",
                     (float)ts.counts[BGP_STATS_SPACE] /
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 8)),
                     VTY_NEWLINE);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 25)
              break;
            vty_out (vty, "%30s: ", "/24 equivalent ");
            vty_out (vty, "%12.2f",
                     (float)ts.counts[BGP_STATS_SPACE] /
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 24)));
            break;
          default:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12"fRL"u", ts.counts[i]);
        }

      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}

static int
bgp_table_stats_vty (struct vty *vty, const char *name,
                     const char *afi_str, const char *safi_str)
{
  struct bgp *bgp;
  qAFI_t  q_afi ;
  qSAFI_t q_safi ;

  if (name != NULL)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (bgp == NULL)
    {
      vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if      (strncmp (afi_str, "ipv4", 4) == 0)
    q_afi = qAFI_IP ;
#ifdef HAVE_IPV6
  else if (strncmp (afi_str, "ipv6", 4) == 0)
    q_afi = qAFI_IP6 ;
#endif
  else
    {
      vty_out (vty, "%% Invalid address family %s\n", afi_str);
      return CMD_WARNING;
    } ;

  if      (safi_str[0] == 'u')
    q_safi = qSAFI_Unicast ;
  else if (safi_str[0] == 'm')
    q_safi = qSAFI_Multicast ;
  else if ( (strncmp (safi_str, "vpnv4", 5) == 0)
#ifdef HAVE_IPV6
         || (strncmp (safi_str, "vpnv6", 5) == 0)
#endif
          )
    q_safi = qSAFI_MPLS_VPN ;
  else
    {
      vty_out (vty, "%% Invalid subsequent address family %s\n", safi_str);
      return CMD_WARNING;
    } ;

  return bgp_table_stats (vty, bgp, qafx_from_q(q_afi, q_safi));
}

DEFUN (show_bgp_statistics,
       show_bgp_statistics_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics,
       show_bgp_statistics_vpnv4_cmd,
       "show bgp (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

DEFUN (show_bgp_statistics_view,
       show_bgp_statistics_view_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics_view,
       show_bgp_statistics_view_vpnv4_cmd,
       "show bgp view WORD (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

enum bgp_pcounts
{
  PCOUNT_ADJ_IN = 0,
  PCOUNT_DAMPED,
  PCOUNT_REMOVED,
  PCOUNT_HISTORY,
  PCOUNT_STALE,
  PCOUNT_VALID,
  PCOUNT_ALL,
  PCOUNT_COUNTED,
  PCOUNT_PFCNT, /* the figure we display to users */
  PCOUNT_MAX,
};

static const char *pcount_strs[] =
{
  [PCOUNT_ADJ_IN]  = "Adj-in",
  [PCOUNT_DAMPED]  = "Damped",
  [PCOUNT_REMOVED] = "Removed",
  [PCOUNT_HISTORY] = "History",
  [PCOUNT_STALE]   = "Stale",
  [PCOUNT_VALID]   = "Valid",
  [PCOUNT_ALL]     = "All RIB",
  [PCOUNT_COUNTED] = "PfxCt counted",
  [PCOUNT_PFCNT]   = "Useable",
  [PCOUNT_MAX]     = NULL,
};

struct peer_pcounts
{
  unsigned int count[PCOUNT_MAX];
  const struct peer *peer;
  const struct bgp_table *table;
};

static int
bgp_peer_count_walker (struct thread *t)
{
  bgp_node  rn;
  struct peer_pcounts *pc = THREAD_ARG (t);
  const struct peer *peer = pc->peer;

  for (rn = bgp_table_top (pc->table); rn; rn = bgp_route_next (rn))
    {
      bgp_adj_in ai;
      struct bgp_info *ri;

      for (ai = rn->adj_in; ai; ai = ai->adj.next)
        if (ai->peer == peer)
          pc->count[PCOUNT_ADJ_IN]++;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          char buf[SU_ADDRSTRLEN];

          if (ri->peer != peer)
            continue;

          pc->count[PCOUNT_ALL]++;

          if (CHECK_FLAG (ri->flags, BGP_INFO_DAMPED))
            pc->count[PCOUNT_DAMPED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
            pc->count[PCOUNT_HISTORY]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_REMOVED))
            pc->count[PCOUNT_REMOVED]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_STALE))
            pc->count[PCOUNT_STALE]++;
          if (CHECK_FLAG (ri->flags, BGP_INFO_VALID))
            pc->count[PCOUNT_VALID]++;
          if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
            pc->count[PCOUNT_PFCNT]++;

          if (CHECK_FLAG (ri->flags, BGP_INFO_COUNTED))
            {
              pc->count[PCOUNT_COUNTED]++;
              if (CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                plog_warn (peer->log,
                           "%s [pcount] %s/%d is counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
          else
            {
              if (!CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
                plog_warn (peer->log,
                           "%s [pcount] %s/%d not counted but flags 0x%x",
                           peer->host,
                           inet_ntop(rn->p.family, &rn->p.u.prefix,
                                     buf, SU_ADDRSTRLEN),
                           rn->p.prefixlen,
                           ri->flags);
            }
        }
    }
  return 0;
}

static int
bgp_peer_counts (struct vty *vty, struct peer *peer, qafx_t qafx)
{
  peer_rib prib ;
  struct   peer_pcounts pcounts ;
  uint     i ;

  if (!peer || !peer->bgp || ((prib = peer_family_prib(peer, qafx)) == NULL)
                          || (peer->bgp->rib[qafx] == NULL))
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.peer = peer;
  pcounts.table = peer->bgp->rib[qafx][rib_main];

  /* in-place call via thread subsystem so as to record execution time
   * stats for the thread-walk (i.e. ensure this can't be blamed on
   * on just vty_read()).
   */
  thread_execute (bm->master, bgp_peer_count_walker, &pcounts, 0);

  vty_out (vty, "Prefix counts for %s, %s\n", peer->host, get_qafx_name(qafx));
  vty_out (vty, "PfxCt: %u\n", prib->pcount);
  vty_out (vty, "\nCounts from RIB table walk:\n\n") ;

  for (i = 0; i < PCOUNT_MAX; i++)
      vty_out (vty, "%20s: %-10d\n", pcount_strs[i], pcounts.count[i]);

  if (pcounts.count[PCOUNT_PFCNT] != prib->pcount)
    {
      vty_out (vty, "%s [pcount] PfxCt drift!\n", peer->host);
      vty_out (vty, "Please report this bug, with the above command output\n") ;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_prefix_counts,
       show_ip_bgp_neighbor_prefix_counts_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, qafx_ipv4_unicast);
}

DEFUN (show_bgp_ipv6_neighbor_prefix_counts,
       show_bgp_ipv6_neighbor_prefix_counts_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, qafx_ipv6_unicast);
}

DEFUN (show_ip_bgp_ipv4_neighbor_prefix_counts,
       show_ip_bgp_ipv4_neighbor_prefix_counts_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;
  qafx_t qafx ;

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return bgp_peer_counts (vty, peer, qafx);
}

DEFUN (show_ip_bgp_vpnv4_neighbor_prefix_counts,
       show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd,
       "show ip bgp vpnv4 all neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  struct peer *peer;

  peer = peer_lookup_in_view (vty, NULL, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_peer_counts (vty, peer, qafx_ipv4_mpls_vpn) ;
}


struct bgp_table *bgp_distance_table;

struct bgp_distance
{
  /* Distance value for the IP source prefix. */
  u_char distance;

  /* Name of the access-list to be matched. */
  char *access_list;
};

static struct bgp_distance *
bgp_distance_new (void)
{
  return XCALLOC (MTYPE_BGP_DISTANCE, sizeof (struct bgp_distance));
}

static void
bgp_distance_free (struct bgp_distance *bdistance)
{
  XFREE (MTYPE_BGP_DISTANCE, bdistance);
}

static int
bgp_distance_set (struct vty *vty, const char *distance_str,
                  const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  u_char distance;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  distance = atoi (distance_str);

  /* Get BGP distance node. */
  rn = bgp_node_get (bgp_distance_table, (struct prefix *) &p);
  if (rn->info)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      bdistance = bgp_distance_new ();
      rn->info = bdistance;
    }

  /* Set distance value. */
  bdistance->distance = distance;

  /* Reset access-list configuration. */
  if (bdistance->access_list)
    {
      free (bdistance->access_list);
      bdistance->access_list = NULL;
    }
  if (access_list_str)
    bdistance->access_list = strdup (access_list_str);

  return CMD_SUCCESS;
}

static int
bgp_distance_unset (struct vty *vty, const char *distance_str,
                    const char *ip_str, const char *access_list_str)
{
  int ret;
  struct prefix_ipv4 p;
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  ret = str2prefix_ipv4 (ip_str, &p);
  if (ret == 0)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  rn = bgp_node_lookup (bgp_distance_table, (struct prefix *)&p);
  if (! rn)
    {
      vty_out (vty, "Can't find specified prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bdistance = rn->info;

  if (bdistance->access_list)
    free (bdistance->access_list);
  bgp_distance_free (bdistance);

  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Apply BGP information to distance method.
 */
extern byte
bgp_distance_apply (bgp_peer peer, prefix_c p)
{
  struct bgp_node *rn;
  struct prefix_ipv4 q;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (p->family != AF_INET)
    return 0;

  if (peer->su_name.sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family    = AF_INET ;
  q.prefix    = peer->su_name.sin.sin_addr ;
  q.prefixlen = IPV4_MAX_BITLEN ;

  /* Check source address.
   */
  rn = bgp_node_match (bgp_distance_table, (prefix)&q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list != NULL)
        {
          alist = access_list_lookup (qAFI_IP, bdistance->access_list);
          if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
            return bdistance->distance;
        }
      else
        return bdistance->distance;
    } ;

  /* Backdoor check.
   */
  rn = bgp_node_lookup (peer->bgp->route[qafx_ipv4_unicast], p) ;
  if (rn != NULL)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
        {
          if (peer->bgp->distance_local)
            return peer->bgp->distance_local;
          else
            return ZEBRA_IBGP_DISTANCE_DEFAULT;
        }
    }

  if (peer->sort == BGP_PEER_EBGP)
    {
      if (peer->bgp->distance_ebgp != 0)
        return peer->bgp->distance_ebgp ;

      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (peer->bgp->distance_ibgp != 0)
        return peer->bgp->distance_ibgp;

      return ZEBRA_IBGP_DISTANCE_DEFAULT;
    }
}

DEFUN (bgp_distance,
       bgp_distance_cmd,
       "distance bgp <1-255> <1-255> <1-255>",
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp  = atoi (argv[0]);
  bgp->distance_ibgp  = atoi (argv[1]);
  bgp->distance_local = atoi (argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance,
       no_bgp_distance_cmd,
       "no distance bgp <1-255> <1-255> <1-255>",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n"
       "Distance for routes external to the AS\n"
       "Distance for routes internal to the AS\n"
       "Distance for local routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  bgp->distance_ebgp  = 0;
  bgp->distance_ibgp  = 0;
  bgp->distance_local = 0;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_distance,
       no_bgp_distance2_cmd,
       "no distance bgp",
       NO_STR
       "Define an administrative distance\n"
       "BGP distance\n")

DEFUN (bgp_distance_source,
       bgp_distance_source_cmd,
       "distance <1-255> A.B.C.D/M",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_set (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source,
       no_bgp_distance_source_cmd,
       "no distance <1-255> A.B.C.D/M",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], NULL);
  return CMD_SUCCESS;
}

DEFUN (bgp_distance_source_access_list,
       bgp_distance_source_access_list_cmd,
       "distance <1-255> A.B.C.D/M WORD",
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_set (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_distance_source_access_list,
       no_bgp_distance_source_access_list_cmd,
       "no distance <1-255> A.B.C.D/M WORD",
       NO_STR
       "Define an administrative distance\n"
       "Administrative distance\n"
       "IP source prefix\n"
       "Access list name\n")
{
  bgp_distance_unset (vty, argv[0], argv[1], argv[2]);
  return CMD_SUCCESS;
}

DEFUN (bgp_damp_set,
       bgp_damp_set_cmd,
       "bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")
{
  struct bgp *bgp;
  int half = DEFAULT_HALF_LIFE * 60;
  int reuse = DEFAULT_REUSE;
  int suppress = DEFAULT_SUPPRESS;
  int max = 4 * half;

  if (argc == 4)
    {
      half = atoi (argv[0]) * 60;
      reuse = atoi (argv[1]);
      suppress = atoi (argv[2]);
      max = atoi (argv[3]) * 60;
    }
  else if (argc == 1)
    {
      half = atoi (argv[0]) * 60;
      max = 4 * half;
    }

  bgp = vty->index;
  return bgp_damp_enable (bgp,
                         qafx_from_q(bgp_node_afi (vty), bgp_node_safi (vty)),
                          half, reuse, suppress, max);
}

ALIAS (bgp_damp_set,
       bgp_damp_set2_cmd,
       "bgp dampening <1-45>",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n")

ALIAS (bgp_damp_set,
       bgp_damp_set3_cmd,
       "bgp dampening",
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")

DEFUN (bgp_damp_unset,
       bgp_damp_unset_cmd,
       "no bgp dampening",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  return bgp_damp_disable (bgp,
                          qafx_from_q(bgp_node_afi (vty), bgp_node_safi (vty)));
}

ALIAS (bgp_damp_unset,
       bgp_damp_unset2_cmd,
       "no bgp dampening <1-45> <1-20000> <1-20000> <1-255>",
       NO_STR
       "BGP Specific commands\n"
       "Enable route-flap dampening\n"
       "Half-life time for the penalty\n"
       "Value to start reusing a route\n"
       "Value to start suppressing a route\n"
       "Maximum duration to suppress a stable route\n")

DEFUN (show_ip_bgp_dampened_paths,
       show_ip_bgp_dampened_paths_cmd,
       "show ip bgp dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display paths suppressed due to dampening\n")
{
  return bgp_show (vty, NULL, qafx_ipv4_unicast, bgp_show_type_damped_paths,
                   NULL);
}

DEFUN (show_ip_bgp_flap_statistics,
       show_ip_bgp_flap_statistics_cmd,
       "show ip bgp flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n")
{
  return bgp_show (vty, NULL, qafx_ipv4_unicast,
                   bgp_show_type_flap_statistics, NULL);
}

/* Display specified route of BGP table. */
static int
bgp_clear_damp_route (struct vty *vty, const char *view_name,
                      const char *ip_str, afi_t q_afi, safi_t q_safi,
                      struct prefix_rd *prd, int prefix_check)
{
  int ret;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_info *ri_temp;
  struct bgp *bgp;
  struct bgp_table *table;
  qafx_t qafx ;

  qafx = qafx_from_q(q_afi, q_safi) ;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (bgp == NULL)
        {
          vty_out (vty, "%% Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        {
          vty_out (vty, "%% No BGP process is configured%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = get_qafx_sa_family(qafx) ;

  if (qafx_is_mpls_vpn(qafx))
    {
      for (rn = bgp_table_top (bgp->rib[qafx]); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            if ((rm = bgp_node_match (table, &match)) != NULL)
              {
                if (! prefix_check || rm->p.prefixlen == match.prefixlen)
                  {
                    ri = rm->info;
                    while (ri)
                      {
                        if (ri->extra && ri->extra->damp_info)
                          {
                            ri_temp = ri->info.next;
                            bgp_damp_info_free (ri->extra->damp_info, 1);
                            ri = ri_temp;
                          }
                        else
                          ri = ri->info.next;
                      }
                  }
                bgp_unlock_node (rm);
              }
        }
    }
  else
    {
      if ((rn = bgp_node_match (bgp->rib[qafx][rib_main], &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              ri = rn->info;
              while (ri)
                {
                  if (ri->extra && ri->extra->damp_info)
                    {
                      ri_temp = ri->info.next;
                      bgp_damp_info_free (ri->extra->damp_info, 1);
                      ri = ri_temp;
                    }
                  else
                    ri = ri->info.next;
                }
            }
          bgp_unlock_node (rn);
        }
    }

  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening,
       clear_ip_bgp_dampening_cmd,
       "clear ip bgp dampening",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n")
{
  bgp_damp_info_clean ();
  return CMD_SUCCESS;
}

DEFUN (clear_ip_bgp_dampening_prefix,
       clear_ip_bgp_dampening_prefix_cmd,
       "clear ip bgp dampening A.B.C.D/M",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
                               SAFI_UNICAST, NULL, 1);
}

DEFUN (clear_ip_bgp_dampening_address,
       clear_ip_bgp_dampening_address_cmd,
       "clear ip bgp dampening A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n")
{
  return bgp_clear_damp_route (vty, NULL, argv[0], AFI_IP,
                               SAFI_UNICAST, NULL, 0);
}

DEFUN (clear_ip_bgp_dampening_address_mask,
       clear_ip_bgp_dampening_address_mask_cmd,
       "clear ip bgp dampening A.B.C.D A.B.C.D",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear route flap dampening information\n"
       "Network to clear damping information\n"
       "Network mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);
  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_clear_damp_route (vty, NULL, prefix_str, AFI_IP,
                               SAFI_UNICAST, NULL, 0);
}

static int
bgp_config_write_network_vpnv4 (struct vty *vty, struct bgp *bgp, qafx_t qafx,
                                                                     int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct bgp_static *bgp_static;
  uint32_t label;

  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[qafx]); prn;
                                                    prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        if ((bgp_static = rn->info) != NULL)
          {
            p = &rn->p;
            prd = (struct prefix_rd *) &prn->p;

            /* "address-family" display.
             */
            bgp_config_write_family_header (vty, qafx, write);

            /* "network" configuration display.
             */
            label = mpls_label_decode (bgp_static->tag);

            vty_out (vty, " network %s rd %s tag %u\n",
                      spfxtoa(p).str, srdtoa((struct prefix_rd *)&prn->p).str,
                                                                         label);
          }
  return 0;
}

/* Configuration of static route announcement and aggregate
   information. */
extern int
bgp_config_write_network (struct vty *vty, struct bgp *bgp, qafx_t qafx,
                                                                  int* p_write)
{
  struct bgp_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  struct bgp_aggregate *bgp_aggregate;
  char buf[SU_ADDRSTRLEN];

  if (qafx == qafx_ipv4_mpls_vpn)
    return bgp_config_write_network_vpnv4 (vty, bgp, qafx, p_write);

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route[qafx]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, qafx, p_write);

        /* "network" configuration display.  */
        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && qafx_is_ipv4(qafx))
          {
            u_int32_t destination;
            struct in_addr netmask;

            destination = ntohl (p->u.prefix4.s_addr);
            masklen2ip (p->prefixlen, &netmask);
            vty_out (vty, " network %s",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN));

            if ((IN_CLASSC (destination) && p->prefixlen == 24)
                || (IN_CLASSB (destination) && p->prefixlen == 16)
                || (IN_CLASSA (destination) && p->prefixlen == 8)
                || p->u.prefix4.s_addr == 0)
              {
                /* Natural mask is not display. */
              }
            else
              vty_out (vty, " mask %s", safe_inet_ntoa (netmask));
          }
        else
          {
            vty_out (vty, " network %s/%d",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     p->prefixlen);
          }

        if (bgp_static->rmap.name)
          vty_out (vty, " route-map %s", bgp_static->rmap.name);
        else
          {
            if (bgp_static->backdoor)
              vty_out (vty, " backdoor");
          }

        vty_out (vty, "%s", VTY_NEWLINE);
      }

  /* Aggregate-address configuration.
   */
  for (rn = bgp_table_top (bgp->aggregate[qafx]); rn;
                                                      rn = bgp_route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, qafx, p_write);

        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && qafx_is_ipv4(qafx))
          {
            struct in_addr netmask;

            masklen2ip (p->prefixlen, &netmask);
            vty_out (vty, " aggregate-address %s %s",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     safe_inet_ntoa (netmask));
          }
        else
          {
            vty_out (vty, " aggregate-address %s/%d",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     p->prefixlen);
          }

        if (bgp_aggregate->as_set)
          vty_out (vty, " as-set");

        if (bgp_aggregate->summary_only)
          vty_out (vty, " summary-only");

        vty_out (vty, "%s", VTY_NEWLINE);
      }

  return 0;
}

int
bgp_config_write_distance (struct vty *vty, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct bgp_distance *bdistance;

  /* Distance configuration. */
  if (   (   (bgp->distance_ebgp   != 0)
          && (bgp->distance_ibgp   != 0)
          && (bgp->distance_local  != 0) )
      && (   (bgp->distance_ebgp  != ZEBRA_EBGP_DISTANCE_DEFAULT)
          || (bgp->distance_ibgp  != ZEBRA_IBGP_DISTANCE_DEFAULT)
          || (bgp->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT) ) )
    vty_out (vty, " distance bgp %d %d %d%s",
             bgp->distance_ebgp, bgp->distance_ibgp, bgp->distance_local,
             VTY_NEWLINE);

  for (rn = bgp_table_top (bgp_distance_table); rn; rn = bgp_route_next (rn))
    if ((bdistance = rn->info) != NULL)
      {
        vty_out (vty, " distance %d %s/%d %s%s", bdistance->distance,
                 safe_inet_ntoa (rn->p.u.prefix4), rn->p.prefixlen,
                 bdistance->access_list ? bdistance->access_list : "",
                 VTY_NEWLINE);
      }

  return 0;
}

/*------------------------------------------------------------------------------
 * Table of bgp_route commands
 */
CMD_INSTALL_TABLE(static, bgp_route_cmd_table, BGPD) =
{
  /* IPv4 BGP commands. */
  { BGP_NODE,        &bgp_network_cmd                                   },
  { BGP_NODE,        &bgp_network_mask_cmd                              },
  { BGP_NODE,        &bgp_network_mask_natural_cmd                      },
  { BGP_NODE,        &bgp_network_route_map_cmd                         },
  { BGP_NODE,        &bgp_network_mask_route_map_cmd                    },
  { BGP_NODE,        &bgp_network_mask_natural_route_map_cmd            },
  { BGP_NODE,        &bgp_network_backdoor_cmd                          },
  { BGP_NODE,        &bgp_network_mask_backdoor_cmd                     },
  { BGP_NODE,        &bgp_network_mask_natural_backdoor_cmd             },
  { BGP_NODE,        &no_bgp_network_cmd                                },
  { BGP_NODE,        &no_bgp_network_mask_cmd                           },
  { BGP_NODE,        &no_bgp_network_mask_natural_cmd                   },
  { BGP_NODE,        &no_bgp_network_route_map_cmd                      },
  { BGP_NODE,        &no_bgp_network_mask_route_map_cmd                 },
  { BGP_NODE,        &no_bgp_network_mask_natural_route_map_cmd         },
  { BGP_NODE,        &no_bgp_network_backdoor_cmd                       },
  { BGP_NODE,        &no_bgp_network_mask_backdoor_cmd                  },
  { BGP_NODE,        &no_bgp_network_mask_natural_backdoor_cmd          },
  { BGP_NODE,        &aggregate_address_cmd                             },
  { BGP_NODE,        &aggregate_address_mask_cmd                        },
  { BGP_NODE,        &aggregate_address_summary_only_cmd                },
  { BGP_NODE,        &aggregate_address_mask_summary_only_cmd           },
  { BGP_NODE,        &aggregate_address_as_set_cmd                      },
  { BGP_NODE,        &aggregate_address_mask_as_set_cmd                 },
  { BGP_NODE,        &aggregate_address_as_set_summary_cmd              },
  { BGP_NODE,        &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_NODE,        &aggregate_address_summary_as_set_cmd              },
  { BGP_NODE,        &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_NODE,        &no_aggregate_address_cmd                          },
  { BGP_NODE,        &no_aggregate_address_summary_only_cmd             },
  { BGP_NODE,        &no_aggregate_address_as_set_cmd                   },
  { BGP_NODE,        &no_aggregate_address_as_set_summary_cmd           },
  { BGP_NODE,        &no_aggregate_address_summary_as_set_cmd           },
  { BGP_NODE,        &no_aggregate_address_mask_cmd                     },
  { BGP_NODE,        &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_NODE,        &no_aggregate_address_mask_as_set_cmd              },
  { BGP_NODE,        &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_NODE,        &no_aggregate_address_mask_summary_as_set_cmd      },

  /* IPv4 unicast configuration.  */
  { BGP_IPV4_NODE,   &bgp_network_cmd                                   },
  { BGP_IPV4_NODE,   &bgp_network_mask_cmd                              },
  { BGP_IPV4_NODE,   &bgp_network_mask_natural_cmd                      },
  { BGP_IPV4_NODE,   &bgp_network_route_map_cmd                         },
  { BGP_IPV4_NODE,   &bgp_network_mask_route_map_cmd                    },
  { BGP_IPV4_NODE,   &bgp_network_mask_natural_route_map_cmd            },
  { BGP_IPV4_NODE,   &no_bgp_network_cmd                                },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_cmd                           },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_natural_cmd                   },
  { BGP_IPV4_NODE,   &no_bgp_network_route_map_cmd                      },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_route_map_cmd                 },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_natural_route_map_cmd         },
  { BGP_IPV4_NODE,   &aggregate_address_cmd                             },
  { BGP_IPV4_NODE,   &aggregate_address_mask_cmd                        },
  { BGP_IPV4_NODE,   &aggregate_address_summary_only_cmd                },
  { BGP_IPV4_NODE,   &aggregate_address_mask_summary_only_cmd           },
  { BGP_IPV4_NODE,   &aggregate_address_as_set_cmd                      },
  { BGP_IPV4_NODE,   &aggregate_address_mask_as_set_cmd                 },
  { BGP_IPV4_NODE,   &aggregate_address_as_set_summary_cmd              },
  { BGP_IPV4_NODE,   &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_IPV4_NODE,   &aggregate_address_summary_as_set_cmd              },
  { BGP_IPV4_NODE,   &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_IPV4_NODE,   &no_aggregate_address_cmd                          },
  { BGP_IPV4_NODE,   &no_aggregate_address_summary_only_cmd             },
  { BGP_IPV4_NODE,   &no_aggregate_address_as_set_cmd                   },
  { BGP_IPV4_NODE,   &no_aggregate_address_as_set_summary_cmd           },
  { BGP_IPV4_NODE,   &no_aggregate_address_summary_as_set_cmd           },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_cmd                     },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_as_set_cmd              },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_summary_as_set_cmd      },

  /* IPv4 multicast configuration.  */
  { BGP_IPV4M_NODE,  &bgp_network_cmd                                   },
  { BGP_IPV4M_NODE,  &bgp_network_mask_cmd                              },
  { BGP_IPV4M_NODE,  &bgp_network_mask_natural_cmd                      },
  { BGP_IPV4M_NODE,  &bgp_network_route_map_cmd                         },
  { BGP_IPV4M_NODE,  &bgp_network_mask_route_map_cmd                    },
  { BGP_IPV4M_NODE,  &bgp_network_mask_natural_route_map_cmd            },
  { BGP_IPV4M_NODE,  &no_bgp_network_cmd                                },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_cmd                           },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_natural_cmd                   },
  { BGP_IPV4M_NODE,  &no_bgp_network_route_map_cmd                      },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_route_map_cmd                 },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_natural_route_map_cmd         },
  { BGP_IPV4M_NODE,  &aggregate_address_cmd                             },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_cmd                        },
  { BGP_IPV4M_NODE,  &aggregate_address_summary_only_cmd                },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_summary_only_cmd           },
  { BGP_IPV4M_NODE,  &aggregate_address_as_set_cmd                      },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_as_set_cmd                 },
  { BGP_IPV4M_NODE,  &aggregate_address_as_set_summary_cmd              },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_IPV4M_NODE,  &aggregate_address_summary_as_set_cmd              },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_IPV4M_NODE,  &no_aggregate_address_cmd                          },
  { BGP_IPV4M_NODE,  &no_aggregate_address_summary_only_cmd             },
  { BGP_IPV4M_NODE,  &no_aggregate_address_as_set_cmd                   },
  { BGP_IPV4M_NODE,  &no_aggregate_address_as_set_summary_cmd           },
  { BGP_IPV4M_NODE,  &no_aggregate_address_summary_as_set_cmd           },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_cmd                     },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_as_set_cmd              },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_summary_as_set_cmd      },
  { VIEW_NODE,       &show_ip_bgp_cmd                                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_cmd                              },
  { VIEW_NODE,       &show_bgp_ipv4_safi_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_route_cmd                             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_route_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv4_safi_route_cmd                      },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_route_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_prefix_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv4_safi_prefix_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_view_cmd                              },
  { VIEW_NODE,       &show_ip_bgp_view_route_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_view_prefix_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_regexp_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_ipv4_regexp_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_prefix_list_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_filter_list_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_ipv4_filter_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_route_map_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_route_map_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_cidr_only_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_cidr_only_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_community_all_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_all_cmd                },
  { VIEW_NODE,       &show_ip_bgp_community_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_community2_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_community3_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_community4_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community2_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community3_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community4_cmd                   },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community_all_cmd          },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community_cmd              },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community2_cmd             },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community3_cmd             },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community4_cmd             },
  { VIEW_NODE,       &show_ip_bgp_community_exact_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_community2_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_community3_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_community4_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_exact_cmd              },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community2_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community3_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community4_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_community_list_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_list_cmd               },
  { VIEW_NODE,       &show_ip_bgp_community_list_exact_cmd              },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_list_exact_cmd         },
  { VIEW_NODE,       &show_ip_bgp_prefix_longer_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_longer_cmd                },
  { VIEW_NODE,       &show_ip_bgp_neighbor_advertised_route_cmd         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_advertised_route_cmd    },
  { VIEW_NODE,       &show_ip_bgp_neighbor_received_routes_cmd          },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_received_routes_cmd     },
  { VIEW_NODE,       &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd },
  { VIEW_NODE,       &show_ip_bgp_neighbor_routes_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_routes_cmd              },
  { VIEW_NODE,       &show_ip_bgp_neighbor_received_prefix_filter_cmd   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_ip_bgp_dampened_paths_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_flap_statistics_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_flap_address_cmd                      },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_flap_cidr_only_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_flap_regexp_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_flap_filter_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_longer_cmd                },
  { VIEW_NODE,       &show_ip_bgp_flap_route_map_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_neighbor_flap_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_neighbor_damp_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_rsclient_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_rsclient_route_cmd                    },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { VIEW_NODE,       &show_ip_bgp_rsclient_prefix_cmd                   },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { VIEW_NODE,       &show_ip_bgp_view_neighbor_advertised_route_cmd    },
  { VIEW_NODE,       &show_ip_bgp_view_neighbor_received_routes_cmd     },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_cmd                     },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_cmd              },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_route_cmd               },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_prefix_cmd              },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },

  /* Restricted node: VIEW_NODE - (set of dangerous commands) */
  { RESTRICTED_NODE, &show_ip_bgp_route_cmd                             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_route_cmd                        },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_route_cmd                      },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_prefix_cmd                            },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_cmd                     },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_view_route_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_view_prefix_cmd                       },
  { RESTRICTED_NODE, &show_ip_bgp_community_cmd                         },
  { RESTRICTED_NODE, &show_ip_bgp_community2_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_community3_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_community4_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_cmd                   },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community_all_cmd          },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community_cmd              },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community2_cmd             },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community3_cmd             },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community4_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_community_exact_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_community2_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_community3_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_community4_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community_exact_cmd              },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_route_cmd                    },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_prefix_cmd                   },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { RESTRICTED_NODE, &show_ip_bgp_view_rsclient_route_cmd               },
  { RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { RESTRICTED_NODE, &show_ip_bgp_view_rsclient_prefix_cmd              },
  { RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },
  { ENABLE_NODE,     &show_ip_bgp_cmd                                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_cmd                              },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_route_cmd                             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_route_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_route_cmd                      },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_route_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_prefix_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_prefix_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_view_cmd                              },
  { ENABLE_NODE,     &show_ip_bgp_view_route_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_view_prefix_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_regexp_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_regexp_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_prefix_list_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_filter_list_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_filter_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_route_map_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_route_map_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_cidr_only_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_cidr_only_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_community_all_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_all_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_community_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_community2_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_community3_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_community4_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community2_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community3_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community4_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community_all_cmd          },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community_cmd              },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community2_cmd             },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community3_cmd             },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community4_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_community_exact_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_community2_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_community3_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_community4_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_exact_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community2_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community3_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community4_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_community_list_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_list_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_community_list_exact_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_list_exact_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_prefix_longer_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_longer_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_advertised_route_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_advertised_route_cmd    },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_received_routes_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_received_routes_cmd     },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_routes_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_routes_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_received_prefix_filter_cmd   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_ip_bgp_dampened_paths_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_flap_statistics_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_flap_address_cmd                      },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_flap_cidr_only_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_flap_regexp_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_flap_filter_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_longer_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_flap_route_map_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_flap_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_damp_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_route_cmd                    },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_prefix_cmd                   },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { ENABLE_NODE,     &show_ip_bgp_view_neighbor_advertised_route_cmd    },
  { ENABLE_NODE,     &show_ip_bgp_view_neighbor_received_routes_cmd     },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_cmd                     },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_route_cmd               },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_prefix_cmd              },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },

 /* BGP dampening clear commands */
  { ENABLE_NODE,     &clear_ip_bgp_dampening_cmd                        },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_prefix_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_address_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_dampening_address_mask_cmd           },

  /* prefix count */
  { ENABLE_NODE,     &show_ip_bgp_neighbor_prefix_counts_cmd            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_prefix_counts_cmd       },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd      },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_prefix_counts_cmd          },

  /* New config IPv6 BGP commands.  */
  { BGP_IPV6_NODE,   &ipv6_bgp_network_cmd                              },
  { BGP_IPV6_NODE,   &ipv6_bgp_network_route_map_cmd                    },
  { BGP_IPV6_NODE,   &no_ipv6_bgp_network_cmd                           },
  { BGP_IPV6_NODE,   &no_ipv6_bgp_network_route_map_cmd                 },
  { BGP_IPV6_NODE,   &ipv6_aggregate_address_cmd                        },
  { BGP_IPV6_NODE,   &ipv6_aggregate_address_summary_only_cmd           },
  { BGP_IPV6_NODE,   &no_ipv6_aggregate_address_cmd                     },
  { BGP_IPV6_NODE,   &no_ipv6_aggregate_address_summary_only_cmd        },

  { BGP_IPV6M_NODE,  &ipv6_bgp_network_cmd                              },
  { BGP_IPV6M_NODE,  &no_ipv6_bgp_network_cmd                           },

  /* Old config IPv6 BGP commands.  */
  { BGP_NODE,        &old_ipv6_bgp_network_cmd                          },
  { BGP_NODE,        &old_no_ipv6_bgp_network_cmd                       },
  { BGP_NODE,        &old_ipv6_aggregate_address_cmd                    },
  { BGP_NODE,        &old_ipv6_aggregate_address_summary_only_cmd       },
  { BGP_NODE,        &old_no_ipv6_aggregate_address_cmd                 },
  { BGP_NODE,        &old_no_ipv6_aggregate_address_summary_only_cmd    },
  { VIEW_NODE,       &show_bgp_cmd                                      },
  { VIEW_NODE,       &show_bgp_ipv6_cmd                                 },
  { VIEW_NODE,       &show_bgp_ipv6_safi_cmd                            },
  { VIEW_NODE,       &show_bgp_route_cmd                                },
  { VIEW_NODE,       &show_bgp_ipv6_route_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_safi_route_cmd                      },
  { VIEW_NODE,       &show_bgp_prefix_cmd                               },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_safi_prefix_cmd                     },
  { VIEW_NODE,       &show_bgp_regexp_cmd                               },
  { VIEW_NODE,       &show_bgp_ipv6_regexp_cmd                          },
  { VIEW_NODE,       &show_bgp_prefix_list_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_list_cmd                     },
  { VIEW_NODE,       &show_bgp_filter_list_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_filter_list_cmd                     },
  { VIEW_NODE,       &show_bgp_route_map_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_route_map_cmd                       },
  { VIEW_NODE,       &show_bgp_community_all_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_community_all_cmd                   },
  { VIEW_NODE,       &show_bgp_community_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_community_cmd                       },
  { VIEW_NODE,       &show_bgp_community2_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community2_cmd                      },
  { VIEW_NODE,       &show_bgp_community3_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community3_cmd                      },
  { VIEW_NODE,       &show_bgp_community4_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community4_cmd                      },
  { VIEW_NODE,       &show_bgp_community_exact_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_community_exact_cmd                 },
  { VIEW_NODE,       &show_bgp_community2_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community2_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community3_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community3_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community4_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community4_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community_list_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_community_list_cmd                  },
  { VIEW_NODE,       &show_bgp_community_list_exact_cmd                 },
  { VIEW_NODE,       &show_bgp_ipv6_community_list_exact_cmd            },
  { VIEW_NODE,       &show_bgp_prefix_longer_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_longer_cmd                   },
  { VIEW_NODE,       &show_bgp_neighbor_advertised_route_cmd            },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_advertised_route_cmd       },
  { VIEW_NODE,       &show_bgp_neighbor_received_routes_cmd             },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_received_routes_cmd        },
  { VIEW_NODE,       &show_bgp_neighbor_routes_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_routes_cmd                 },
  { VIEW_NODE,       &show_bgp_neighbor_received_prefix_filter_cmd      },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_neighbor_flap_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_flap_cmd                   },
  { VIEW_NODE,       &show_bgp_neighbor_damp_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_damp_cmd                   },
  { VIEW_NODE,       &show_bgp_rsclient_cmd                             },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_cmd                   },
  { VIEW_NODE,       &show_bgp_rsclient_route_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { VIEW_NODE,       &show_bgp_rsclient_prefix_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { VIEW_NODE,       &show_bgp_view_cmd                                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_cmd                            },
  { VIEW_NODE,       &show_bgp_view_route_cmd                           },
  { VIEW_NODE,       &show_bgp_view_ipv6_route_cmd                      },
  { VIEW_NODE,       &show_bgp_view_prefix_cmd                          },
  { VIEW_NODE,       &show_bgp_view_ipv6_prefix_cmd                     },
  { VIEW_NODE,       &show_bgp_view_neighbor_advertised_route_cmd       },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_advertised_route_cmd  },
  { VIEW_NODE,       &show_bgp_view_neighbor_received_routes_cmd        },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_received_routes_cmd   },
  { VIEW_NODE,       &show_bgp_view_neighbor_routes_cmd                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_routes_cmd            },
  { VIEW_NODE,       &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_view_neighbor_flap_cmd                   },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_flap_cmd              },
  { VIEW_NODE,       &show_bgp_view_neighbor_damp_cmd                   },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_damp_cmd              },
  { VIEW_NODE,       &show_bgp_view_rsclient_cmd                        },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_cmd              },
  { VIEW_NODE,       &show_bgp_view_rsclient_route_cmd                  },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { VIEW_NODE,       &show_bgp_view_rsclient_prefix_cmd                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },

  /* Restricted:
   * VIEW_NODE - (set of dangerous commands) - (commands dependent on prev)
   */
  { RESTRICTED_NODE, &show_bgp_route_cmd                                },
  { RESTRICTED_NODE, &show_bgp_ipv6_route_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_route_cmd                      },
  { RESTRICTED_NODE, &show_bgp_prefix_cmd                               },
  { RESTRICTED_NODE, &show_bgp_ipv6_prefix_cmd                          },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_cmd                     },
  { RESTRICTED_NODE, &show_bgp_community_cmd                            },
  { RESTRICTED_NODE, &show_bgp_ipv6_community_cmd                       },
  { RESTRICTED_NODE, &show_bgp_community2_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community2_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community3_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community3_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community4_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community4_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community_exact_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv6_community_exact_cmd                 },
  { RESTRICTED_NODE, &show_bgp_community2_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community2_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_community3_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community3_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_community4_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community4_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_rsclient_route_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { RESTRICTED_NODE, &show_bgp_rsclient_prefix_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { RESTRICTED_NODE, &show_bgp_view_route_cmd                           },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_route_cmd                      },
  { RESTRICTED_NODE, &show_bgp_view_prefix_cmd                          },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_prefix_cmd                     },
  { RESTRICTED_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { RESTRICTED_NODE, &show_bgp_view_rsclient_route_cmd                  },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { RESTRICTED_NODE, &show_bgp_view_rsclient_prefix_cmd                 },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },
  { ENABLE_NODE,     &show_bgp_cmd                                      },
  { ENABLE_NODE,     &show_bgp_ipv6_cmd                                 },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_cmd                            },
  { ENABLE_NODE,     &show_bgp_route_cmd                                },
  { ENABLE_NODE,     &show_bgp_ipv6_route_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_route_cmd                      },
  { ENABLE_NODE,     &show_bgp_prefix_cmd                               },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_prefix_cmd                     },
  { ENABLE_NODE,     &show_bgp_regexp_cmd                               },
  { ENABLE_NODE,     &show_bgp_ipv6_regexp_cmd                          },
  { ENABLE_NODE,     &show_bgp_prefix_list_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_list_cmd                     },
  { ENABLE_NODE,     &show_bgp_filter_list_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_filter_list_cmd                     },
  { ENABLE_NODE,     &show_bgp_route_map_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_route_map_cmd                       },
  { ENABLE_NODE,     &show_bgp_community_all_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_community_all_cmd                   },
  { ENABLE_NODE,     &show_bgp_community_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_community_cmd                       },
  { ENABLE_NODE,     &show_bgp_community2_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community2_cmd                      },
  { ENABLE_NODE,     &show_bgp_community3_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community3_cmd                      },
  { ENABLE_NODE,     &show_bgp_community4_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community4_cmd                      },
  { ENABLE_NODE,     &show_bgp_community_exact_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_community_exact_cmd                 },
  { ENABLE_NODE,     &show_bgp_community2_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community2_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community3_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community3_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community4_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community4_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community_list_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_community_list_cmd                  },
  { ENABLE_NODE,     &show_bgp_community_list_exact_cmd                 },
  { ENABLE_NODE,     &show_bgp_ipv6_community_list_exact_cmd            },
  { ENABLE_NODE,     &show_bgp_prefix_longer_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_longer_cmd                   },
  { ENABLE_NODE,     &show_bgp_neighbor_advertised_route_cmd            },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_advertised_route_cmd       },
  { ENABLE_NODE,     &show_bgp_neighbor_received_routes_cmd             },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_received_routes_cmd        },
  { ENABLE_NODE,     &show_bgp_neighbor_routes_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_routes_cmd                 },
  { ENABLE_NODE,     &show_bgp_neighbor_received_prefix_filter_cmd      },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_neighbor_flap_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_flap_cmd                   },
  { ENABLE_NODE,     &show_bgp_neighbor_damp_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_damp_cmd                   },
  { ENABLE_NODE,     &show_bgp_rsclient_cmd                             },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_cmd                   },
  { ENABLE_NODE,     &show_bgp_rsclient_route_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { ENABLE_NODE,     &show_bgp_rsclient_prefix_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { ENABLE_NODE,     &show_bgp_view_cmd                                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_cmd                            },
  { ENABLE_NODE,     &show_bgp_view_route_cmd                           },
  { ENABLE_NODE,     &show_bgp_view_ipv6_route_cmd                      },
  { ENABLE_NODE,     &show_bgp_view_prefix_cmd                          },
  { ENABLE_NODE,     &show_bgp_view_ipv6_prefix_cmd                     },
  { ENABLE_NODE,     &show_bgp_view_neighbor_advertised_route_cmd       },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_advertised_route_cmd  },
  { ENABLE_NODE,     &show_bgp_view_neighbor_received_routes_cmd        },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_received_routes_cmd   },
  { ENABLE_NODE,     &show_bgp_view_neighbor_routes_cmd                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_routes_cmd            },
  { ENABLE_NODE,     &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_view_neighbor_flap_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_flap_cmd              },
  { ENABLE_NODE,     &show_bgp_view_neighbor_damp_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_damp_cmd              },
  { ENABLE_NODE,     &show_bgp_view_rsclient_cmd                        },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_cmd              },
  { ENABLE_NODE,     &show_bgp_view_rsclient_route_cmd                  },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { ENABLE_NODE,     &show_bgp_view_rsclient_prefix_cmd                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },

  /* Statistics */
  { ENABLE_NODE,     &show_bgp_statistics_cmd                           },
  { ENABLE_NODE,     &show_bgp_statistics_vpnv4_cmd                     },
  { ENABLE_NODE,     &show_bgp_statistics_view_cmd                      },
  { ENABLE_NODE,     &show_bgp_statistics_view_vpnv4_cmd                },

  /* old command */
  { VIEW_NODE,       &show_ipv6_bgp_cmd                                 },
  { VIEW_NODE,       &show_ipv6_bgp_route_cmd                           },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_cmd                          },
  { VIEW_NODE,       &show_ipv6_bgp_regexp_cmd                          },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_list_cmd                     },
  { VIEW_NODE,       &show_ipv6_bgp_filter_list_cmd                     },
  { VIEW_NODE,       &show_ipv6_bgp_community_all_cmd                   },
  { VIEW_NODE,       &show_ipv6_bgp_community_cmd                       },
  { VIEW_NODE,       &show_ipv6_bgp_community2_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community3_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community4_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community_exact_cmd                 },
  { VIEW_NODE,       &show_ipv6_bgp_community2_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community3_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community4_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community_list_cmd                  },
  { VIEW_NODE,       &show_ipv6_bgp_community_list_exact_cmd            },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_longer_cmd                   },
  { VIEW_NODE,       &show_ipv6_mbgp_cmd                                },
  { VIEW_NODE,       &show_ipv6_mbgp_route_cmd                          },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_regexp_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_list_cmd                    },
  { VIEW_NODE,       &show_ipv6_mbgp_filter_list_cmd                    },
  { VIEW_NODE,       &show_ipv6_mbgp_community_all_cmd                  },
  { VIEW_NODE,       &show_ipv6_mbgp_community_cmd                      },
  { VIEW_NODE,       &show_ipv6_mbgp_community2_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community3_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community4_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_mbgp_community2_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community3_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community4_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community_list_cmd                 },
  { VIEW_NODE,       &show_ipv6_mbgp_community_list_exact_cmd           },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_longer_cmd                  },

  /* old command */
  { ENABLE_NODE,     &show_ipv6_bgp_cmd                                 },
  { ENABLE_NODE,     &show_ipv6_bgp_route_cmd                           },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_cmd                          },
  { ENABLE_NODE,     &show_ipv6_bgp_regexp_cmd                          },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_list_cmd                     },
  { ENABLE_NODE,     &show_ipv6_bgp_filter_list_cmd                     },
  { ENABLE_NODE,     &show_ipv6_bgp_community_all_cmd                   },
  { ENABLE_NODE,     &show_ipv6_bgp_community_cmd                       },
  { ENABLE_NODE,     &show_ipv6_bgp_community2_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community3_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community4_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community_exact_cmd                 },
  { ENABLE_NODE,     &show_ipv6_bgp_community2_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community3_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community4_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community_list_cmd                  },
  { ENABLE_NODE,     &show_ipv6_bgp_community_list_exact_cmd            },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_longer_cmd                   },
  { ENABLE_NODE,     &show_ipv6_mbgp_cmd                                },
  { ENABLE_NODE,     &show_ipv6_mbgp_route_cmd                          },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_regexp_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_list_cmd                    },
  { ENABLE_NODE,     &show_ipv6_mbgp_filter_list_cmd                    },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_all_cmd                  },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_cmd                      },
  { ENABLE_NODE,     &show_ipv6_mbgp_community2_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community3_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community4_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_mbgp_community2_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community3_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community4_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_list_cmd                 },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_list_exact_cmd           },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_longer_cmd                  },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_advertised_route_cmd            },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_advertised_route_cmd            },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_advertised_route_cmd           },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_advertised_route_cmd           },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_received_routes_cmd             },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_received_routes_cmd             },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_received_routes_cmd            },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_received_routes_cmd            },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_routes_cmd                      },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_routes_cmd                      },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_routes_cmd                     },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_routes_cmd                     },
#endif /* HAVE_IPV6 */
  { BGP_NODE,        &bgp_distance_cmd                                  },
  { BGP_NODE,        &no_bgp_distance_cmd                               },
  { BGP_NODE,        &no_bgp_distance2_cmd                              },
  { BGP_NODE,        &bgp_distance_source_cmd                           },
  { BGP_NODE,        &no_bgp_distance_source_cmd                        },
  { BGP_NODE,        &bgp_distance_source_access_list_cmd               },
  { BGP_NODE,        &no_bgp_distance_source_access_list_cmd            },
  { BGP_NODE,        &bgp_damp_set_cmd                                  },
  { BGP_NODE,        &bgp_damp_set2_cmd                                 },
  { BGP_NODE,        &bgp_damp_set3_cmd                                 },
  { BGP_NODE,        &bgp_damp_unset_cmd                                },
  { BGP_NODE,        &bgp_damp_unset2_cmd                               },
  { BGP_IPV4_NODE,   &bgp_damp_set_cmd                                  },
  { BGP_IPV4_NODE,   &bgp_damp_set2_cmd                                 },
  { BGP_IPV4_NODE,   &bgp_damp_set3_cmd                                 },
  { BGP_IPV4_NODE,   &bgp_damp_unset_cmd                                },
  { BGP_IPV4_NODE,   &bgp_damp_unset2_cmd                               },

  /* Deprecated AS-Pathlimit commands */
  { BGP_NODE,        &bgp_network_ttl_cmd                               },
  { BGP_NODE,        &bgp_network_mask_ttl_cmd                          },
  { BGP_NODE,        &bgp_network_mask_natural_ttl_cmd                  },
  { BGP_NODE,        &bgp_network_backdoor_ttl_cmd                      },
  { BGP_NODE,        &bgp_network_mask_backdoor_ttl_cmd                 },
  { BGP_NODE,        &bgp_network_mask_natural_backdoor_ttl_cmd         },
  { BGP_NODE,        &no_bgp_network_ttl_cmd                            },
  { BGP_NODE,        &no_bgp_network_mask_ttl_cmd                       },
  { BGP_NODE,        &no_bgp_network_mask_natural_ttl_cmd               },
  { BGP_NODE,        &no_bgp_network_backdoor_ttl_cmd                   },
  { BGP_NODE,        &no_bgp_network_mask_backdoor_ttl_cmd              },
  { BGP_NODE,        &no_bgp_network_mask_natural_backdoor_ttl_cmd      },
  { BGP_IPV4_NODE,   &bgp_network_ttl_cmd                               },
  { BGP_IPV4_NODE,   &bgp_network_mask_ttl_cmd                          },
  { BGP_IPV4_NODE,   &bgp_network_mask_natural_ttl_cmd                  },
  { BGP_IPV4_NODE,   &bgp_network_backdoor_ttl_cmd                      },
  { BGP_IPV4_NODE,   &bgp_network_mask_backdoor_ttl_cmd                 },
  { BGP_IPV4_NODE,   &bgp_network_mask_natural_backdoor_ttl_cmd         },
  { BGP_IPV4_NODE,   &no_bgp_network_ttl_cmd                            },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_ttl_cmd                       },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_natural_ttl_cmd               },
  { BGP_IPV4_NODE,   &no_bgp_network_backdoor_ttl_cmd                   },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_backdoor_ttl_cmd              },
  { BGP_IPV4_NODE,   &no_bgp_network_mask_natural_backdoor_ttl_cmd      },
  { BGP_IPV4M_NODE,  &bgp_network_ttl_cmd                               },
  { BGP_IPV4M_NODE,  &bgp_network_mask_ttl_cmd                          },
  { BGP_IPV4M_NODE,  &bgp_network_mask_natural_ttl_cmd                  },
  { BGP_IPV4M_NODE,  &bgp_network_backdoor_ttl_cmd                      },
  { BGP_IPV4M_NODE,  &bgp_network_mask_backdoor_ttl_cmd                 },
  { BGP_IPV4M_NODE,  &bgp_network_mask_natural_backdoor_ttl_cmd         },
  { BGP_IPV4M_NODE,  &no_bgp_network_ttl_cmd                            },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_ttl_cmd                       },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_natural_ttl_cmd               },
  { BGP_IPV4M_NODE,  &no_bgp_network_backdoor_ttl_cmd                   },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_backdoor_ttl_cmd              },
  { BGP_IPV4M_NODE,  &no_bgp_network_mask_natural_backdoor_ttl_cmd      },

#ifdef HAVE_IPV6
  { BGP_IPV6_NODE,   &ipv6_bgp_network_ttl_cmd                          },
  { BGP_IPV6_NODE,   &no_ipv6_bgp_network_ttl_cmd                       },
#endif

  CMD_INSTALL_END
} ;

/* Install commands                                                     */
extern void
bgp_route_cmd_init (void)
{
  cmd_install_table(bgp_route_cmd_table) ;
} ;

/* Allocate routing table structure                                     */
extern void
bgp_route_init (void)
{
  /* Init BGP distance table. */
  bgp_distance_table = bgp_table_init (qafx_ipv4_unicast);
} ;

void
bgp_route_finish (void)
{
  bgp_table_unlock (bgp_distance_table);
  bgp_distance_table = NULL;
}
