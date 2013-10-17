/* BGP routing decisions
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 *
 * Recast: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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
#include <zebra.h>


#include "prefix.h"
#include "linklist.h"
#include "memory.h"
#include "command.h"
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
#include "qtimers.h"

#include "svector.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_route_static.h"
#include "bgpd/bgp_rcontext.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgp_adj_out.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_routemap.h"
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
 * Inbound update filtering.
 *
 */


/*------------------------------------------------------------------------------
 * Issue UPDATE_IN debug message as required.
 */
inline static void
bgp_update_filter_in_log(bgp_prun prun, prefix_c pfx, const char* reason)
{
  if (BGP_DEBUG (update, UPDATE_IN) && (reason != NULL))
    zlog (prun->log, LOG_DEBUG,
             "%s rcvd UPDATE about %s -- DENIED due to: %s",
                                       prun->name, spfxtoa(pfx).str, reason) ;
} ;


#define FILTER_EXIST_WARN(type, is_set, filter_name) \
  if (BGP_DEBUG (update, UPDATE_IN) && !(is_set)) \
    plog_warn (prun->log, "%s: %s %s not set", prun->name, type, filter_name)

/*------------------------------------------------------------------------------
 * Process the attributes & prefix for the 'in' filtering.
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
 * Returns:  NULL <=> filtered out -- attribute locking unchanged.
 *           otherwise set of attributes to use now...
 *
 * ...where:
 *
 *   * if the attributes are unchanged, we return the original attributes,
 *     with an extra lock on them...
 *
 *   * if the attributes are changed, we return the new attributes, with
 *     an (extra) lock on them...
 *
 * In either case, the returned attributes can be attached to something,
 * complete with a lock, and if that replaces the original attributes, those
 * can be unlocked !
 */
extern attr_set
bgp_route_in_filter(bgp_prib prib, attr_set attr, prefix_id_entry_c pie)
{
  bgp_prun    prun ;
  attr_pair_t pair[1] ;
  as_path     asp ;
  access_list dlist ;
  prefix_list plist ;
  as_list     aslist ;
  route_map   rmap ;
  const char* reason;
  bgp_peer_sort_t sort ;
  qafx_t  qafx ;

  qafx = prib->qafx ;
  prun = prib->prun ;
  sort = prun->sort ;

  /* Load attribute pair in preparation for any changes later on.
   *
   * Loading takes an extra lock on the original attributes.
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
   *           if confed_id is defined, check for bgp->my_as as well.
   *
   * For other peers:
   *
   *           no check for directly connected next hop.
   *
   *           look for the bgp->my_as -- with allow_as_in.
   *
   *           if confed_id is defined, check for that as well.
   */
  asp = pair->working->asp ;

  if (sort == BGP_PEER_EBGP)
    {
      /* If the prun is EBGP and nexthop is not on connected route,
       * discard it.
       *
       * TODO nexthop check for IPv6 ????..............................................
       */
      if ( (prun->cops_r.ttl == 1)
              && ! bgp_nexthop_onlink (qAFI_IPv4, &attr->next_hop)
              && ! (prun->disable_connected_check) )
        {
          reason = "non-connected next-hop;";
          goto filtered;
        } ;

      /* If we have a change_local_as which is not the same as the as the
       * bgp->ebgp_as, then need to check for that.
       *
       * Note that the 'allow_as_in' does not apply to this check.
       */
      if ( (prun->change_local_as != BGP_ASN_NULL) &&
           (prun->change_local_as != prun->ebgp_as_r) )
        {
          if (!as_path_loop_check (asp, prun->change_local_as, 0))
            {
              reason = "as-path contains our own (change-local) AS;";
              goto filtered;
            } ;
        } ;

      /* AS path eBGP loop check -- this is the standard check for loop.
       */
      if (!as_path_loop_check(asp, prun->ebgp_as_r, prib->allow_as_in))
        {
          if (prun->confed_id_r == BGP_ASN_NULL)
            reason = "as-path contains our own AS;";
          else
            reason = "as-path contains our own (Confed_ID) AS;";
          goto filtered;
        } ;

      /* Final check, if there is a confed_id which is not the same as the
       * bgp->my_as, then we check for the bgp->my_as too.
       *
       * This is a belt-and-braces thing.  If confed_id != bgp->my_as, then the
       * bgp->my_as is the Confederation Member AS, which should not have
       * leaked out to the outside world.
       *
       * The AS-PATH really should not contain any of the Confederation Member
       * ASes (the confed_peers) -- but we do not check for that.
       */
      if (prun->do_check_confed_id_r &&
                             !as_path_loop_check(asp, prun->args_r.local_as, 0))
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
       * an internal prun is sending with our AS in it.
       *
       * For Confed -- that is a prun in the same confederation, but in a
       * different member AS -- this traps route loops within the confederation.
       * (In this case the bgp->my_as ought to be in Confed segments -- but we
       * don't actually worry about that !)
       */
      if (!as_path_loop_check(asp, prun->my_as_r, prib->allow_as_in))
        {
          reason = "as-path contains our own AS;";
          goto filtered;
        } ;

      /* Final check, if there is a confed_id which is not the same as the
       * bgp->my_as, then we check for that too.
       *
       * This is a belt-and-braces thing.  The confed_id should not appear in
       * the AS-PATH, unless it is a Member AS, in which case it should not
       * appear in any not-confederation segment.
       */
      if (prun->do_check_confed_id_r)
        {
          if (prun->do_check_confed_id_all_r)
            {
              if (!as_path_loop_check(asp, prun->confed_id_r, 0))
                {
                  reason = "as-path contains our own (Confed_ID) AS;";
                  goto filtered ;
                } ;
            }
          else
            {
              if (!as_path_loop_check_not_confed(asp, prun->confed_id_r, 0))
                {
                  reason = "as-path contains our own (Confed_ID) AS;";
                  goto filtered;
                } ;
            } ;
        } ;
    } ;

  /* Check that we are not the originator of this route
   */
  if ((prun->router_id_r == pair->working->originator_id)
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
      if (!attr_cluster_check (pair->working->cluster, prun->cluster_id_r))
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

      if (access_list_apply (dlist, pie->pfx) == FILTER_DENY)
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

      if (prefix_list_apply (plist, pie->pfx) == PREFIX_DENY)
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

  if (prun->weight != 0)
    bgp_attr_pair_set_weight(pair, prun->weight) ;

  /* change_local-as prepend
   *
   * Where we are inserting the "phantom" change_local_as at the head of
   * the AS_PATH on output to the prun, we do the same on input from that
   * prun -- unless PEER_FLAG_LOCAL_AS_NO_PREPEND.
   *
   * The effect of this is as if the "phantom" ASN still existed, between
   * us and the prun.
   *
   * Except: if the "phantom" ASN is the same as the current bgp->ebp_as,
   *         then the change_local_as is ignored.
   */
  if (prun->change_local_as_prepend && (prun->change_local_as != BGP_ASN_NULL))
    bgp_attr_pair_set_as_path(pair,
                               as_path_add_seq (asp, prun->change_local_as)) ;

  /* Process prefix and attributes against any 'in' route-map.
   */
  rmap = prib->rmap[RMAP_IN] ;

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      FILTER_EXIST_WARN("route-map in", route_map_is_set(rmap),
                                        route_map_get_name(rmap)) ;

      brm->prun      = prun ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_IN ;

      if (route_map_apply(rmap, pie->pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          reason = "route-map in;";
          goto  filtered ;
        } ;
    } ;

  /* Deal with locks and then we are done -- see above.
   */
  return bgp_attr_pair_store(pair) ;

  /* This BGP update is filtered out.  Log the reason and then:
   *
   *   * discard any new attributes.
   *
   *   * undo the extra lock we acquired earlier on the original attributes.
   */
 filtered:
  bgp_update_filter_in_log(prun, pie->pfx, reason) ;

  bgp_attr_pair_unload(pair) ;
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Process the attributes & prefix for the 'inx' filtering.
 *
 * Performs the following checks and filters:
 *
 *   * 'route-map inx'    -- if any
 *
 * Returns:  NULL <=> the route has been filtered out.
 *           attributes after the route-map, if any -- stored and locked.
 *
 * NB: any attribute set returned has been locked by this function, ready to be
 *     assigned to something.
 *
 *     If the route-maps did not change the attributes, then returns the
 *     given attributes *with* an extra lock.
 *
 *     If the route-maps did change the attributes, then returns the new
 *     attributes, stored with one level of lock.
 */
extern attr_set
bgp_route_inx_filter(bgp_prib prib, attr_set attr, prefix_id_entry_c pie)
{
  bgp_prun    prun ;
  attr_pair_t pair[1] ;
  route_map rmap ;
  const char *reason;
  qafx_t  qafx ;

  qafx = prib->qafx ;
  prun = prib->prun ;

  /* Load attribute pair in preparation for any changes later on.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* AS path loop check
   *
   * This is a duplicate of the Main RIB check -- so no need to log.
   */
  if (!as_path_loop_check(pair->working->asp, prun->my_as_r, 0))
    {
      reason = NULL ;
      goto filtered ;
    } ;

  /* Check that we are not the originator of this route
   *
   * This is a duplicate of the Main RIB check -- so no need to log.
   */
  if ((prun->router_id_r == pair->working->originator_id)
                                   && (pair->working->have & atb_originator_id))
    {
      reason = NULL ;
      goto filtered ;
    } ;

  /* Set 'weight' if required.
   */
  qassert(pair->working->weight == 0) ;

  if (prun->weight != 0)
    bgp_attr_pair_set_weight(pair, prun->weight) ;

  /* Process prefix and attributes against any 'inx' route-map.
   */
  rmap = prib->rmap[RMAP_INX] ;

  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      FILTER_EXIST_WARN("route-map inx", route_map_is_set(rmap),
                                         route_map_get_name(rmap)) ;

      brm->prun      = prun ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_RS_IN ;

      if (route_map_apply(rmap, pie->pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        {
          reason = "route-map inx;";
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
  bgp_update_filter_in_log(prun, pie->pfx, reason) ;

  return bgp_attr_pair_unload(pair) ;
} ;

/*------------------------------------------------------------------------------
 * Process attributes and prefix from source prib to given destination.
 *
 * Process the given route_info to construct the attributes for the given
 * Route Context.
 *
 * Starts from the given attributes, which are the the result of the view level
 * 'in' filtering for the source, followed by 'inx' filtering for the source
 * (the 'inx' filtering allows the route-context world to have a stricter
 * view of the incoming routes than the general view.
 *
 * Runs: 1) the *source* route-context's rc_in_to routemap.
 *
 *          The rc_in_to route-map allows the source route-context to make
 *          decisions about the route, depending on the destination.
 *
 *       2) the *destination* route-context's rc_in_from routemap.
 *
 *          The rc_in_from route-map allows the destination route-context to
 *          make decisions about the route, depending on the source.
 *
 * Returns:  NULL <=> the route has been filtered out.
 *           attributes after the route-map(s), if any -- stored and locked.
 *
 * NB: any attribute set returned has been locked by this function, ready to be
 *     assigned to the destination route-context.
 *
 *     If the route-maps did not change the attributes, then returns the
 *     given attributes *with* an extra lock.
 *
 *     If the route-maps did change the attributes, then returns the new
 *     attributes, stored with one level of lock.
 */
extern attr_set
bgp_route_rc_to_from_filter(bgp_lcontext lc_from, attr_set attr,
                                      prefix_id_entry_c pie, bgp_lcontext lc_to)
{
  attr_pair_t pair[1] ;
  route_map   rmap ;

  /* Load attribute pair in preparation for any changes later on.
   */
  bgp_attr_pair_load(pair, attr) ;

  /* Apply the rc_in_from route-map for the given source lcontext.
   *
   * Route map apply.
   *
   * Note that the peer for relevant matches is the client which is the
   * *destination* for the route.  (The route-map itself belongs to the peer
   * which is the *source* of the route.)
   */
  rmap = lc_from->in_from ;
  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->prun      = NULL ;   /* TODO was: drib->peer         */
      brm->attrs     = pair ;
      brm->qafx      = lc_from->qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_EXPORT ;

      if (route_map_apply(rmap, pie->pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        return bgp_attr_pair_unload(pair) ;
    } ;

  /* Apply the rc_in_to route-map for the given destination lcontext
   *
   * Note that the peer for relevant matches is the peer which is the
   * *source* of the route.  (The route-map itself belongs to the client
   * which is the *destination* of the route.)
   */
  rmap = lc_to->in_to ;
  if (rmap != NULL)
    {
      bgp_route_map_t  brm[1] ;

      brm->prun      = NULL ;   /* TODO was: srib->peer         */
      brm->attrs     = pair ;
      brm->qafx      = lc_to->qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_IMPORT ;

      if (route_map_apply(rmap, pie->pfx, RMAP_BGP, brm) == RMAP_DENY_MATCH)
        return bgp_attr_pair_unload(pair) ;
    } ;

  /* Need a stored version of the attributes -- if anything has changed.
   *
   * If this is the same result as the last time, then we discard the result
   * and we can re-use the existing merit.
   */
  return bgp_attr_pair_store(pair) ;
} ;

#undef FILTER_EXIST_WARN

/*------------------------------------------------------------------------------
 * next-hop check.
 *
 * TODO sort out interaction with the south-side !!
 *
 */
extern bool
bgp_update_filter_next_hop(bgp_prib prib, prefix_c pfx)
{
  attr_next_hop next_hop ;
  const char* reason ;

  switch (prib->qafx)
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
  zlog(prib->prun->log, LOG_INFO,
            "%s rcvd UPDATE about %s -- DENIED due to: %s",
                                 prib->prun->name, spfxtoa(pfx).str, reason) ;

   return false ;
} ;

/*==============================================================================
 * Processing of rib_node to update current selection, and announce as required.
 *
 * This is the background stuff...
 */
static wq_ret_code_t bgp_process_walker(void* data, qtime_mono_t yield_time) ;
static void bgp_process_node(bgp_rib_node rn, bgp_rib_walker rw) ;
static void bgp_process_update_lc(bgp_rib_node rn, prefix_id_entry pie,
                                                                  bgp_lc_id_t lc) ;
static void bgp_route_announce(bgp_prib prib,
                                          prefix_id_entry pie, route_info ris) ;

/*------------------------------------------------------------------------------
 * Schedule the given route_node for "update" processing in the given bgp_rib,
 *                                                                  if required.
 *
 * Starts the rib's walker going, if required.
 */
extern void
bgp_rib_process_schedule(bgp_rib_node rn)
{
  bgp_rib rib ;

  rib = rn->it.rib ;

  /* If not already scheduled for processing, reschedule at the end of the
   * queue.
   */
  if (rn->flags & rnf_processed)
    {
      rn->flags ^= rnf_processed ;

      ddl_del(rib->queue_base, &rn->it, queue) ;
      ddl_append(rib->queue_base, &rn->it, queue) ;
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
  bgp_prib        prib ;

  rw = data ;

  qassert(rw->it.type == rib_it_walker) ;
  qassert( (rw->it.flags & (rib_itf_rib_queue | rib_itf_wq_queue))
                        == (rib_itf_rib_queue | rib_itf_wq_queue) );

  /* Start by removing the walker from the RIB queue
   */
  rib = rw->it.rib ;

  item = ddl_next(&rw->it, queue) ;
  ddl_del(rib->queue_base, &rw->it, queue) ;
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

      qassert(!(rw->it.flags & rib_itf_update) && (rw != rib->walker)) ;

      qassert(rwx->it.type == rib_it_walker) ;
      qassert(rwx->it.flags & rib_itf_rib_queue) ;

      for (prib = ddl_head(rw->refresh_peers) ; prib != NULL ;
                                              prib = ddl_next(prib, walk_list))
        {
          qassert((prib->walker == rw) && prib->refresh) ;
          prib->walker = rwx ;
        } ;

      ddl_prepend_list(rwx->refresh_peers, rw->refresh_peers, walk_list) ;

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

      bgp_process_node(rn, rw) ;

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
          ddl_in_after(item, rib->queue_base, &rw->it, queue) ;
          rw->it.flags |= rib_itf_rib_queue ;

          if (ddl_head(rw->refresh_peers) != NULL)
            return wqrc_something | wqrc_rerun ;
          else
            return wqrc_something | wqrc_rerun_reschedule ;
        } ;
    } ;

  /* We have processed the last item in the queue of nodes to process.
   *
   * That implies that the walker must be the rib's upate walker !
   *
   * Send EoR to all 'refresh' peers, and rehoming them on the relevant update
   * peer list on the bgp-rib.
   */
  qassert((rw->it.flags & rib_itf_update) && (rw == rib->walker)) ;

  while ((prib = ddl_pop(&prib, rw->refresh_peers, walk_list)) != NULL)
    {
      /* We want to transfer the refresh list to relevant update list, and send
       * EoR as required.
       */
      bgp_prib* p_base ;

      qassert((prib->walker == rw) && prib->refresh) ;

      if (prib->eor_required)
        bgp_adj_out_eor(prib) ;     // TODO when negotiated !!

      prib->refresh      = false ;
      prib->eor_required = false ;

      if (prib->lc_id == lc_view_id)
        p_base = &prib->rib->update_view_peers ;
      else
        p_base = svec_get_p(prib->rib->update_peers, prib->lc_id) ;

      sdl_push(*p_base, prib, walk_list) ;
   } ;

  /* We have completely processed the queue with the "update" walker,
   * which we leave at the end of the queue.
   *
   * We return wqrc_remove, signalling the work queue stuff to remove the
   * work queue item from the work queue.
   */
  ddl_append(rib->queue_base, &rw->it, queue) ;
  rw->it.flags = (rw->it.flags & ~rib_itf_wq_queue) | rib_itf_rib_queue ;

  return wqrc_something | wqrc_remove ;
} ;

/*------------------------------------------------------------------------------
 * Work queue process a RIB Node.
 *
 */
static void
bgp_process_node(bgp_rib_node rn, bgp_rib_walker rw)
{
  bgp_prib        refresh_prib ;
  prefix_id_entry pie ;

  qassert(rw->it.rib  == rn->it.rib) ;
  qassert(rw->it.type == rib_it_walker) ;
  qassert(rn->it.type == rib_it_node) ;

  pie = prefix_id_get_entry(rn->pfx_id) ;

  /* If this is the main rib walker, then now is the time to update the main
   * RIB and any peers and the south-side/kernel.
   */
  if (rw->it.flags & rib_itf_update)
    {
      bgp_lc_id_t lc_next ;

      qassert(rw == rw->it.rib->walker) ;

#if 0
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
#endif
      /* Run the selection process for all contexts that require it.
       *
       * Then perform any tie-break required to finally select a route.
       */
      lc_next = rn->changed->head ;
      if (lc_next != lc_end_id)
        {
          rn->changed->head = rn->changed->tail = lc_end_id ;
          do
            {
              bgp_lc_id_t lc ;

              lc      = lc_next ;
              lc_next = rn->aroutes[lc].next ;
              rn->aroutes[lc].next = lc_id_null ;

              bgp_process_update_lc(rn, pie, lc) ;
            }
          while (lc_next != lc_end_id) ;
        } ;
    } ;

  /* If updates are, in fact, suppressed, then we can stop now.
   */
  if (DISABLE_BGP_ANNOUNCE)
    return ;

  /* If there are any refresh peers, we need to send them the current
   * selection for the relevant context.
   */
  for (refresh_prib = ddl_head(rw->refresh_peers) ;
       refresh_prib != NULL ;
       refresh_prib = ddl_next(refresh_prib, walk_list))
    {
      /* Get the relevant route-info and tell the peer.
       */
      bgp_lc_id_t   lc ;
      route_info ris ;

      lc  = refresh_prib->lc_id ;
      ris = svs_head(rn->aroutes[lc].base, rn->avail) ;
      bgp_route_announce(refresh_prib, pie, ris) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * We have a change in the given rib-node, for the given context.
 */
static void
bgp_process_update_lc(bgp_rib_node rn, prefix_id_entry pie, bgp_lc_id_t lc)
{
  route_info ris ;
  bgp_prib   update_prib ;

  /* Run the route selection process for this context.
   */
  ris = bgp_route_select(rn, lc) ;

  /* But if we are not announcing anything, we can stop now !
   */
  if (DISABLE_BGP_ANNOUNCE)
    return ;

  /* TODO  .. Southbound stuff including Kernel !!
   */

  /* Tell all the "update" peers for this context.
   */
  if (lc == lc_view_id)
    update_prib = rn->it.rib->update_view_peers ;
  else
    update_prib = svec_get(rn->it.rib->update_peers, lc) ;

  while (update_prib != NULL)
    {
      bgp_route_announce(update_prib, pie, ris) ;

      update_prib = sdl_next(update_prib, walk_list) ;
    } ;
} ;

/*==============================================================================
 * Making and sending new announcements
 */
static attr_set bgp_route_announce_check(bgp_prib prib, prefix_id_entry pie,
                                                               route_info ris) ;
static bool bgp_community_filter_out (bgp_prun prun, attr_set attr) ;
static bool bgp_output_filter (bgp_prib prib, prefix pfx, attr_set attr) ;

/*------------------------------------------------------------------------------
 * Announce given route from RIB to the given peer.
 */
static void
bgp_route_announce(bgp_prib prib, prefix_id_entry pie, route_info ris)
{
  attr_set  attr ;
  mpls_tags_t tags ;

  if (ris == NULL)
    {
      /* Withdraw.
       */
      attr = NULL ;
      tags = mpls_tags_null ;
    }
  else
    {
      /* Result is an update -- but we have some filtering to do now.
       */
      attr = bgp_route_announce_check(prib, pie, ris) ;

      if (attr != NULL)
        tags = ris->current.tags ;
      else
        tags = mpls_tags_null ;
    } ;

  bgp_adj_out_update(prib, pie, attr, tags) ;
} ;

/*------------------------------------------------------------------------------
 * Decide whether and how to announce the given route to the given peer.
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
 * Returns:  NULL <=> do not announce -- withdraw instead.
 *           attribute set to be announced -- with one level of lock
 */
static attr_set
bgp_route_announce_check(bgp_prib prib, prefix_id_entry pie, route_info ris)
{
  bgp_prun from_prun, to_prun ;
  attr_set  attr ;
  attr_pair_t pair[1] ;
  route_map rmap ;
  bool reflecting, set_next_hop ;
  qafx_t    qafx ;
  bgp_lc_id_t  lc ;

  qassert(!prib->route_server_client) ;

  qafx = prib->qafx ;
  lc   = prib->lc_id ;

  from_prun = ris->prib->prun ;
  to_prun   = prib->prun ;

  if (from_prun == to_prun)
    return NULL ;                       /* No return to sender          */

  attr = ris->iroutes[lc].attr ;        /* NB: unchanged until loaded   */

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
        if (to_prun->args_r.remote_id == attr->next_hop.ip.v4)
          return NULL ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
#if 0
        if (to_prun->args.remote_id == attr->next_hop.ip.v4)
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
      rmap = to_prun->filter[qafx].us_rmap ;
      if (rmap == NULL)
        return NULL ;
    }
  else
#endif
    rmap = prib->rmap[RMAP_OUT] ;

  /* Default route check -- if we have sent a default, do not send another.
   */
  if (prib->default_sent)
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
  if (bgp_community_filter_out (to_prun, attr))
    return NULL ;

  /* If the attribute has originator-id and it is same as remote to_peer's id.
   *
   * If the attribute has no originator-id, then it will be zero, which is
   * unlikely to be the same as the remote to_peer's id -- but for completeness
   * we check for the existence of an originator-id *after* find equality.
   */
  if ((to_prun->args_r.remote_id == attr->originator_id) &&
                                            (attr->have & atb_originator_id))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (to_prun->log, LOG_DEBUG,
               "%s [Update:SEND] %s originator-id is same as remote router-id",
                                       to_prun->name, spfxtoa(pie->pfx).str) ;
      return NULL ;
    } ;

  /* ORF prefix-list filter check
   */
  if (prib->orf_plist != NULL)
    {
      if (prefix_list_apply (prib->orf_plist, pie->pfx) == PREFIX_DENY)
        {
          if (BGP_DEBUG (filter, FILTER))
           zlog (to_prun->log, LOG_DEBUG,
                 "%s [Update:SEND] %s/ is filtered by ORF",
                                         to_prun->name, spfxtoa(pie->pfx).str) ;
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
        zlog (to_prun->log, LOG_DEBUG, "%s [Update:SEND] %s is filtered",
                                         to_prun->name, spfxtoa(pie->pfx).str) ;
      return NULL ;
    } ;

  /* Outgoing AS path loop check, if required.
   */
  if (bgp_send_aspath_check)
    {
      /* AS path loop check.
       */
      if (as_path_loop_check (attr->asp, to_prun->args_r.remote_as, 0))
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (to_prun->log, LOG_DEBUG,
                  "%s [Update:SEND] suppress announcement to to_peer AS %u"
                                                                " is AS path.",
                  to_prun->name, to_prun->args_r.remote_as);
          return NULL ;
        }

      /* If we're a CONFED we need to loop check the CONFED ID too
       */
      if (to_prun->confed_id_r != BGP_ASN_NULL)
        {
          if (as_path_loop_check(attr->asp, to_prun->confed_id_r, 0))
            {
              if (BGP_DEBUG (filter, FILTER))
                zlog (to_prun->log, LOG_DEBUG,
                      "%s [Update:SEND] suppress announcement to to_peer AS %u"
                                                                " is AS path.",
                      to_prun->name, to_prun->confed_id_r);
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

  switch (to_prun->sort)
    {
      /* For iBGP destination, worry about iBGP source.
       */
      case BGP_PEER_IBGP:
        if (from_prun->sort == BGP_PEER_IBGP)
          {
            /* Both source and destination peers are iBGP.
             *
             * If we are not reflecting between these peers, we do not
             * announce the route.
             */
            if (from_prun->prib[qafx]->route_reflector_client)
              {
                /* A route from a Route-Reflector Client.
                 *
                 * Reflect to all iBGP peers (Client and Non-Client), other
                 * other than the originator.  Have already checked the
                 * originator.  So there is nothing to do...
                 *
                 * ...except for the "no bgp client-to-client" option.
                 */
                if (to_prun->no_client_to_client_r
                                                && prib->route_reflector_client)
                  return bgp_attr_pair_unload(pair) ;
              }
            else
              {
                /* A route from a Non-client.  Reflect only to clients.
                 */
                if (!prib->route_reflector_client)
                  return bgp_attr_pair_unload(pair) ;
              } ;

            reflecting   = true ;
            set_next_hop = false ;

            /* If we don't have an ORIGINATOR-ID, we now set the default.
             */
            if (!(attr->have & atb_originator_id))
              attr = bgp_attr_pair_set_originator_id(pair,
                                                    from_prun->args_r.remote_id) ;
          } ;

        fall_through ;

        /* For iBGP and cBGP destination, worry about local pref
         */
      case BGP_PEER_CBGP:
        if (!(attr->have & atb_local_pref))
          attr = bgp_attr_pair_set_local_pref(pair, brun->args_r.local_pref) ;
        break ;

      /* For eBGP destination:
       *
       *   * clear the MED, unless required to keep it, or unless the source is
       *     ourselves -- may be overridden by route-maps
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
            if ((from_prun != brun->prun_self) && ! prib->med_unchanged)
              attr = bgp_attr_pair_clear_med(pair) ;
          } ;

        if (prib->remove_private_as)
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

      if (prib->next_hop_unchanged)
        set_next_hop = !have_next_hop ;
      else if (prib->next_hop_self)
        set_next_hop = true ;
      else if (!have_next_hop)
        set_next_hop = true ;
      else if ((to_prun->sort == BGP_PEER_EBGP)
                                            && (attr->next_hop.type == nh_ipv4))
        set_next_hop = (bgp_multiaccess_check_v4 (attr->next_hop.ip.v4,
                                                     to_prun->su_name) == 0) ;
      else
        set_next_hop = false ;
    } ;

  if (set_next_hop)
    {
      switch (pie->pfx->family)
        {
          case AF_INET:
            attr = bgp_attr_pair_set_next_hop(pair, nh_ipv4,
                                                  &to_prun->nexthop.v4.s_addr) ;
            break ;

#ifdef HAVE_IPV6
          case AF_INET6:
            attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_1,
                                                  &to_prun->nexthop.v6_global) ;
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

      if (!prib->next_hop_local_unchanged)
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

          if (to_prun->shared_network && !reflecting
                      && ! IN6_IS_ADDR_UNSPECIFIED (&to_prun->nexthop.v6_local))
            {
              attr = bgp_attr_pair_set_next_hop(pair, nh_ipv6_2,
                                                   &to_prun->nexthop.v6_local) ;
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

      brm->prun      = to_prun ;
      brm->attrs     = pair ;
      brm->qafx      = qafx ;
      brm->rmap_type = BGP_RMAP_TYPE_OUT ;

      if (route_map_apply(rmap, pie->pfx,
                           RMAP_BGP | (reflecting ? RMAP_NO_SET : 0), brm)
                                                             == RMAP_DENY_MATCH)
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (to_prun->log, LOG_DEBUG,
                 "%s [Update:SEND] %s is filtered by %s route-map",
                                         to_prun->name, spfxtoa(pie->pfx).str,
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
bgp_community_filter_out (bgp_prun prun, attr_set attr)
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

      switch (prun->sort)
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
bgp_output_filter (bgp_prib prib, prefix pfx, attr_set attr)
{
  access_list dlist ;
  prefix_list plist ;
  as_list     aslist ;

#define FILTER_EXIST_WARN(type, is_set, filter_name) \
  if (BGP_DEBUG (update, UPDATE_OUT) && !(is_set)) \
    plog_warn (prib->prun->log, "%s: output %s-list %s not set", \
                                          prib->prun->name, type, (filter_name))

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
bgp_soft_reconfig_in (bgp_prun prun, qafx_t qafx)
{
  bgp_prib       prib ;

  if (prun->state != bgp_pEstablished)
    return;

  prib = prun->prib[qafx] ;
  qassert(prib != NULL) ;

  if (prib == NULL)
    return ;

  qassert((prun == prib->prun) && (qafx == prib->qafx)) ;

  bgp_adj_in_refresh(prib) ;
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
bgp_soft_reconfig_rsclient_in (bgp_prun rsclient, qafx_t qafx)
{
} ;

/*------------------------------------------------------------------------------
 * Announce all AFI/SAFI to peer
 *
 * Used (eg) when peer becomes established.
 */
extern void
bgp_announce_all_families (bgp_prun prun, uint delay)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    bgp_announce_family (prun, qafx, delay) ;
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
bgp_announce_family (bgp_prun prun, qafx_t qafx, uint delay)
{
  bgp_prib     prib ;

  /* Reasons not to announce the given family to the given peer
   */
  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (prun->state != bgp_pEstablished)
    return;

  if (!(prun->af_running & qafx_bit(qafx)))
    return ;

  prib = prun->prib[qafx] ;
  qassert((prun == prib->prun) && (qafx == prib->qafx)) ;

  if (prib->orf_pfx_wait)
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
  prib->walker = bgp_rib_walker_start_refresh(prib, bgp_process_walker) ;
} ;

/*==============================================================================
 * Clearing.
 *
 */

/*------------------------------------------------------------------------------
 * Normal clearing of given peer for all AFI/SAFI -- in and out.
 */
extern void
bgp_clear_routes(bgp_prun prun, bool nsf)
{
  uint i ;

  assert((prun->state == bgp_pResetting) || (prun->state == bgp_pDeleting)) ;

  prun->nsf_restarting = false ;

  for (i = 0 ; i < prun->prib_running_count ; ++i)
    {
      bgp_prib prib ;

      prib = prun->prib_running[i] ;

      bgp_clear_adj_in(prib, nsf) ;
      bgp_adj_out_discard(prib) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Clear the adj-in for the given prib -- completely or setting everything
 * stale.
 */
extern void
bgp_clear_adj_in(bgp_prib prib, bool nsf)
{
  /* If NSF requested and nsf configured for this q_afi/q_safi, do nsf and
   * set flag to indicate that at least one q_afi/q_safi may have stale routes.
   *
   * Walk the main adj-in and either mark stale or discard.
   */
  if (nsf && prib->nsf_mode)
    {
      prib->prun->nsf_restarting = true ;
      bgp_adj_in_set_stale(prib) ;
    }
  else
    {
      bgp_adj_in_discard(prib) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Walk main RIB and remove all stale routes for the given peer.
 *
 * NB: is required to complete immediately !
 *
 * TODO: walk peer->routes_head[q_afi][q_safi]
 */
extern void
bgp_clear_stale_route(bgp_prun prun, qafx_t qafx)
{
  bgp_prib prib ;

  prib = prun->prib[qafx] ;
  if (prib != NULL)
    bgp_adj_in_discard_stale(prib) ;
} ;


/*==============================================================================
 * Default Route.
 */

/*------------------------------------------------------------------------------
 * Originate a default route from us.
 *
 * Cannot, and does not, announce a default route for MPLS VPN.
 */
extern void
bgp_default_originate (bgp_prun prun, qafx_t qafx, bool withdraw)
{
  bgp_prib        prib ;
  attr_pair_t     attrs[1] ;
  prefix_t        pfx[1] ;
  prefix_id_entry pie ;

  prib = prun->prib[qafx] ;
  qassert(prib != NULL) ;
  if (prib == NULL)
    return ;

  switch (qafx)
    {
      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        prefix_default(pfx, AF_INET) ;
        break ;

#ifdef HAVE_IPV6
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        prefix_default(pfx, AF_INET6) ;
        break ;
#endif

      case qafx_ipv4_mpls_vpn:
      case qafx_ipv6_mpls_vpn:
      default:
        return ;
    } ;

  pie = prefix_id_find_entry(pfx, NULL) ;

  if (!withdraw)
    {
      bgp_run    brun;
      route_map  default_rmap ;

      bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP);

      default_rmap = prib->default_rmap ;

      brun = prun->brun;

      bgp_attr_pair_set_local_pref(attrs, brun->args_r.local_pref) ;

// TODO .......... either set self as next hop at the last moment, or  ...............
//                 have a common function for doing this ??

      switch (qafx)
        {
          case qafx_ipv4_unicast:
          case qafx_ipv4_multicast:
            bgp_attr_pair_set_next_hop(attrs, nh_ipv4,
                                                    &prun->nexthop.v4.s_addr) ;
            break ;

#ifdef HAVE_IPV6
          case qafx_ipv6_unicast:
          case qafx_ipv6_multicast:
            bgp_attr_pair_set_next_hop(attrs, nh_ipv6_1,
                                                     &prun->nexthop.v6_global) ;

            if (prun->shared_network
                         && !IN6_IS_ADDR_UNSPECIFIED (&prun->nexthop.v6_local))
              bgp_attr_pair_set_next_hop(attrs, nh_ipv6_2,
                                                      &prun->nexthop.v6_local) ;
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

          brm->prun      = brun->prun_self ;
          brm->attrs     = attrs ;
          brm->qafx      = qafx ;
          brm->rmap_type = BGP_RMAP_TYPE_DEFAULT ;

          withdraw = route_map_apply(default_rmap, pfx, RMAP_BGP, brm)
                                                            == RMAP_DENY_MATCH ;
        } ;
    } ;

  if (withdraw)
    {
      if (prib->default_sent)
        {
          bgp_adj_out_update(prib, pie, NULL, mpls_tags_null) ;
          prib->default_sent = false ;
        } ;
    }
  else
    {
      attr_set  stored ;

      stored = bgp_attr_pair_store(attrs) ;

      bgp_adj_out_update(prib, pie, stored, mpls_tags_null) ;
      prib->default_sent = true ;
    } ;

  /* Tidy up reference counts etc.
   */
  prefix_id_entry_dec_ref(pie) ;
  bgp_attr_pair_unload(attrs) ;
} ;


/*==============================================================================
 * Redistribution of routes from Zebra -- TODO !!!
 */
extern void
bgp_redistribute_add (prefix p, ip_union next_hop, uint32_t metric, byte type)
{
  assert(false) ;
} ;

extern void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  assert(false) ;
} ;

extern void
bgp_redistribute_withdraw_all(bgp_inst bgp, qAFI_t q_afi, int type)
{
  assert(false) ;
} ;

#if 0

static void bgp_redistribute_update(bgp_inst bgp, prefix p, attr_pair attrs,
                                                       qafx_t qafx, byte type) ;
static void bgp_redistribute_withdraw(bgp_inst bgp, prefix p,
                                                       qafx_t qafx, byte type) ;

/*------------------------------------------------------------------------------
 * Redistribute route treatment.
 */
extern void
bgp_redistribute_add (prefix p, ip_union next_hop, uint32_t metric, byte type)
{
  bgp_inst bgp;
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

extern void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  bgp_inst bgp;
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
bgp_redistribute_withdraw_all(bgp_inst bgp, qAFI_t q_afi, int type)
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
bgp_redistribute_update(bgp_inst bgp, prefix p, attr_pair attrs,
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
bgp_redistribute_withdraw(bgp_inst bgp, prefix p, qafx_t qafx, byte type)
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
#endif





/*==============================================================================
 *
 */


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


extern int
bgp_config_write_distance (vty vty, bgp_inst bgp)
{
  struct bgp_node *rn;
  struct bgp_distance *bdistance;
  bgp_args args_c ;

  /* Distance configuration.
   */
  args_c = &bgp->config->c_args ;
  if (   (   (args_c->distance_ebgp   != 0)
          && (args_c->distance_ibgp   != 0)
          && (args_c->distance_local  != 0) )
      && (   (args_c->distance_ebgp  != ZEBRA_EBGP_DISTANCE_DEFAULT)
          || (args_c->distance_ibgp  != ZEBRA_IBGP_DISTANCE_DEFAULT)
          || (args_c->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT) ) )
    vty_out (vty, " distance bgp %d %d %d\n",
             args_c->distance_ebgp,
             args_c->distance_ibgp,
             args_c->distance_local);

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
bgp_distance_apply (bgp_prun prun, prefix_c p)
{
  struct bgp_node *rn;
  struct prefix_ipv4 q;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (p->family != AF_INET)
    return 0;

  if (prun->su_name->sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family    = AF_INET ;
  q.prefix    = prun->su_name->sin.sin_addr ;
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
  rn = bgp_node_lookup (prun->brun->rib[qafx_ipv4_unicast]->route, p) ;
  if (rn != NULL)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
        {
          if (prun->brun->args_r.distance_local)
            return prun->brun->args_r.distance_local;
          else
            return ZEBRA_IBGP_DISTANCE_DEFAULT;
        }
    }

  if (prun->sort == BGP_PEER_EBGP)
    {
      if (prun->brun->args_r.distance_ebgp != 0)
        return prun->brun->args_r.distance_ebgp ;

      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (prun->brun->args_r.distance_ibgp != 0)
        return prun->brun->args_r.distance_ibgp;

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
  bgp_inst bgp;

  bgp = vty->index;

  bgp->config->c_args.distance_ebgp  = atoi (argv[0]);
  bgp->config->c_args.distance_ibgp  = atoi (argv[1]);
  bgp->config->c_args.distance_local = atoi (argv[2]);
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
  bgp_inst bgp;

  bgp = vty->index;

  bgp->config->c_args.distance_ebgp  = 0;
  bgp->config->c_args.distance_ibgp  = 0;
  bgp->config->c_args.distance_local = 0;
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

/*------------------------------------------------------------------------------
 * Table of bgp_route commands
 */
CMD_INSTALL_TABLE(static, bgp_route_cmd_table, BGPD) =
{
  { BGP_NODE,        &bgp_distance_cmd                                  },
  { BGP_NODE,        &no_bgp_distance_cmd                               },
  { BGP_NODE,        &no_bgp_distance2_cmd                              },
  { BGP_NODE,        &bgp_distance_source_cmd                           },
  { BGP_NODE,        &no_bgp_distance_source_cmd                        },
  { BGP_NODE,        &bgp_distance_source_access_list_cmd               },
  { BGP_NODE,        &no_bgp_distance_source_access_list_cmd            },

  CMD_INSTALL_END
} ;

/*============================================================================*/

extern void
bgp_route_cmd_init (void)
{
  cmd_install_table(bgp_route_cmd_table) ;
}

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

/* Allocate routing table structure                                     */
extern void
bgp_route_init (void)
{
  /* Init BGP distance table.
   */
  bgp_distance_table = bgp_table_init (qafx_ipv4_unicast);
} ;

void
bgp_route_finish (void)
{
  bgp_table_unlock (bgp_distance_table);
  bgp_distance_table = NULL;
}
