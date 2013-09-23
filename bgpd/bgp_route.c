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

#include "bgpd/bgpd.h"

#include "bgpd/bgp_peer.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
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
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_names.h"

/*------------------------------------------------------------------------------
 * For given table and prefix: find or add node --
 *
 * Once a node has been created, the prefix and any prn are stable, until the
 * lock expires.
 */
static struct bgp_node *
bgp_afi_node_get (struct bgp_table *table, afi_t afi, safi_t safi, struct prefix *p,
                  struct prefix_rd *prd)
{
  struct bgp_node *rn;
  struct bgp_node *prn = NULL;

  assert (table);
  if (!table)
    return NULL;

  if (safi == SAFI_MPLS_VPN)
    {
      prn = bgp_node_get (table, (struct prefix *) prd);

      if (prn->info == NULL)
        prn->info = bgp_table_init (afi, safi);
      else
        bgp_unlock_node (prn);

      table = prn->info;
    }

  rn = bgp_node_get (table, p);

  if (safi == SAFI_MPLS_VPN)
    rn->prn = prn;

  return rn;
}

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
static struct bgp_info *
bgp_info_new (void)
{
  return XCALLOC (MTYPE_BGP_ROUTE, sizeof (struct bgp_info));
}

/*------------------------------------------------------------------------------
 * Free bgp route information.
 *
 * By the time we get to here MUST have been through bgp_info_reap(), which
 * discards the contents of the bgp_info and does all the necessary unlocks.
 */
static void
bgp_info_free (struct bgp_info *binfo)
{
  qassert(binfo->attr  == NULL) ;
  qassert(binfo->extra == NULL) ;
  qassert(binfo->peer  == NULL) ;
  qassert(binfo->rn    == NULL) ;

  if (binfo->attr)
    bgp_attr_unintern (binfo->attr);    /* belt-and-braces              */

  bgp_info_extra_free (&binfo->extra);  /* ditto                        */

  XFREE (MTYPE_BGP_ROUTE, binfo);
}

struct bgp_info *
bgp_info_lock (struct bgp_info *binfo)
{
  binfo->lock++;
  return binfo;
}

struct bgp_info *
bgp_info_unlock (struct bgp_info *binfo)
{
  assert (binfo && binfo->lock > 0);
  binfo->lock--;

  if (binfo->lock == 0)
    {
#if 0
      zlog_debug ("%s: unlocked and freeing", __func__);
      zlog_backtrace (LOG_DEBUG);
#endif
      bgp_info_free (binfo);
      return NULL;
    }

#if 0
  if (binfo->lock == 1)
    {
      zlog_debug ("%s: unlocked to 1", __func__);
      zlog_backtrace (LOG_DEBUG);
    }
#endif

  return binfo;
}

/*------------------------------------------------------------------------------
 * Add the given (new) bgp_info to the given bgp_node, and add to peer's list.
 *
 * Takes a lock on: bgp_node, the peer and itself.
 */
extern void
bgp_info_add (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_peer          peer = ri->peer ;
  struct bgp_info** routes_head ;

  /* add to list of routes for this bgp_node
   */
  ri->rn = rn ;
  ri->info_next = rn->info;
  ri->info_prev = NULL;
  if (rn->info != NULL)
    ((struct bgp_info*)rn->info)->info_prev = ri;
  rn->info = ri;

  /* add to list of routes for this peer
   */
  routes_head = &(peer->routes_head[rn->table->afi][rn->table->safi]) ;
  ri->routes_next = *routes_head ;
  ri->routes_prev = NULL ;
  if (*routes_head != NULL)
    (*routes_head)->routes_prev = ri ;
  *routes_head = ri ;

  bgp_info_lock (ri);           /* rn->info                     */
  bgp_peer_lock (peer);         /* ri->peer                     */
  bgp_lock_node (rn);           /* ri->rn                       */
}

/*------------------------------------------------------------------------------
 * Do the actual removal of info from RIB, for use by bgp_process
 * completion callback *only*
 *
 * The bgp_info is hung off the bgp_node and represents an available route
 * for that prefix from the peer.
 *
 * It is also referred to by all currently active bgp_advertise objects,
 * one per being-updated peer.
 *
 * So, when a route becomes unavailable, the bgp_info remains, until the
 * bgp_process mechanism selects a new route for the prefix, and cleans up
 * all advertisements for the prefix -- across all peers.
 *
 * Between changing the state of a route and getting to bgp_process, it is
 * possible (one assumes) that currently pending advertisements may be
 * sent... so a route which was selected and announced will be dispatched,
 * even if it has been withdrawn or changed in the meantime.  Such is life.
 *
 * More serious would be any failure to clean up all bgp_advertise (adv)
 * objects referring to a *reaped* bgp_info...
 *
 * ...so, what this does is remove the bgp_info from the routes known to the
 * bgp_node and the owning peer.  It is possible that are then a number of
 * adv objects pointing to this bgp_info -- each owning a lock on the bgp_info.
 * It is expected that following the reap, all adv objects will be killed
 * off, before the adv is processed into an update.  However, in case that
 * does not happen the binfo is left in a cleared down:
 *
 *   * NULL rn pointer
 *
 *   * NULL peer pointer
 *
 *   * no attributes
 *
 *   * flags = BGP_INFO_REAPED
 *
 *   * no uptime.
 *
 * But:
 *
 *   * the type and subtype of the route are preserved.
 *
 * Any adv found in this state are turned into withdraws.
 */
static void
bgp_info_reap (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_peer          peer = ri->peer ;
  struct bgp_info** routes_head ;

  assert(ri->rn == rn) ;

  /* remove from list of routes for the bgp_node        */
  if (ri->info_next)
    ri->info_next->info_prev = ri->info_prev;
  if (ri->info_prev)
    ri->info_prev->info_next = ri->info_next;
  else
    rn->info = ri->info_next;

  /* remove from list of routes for the peer            */
  routes_head = &(peer->routes_head[rn->table->afi][rn->table->safi]) ;
  if (ri->routes_next != NULL)
    ri->routes_next->routes_prev = ri->routes_prev ;
  if (ri->routes_prev != NULL)
    ri->routes_prev->routes_next = ri->routes_next ;
  else
    *routes_head = ri->routes_next ;

  /* Unlock everything and dismantle pretty much everything -- leaves:
   *
   *   * type and subtype of route
   */
  if (ri->attr)
    ri->attr = bgp_attr_unintern (ri->attr);

  bgp_info_extra_free (&ri->extra);

  bgp_peer_unlock (ri->peer) ;          /* fewer references to peer     */
  ri->peer = NULL ;

  bgp_unlock_node (ri->rn) ;            /* fewer references to bgp_node */
  ri->rn   = NULL ;

  ri->flags = BGP_INFO_REAPED ;         /* no longer anything           */

  ri->uptime = 0 ;                      /* not up !                     */

  /* Finally, unlock self which may (well) free the object.
   */
  bgp_info_unlock (ri);
} ;

/*------------------------------------------------------------------------------
 * "Delete" route
 *
 * Sets BGP_INFO_REMOVED and clears BGP_INFO_VALID and then leaves it up to the
 * processing logic to actually flush the route away.
 */
extern void
bgp_info_delete (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_set_flag (rn, ri, BGP_INFO_REMOVED);
  /* set of previous already took care of pcount */
  UNSET_FLAG (ri->flags, BGP_INFO_VALID);
}

/*------------------------------------------------------------------------------
 * undo the effects of a previous call to bgp_info_delete; typically
 * called when a route is deleted and then quickly re-added before the
 * deletion has been processed
 */
static void
bgp_info_restore (struct bgp_node *rn, struct bgp_info *ri)
{
  bgp_info_unset_flag (rn, ri, BGP_INFO_REMOVED);
  /* unset of previous already took care of pcount */
  SET_FLAG (ri->flags, BGP_INFO_VALID);
}

/* Adjust pcount as required
 */
static void
bgp_pcount_adjust (struct bgp_node *rn, struct bgp_info *ri)
{
  assert (rn && rn->table);
  assert (ri && ri->peer && ri->peer->bgp);

  /* Ignore 'pcount' for RS-client tables
   */
  if ((rn->table->type != BGP_TABLE_MAIN) ||
                                         (ri->peer == ri->peer->bgp->peer_self))
    return;

  if (BGP_INFO_HOLDDOWN (ri) && (ri->flags & BGP_INFO_COUNTED))
    {
      UNSET_FLAG (ri->flags, BGP_INFO_COUNTED);

      /* slight hack, but more robust against errors.
       */
      if (ri->peer->pcount[rn->table->afi][rn->table->safi])
        ri->peer->pcount[rn->table->afi][rn->table->safi]--;
      else
        {
          zlog_warn ("%s: Asked to decrement 0 prefix count for peer %s",
                     __func__, ri->peer->host);
          zlog_backtrace (LOG_WARNING);
          zlog_warn ("%s: Please report to Quagga bugzilla", __func__);
        }
    }
  else if (!BGP_INFO_HOLDDOWN (ri) && !(ri->flags & BGP_INFO_COUNTED))
    {
      SET_FLAG (ri->flags, BGP_INFO_COUNTED);
      ri->peer->pcount[rn->table->afi][rn->table->safi]++;
    }
}

/* Set/unset bgp_info flags, adjusting any other state as needed.
 * This is here primarily to keep prefix-count in check.
 */
void
bgp_info_set_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  SET_FLAG (ri->flags, flag);

  /* early bath if we know it's not a flag that changes useability state
   */
  if (flag & (BGP_INFO_VALID | BGP_INFO_UNUSEABLE))
    bgp_pcount_adjust (rn, ri);
}

void
bgp_info_unset_flag (struct bgp_node *rn, struct bgp_info *ri, u_int32_t flag)
{
  UNSET_FLAG (ri->flags, flag);

  /* early bath if we know it's not a flag that changes useability state
   */
  if (flag & (BGP_INFO_VALID | BGP_INFO_UNUSEABLE))
    bgp_pcount_adjust (rn, ri);
}

/* Get MED value.  If MED value is missing and "bgp bestpath
   missing-as-worst" is specified, treat it as the worst value. */
static u_int32_t
bgp_med_value (struct attr *attr, struct bgp *bgp)
{
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    return attr->med;
  else
    {
      if (bgp_flag_check (bgp, BGP_FLAG_MED_MISSING_AS_WORST))
        return BGP_MED_MAX;
      else
        return 0;
    }
}

/* Compare two bgp route entity.  br is preferable then return 1. */
static int
bgp_info_cmp (struct bgp *bgp, struct bgp_info *new, struct bgp_info *exist)
{
  u_int32_t new_pref;
  u_int32_t exist_pref;
  u_int32_t new_med;
  u_int32_t exist_med;
  u_int32_t new_weight = 0;
  u_int32_t exist_weight = 0;
  struct in_addr new_id;
  struct in_addr exist_id;
  int new_cluster;
  int exist_cluster;
  int internal_as_route = 0;
  int confed_as_route = 0;
  int ret;
  bgp_peer_sort_t new_sort, exist_sort ;

  /* 0. Null check.
   */
  if (new == NULL)
    return 0;
  if (exist == NULL)
    return 1;

  /* 1. Weight check.
   */
  if (new->attr->extra)
    new_weight = new->attr->extra->weight;
  if (exist->attr->extra)
    exist_weight = exist->attr->extra->weight;
  if (new_weight > exist_weight)
    return 1;
  if (new_weight < exist_weight)
    return 0;

  /* 2. Local preference check.
   */
  if (new->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    new_pref = new->attr->local_pref;
  else
    new_pref = bgp->default_local_pref;

  if (exist->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    exist_pref = exist->attr->local_pref;
  else
    exist_pref = bgp->default_local_pref;

  if (new_pref > exist_pref)
    return 1;
  if (new_pref < exist_pref)
    return 0;

  /* 3. Local route check.
   */
  if (new->sub_type == BGP_ROUTE_STATIC)
    return 1;
  if (exist->sub_type == BGP_ROUTE_STATIC)
    return 0;

  if (new->sub_type == BGP_ROUTE_REDISTRIBUTE)
    return 1;
  if (exist->sub_type == BGP_ROUTE_REDISTRIBUTE)
    return 0;

  if (new->sub_type == BGP_ROUTE_AGGREGATE)
    return 1;
  if (exist->sub_type == BGP_ROUTE_AGGREGATE)
    return 0;

  /* 4. AS path length check.
   */
  if (! bgp_flag_check (bgp, BGP_FLAG_ASPATH_IGNORE))
    {
      int exist_hops = aspath_count_hops (exist->attr->aspath);
      int exist_confeds = aspath_count_confeds (exist->attr->aspath);

      if (bgp_flag_check (bgp, BGP_FLAG_ASPATH_CONFED))
        {
          int aspath_hops;

          aspath_hops = aspath_count_hops (new->attr->aspath);
          aspath_hops += aspath_count_confeds (new->attr->aspath);

          if ( aspath_hops < (exist_hops + exist_confeds))
            return 1;
          if ( aspath_hops > (exist_hops + exist_confeds))
            return 0;
        }
      else
        {
          int newhops = aspath_count_hops (new->attr->aspath);

          if (newhops < exist_hops)
            return 1;
          if (newhops > exist_hops)
            return 0;
        }
    }

  /* 5. Origin check.
   */
  if (new->attr->origin < exist->attr->origin)
    return 1;
  if (new->attr->origin > exist->attr->origin)
    return 0;

  /* 6. MED check.
   */
  internal_as_route = ((aspath_count_hops (new->attr->aspath) == 0) &&
                       (aspath_count_hops (exist->attr->aspath) == 0));
  confed_as_route = ((aspath_count_confeds (new->attr->aspath) > 0) &&
                     (aspath_count_confeds (exist->attr->aspath) > 0) &&
                     (aspath_count_hops (new->attr->aspath) == 0) &&
                     (aspath_count_hops (exist->attr->aspath) == 0));

  if (bgp_flag_check (bgp, BGP_FLAG_ALWAYS_COMPARE_MED)
      || (bgp_flag_check (bgp, BGP_FLAG_MED_CONFED) && confed_as_route)
      || aspath_cmp_left (new->attr->aspath, exist->attr->aspath)
      || aspath_cmp_left_confed (new->attr->aspath, exist->attr->aspath)
      || internal_as_route)
    {
      new_med = bgp_med_value (new->attr, bgp);
      exist_med = bgp_med_value (exist->attr, bgp);

      if (new_med < exist_med)
        return 1;
      if (new_med > exist_med)
        return 0;
    }

  /* 7. Peer type check.  CONFED and iBGP rank equal, "internal" (RFC5065)
   */
  new_sort   = peer_sort(new->peer) ;
  exist_sort = peer_sort(exist->peer) ;

  if ((new_sort == BGP_PEER_EBGP)   && (exist_sort == BGP_PEER_IBGP))
    return 1;
  if ((new_sort == BGP_PEER_EBGP)   && (exist_sort == BGP_PEER_CONFED))
    return 1;
  if ((new_sort == BGP_PEER_IBGP)   && (exist_sort == BGP_PEER_EBGP))
    return 0;
  if ((new_sort == BGP_PEER_CONFED) && (exist_sort == BGP_PEER_EBGP))
    return 0;

  /* 8. IGP metric check.
   */
  if (new->extra || exist->extra)
    {
      uint32_t newm = (new->extra ? new->extra->igpmetric : 0);
      uint32_t existm = (exist->extra ? exist->extra->igpmetric : 0);

      if (newm < existm)
        return 1;
      if (newm > existm)
        return 0;
    }

  /* 9. Maximum path check. */

  /* 10. If both paths are external, prefer the path that was received
     first (the oldest one).  This step minimizes route-flap, since a
     newer path won't displace an older one, even if it was the
     preferred route based on the additional decision criteria below.
   */
  if (! bgp_flag_check (bgp, BGP_FLAG_COMPARE_ROUTER_ID)
      && (new_sort   == BGP_PEER_EBGP)
      && (exist_sort == BGP_PEER_EBGP) )
    {
      if (new->flags & BGP_INFO_SELECTED)
        return 1;
      if (exist->flags & BGP_INFO_SELECTED)
        return 0;
    }

  /* 11. Router-ID comparision.
   */
  if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    new_id.s_addr = new->attr->extra->originator_id.s_addr;
  else
    new_id.s_addr = new->peer->remote_id.s_addr;
  if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
    exist_id.s_addr = exist->attr->extra->originator_id.s_addr;
  else
    exist_id.s_addr = exist->peer->remote_id.s_addr;

  if (ntohl (new_id.s_addr) < ntohl (exist_id.s_addr))
    return 1;
  if (ntohl (new_id.s_addr) > ntohl (exist_id.s_addr))
    return 0;

  /* 12. Cluster length comparision.
   */
  if (new->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    new_cluster = new->attr->extra->cluster->length;
  else
    new_cluster = 0;
  if (exist->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
    exist_cluster = exist->attr->extra->cluster->length;
  else
    exist_cluster = 0;

  if (new_cluster < exist_cluster)
    return 1;
  if (new_cluster > exist_cluster)
    return 0;

  /* 13. Neighbor address comparision.
   */
  ret = sockunion_cmp (new->peer->su_remote, exist->peer->su_remote);

  if (ret == 1)
    return 0;
  if (ret == -1)
    return 1;

  return 1;
}

static enum filter_type
bgp_input_filter (struct peer *peer, struct prefix *p, struct attr *attr,
                  afi_t afi, safi_t safi)
{
  struct bgp_filter *filter ;
  struct prefix_list* plist ;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARNING(F,f,filter) \
  plog_warn (peer->log, "%s: Could not find configured input %s-list %s!", \
               peer->host, #f, F ## _IN_NAME(filter))


#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_IN) && !(F ## _IN_LIST (filter))) \
    FILTER_EXIST_WARNING(F,f,filter)

  if (DISTRIBUTE_IN_NAME (filter))
    {
      FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter) ;

      if (access_list_apply (DISTRIBUTE_IN_LIST (filter), p) == FILTER_DENY)
        return FILTER_DENY;
    }

  plist = PREFIX_LIST_IN_LIST(filter) ;
  if (plist != NULL)
    {
      if (!prefix_list_is_set(plist))
        FILTER_EXIST_WARNING(PREFIX_LIST, prefix, filter) ;

      if (prefix_list_apply (plist, p) == PREFIX_DENY)
        return FILTER_DENY;
    }

  if (FILTER_LIST_IN_NAME (filter))
    {
      FILTER_EXIST_WARN(FILTER_LIST, as, filter);

      if (as_list_apply (FILTER_LIST_IN_LIST (filter), attr->aspath)
                                                              == AS_FILTER_DENY)
        return FILTER_DENY;
    }

  return FILTER_PERMIT;

#undef FILTER_EXIST_WARNING
#undef FILTER_EXIST_WARN
}

static enum filter_type
bgp_output_filter (struct peer *peer, struct prefix *p, struct attr *attr,
                   afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct prefix_list* plist ;

  filter = &peer->filter[afi][safi];

#define FILTER_EXIST_WARNING(F,f,filter) \
  plog_warn (peer->log, "%s: Could not find configured output %s-list %s!", \
             peer->host, #f, F ## _OUT_NAME(filter))

#define FILTER_EXIST_WARN(F,f,filter) \
  if (BGP_DEBUG (update, UPDATE_OUT) && !(F ## _OUT_LIST (filter))) \
    FILTER_EXIST_WARNING(F,f,filter)

  if (DISTRIBUTE_OUT_NAME (filter))
    {
      FILTER_EXIST_WARN(DISTRIBUTE, distribute, filter);

      if (access_list_apply (DISTRIBUTE_OUT_LIST (filter), p) == FILTER_DENY)
        return FILTER_DENY;
    }

  plist = PREFIX_LIST_OUT_LIST (filter) ;
  if (plist != NULL)
    {
      if (!prefix_list_is_set(plist))
        FILTER_EXIST_WARNING(PREFIX_LIST, prefix, filter) ;

      if (prefix_list_apply (plist, p) == PREFIX_DENY)
        return FILTER_DENY;
    }

  if (FILTER_LIST_OUT_NAME (filter))
    {
      FILTER_EXIST_WARN(FILTER_LIST, as, filter);

      if (as_list_apply (FILTER_LIST_OUT_LIST (filter), attr->aspath)
                                                              == AS_FILTER_DENY)
      return FILTER_DENY;
    }

  return FILTER_PERMIT;

#undef FILTER_EXIST_WARNING
#undef FILTER_EXIST_WARN
}

/* If community attribute includes no_export then return 1.
 */
static int
bgp_community_filter (struct peer *peer, struct attr *attr)
{
  if (attr->community)
    {
      bgp_peer_sort_t sort = peer_sort(peer) ;

      /* NO_ADVERTISE check. */
      if (community_include (attr->community, COMMUNITY_NO_ADVERTISE))
        return 1;

      /* NO_EXPORT check. */
      if ((sort == BGP_PEER_EBGP) &&
          community_include (attr->community, COMMUNITY_NO_EXPORT))
        return 1;

      /* NO_EXPORT_SUBCONFED check. */
      if ((sort == BGP_PEER_EBGP) || (sort == BGP_PEER_CONFED))
        if (community_include (attr->community, COMMUNITY_NO_EXPORT_SUBCONFED))
          return 1;
    }
  return 0;
}

/* Route reflection loop check.
 */
static int
bgp_cluster_filter (struct peer *peer, struct attr *attr)
{
  struct in_addr cluster_id;

  if (attr->extra && attr->extra->cluster)
    {
      if (peer->bgp->config & BGP_CONFIG_CLUSTER_ID)
        cluster_id = peer->bgp->cluster_id;
      else
        cluster_id = peer->bgp->router_id;

      if (cluster_loop_check (attr->extra->cluster, cluster_id))
        return 1;
    }
  return 0;
}

/*------------------------------------------------------------------------------
 * Process given attributes against any in route-map.
 *
 * Returns:  *copy* of the given attr, modified and interned
 *       or: NULL <=> denied.
 *
 * NB: the structure pointed to by attr is untouched.
 *
 * NB: All the elements of the incoming attr MUST have been internalised.
 *
 *    This is because a copy -- bgp_attr_dup() -- of those attributes is handed
 *    to the route-map.  Any element of the attributes which is changed is
 *    overwritten by the route-map, with a reference count of '0'.  So, any
 *    further changes in the route-map can discard previous entries whose
 *    reference count is 0 -- because otherwise memory would leak.  So, if
 *    any element started with a 0 reference count, it could be discarded,
 *    but would leave a dangling reference in the original !
 */
static struct attr*
bgp_input_modifier (struct peer *peer, struct prefix *p, struct attr *attr,
                    afi_t afi, safi_t safi)
{
  struct bgp_filter *filter;
  struct attr        rmap_attr_s ;
  struct attr*       rmap_attr ;

  qassert(bgp_sub_attr_are_interned(attr)) ;

  rmap_attr = NULL ;

  /* Apply default weight value.
   */
  if (peer->weight)
    {
      rmap_attr = bgp_attr_dup (&rmap_attr_s, attr) ;

      (bgp_attr_extra_get (rmap_attr))->weight = peer->weight;
    } ;

  /* Route map apply.
   */
  filter = &peer->filter[afi][safi];

  if (ROUTE_MAP_IN_NAME (filter))
    {
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      /* Duplicate current value to new structure for modification.
       */
      if (rmap_attr == NULL)
        rmap_attr = bgp_attr_dup (&rmap_attr_s, attr) ;

      /* Apply BGP route map to the attribute.
       */
      info_s.peer = peer;
      info_s.attr = rmap_attr;

      info_s.peer->rmap_type = PEER_RMAP_TYPE_IN ;
      ret = route_map_apply (ROUTE_MAP_IN (filter), p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
        {
          /* Discard any new elements set by the route-map -- these will have
           * reference counts == 0.
           *
           * Discard any "extra" part of the duplicated attributes.
           */
          return bgp_attr_flush (rmap_attr);
        } ;
    } ;

  /* If the attributes may have changed, intern the result.
   *
   * Otherwise, intern the incoming stuff
   */
  if (rmap_attr != NULL)
    return bgp_attr_intern_temp(rmap_attr) ;
  else
    return bgp_attr_intern(attr) ;
} ;

/*------------------------------------------------------------------------------
 * Structure to capture route-server route.
 *
 * Main purpose of this is to do any required rs-in route-map once when
 * updating a set of route server clients, and not at all if there are no
 * route server clients for the given afi/safi.
 */
struct rs_route
{
  bool              rs_in_applied ;     /* whether rs-in applied yet          */
  bool              rs_in_deny ;        /* answer when it has been            */

  /* The orig_attr MUST have all elements interned, but may or may not be
   * interned itself.
   */
  struct attr*      orig_attr ;         /* attributes before rs-in applied    */

  /* The rs_in_attr is interned when the pointer is set.
   *
   * The pointer is NULL if the rs-in has not been applied, and remains NULL
   * if the answer is RMAP_DENY.
   */
  struct attr*      rs_in_attr ;        /* attributes after rs-in applied     */

  /* The other attributes of the route                          */

  struct peer*      peer ;

  afi_t             afi ;
  safi_t            safi ;

  struct prefix*    p ;

  int               type ;
  int               sub_type ;

  struct prefix_rd* prd ;
  u_char*           tag ;
};

/*------------------------------------------------------------------------------
 * Set up an rs_route object.
 */
static void
bgp_rs_route_init(struct rs_route* rt, afi_t afi, safi_t safi,
                   struct attr* attr, struct peer* peer, struct prefix* p,
                    int type, int sub_type, struct prefix_rd* prd, u_char* tag)
{
  rt->rs_in_applied  = false ;
  rt->rs_in_deny     = true ;   /* invalid while !rs_in_applied */
  rt->rs_in_attr     = NULL ;   /* nothing yet                  */

  qassert(bgp_sub_attr_are_interned(attr)) ;

  rt->orig_attr      = attr ;

  rt->peer           = peer ;
  rt->afi            = afi ;
  rt->safi           = safi ;
  rt->p              = p ;
  rt->type           = type ;
  rt->sub_type       = sub_type ;
  rt->prd            = prd ;
  rt->tag            = tag ;
} ;

/*------------------------------------------------------------------------------
 * Reset an rs_route object.
 *
 * Discards any rs_in_attr and clears the rs_in_applied flag.
 *
 * Leaves everything else -- so can be reused pretty much as is.
 */
static void
bgp_rs_route_reset(struct rs_route* rt)
{
  rt->rs_in_applied  = false ;
  rt->rs_in_deny     = true ;   /* invalid while !rs_in_applied */
  if (rt->rs_in_attr != NULL)
    rt->rs_in_attr = bgp_attr_unintern(rt->rs_in_attr) ;
} ;

/*------------------------------------------------------------------------------
 * Process rt->orig_attr against any rs-in route-map.
 *
 * If the result is RMAP_PERMIT, then rt->rs_in_attr will be set to a newly
 * internalised version of the attributes.
 *
 * If the result is RMAP_DENY, then rt->rs_in_attr is left NULL.
 *
 * The structure pointed to by rt->orig_attr is untouched.
 *
 * NB: All the elements of the incoming rt->orig_attr must have been
 *     internalised.
 *
 *    This is because a copy -- bgp_attr_dup() -- of those attributes is handed
 *    to the route-map.  Any element of the attributes which is changed is
 *    overwritten by the route-map -- and if it has a 0 reference count, the
 *    sub-attr will be deleted.  So, by ensuring that all sub-attr which are
 *    copied in are interned, the only uninterned sub-attr are created by
 *    the route-map.
 *
 *    Note that we do not care whether the rt->orig_attr itself is interned
 *    or not.  The resulting rt->rs_in_attr is a freshly interned copy of
 *    rt->orig_attr.
 *
 * NB: must NOT be called more than once for the same "rt", hence the
 *     "rs_in_applied" flag.
 */
static void
bgp_rs_input_modifier (struct rs_route* rt)
{
  struct bgp_filter *filter;

  assert(! rt->rs_in_applied && (rt->rs_in_attr == NULL)) ;
  qassert(bgp_sub_attr_are_interned(rt->orig_attr)) ;

  rt->rs_in_applied = true ;

  /* Route map apply.
   */
  filter = &rt->peer->filter[rt->afi][rt->safi];

  if (ROUTE_MAP_RS_IN_NAME (filter))
    {
      struct bgp_info    info_s = { 0 } ;
      route_map_result_t ret ;
      struct attr*       rmap_attr ;
      struct attr        rmap_attr_s ;

      /* bgp_attr_dup(), copies the contents of the attributes, complete with
       * a new 'extra', which contains a copy of the original.
       */
      rmap_attr = bgp_attr_dup(&rmap_attr_s, rt->orig_attr) ;

      /* Apply BGP route map to the attribute.
       */
      info_s.peer = rt->peer;
      info_s.attr = rmap_attr ;

      info_s.peer->rmap_type = PEER_RMAP_TYPE_RS_IN ;
      ret = route_map_apply(ROUTE_MAP_RS_IN(filter), rt->p, RMAP_BGP, &info_s) ;

      if (ret == RMAP_DENYMATCH)
        {
          /* Discard any new elements set by the route-map -- these will have
           * reference counts == 0.
           */
          rt->rs_in_attr = bgp_attr_flush (rmap_attr);
          rt->rs_in_deny = true ;
        }
      else
        {
          /* Intern the result of the route-map as the rs_in_attr.
           */
          rt->rs_in_attr = bgp_attr_intern_temp(rmap_attr) ;
          rt->rs_in_deny = false ;
        } ;

    }
  else
    {
      /* Simply intern the original
       */
      rt->rs_in_attr = bgp_attr_intern(rt->orig_attr) ;
      rt->rs_in_deny = false ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Take the already interned client_attr, and if required apply the export
 * route-map for the peer.
 *
 * If not DENY, returns interned client_attr, which may or may not have changed.
 *
 * If DENY, returns NULL and the client_attr will have been uninterned.
 */
static struct attr*
bgp_export_modifier (struct peer *rsclient, struct rs_route* rt,
                                                       struct attr* client_attr)
{
  struct bgp_filter *filter;

  qassert(bgp_attr_is_interned(client_attr)) ;

  /* Route map apply.
   */
  filter = &rt->peer->filter[rt->afi][rt->safi];

  if (ROUTE_MAP_EXPORT_NAME (filter))
    {
      struct bgp_info    info_s = { 0 } ;
      struct attr        rmap_attr_s ;
      struct attr*       rmap_attr ;
      struct attr*       old_attr ;
      route_map_result_t ret;

      /* Duplicate current value to new structure for modification.
       */
      rmap_attr = bgp_attr_dup (&rmap_attr_s, client_attr) ;

      /* Apply BGP route map to the attribute.
       */
      info_s.peer = rsclient;
      info_s.attr = rmap_attr ;

      info_s.peer->rmap_type = PEER_RMAP_TYPE_EXPORT ;
      ret = route_map_apply(ROUTE_MAP_EXPORT(filter), rt->p, RMAP_BGP, &info_s);

      old_attr = client_attr ;
      if (ret == RMAP_DENYMATCH)
        {
          /* Discard any new elements set by the route-map -- these will have
           * reference counts == 0.
           */
          client_attr = bgp_attr_flush (rmap_attr);
        }
      else
        {
          /* Intern the result of the rmap and unintern the old version
           *
           * Done in this order so that any unchanged elements in rmap_attr
           * gain a reference before they are released from the old interned
           * attributes.
           */
          client_attr = bgp_attr_intern_temp(rmap_attr) ;
        } ;

      /* Must unintern the original client_attr after interning any new one,
       * because the interned sub-attr in rmap_attr depend on the original
       * client_attr.
       */
      bgp_attr_unintern(old_attr) ;
    } ;

  return client_attr ;
} ;

/*------------------------------------------------------------------------------
 * Take the already interned client_attr, and if required apply the import
 * route-map for the route server client.
 *
 * If not DENY, returns interned client_attr, which may or may not have changed.
 *
 * If DENY, returns NULL and the client_attr will have been uninterned.
 */
static struct attr*
bgp_import_modifier (struct peer *rsclient, struct rs_route* rt,
                                   struct attr* client_attr, uint16_t rmap_type)
{
  struct bgp_filter *filter;
  struct attr        rmap_attr_s ;
  struct attr*       rmap_attr ;
  struct attr*       old_attr ;

  qassert(bgp_attr_is_interned(client_attr)) ;

  rmap_attr = NULL ;
  old_attr  = client_attr ;

  /* Apply default weight value.
   */
  if (rt->peer->weight)
    {
      rmap_attr = bgp_attr_dup (&rmap_attr_s, client_attr) ;

      (bgp_attr_extra_get (rmap_attr))->weight = rt->peer->weight;
    } ;

  /* Route map apply.
   */
  filter = &rsclient->filter[rt->afi][rt->safi];

  if (ROUTE_MAP_IMPORT_NAME (filter))
    {
      struct bgp_info    info_s = { 0 } ;
      route_map_result_t ret ;

      /* Duplicate current value to new structure for modification.
       */
      if (rmap_attr == NULL)
        rmap_attr = bgp_attr_dup (&rmap_attr_s, client_attr) ;

      /* Apply BGP route map to the attribute.
       */
      info_s.peer = rt->peer;
      info_s.attr = rmap_attr;

      info_s.peer->rmap_type = rmap_type | PEER_RMAP_TYPE_IMPORT ;
      ret = route_map_apply(ROUTE_MAP_IMPORT(filter), rt->p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
        {
          /* Discard any new elements set by the route-map -- these will have
           * reference counts == 0.
           *
           * Discard any "extra" part of the duplicated attributes.
           */
          rmap_attr   = bgp_attr_flush (rmap_attr) ;
          client_attr = NULL ;
        } ;
    } ;

  /* If the attributes may have changed, intern the new result and unintern the
   * old version
   *
   * Done in this order so that any unchanged elements in rmap_attr gain
   * an extra reference before they are released from the old interned
   * attributes.
   */
  if (rmap_attr != NULL)
    client_attr = bgp_attr_intern_temp(rmap_attr) ;

  if (client_attr != old_attr)
    bgp_attr_unintern(old_attr) ;

  return client_attr ;
} ;

/*------------------------------------------------------------------------------
 * Check that can announce the given bgp_info route, for the given prefix,
 *                                                           to the given peer.
 *
 * Returns:  newly interned attributes, ready to be advertised.
 *       or: NULL announce nothing.
 */
static struct attr*
bgp_announce_check (struct bgp_info *ri, struct peer *peer, struct prefix *p,
                                                        afi_t afi, safi_t safi)
{
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct peer *from;
  struct bgp *bgp;
  bool transparent;
  bool reflect;
  bgp_peer_sort_t sort, from_sort ;
  struct attr  attr_s ;
  struct attr* attr ;
  struct attr* attr_reflect ;

  from = ri->peer;
  filter = &peer->filter[afi][safi];
  bgp = peer->bgp;

  if (DISABLE_BGP_ANNOUNCE)
    return NULL ;

  /* Do not send announces to RS-clients from the 'normal' bgp_table.
   */
  if (peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)
    return NULL ;

  /* Do not send back route to sender.
   */
  if (from == peer)
    return NULL ;

  /* If peer's id and route's nexthop are same. draft-ietf-idr-bgp4-23 5.1.3
   */
  if ((p->family == AF_INET) &&
                           IPV4_ADDR_SAME(&peer->remote_id, &ri->attr->nexthop))
    return NULL ;
#ifdef HAVE_IPV6
  if ((p->family == AF_INET6)
                        && IPV6_ADDR_SAME(&peer->remote_id, &ri->attr->nexthop))
    return NULL ;
#endif

  /* Aggregate-address suppress check.
   */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return NULL ;

  /* Default route check.
   */
  if (peer->af_sflags[afi][safi] & PEER_STATUS_DEFAULT_ORIGINATE)
    {
      if ((p->family == AF_INET) && (p->u.prefix4.s_addr == INADDR_ANY))
        return NULL ;
#ifdef HAVE_IPV6
      else if ((p->family == AF_INET6) && (p->prefixlen == 0))
        return NULL ;
#endif /* HAVE_IPV6 */
    }

  /* Transparency check.
   */
  transparent = ((peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT) &&
                 (from->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)) ;

  /* If community is not disabled check the no-export and local.
   */
  if (! transparent && bgp_community_filter (peer, ri->attr))
    return NULL ;

  /* If the attribute has originator-id and it is same as remote peer's id.
   */
  if (ri->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&peer->remote_id, &ri->attr->extra->originator_id))
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (peer->log, LOG_DEBUG,
                  "%s [Update:SEND] %s/%d originator-id is same as remote router-id",
                  peer->host,
                  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                  p->prefixlen);
          return NULL ;
        }
    }

  /* ORF prefix-list filter check
   */
  if ( (peer->af_cap[afi][safi] & PEER_CAP_ORF_PREFIX_RM_ADV) &&
       (peer->af_cap[afi][safi] & (PEER_CAP_ORF_PREFIX_SM_RCV |
                                   PEER_CAP_ORF_PREFIX_SM_OLD_RCV)) )
    if (peer->orf_plist[afi][safi])
      {
        if (prefix_list_apply (peer->orf_plist[afi][safi], p) == PREFIX_DENY)
          return NULL ;
      }

  /* Output filter check.
   */
  if (bgp_output_filter (peer, p, ri->attr, afi, safi) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (peer->log, LOG_DEBUG,
              "%s [Update:SEND] %s/%d is filtered",
              peer->host,
              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
              p->prefixlen);
      return NULL ;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check.
   */
  if (aspath_loop_check (ri->attr->aspath, peer->as))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (peer->log, LOG_DEBUG,
              "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
              peer->host, peer->as);
      return NULL ;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* If we're a CONFED we need to loop check the CONFED ID too
   */
  if (bgp->config & BGP_CONFIG_CONFEDERATION)
    {
      if (aspath_loop_check(ri->attr->aspath, bgp->confed_id))
        {
          if (BGP_DEBUG (filter, FILTER))
            zlog (peer->log, LOG_DEBUG,
                  "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
                  peer->host,
                  bgp->confed_id);
          return NULL ;
        }
    }

  /* Route-Reflect check.
   */
  from_sort = peer_sort (from) ;
  sort      = peer_sort (peer) ;

  reflect = ((from_sort == BGP_PEER_IBGP) && (sort == BGP_PEER_IBGP)) ;

  /* IBGP reflection check.
   */
  if (reflect)
    {
      /* A route from a Client peer.
       */
      if (from->af_flags[afi][safi] & PEER_FLAG_REFLECTOR_CLIENT)
        {
          /* Reflect to all the Non-Client peers and also to the
             Client peers other than the originator.  Originator check
             is already done.  So there is noting to do. */
          /* no bgp client-to-client reflection check. */
          if (bgp_flag_check (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT))
            if (peer->af_flags[afi][safi] & PEER_FLAG_REFLECTOR_CLIENT)
              return NULL ;
        }
      else
        {
          /* A route from a Non-client peer. Reflect to all other clients.
           */
          if (!(peer->af_flags[afi][safi] & PEER_FLAG_REFLECTOR_CLIENT))
            return NULL ;
        }
    }

  /* For modify attribute, copy it to temporary structure.
   *
   * The ri->attr is interned, so can replace any part of the copy, with
   * uninterned values -- provided discard a previous uninterned value !
   */
  qassert(bgp_attr_is_interned(ri->attr)) ;
  attr = bgp_attr_dup (&attr_s, ri->attr);

  /* If local-preference is not set.
   */
  if (((sort == BGP_PEER_IBGP) || (sort == BGP_PEER_CONFED))
      && (! (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))))
    {
      attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);
      attr->local_pref = bgp->default_local_pref;
    }

  /* Remove MED if its an EBGP peer - will get overwritten by route-maps
   */
  if ((sort == BGP_PEER_EBGP)
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC)))
    {
      if ((ri->peer != bgp->peer_self) && ! transparent
          && !(peer->af_flags[afi][safi] & PEER_FLAG_MED_UNCHANGED))
        attr->flag &= ~(ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC));
    }

  /* next-hop-set
   */
  if (transparent || reflect
      || ((peer->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_UNCHANGED)
          && (((p->family == AF_INET) && attr->nexthop.s_addr)
#ifdef HAVE_IPV6
              || ((p->family == AF_INET6) &&
                  ! IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
              )))
    {
      /* NEXT-HOP Unchanged.
       */
    }
  else if ((peer->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_SELF)
           || ((p->family == AF_INET) && (attr->nexthop.s_addr == 0))
#ifdef HAVE_IPV6
           || ((p->family == AF_INET6) &&
               IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
           || ((sort == BGP_PEER_EBGP)
               && (bgp_multiaccess_check_v4 (attr->nexthop, peer->host) == 0)))
    {
      /* Set IPv4 nexthop.
       */
      if (p->family == AF_INET)
        {
          if (safi == SAFI_MPLS_VPN)
            memcpy (&attr->extra->mp_nexthop_global_in, &peer->nexthop.v4,
                                                       IPV4_MAX_BYTELEN);
          else
            memcpy (&attr->nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);
        }
#ifdef HAVE_IPV6
      /* Set IPv6 nexthop.
       */
      if (p->family == AF_INET6)
        {
          /* IPv6 global nexthop must be included.
           */
          memcpy (&attr->extra->mp_nexthop_global, &peer->nexthop.v6_global,
                  IPV6_MAX_BYTELEN);
          attr->extra->mp_nexthop_len = 16;
        }
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      /* Leave nexthop_local unchanged if so configured.
       */
      if (peer->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attr->extra->mp_nexthop_local) )
            attr->extra->mp_nexthop_len=32;
          else
            attr->extra->mp_nexthop_len=16;
        }
      else
        {
          /* Default nexthop_local treatment for non-RS-Clients
           *
           * Link-local address should not be transit to different peer.
           */
          attr->extra->mp_nexthop_len = 16;

          /* Set link-local address for shared network peer.
           */
          if (peer->shared_network
                        && ! IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
            {
              memcpy (&attr->extra->mp_nexthop_local, &peer->nexthop.v6_local,
                  IPV6_MAX_BYTELEN);
              attr->extra->mp_nexthop_len = 32;
            }

          /* If bgpd act as BGP-4+ route-reflector, do not send link-local
           * address.
           */
          if (reflect)
            attr->extra->mp_nexthop_len = 16;

          /* If BGP-4+ link-local nexthop is not link-local nexthop.
           */
          if (! IN6_IS_ADDR_LINKLOCAL (&peer->nexthop.v6_local))
            attr->extra->mp_nexthop_len = 16;
        }
    }
#endif /* HAVE_IPV6 */

  /* If this is EBGP peer and remove-private-AS is set
   */
  if ((sort == BGP_PEER_EBGP)
      && peer_af_flag_check (peer, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS)
      && aspath_private_as_check (attr->aspath))
    attr->aspath = aspath_empty (false /* !intern */);

  /* Route map & unsuppress-map apply.
   */
  attr_reflect = NULL ;

  if (ROUTE_MAP_OUT_NAME (filter) || (ri->extra && ri->extra->suppress))
    {
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      /* The route reflector is not allowed to modify the attributes
       * of the reflected IBGP routes.
       *
       * So we intern what we have so far, which we will need, unless the
       * route-map denies the route.  Then make a new copy of those for the
       * route-map to work on.
       */
      if (reflect)
        {
          attr_reflect = bgp_attr_intern_temp(attr) ;
          attr = bgp_attr_dup (&attr_s, attr_reflect);
        } ;

      info_s.peer = peer;
      info_s.attr = attr;
      info_s.peer->rmap_type = PEER_RMAP_TYPE_OUT ;

      if (ri->extra && ri->extra->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info_s);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
        {
          if (attr_reflect != NULL)
            attr_reflect = bgp_attr_unintern(attr_reflect) ;

          return bgp_attr_flush (attr);
        } ;
    } ;

  if (attr_reflect == NULL)
    return bgp_attr_intern_temp(attr) ;
  else
    {
      /* For route-reflector we interned the attributes earlier, so can now
       * discard any changes made by the route-map to the (now) dummy attr,
       * and return the interned set.
       */
      bgp_attr_flush (attr);
      return attr_reflect ;
    } ;
}

/*------------------------------------------------------------------------------
 * Check that can announce the given bgp_info route, for the given prefix,
 *                                                           to the given peer.
 *
 * Returns:  newly interned attributes, ready to be advertised.
 *       or: NULL announce nothing.
 */
static struct attr*
bgp_announce_check_rsclient (struct bgp_info *ri, struct peer *rsclient,
                                       struct prefix *p, afi_t afi, safi_t safi)
{
  char buf[SU_ADDRSTRLEN];
  struct bgp_filter *filter;
  struct peer *from;
  struct attr  attr_s ;
  struct attr* attr ;

  from = ri->peer;
  filter = &rsclient->filter[afi][safi];

  if (DISABLE_BGP_ANNOUNCE)
    return NULL ;

  /* Do not send back route to sender.
   */
  if (from == rsclient)
    return NULL ;

  /* Aggregate-address suppress check.
   */
  if (ri->extra && ri->extra->suppress)
    if (! UNSUPPRESS_MAP_NAME (filter))
      return NULL ;

  /* Default route check.
   */
  if (rsclient->af_sflags[afi][safi] & PEER_STATUS_DEFAULT_ORIGINATE)
    {
      if ((p->family == AF_INET) && (p->u.prefix4.s_addr == INADDR_ANY))
        return NULL ;
#ifdef HAVE_IPV6
      else if ((p->family == AF_INET6) && (p->prefixlen == 0))
        return NULL ;
#endif /* HAVE_IPV6 */
    }

  /* If the attribute has originator-id and it is same as remote peer's id.
   */
  if (ri->attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
    {
      if (IPV4_ADDR_SAME (&rsclient->remote_id,
                          &ri->attr->extra->originator_id))
        {
         if (BGP_DEBUG (filter, FILTER))
           zlog (rsclient->log, LOG_DEBUG,
                 "%s [Update:SEND] %s/%d originator-id is same as remote router-id",
                 rsclient->host,
                 inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                 p->prefixlen);
         return NULL ;
       }
    }

  /* ORF prefix-list filter check
   */
  if ( (rsclient->af_cap[afi][safi] & PEER_CAP_ORF_PREFIX_RM_ADV) &&
       (rsclient->af_cap[afi][safi] & (PEER_CAP_ORF_PREFIX_SM_RCV |
                                       PEER_CAP_ORF_PREFIX_SM_OLD_RCV)) )
    if (rsclient->orf_plist[afi][safi])
      {
       if (prefix_list_apply (rsclient->orf_plist[afi][safi], p) == PREFIX_DENY)
         {
           if (BGP_DEBUG (filter, FILTER))
            zlog (rsclient->log, LOG_DEBUG,
                  "%s [Update:SEND] %s/%d is filtered by ORF",
                  rsclient->host,
                  inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                  p->prefixlen);

          return NULL ;
         }
      }

  /* Output filter check.
   */
  if (bgp_output_filter (rsclient, p, ri->attr, afi, safi) == FILTER_DENY)
    {
      if (BGP_DEBUG (filter, FILTER))
       zlog (rsclient->log, LOG_DEBUG,
             "%s [Update:SEND] %s/%d is filtered",
             rsclient->host,
             inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
             p->prefixlen);
      return NULL ;
    }

#ifdef BGP_SEND_ASPATH_CHECK
  /* AS path loop check.
   */
  if (aspath_loop_check (ri->attr->aspath, rsclient->as))
    {
      if (BGP_DEBUG (filter, FILTER))
        zlog (rsclient->log, LOG_DEBUG,
             "%s [Update:SEND] suppress announcement to peer AS %u is AS path.",
             rsclient->host, rsclient->as);
      return NULL ;
    }
#endif /* BGP_SEND_ASPATH_CHECK */

  /* For modify attribute, copy it to temporary structure.
   */
  qassert(bgp_attr_is_interned(ri->attr)) ;
  attr = bgp_attr_dup (&attr_s, ri->attr);

  /* next-hop-set
   */
  if (((p->family == AF_INET) && (attr->nexthop.s_addr == 0))
#ifdef HAVE_IPV6
   || ((p->family == AF_INET6) &&
                      IN6_IS_ADDR_UNSPECIFIED(&attr->extra->mp_nexthop_global))
#endif /* HAVE_IPV6 */
     )
  {
    /* Set IPv4 nexthop.
     */
    if (p->family == AF_INET)
      {
        if (safi == SAFI_MPLS_VPN)
          memcpy (&attr->extra->mp_nexthop_global_in, &rsclient->nexthop.v4,
                                                              IPV4_MAX_BYTELEN);
        else
          memcpy (&attr->nexthop, &rsclient->nexthop.v4, IPV4_MAX_BYTELEN);
      }
#ifdef HAVE_IPV6
    /* Set IPv6 nexthop.
     */
    if (p->family == AF_INET6)
      {
        /* IPv6 global nexthop must be included.
         */
        memcpy (&attr->extra->mp_nexthop_global, &rsclient->nexthop.v6_global,
                                                              IPV6_MAX_BYTELEN);
        attr->extra->mp_nexthop_len = 16;
      }
#endif /* HAVE_IPV6 */
  }

#ifdef HAVE_IPV6
  if (p->family == AF_INET6)
    {
      struct attr_extra *attre = attr->extra;

      assert (attr->extra);

      /* Leave nexthop_local unchanged if so configured.
       */
      if (rsclient->af_flags[afi][safi] & PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)
        {
          if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
            attre->mp_nexthop_len=32;
          else
            attre->mp_nexthop_len=16;
        }
      else
        {
          /* Default nexthop_local treatment for RS-Clients
           *
           * Announcer and RS-Client are both in the same network
           */
          if (rsclient->shared_network && from->shared_network &&
              (rsclient->ifindex == from->ifindex))
            {
              if ( IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local) )
                attre->mp_nexthop_len=32;
              else
                attre->mp_nexthop_len=16;
            }

          /* Set link-local address for shared network peer.
           */
          else if (rsclient->shared_network
                       && IN6_IS_ADDR_LINKLOCAL (&rsclient->nexthop.v6_local))
            {
              memcpy (&attre->mp_nexthop_local, &rsclient->nexthop.v6_local,
                                                              IPV6_MAX_BYTELEN);
              attre->mp_nexthop_len = 32;
            }
          else
            attre->mp_nexthop_len = 16;
        }
    }
#endif /* HAVE_IPV6 */

  /* If this is EBGP peer and remove-private-AS is set.
   */
  if ((peer_sort (rsclient) == BGP_PEER_EBGP) &&
      peer_af_flag_check (rsclient, afi, safi, PEER_FLAG_REMOVE_PRIVATE_AS) &&
      aspath_private_as_check (attr->aspath))
    attr->aspath = aspath_empty (false /* !intern */);

  /* Route map & unsuppress-map apply.
   */
  if (ROUTE_MAP_OUT_NAME (filter) || (ri->extra && ri->extra->suppress) )
    {
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      info_s.peer = rsclient;
      info_s.attr = attr;
      info_s.peer->rmap_type = PEER_RMAP_TYPE_OUT ;

      if (ri->extra && ri->extra->suppress)
        ret = route_map_apply (UNSUPPRESS_MAP (filter), p, RMAP_BGP, &info_s);
      else
        ret = route_map_apply (ROUTE_MAP_OUT (filter), p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
       {
         if (BGP_DEBUG (filter, FILTER))
          zlog (rsclient->log, LOG_DEBUG,
                "%s [Update:SEND] %s/%d is filtered by %s route-map",
                rsclient->host,
                inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                p->prefixlen,
                (ri->extra && ri->extra->suppress) ? "Unsuppress" : "Out");

         return bgp_attr_flush (attr);
       }
    } ;

  return bgp_attr_intern_temp(attr) ;
}

struct bgp_info_pair
{
  struct bgp_info *old;
  struct bgp_info *new;
};

static void
bgp_best_selection (struct bgp *bgp, struct bgp_node *rn,
                                                   struct bgp_info_pair *result)
{
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info *ri;
  struct bgp_info *ri1;
  struct bgp_info *ri2;
  struct bgp_info *nextri = NULL;

  /* bgp deterministic-med
   */
  new_select = NULL;
  if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
    for (ri1 = rn->info; ri1; ri1 = ri1->info_next)
      {
        if (ri1->flags & BGP_INFO_DMED_CHECK)
          continue;
        if (BGP_INFO_HOLDDOWN (ri1))
          continue;

        new_select = ri1;
        if (ri1->info_next)
          for (ri2 = ri1->info_next; ri2; ri2 = ri2->info_next)
            {
              if (ri2->flags & BGP_INFO_DMED_CHECK)
                continue;
              if (BGP_INFO_HOLDDOWN (ri2))
                continue;

              if (aspath_cmp_left (ri1->attr->aspath, ri2->attr->aspath)
                  || aspath_cmp_left_confed (ri1->attr->aspath,
                                             ri2->attr->aspath))
                {
                  if (bgp_info_cmp (bgp, ri2, new_select))
                    {
                      bgp_info_unset_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
                      new_select = ri2;
                    }

                  bgp_info_set_flag (rn, ri2, BGP_INFO_DMED_CHECK);
                }
            }
        bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_CHECK);
        bgp_info_set_flag (rn, new_select, BGP_INFO_DMED_SELECTED);
      }

  /* Check old selected route and new selected route.
   */
  old_select = NULL;
  new_select = NULL;
  for (ri = rn->info; (ri != NULL) && (nextri = ri->info_next, 1); ri = nextri)
    {
      if (ri->flags & BGP_INFO_SELECTED)
        old_select = ri;

      if (BGP_INFO_HOLDDOWN (ri))
        {
          /* reap REMOVED routes, if needs be
           * selected route must stay for a while longer though
           */
          if ((ri->flags & BGP_INFO_REMOVED) && (ri != old_select))
            bgp_info_reap (rn, ri);

          continue;
        }

      if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED)
                                      && !(ri->flags & BGP_INFO_DMED_SELECTED))
        {
          bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
          continue;
        }
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_CHECK);
      bgp_info_unset_flag (rn, ri, BGP_INFO_DMED_SELECTED);

      if (bgp_info_cmp (bgp, ri, new_select))
        new_select = ri;
    }

    result->old = old_select;
    result->new = new_select;

    return;
}

/*------------------------------------------------------------------------------
 * Announce selected route to given peer.
 */
static void
bgp_process_announce_selected (struct peer *peer, struct bgp_info *selected,
                               struct bgp_node *rn, afi_t afi, safi_t safi)
{
  struct prefix *p;
  struct attr* attr ;
  bool rsclient ;

  rsclient = (peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT) ;

  p = &rn->p;

  /* Announce route to Established peer.
   */
  if (peer->state != bgp_peer_pEstablished)
    return ;

  /* Address family configuration check.
   */
  if (! peer->afc_nego[afi][safi])
    return ;

  /* First update is deferred until ORF or ROUTE-REFRESH is received
   */
  if (peer->af_sflags[afi][safi] & PEER_STATUS_ORF_WAIT_REFRESH)
    return ;

  if (selected == NULL)
    attr = NULL ;
  else
    {
      switch (rn->table->type)
        {
          case BGP_TABLE_MAIN:
            qassert(!rsclient) ;
            attr = bgp_announce_check (selected, peer, p, afi, safi) ;
            break ;

          case BGP_TABLE_RSCLIENT:
            qassert(rsclient) ;
            attr = bgp_announce_check_rsclient (selected, peer, p, afi, safi);
            break;

          default:
            attr = NULL ;
            break ;
        } ;
    } ;

   if (attr != NULL)
     bgp_adj_out_set (rn, peer, p, attr, afi, safi, selected);
   else
     bgp_adj_out_unset (rn, peer, p, afi, safi);
} ;

struct bgp_process_queue
{
  struct bgp*      bgp ;
  struct bgp_node* head ;
  struct bgp_node* tail ;
};

WQ_ARGS_SIZE_OK(bgp_process_queue) ;

static wq_item_status
bgp_process_rsclient (struct work_queue *wq, work_queue_item item)
{
  struct bgp_process_queue *pq = work_queue_item_args(item) ;
  struct bgp *bgp = pq->bgp ;
  struct bgp_node *rn ;
  afi_t  afi ;
  safi_t safi ;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct bgp_table *table ;
  struct peer *rsclient ;

  assert(wq->spec.data == item) ;

  /* Is there anything left on the queue ?
   */
  rn = pq->head ;
  if (rn == NULL)
    return WQ_SUCCESS ;

  /* hack off queue and prepare to process
   */
  qassert(rn->on_wq && (rn->lock > 0)) ;

  pq->head    = rn->wq_next ;
  rn->wq_next = NULL ;          /* Keep tidy    */
  rn->on_wq   = false ;

  table    = rn->table ;
  rsclient = table->owner;
  afi      = table->afi;
  safi     = table->safi;

  dassert(table->lock    > 0) ;
  dassert(rsclient->lock > 0) ;

  /* Best path selection.
   */
  bgp_best_selection (bgp, rn, &old_and_new);
  new_select = old_and_new.new;
  old_select = old_and_new.old;

  if (rsclient->sflags & PEER_STATUS_GROUP)
    {
      if (rsclient->group)
        for (ALL_LIST_ELEMENTS (rsclient->group->peer, node, nnode, rsclient))
          {
            /* Nothing to do. */
            if (old_select && old_select == new_select)
              if (!(old_select->flags & BGP_INFO_ATTR_CHANGED))
                continue;

            if (old_select)
              bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
            if (new_select)
              {
                bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
                bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
              }

            bgp_process_announce_selected (rsclient, new_select, rn,
                                           afi, safi);
          }
    }
  else
    {
      if (old_select)
        bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
      if (new_select)
        {
          bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
          bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
        }
      bgp_process_announce_selected (rsclient, new_select, rn, afi, safi);
    }

  if (old_select && (old_select->flags & BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);

  bgp_unlock_node (rn);
  bgp_table_unlock (table);     /* NB: *after* node, in case table is deleted */
  bgp_unlock (bgp);

  if (pq->head == NULL)
    return WQ_SUCCESS ;
  else
    return WQ_REQUEUE ;
}

static wq_item_status
bgp_process_main (struct work_queue *wq, work_queue_item item)
{
  struct bgp_process_queue *pq = work_queue_item_args(item) ;
  struct bgp *bgp = pq->bgp ;
  struct bgp_node *rn ;
  afi_t  afi ;
  safi_t safi ;
  struct prefix *p ;
  struct bgp_info *new_select;
  struct bgp_info *old_select;
  struct bgp_info_pair old_and_new;
  struct listnode *node, *nnode;
  struct bgp_table *table ;
  struct peer *peer;

  assert(wq->spec.data == item) ;

  /* Is there anything left on the queue ?
   */
  rn = pq->head ;
  if (rn == NULL)
    return WQ_SUCCESS ;

  /* hack off queue and prepare to process
   */
  qassert(rn->on_wq && (rn->lock > 0)) ;

  pq->head    = rn->wq_next ;
  rn->wq_next = NULL ;          /* Keep tidy    */
  rn->on_wq   = false ;

  table    = rn->table ;
  afi      = table->afi;
  safi     = table->safi;

  dassert(table->lock    > 0) ;

  p    = &rn->p ;

  /* Best path selection.
   */
  bgp_best_selection (bgp, rn, &old_and_new);
  old_select = old_and_new.old;
  new_select = old_and_new.new;

  /* Nothing to do.
   */
  if (old_select && (old_select == new_select))
    {
      if (!(old_select->flags & BGP_INFO_ATTR_CHANGED))
        {
          if (old_select->flags & BGP_INFO_IGP_CHANGED)
            bgp_zebra_announce (p, old_select, bgp, safi);

          goto finish ;         /* was return ! */
        }
    }

  if (old_select)
    bgp_info_unset_flag (rn, old_select, BGP_INFO_SELECTED);
  if (new_select)
    {
      bgp_info_set_flag (rn, new_select, BGP_INFO_SELECTED);
      bgp_info_unset_flag (rn, new_select, BGP_INFO_ATTR_CHANGED);
    }

  /* Check each BGP peer.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      bgp_process_announce_selected (peer, new_select, rn, afi, safi);
    }

  /* FIB update.
   */
  if ( ((safi == SAFI_UNICAST) || (safi == SAFI_MULTICAST))
                  && (bgp->name == NULL) && ! bgp_option_check (BGP_OPT_NO_FIB))
    {
      if (new_select && (new_select->type     == ZEBRA_ROUTE_BGP)
                     && (new_select->sub_type == BGP_ROUTE_NORMAL))
        bgp_zebra_announce (p, new_select, bgp, safi);
      else
        {
          /* Withdraw the route from the kernel.
           */
          if (old_select && (old_select->type     == ZEBRA_ROUTE_BGP)
                         && (old_select->sub_type == BGP_ROUTE_NORMAL))
            bgp_zebra_withdraw (p, old_select, safi);
        }
    }

  /* Reap old select bgp_info, it it has been removed
   */
  if (old_select && (old_select->flags & BGP_INFO_REMOVED))
    bgp_info_reap (rn, old_select);

  /* Finish up
   */
finish:
  bgp_unlock_node (rn) ;
  bgp_table_unlock (table) ;    /* NB: *after* node, in case table is deleted */
  bgp_unlock (bgp) ;

  if (pq->head == NULL)
    return WQ_SUCCESS ;
  else
    return WQ_REQUEUE ;
}

/*------------------------------------------------------------------------------
 * Delete item from work queue
 *
 * This is used automagically when the work queue function returns WQ_SUCCESS,
 * since that triggers the removal of the work queue item from the work queue.
 *
 * It is also used at work_queue_free() time.
 */
static void
bgp_processq_del (struct work_queue *wq, work_queue_item item)
{
  struct bgp_process_queue *pq = work_queue_item_args(item) ;
  struct bgp_node *rn ;

  assert(wq->spec.data == item) ;

  while ((rn = pq->head) != NULL)
    {
      struct bgp_table *table ;

      qassert(rn->on_wq && (rn->lock > 0)) ;

      pq->head    = rn->wq_next ;
      rn->wq_next = NULL ;          /* Keep tidy    */
      rn->on_wq   = false ;

      table    = rn->table ;

      qassert(table->lock    > 0) ;

      bgp_unlock_node (rn);
      bgp_table_unlock (table); /* NB: *after* node, in case table is deleted */
      bgp_unlock (pq->bgp);
    } ;

  wq->spec.data = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Create new work queue for given bgp instance and given type of table
 */
static work_queue
bgp_process_queue_init (struct bgp* bgp, bgp_table_t type)
{
  work_queue   wq ;
  const char*  name ;
  wq_workfunc* workfunc ;
  work_queue*  p_wq ;

  switch (type)
    {
      case BGP_TABLE_MAIN:
        p_wq     = &bgp->process_main_queue ;
        name     = "process_main_queue" ;
        workfunc = &bgp_process_main ;
        break ;
      case BGP_TABLE_RSCLIENT:
        p_wq     = &bgp->process_rsclient_queue ;
        name     = "process_rsclient_queue" ;
        workfunc = &bgp_process_rsclient ;
        break ;
      default:
        zabort("invalid BGP table type") ;
    } ;

  wq = work_queue_new (bm->master, name) ;

  wq->spec.data            = NULL ;
  wq->spec.errorfunc       = NULL ;
  wq->spec.workfunc        = workfunc ;
  wq->spec.del_item_data   = &bgp_processq_del ;
  wq->spec.completion_func = NULL ;
  wq->spec.max_retries     = 0 ;
  wq->spec.hold            = 50 ;

  return *p_wq = wq ;
}

/*------------------------------------------------------------------------------
 * Place given route node on appropriate work queue, so that best path
 * selection etc. can take place later.
 */
void
bgp_process (struct bgp *bgp, struct bgp_node *rn, afi_t afi, safi_t safi)
{
  work_queue_item item ;
  struct bgp_process_queue *pq ;
  struct work_queue* wq ;

  /* already scheduled for processing?
   */
  if (rn->on_wq)
    return;

  /* get the required work queue -- making it if necessary
   */
  switch (rn->table->type)
    {
      case BGP_TABLE_MAIN:
        wq = bgp->process_main_queue ;
        if (wq == NULL)
          wq = bgp_process_queue_init(bgp, BGP_TABLE_MAIN) ;
        break;
      case BGP_TABLE_RSCLIENT:
        wq = bgp->process_rsclient_queue ;
        if (wq == NULL)
          wq = bgp_process_queue_init(bgp, BGP_TABLE_RSCLIENT) ;
        break;
      default:
        zabort("invalid rn->table->type") ;
    }

  /* get the work queue item -- making it if necessary
   *
   * There is one work queue for the main table, and one for all RS-Clients.
   *
   * Each work queue has one item.  Hung from that item are all the rn's
   * which require attention.
   */
  item = wq->spec.data ;
  if (item == NULL)
    {
      /* TODO: sort out assumption that item == args
       */
      item = wq->spec.data = work_queue_item_add(wq) ;
      pq = work_queue_item_args(item) ;

      pq->bgp  = bgp ;
      pq->head = NULL ;
      pq->tail = NULL ;
    }
  else
    pq = work_queue_item_args(item) ;

  /* all unlocked when processed or deleted
   */
  bgp_lock (bgp);
  bgp_table_lock (rn->table);
  bgp_lock_node (rn);

  /* add to the queue
   */
  if (pq->head == NULL)
    pq->head = rn ;
  else
    pq->tail->wq_next = rn ;

  pq->tail = rn ;
  rn->wq_next = NULL ;

  rn->on_wq = true ;

  return;
}

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

  qassert(peer->sflags & PEER_STATUS_PREFIX_OVERFLOW) ;

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
      qassert(peer->sflags & PEER_STATUS_PREFIX_OVERFLOW) ;

      BGP_TIMER_OFF (peer->t_pmax_restart);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s Maximum-prefix restart timer cancelled", peer->host) ;
    } ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW) ;
} ;

/*------------------------------------------------------------------------------
 * Number of prefixes has overflowed.
 */
int
bgp_maximum_prefix_overflow (struct peer *peer, afi_t afi,
                             safi_t safi, int always)
{
  if (!(peer->af_flags[afi][safi] & PEER_FLAG_MAX_PREFIX))
    return 0;

  if (peer->pcount[afi][safi] > peer->pmax[afi][safi])
    {
      if ((peer->af_sflags[afi][safi] & PEER_STATUS_PREFIX_LIMIT) && ! always)
       return 0;

      zlog (peer->log, LOG_INFO,
            "%%MAXPFXEXCEED: No. of %s prefix received from %s %ld exceed, "
            "limit %ld", afi_safi_print (afi, safi), peer->host,
            peer->pcount[afi][safi], peer->pmax[afi][safi]);

      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

      if (peer->af_flags[afi][safi] & PEER_FLAG_MAX_PREFIX_WARNING)
        return 0;

      {
       u_int8_t ndata[7];

       if (safi == SAFI_MPLS_VPN)
         safi = SAFI_MPLS_LABELED_VPN;

       ndata[0] = (afi >>  8);
       ndata[1] = afi;
       ndata[2] = safi;
       ndata[3] = (peer->pmax[afi][safi] >> 24);
       ndata[4] = (peer->pmax[afi][safi] >> 16);
       ndata[5] = (peer->pmax[afi][safi] >> 8);
       ndata[6] = (peer->pmax[afi][safi]);

       SET_FLAG (peer->sflags, PEER_STATUS_PREFIX_OVERFLOW);
       /* Disable the peer, the timer routine will reenable. */
       bgp_peer_down_error_with_data(peer, BGP_NOTIFY_CEASE,
                                       BGP_NOTIFY_CEASE_MAX_PREFIX, ndata, 7);
      }

      /* restart timer start */
      if (peer->pmax_restart[afi][safi])
        {
          peer->v_pmax_restart = peer->pmax_restart[afi][safi] * 60;

          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
                        peer->host, peer->v_pmax_restart);

          BGP_TIMER_ON (peer->t_pmax_restart, bgp_maximum_prefix_restart_timer,
                        peer->v_pmax_restart);
        }

      return 1;
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_LIMIT);

  if (peer->pcount[afi][safi] > (peer->pmax[afi][safi] * peer->pmax_threshold[afi][safi] / 100))
    {
      if (CHECK_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD)
         && ! always)
       return 0;

      zlog (peer->log, LOG_INFO,
            "%%MAXPFX: No. of %s prefix received from %s reaches %ld, max %ld",
            afi_safi_print (afi, safi), peer->host, peer->pcount[afi][safi],
            peer->pmax[afi][safi]);
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
    }
  else
    UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_PREFIX_THRESHOLD);
  return 0;
}

/*============================================================================*/

/*------------------------------------------------------------------------------
 * Unconditionally remove the route from the RIB, without taking
 * damping into consideration (eg, because the session went down)
 *
 * Note that does not actually remove the route from the table, but marks
 * it as BGP_INFO_REMOVED and clears BGP_INFO_VALID.  During the selection
 * process, will "reap" the to-be-removed routes.
 *
 * Note that the current selection can be marked BGP_INFO_REMOVED.
 */
static void
bgp_rib_remove (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
                afi_t afi, safi_t safi)
{
  bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);

  if (!(ri->flags & BGP_INFO_HISTORY))
    bgp_info_delete (rn, ri); /* keep historical info */

  bgp_process (peer->bgp, rn, afi, safi);
}

static void
bgp_rib_withdraw (struct bgp_node *rn, struct bgp_info *ri, struct peer *peer,
                  afi_t afi, safi_t safi)
{
  int status = BGP_DAMP_NONE;

  /* apply dampening, if result is suppressed, we'll be retaining
   * the bgp_info in the RIB for historical reference.
   */
  if ((peer->bgp->af_flags[afi][safi] & BGP_CONFIG_DAMPENING)
                                         && (peer_sort (peer) == BGP_PEER_EBGP))
    if ((status = bgp_damp_withdraw (ri, rn, afi, safi, 0))
                                                         == BGP_DAMP_SUPPRESSED)
      {
        bgp_aggregate_decrement (peer->bgp, &rn->p, ri, afi, safi);
        return;
      }

  bgp_rib_remove (rn, ri, peer, afi, safi);
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
bgp_update_rsclient (struct peer *rsclient, struct rs_route* rt,
                                                             bool soft_reconfig)
{
  struct attr* client_attr ;
  struct bgp *bgp;
  struct bgp_node *rn;
  struct bgp_info *ri;
  const char *reason;
  const char* how_recv ;
  char buf[SU_ADDRSTRLEN];

  how_recv = soft_reconfig ? "soft-reconfig" : "recv" ;

  /* Do not insert announces from a rsclient into its own 'bgp_table'.
   */
  if (rt->peer == rsclient)
    return;

  client_attr = NULL ;          /* no attributes, yet   */

  /* Find node for this route
   */
  bgp = rt->peer->bgp;
  rn = bgp_afi_node_get (rsclient->rib[rt->afi][rt->safi], rt->afi, rt->safi,
                                                               rt->p, rt->prd);

  /* Find any previously received route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == rt->peer) && (ri->type     == rt->type)
                               && (ri->sub_type == rt->sub_type))
      break;

  /* If rs-in denies the route, stop now
   *
   * After bgp_rs_in_modifier() the rt->rs_in_attr is set to be an interned
   * copy of the attributes.
   */
  if (!rt->rs_in_applied)
    bgp_rs_input_modifier(rt) ;

  if (rt->rs_in_deny)
    {
      reason = "rs-in-policy;";
      goto filtered;
    } ;

  /* AS path loop check.
   */
  if (aspath_loop_check (rt->rs_in_attr->aspath, rsclient->as) >
                                        rt->peer->allowas_in[rt->afi][rt->safi])
    {
      reason = "as-path contains rs-client AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.
   */
  if ((rt->rs_in_attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
      && IPV4_ADDR_SAME (&rsclient->remote_id,
                                         &rt->rs_in_attr->extra->originator_id))
    {
      reason = "originator is rs-client;";
      goto filtered;
    }

  /* Each RS Client needs its own interned version of the rs_in attributes
   */
  qassert(bgp_attr_is_interned(rt->rs_in_attr)) ;

  client_attr = bgp_attr_intern(rt->rs_in_attr) ;

  /* Apply export policy.
   */
  if (rt->peer->af_flags[rt->afi][rt->safi] & PEER_FLAG_RSERVER_CLIENT)
    {
      client_attr = bgp_export_modifier (rsclient, rt, client_attr) ;
      if (client_attr == NULL)
        {
          reason = "export-policy;";
          goto filtered;
        } ;
    } ;

  /* Apply import policy.
   */
  client_attr = bgp_import_modifier (rsclient, rt, client_attr,
                                                        PEER_RMAP_TYPE_IMPORT) ;
  if (client_attr == NULL)
    {
      reason = "import-policy;";
      goto filtered;
    }

  /* IPv4 unicast next hop check.
   */
  if ( (rt->afi == AFI_IP) &&
                  ((rt->safi == SAFI_UNICAST) || (rt->safi == SAFI_MULTICAST)) )
    {
      /* Next hop must not be 0.0.0.0 nor Class E address.
       */
      if ((client_attr->nexthop.s_addr == 0)
                          || IPV4_CLASS_DE(ntohl(client_attr->nexthop.s_addr)))
       {
         reason = "martian next-hop;";
         goto filtered;
       }
    }

  /* If the update is implicit withdraw.
   */
  if (ri)
    {
      ri->uptime = bgp_clock ();

      /* Same attribute comes in.
       */
      if (((ri->flags & (BGP_INFO_REMOVED | BGP_INFO_VALID))
                     == (                   BGP_INFO_VALID))
                                        && attrhash_cmp (ri->attr, client_attr))
        {
#if 0
          /* BUG: just 'cos we've received the same attr again, does not
           *      mean there hasn't been a change in the past.
           */
          bgp_info_unset_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
#endif

          if (!soft_reconfig)
            {
              if (BGP_DEBUG (update, UPDATE_IN))
                zlog (rt->peer->log, LOG_DEBUG,
                    "%s %s %s/%d for RS-client %s...duplicate ignored",
                    rt->peer->host, how_recv,
                    inet_ntop(rt->p->family, &rt->p->u.prefix,
                                                            buf, SU_ADDRSTRLEN),
                    rt->p->prefixlen, rsclient->host);
            } ;

          /* Discard the duplicate interned attributes
           *
           * We don't need to do anything else.  'cos state is unchanging.
           */
          bgp_attr_unintern (client_attr);

          /* Unlock node -- locked in bgp_afi_node_get()
           */
          bgp_unlock_node (rn);
          return;               /* FIN <-<-<-<-<-<-<-<-<-<      */
        }

      /* Withdraw/Announce before we fully processed the withdraw
       *
       * May or may not be the same attributes.
       */
      if (ri->flags & BGP_INFO_REMOVED)
        bgp_info_restore (rn, ri);

      /* The attribute is changed.
       *
       * NB: if the route was withdrawn, and has now been restored to its
       *     original value, that will still be treated as an attribute
       *     change, which will cause a new update.  BUG ? XXX
       *
       * TODO -- really only need to set this if is the current selection.
       */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

      /* Discard the old attribute
       */
      ri->attr = bgp_attr_unintern (ri->attr);
   }
  else
    {
      /* Make new BGP info.
       */
      ri = bgp_info_new ();
      ri->type     = rt->type;
      ri->sub_type = rt->sub_type;
      ri->peer     = rt->peer;
      ri->uptime   = bgp_clock ();
#if 0                               /* TODO: do we need this ?? */
      /* Update MPLS tag.
       */
      if (safi == SAFI_MPLS_VPN)
        memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);
#endif

      /* Register new BGP information.
       */
      bgp_info_add (rn, ri);
    } ;

  /* Set the new attributes and update any MPLS tag.
   *
   * Any old attributes have been discarded.
   *
   * Note that we are here passing responsibility for the client_attr to the
   * ri entry.
   */
  qassert(ri->attr == NULL) ;
  ri->attr = client_attr ;
  bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

  if (rt->safi == SAFI_MPLS_VPN)
    memcpy ((bgp_info_extra_get (ri))->tag, rt->tag, 3);

  /* Received Logging.
   */
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (rt->peer->log, LOG_DEBUG, "%s %s %s/%d for RS-client %s",
            rt->peer->host, how_recv,
            inet_ntop(rt->p->family, &rt->p->u.prefix, buf, SU_ADDRSTRLEN),
            rt->p->prefixlen, rsclient->host);

  /* Process change.
   */
  bgp_process (bgp, rn, rt->afi, rt->safi);

  /* Unlock node -- locked in bgp_afi_node_get()
   */
  bgp_unlock_node (rn);

  return;               /* FIN <-<-<-<-<-<-<-<-<-<              */

  /* Deal with route which has been filtered out.
   *
   * If there was a previous route, then remove it.
   *
   * If have interned client attributes, then discard those.
   */
filtered:

  /* This BGP update is filtered.  Log the reason then update BGP entry.
   */
  if (BGP_DEBUG (update, UPDATE_IN))
        zlog (rt->peer->log, LOG_DEBUG,
        "%s %s UPDATE about %s/%d -- DENIED for RS-client %s due to: %s",
        rt->peer->host, how_recv,
        inet_ntop (rt->p->family, &rt->p->u.prefix, buf, SU_ADDRSTRLEN),
        rt->p->prefixlen, rsclient->host, reason);

  if (ri)
    bgp_rib_remove (rn, ri, rt->peer, rt->afi, rt->safi);

  if (client_attr != NULL)
    bgp_attr_unintern (client_attr);

  bgp_unlock_node (rn);
  return;
}

static void
bgp_withdraw_rsclient (struct peer *rsclient, afi_t afi, safi_t safi,
      struct peer *peer, struct prefix *p, int type, int sub_type,
      struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  char buf[SU_ADDRSTRLEN];

  if (rsclient == peer)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, prd);

  /* Lookup withdrawn route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* Withdraw specified route from routing table.
   */
  if ((ri != NULL) && !(ri->flags & BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi);
  else if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
          "%s Can't find the route %s/%d", peer->host,
          inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
          p->prefixlen);

  /* Unlock bgp_node_get() lock.
   */
  bgp_unlock_node (rn);
}

/*------------------------------------------------------------------------------
 * Update the main RIB with the given prefix/attributes etc.
 *
 * The given attr may not be interned, but all the sub-attr MUST be.  (In
 * route-maps etc, where the sub-attr may change, uses ref_count == 0 to
 * detect new values.)  The given attr are returned unchanged... though the
 * reference count on each sub-attr may have gone up.
 */
static int
bgp_update_main (struct peer *peer, struct prefix *p, struct attr *attr,
            afi_t afi, safi_t safi, int type, int sub_type,
            struct prefix_rd *prd, u_char *tag, bool soft_reconfig)
{
  struct bgp_node *rn;
  struct bgp *bgp;
  struct attr* use_attr ;
  struct bgp_info *ri;
  struct bgp_info *new;
  const char *reason;
  const char *how_recv;
  char buf[SU_ADDRSTRLEN];
  bgp_peer_sort_t sort ;

  qassert(bgp_sub_attr_are_interned(attr)) ;

  use_attr = NULL ;             /* nothing to use, yet          */

  bgp = peer->bgp;
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  sort = peer_sort(peer) ;

  how_recv = soft_reconfig ? "soft-reconfig" : "recv" ;

  /* When peer's soft reconfiguration enabled.  Record input packet in
   * Adj-RIBs-In.
   *
   * Note that bgp_adj_in_set() interns the attributes as it inserts them into
   * the adj-in -- this does not affect the attributes we have (other than
   * to increase the ref-count on any sub-attributes).
   *
   * Note that this requires all attr sub-attr to be interned, but does not
   * care whether the attr is.
   */
  if ((peer->af_flags[afi][safi] & PEER_FLAG_SOFT_RECONFIG)
                                && (peer != bgp->peer_self) && ! soft_reconfig)
    bgp_adj_in_set (rn, peer, attr);

  /* Check previously received route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* AS path local-as loop check for changed local AS.
   */
  if (peer->change_local_as)
    {
      int aspath_loop_count ;

      if (peer->flags & PEER_FLAG_LOCAL_AS_NO_PREPEND)
        aspath_loop_count = 0 ;
      else
        aspath_loop_count = 1;

      if (aspath_loop_check (attr->aspath, peer->change_local_as) >
                                                              aspath_loop_count)
        {
          reason = "as-path contains our own (change local) AS;";
          goto filtered;
        }
    }

  /* Confederation Id AS path loop check.
   */
  if (bgp->config & BGP_CONFIG_CONFEDERATION)
    {
      if (aspath_loop_check(attr->aspath, bgp->confed_id)
                                                  > peer->allowas_in[afi][safi])
        {
          reason = "as-path contains our own confederation AS;";
          goto filtered;
        } ;
    } ;

  /* AS path loop check.
   */
  if (aspath_loop_check (attr->aspath, bgp->as) > peer->allowas_in[afi][safi])
    {
      reason = "as-path contains our own AS;";
      goto filtered;
    }

  /* Route reflector originator ID check.
   */
  if ((attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID))
               && IPV4_ADDR_SAME (&bgp->router_id, &attr->extra->originator_id))
    {
      reason = "originator is us;";
      goto filtered;
    }

  /* Route reflector cluster ID check.
   */
  if (bgp_cluster_filter (peer, attr))
    {
      reason = "reflected from the same cluster;";
      goto  filtered;
    }

  /* Apply incoming filter.
   */
  if (bgp_input_filter (peer, p, attr, afi, safi) == FILTER_DENY)
    {
      reason = "filter;";
      goto filtered;
    }

  /* Apply incoming route-map.
   *
   * All the attr's sub-attr are interned, so can run that through the
   * route-map by duplicating same.  The attr itslef need not be interned.
   *
   * use_attr is set to a freshly interned copy of the attributes.
   */
  qassert(bgp_sub_attr_are_interned(attr)) ;

  use_attr = bgp_input_modifier(peer, p, attr, afi, safi) ;
  if (use_attr == NULL)
    {
      reason = "route-map;";
      goto filtered;
    }

  /* IPv4 unicast next hop check.
   */
  if ((afi == AFI_IP) && (safi == SAFI_UNICAST))
    {
      /* If the peer is EBGP and nexthop is not on connected route, discard it.
       */
      if ((sort == BGP_PEER_EBGP) && (peer->ttl == 1)
          && ! bgp_nexthop_onlink (afi, use_attr)
          && !(peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK))
        {
          reason = "non-connected next-hop;";
          goto filtered;
        }

      /* Next hop must not be 0.0.0.0 nor Class D/E address. Next hop
       * must not be my own address.
       */
      if (bgp_nexthop_self (afi, use_attr)
          || (use_attr->nexthop.s_addr == 0)
          || IPV4_CLASS_DE(ntohl(use_attr->nexthop.s_addr)))
        {
          reason = "martian next-hop;";
          goto filtered;
        }
    }

  /* If the update is implicit withdraw.
   */
  if (ri)
    {
      ri->uptime = bgp_clock ();

      /* Same attribute comes in -- which may happen with soft_reconfig !
       */
      if (!(ri->flags & BGP_INFO_REMOVED) && attrhash_cmp (ri->attr, use_attr))
        {
#if 0
          /* BUG: just 'cos we've received the same attr again, does not
           *      mean there hasn't been a change in the past.
           */
          bgp_info_unset_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
#endif

          if (!soft_reconfig)
            {
              if ((bgp->af_flags[afi][safi] & BGP_CONFIG_DAMPENING)
                     && (sort == BGP_PEER_EBGP)
                     && (ri->flags & BGP_INFO_HISTORY))
                {
                  if (BGP_DEBUG (update, UPDATE_IN))
                    zlog (peer->log, LOG_DEBUG, "%s %s %s/%d",
                          peer->host, how_recv,
                        inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                        p->prefixlen);

                  if (bgp_damp_update (ri, rn, afi, safi)
                                                        != BGP_DAMP_SUPPRESSED)
                    {
                      bgp_aggregate_increment (bgp, p, ri, afi, safi);
                      bgp_process (bgp, rn, afi, safi);
                    }
                }
              else /* Duplicate - OK for gr, odd otherwise      */
                {
                  bool gr ;

                  /* graceful restart STALE flag unset.
                   */
                  gr = (ri->flags & BGP_INFO_STALE) ;
                  if (gr)
                    {
                      bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);
                      bgp_process (bgp, rn, afi, safi);
                    }

                  if (BGP_DEBUG (update, UPDATE_IN))
                    zlog (peer->log, LOG_DEBUG, "%s %s %s/%d, %s",
                        peer->host, how_recv,
                        inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                        p->prefixlen,
                        gr ? "was stale -- restored as was"
                           : "repeated route -- odd") ;
                } ;
            } ;

          bgp_attr_unintern (use_attr);
          bgp_unlock_node (rn);
          return 0;
        }

      /* Withdraw/Announce before we fully processed the withdraw
       */
      if (ri->flags & BGP_INFO_REMOVED)
        {
          if (BGP_DEBUG (update, UPDATE_IN))
            zlog (peer->log, LOG_DEBUG, "%s %s %s/%d, "
                                              "flapped quicker than processing",
                    peer->host, how_recv,
                    inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                                                                  p->prefixlen);
          bgp_info_restore (rn, ri);
        }
      else if (BGP_DEBUG (update, UPDATE_IN))
        zlog (peer->log, LOG_DEBUG, "%s %s %s/%d",
              peer->host, how_recv,
              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
              p->prefixlen);

      /* graceful restart STALE flag unset.
       */
      if (ri->flags & BGP_INFO_STALE)
        bgp_info_unset_flag (rn, ri, BGP_INFO_STALE);

      /* The attribute is changed.
       *
       * NB: if the route was withdrawn, and has now been restored to its
       *     original value, that will still be treated as an attribute
       *     change, which will cause a new update.  BUG ? XXX
       *
       * TODO: only really need to set this if is the current selection ?
       */
      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

      /* implicit withdraw, decrement aggregate and pcount here.
       * only if update is accepted, they'll increment below.
       */
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);

      /* Update bgp route damping information.
       */
      if ((bgp->af_flags[afi][safi] & BGP_CONFIG_DAMPENING)
                                                    && (sort == BGP_PEER_EBGP))
        {
          /* This is implicit withdraw so we should update damping information.
           */
          if (!(ri->flags & BGP_INFO_HISTORY))
            bgp_damp_withdraw (ri, rn, afi, safi, 1);
        }

      /* Update to new attribute.
       */
      bgp_attr_unintern (ri->attr);
      ri->attr = use_attr ;

      /* Update MPLS tag.
       */
      if (safi == SAFI_MPLS_VPN)
        memcpy ((bgp_info_extra_get (ri))->tag, tag, 3);

      /* Update bgp route damping information.
       */
      if ((bgp->af_flags[afi][safi] & BGP_CONFIG_DAMPENING)
                                                     && (sort == BGP_PEER_EBGP))
        {
          /* Now we do normal update damping.
           */
          int ret ;

          ret = bgp_damp_update (ri, rn, afi, safi);
          if (ret == BGP_DAMP_SUPPRESSED)
            {
              bgp_unlock_node (rn);
              return 0;
            }
        }

      /* Nexthop reachability check.
       *
       * This will check if is IPv4/v6 Unicast, for iBGP and cBGP and for
       * eBGP if is (a) multi-hop or (b) the (usual) single-hop connected check
       * has been disabled.
       */
      if (((afi == AFI_IP) || (afi == AFI_IP6)) && (safi == SAFI_UNICAST)
          && (   (sort == BGP_PEER_IBGP)
              || (sort == BGP_PEER_CONFED)
              || ((sort == BGP_PEER_EBGP) && (peer->ttl != 1))
              || (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK)))
        {
          if (bgp_nexthop_lookup (afi, peer, ri, NULL, NULL))
            bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
          else
            bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
        }
      else
        bgp_info_set_flag (rn, ri, BGP_INFO_VALID);

      /* Process change.
       */
      bgp_aggregate_increment (bgp, p, ri, afi, safi);

      bgp_process (bgp, rn, afi, safi);

      bgp_unlock_node (rn);
      return 0;
    }

  /* Received Logging.
   */
  if (BGP_DEBUG (update, UPDATE_IN))
    {
      zlog (peer->log, LOG_DEBUG, "%s %s %s/%d",
              peer->host, how_recv,
              inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
              p->prefixlen);
    }

  /* Make new BGP info.
   */
  new = bgp_info_new ();
  new->type = type;
  new->sub_type = sub_type;
  new->peer = peer;
  new->attr = use_attr;
  new->uptime = bgp_clock ();

  /* Update MPLS tag.
   */
  if (safi == SAFI_MPLS_VPN)
    memcpy ((bgp_info_extra_get (new))->tag, tag, 3);

  /* Nexthop reachability check.
   */
  if (((afi == AFI_IP) || (afi == AFI_IP6)) && (safi == SAFI_UNICAST)
      && (   (sort == BGP_PEER_IBGP)
          || (sort == BGP_PEER_CONFED)
          || ((sort == BGP_PEER_EBGP) && (peer->ttl != 1))
          || (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK)))
    {
      if (bgp_nexthop_lookup (afi, peer, new, NULL, NULL))
        bgp_info_set_flag (rn, new, BGP_INFO_VALID);
      else
        bgp_info_unset_flag (rn, new, BGP_INFO_VALID);
    }
  else
    bgp_info_set_flag (rn, new, BGP_INFO_VALID);

  /* Increment prefix
   */
  bgp_aggregate_increment (bgp, p, new, afi, safi);

  /* Register new BGP information.
   */
  bgp_info_add (rn, new);

  /* If maximum prefix count is configured and current prefix count exceeds it.
   */
  if (bgp_maximum_prefix_overflow (peer, afi, safi, 0))
    {
      bgp_unlock_node (rn);
      return -1;
    } ;

  /* Process change.
   */
  bgp_process (bgp, rn, afi, safi);

  /* route_node_get lock
   */
  bgp_unlock_node (rn);
  return 0;

  /* This BGP update is filtered.  Log the reason then update BGP entry.
   */
 filtered:
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
          "%s %s UPDATE about %s/%d -- DENIED due to: %s",
          peer->host, how_recv,
          inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
          p->prefixlen, reason);

  if (ri != NULL)
    bgp_rib_remove (rn, ri, peer, afi, safi);

  if (use_attr != NULL)
    bgp_attr_unintern (use_attr);

  bgp_unlock_node (rn);
  return 0;
}

/*------------------------------------------------------------------------------
 * Process update for given prefix.
 *
 * The given attr may not be interned, but all the sub-attr MUST be.  (In
 * route-maps etc, where the sub-attr may change, uses ref_count == 0 to
 * detect new values.)  Caller is responsible for the attr and any 'extra',
 * which will be returned unchanged.
 */
extern int
bgp_update (struct peer *peer, struct prefix *p, struct attr *attr,
            afi_t afi, safi_t safi, int type, int sub_type,
            struct prefix_rd *prd, u_char *tag, bool soft_reconfig)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;
  struct bgp *bgp;
  int ret;

  qassert(bgp_sub_attr_are_interned(attr)) ;

  /* For all neighbors, update the main RIB
   */
  ret = bgp_update_main (peer, p, attr, afi, safi, type, sub_type, prd, tag,
                                                                 soft_reconfig);

  /* Update all Route-Server Client RIBs
   */
  bgp = peer->bgp;

  if (bgp->rsclient != NULL)
    {
      struct rs_route rt_s ;

      /* Prepare the rs_route object, ready to update all rs clients active
       * in this afi/safi.
       */
      bgp_rs_route_init(&rt_s, afi, safi, attr, peer, p, type, sub_type,
                                                                     prd, tag) ;

      /* Process the update for each RS-client.
       */
      for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
        if (rsclient->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)
          bgp_update_rsclient (rsclient, &rt_s, soft_reconfig) ;

      /* Reset the rs_route object -- in particular discard any interned
       * rs_in_attr which may have been created.
       */
      bgp_rs_route_reset(&rt_s) ;
    } ;

  /* Return result from bgp_update_main
   */
  return ret;
}

extern int
bgp_withdraw (struct peer *peer, struct prefix *p, struct attr *attr,
             afi_t afi, safi_t safi, int type, int sub_type,
             struct prefix_rd *prd, u_char *tag)
{
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp = peer->bgp;

  /* Process the withdraw for each RS-client.
   */
  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (rsclient->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)
        bgp_withdraw_rsclient (rsclient, afi, safi, peer, p, type, sub_type,
                                                                      prd, tag);
    }

  /* Logging.
   */
  if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG, "%s rcvd UPDATE about %s/%d -- withdrawn",
          peer->host,
          inet_ntop(p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
          p->prefixlen);

  /* Lookup node.
   */
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* If peer is soft reconfiguration enabled remove recorded route, if any.
   */
  if ((peer->af_flags[afi][safi] & PEER_FLAG_SOFT_RECONFIG)
                                                    && (peer != bgp->peer_self))
    bgp_adj_in_unset (rn, peer);

  /* Lookup withdrawn route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == peer) && (ri->type == type) && (ri->sub_type == sub_type))
      break;

  /* Withdraw specified route from routing table.
   */
  if ((ri != NULL) && !(ri->flags & BGP_INFO_HISTORY))
    bgp_rib_withdraw (rn, ri, peer, afi, safi);
  else if (BGP_DEBUG (update, UPDATE_IN))
    zlog (peer->log, LOG_DEBUG,
          "%s Can't find the route %s/%d", peer->host,
          inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
          p->prefixlen);

  /* Unlock bgp_node_get() lock.
   */
  bgp_unlock_node (rn);

  return 0;
}

extern void
bgp_default_originate (struct peer *peer, afi_t afi, safi_t safi, bool withdraw)
{
  struct bgp *bgp;
  struct attr  attr_s ;
  struct attr* attr ;
  struct prefix p;
  struct peer *from;

  if (!(afi == AFI_IP || afi == AFI_IP6))
    return;

  bgp = peer->bgp;
  from = bgp->peer_self;

  /* We create a temporary set of attributes, with no interned sub-attr.
   */
  attr = bgp_attr_default_set (&attr_s, BGP_ORIGIN_IGP, false /* !intern */);
  attr->local_pref = bgp->default_local_pref;
  memcpy (&attr->nexthop, &peer->nexthop.v4, IPV4_MAX_BYTELEN);

  if (afi == AFI_IP)
    str2prefix ("0.0.0.0/0", &p);
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      struct attr_extra *ae;

      ae = bgp_attr_extra_get (attr);

      str2prefix ("::/0", &p);

      /* IPv6 global nexthop must be included.
       */
      memcpy (&ae->mp_nexthop_global, &peer->nexthop.v6_global,
              IPV6_MAX_BYTELEN);
              ae->mp_nexthop_len = 16;

      /* If the peer is on shared nextwork and we have link-local nexthop,
       * set it.
       */
      if (peer->shared_network
          && !IN6_IS_ADDR_UNSPECIFIED (&peer->nexthop.v6_local))
        {
          memcpy (&ae->mp_nexthop_local, &peer->nexthop.v6_local,
                  IPV6_MAX_BYTELEN);
          ae->mp_nexthop_len = 32;
        }
    }
#endif /* HAVE_IPV6 */

  if ((peer->default_rmap[afi][safi].name != NULL) && !withdraw)
    {
      /* The attr contains only uninterned sub-attr.
       *
       * So can give it directly to the route-map stuff, which will discard
       * any uninterned sub-attr and replace with uninterned sub-attr if
       * any sub-attr is changed.
       */
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      info_s.peer = bgp->peer_self ;
      info_s.attr = attr;
      info_s.peer->rmap_type = PEER_RMAP_TYPE_DEFAULT ;
      ret = route_map_apply (peer->default_rmap[afi][safi].map, &p,
                                                            RMAP_BGP, &info_s);

      withdraw = (ret == RMAP_DENYMATCH) ;
    }

  if (withdraw)
    {
      if (peer->af_sflags[afi][safi] & PEER_STATUS_DEFAULT_ORIGINATE)
        bgp_default_withdraw_send (peer, afi, safi);
      UNSET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
    }
  else
    {
      /* The attributes are uninterned, and all sub-attributes are.  That
       * does not matter to bgp_default_update_send().
       */
      SET_FLAG (peer->af_sflags[afi][safi], PEER_STATUS_DEFAULT_ORIGINATE);
      bgp_default_update_send (peer, attr, afi, safi, from);
    } ;

  bgp_attr_flush(attr) ;
} ;

/*------------------------------------------------------------------------------
 * For the given table and afi/safi, announce all routes for the given peer.
 */
static void
bgp_announce_table (struct peer *peer, afi_t afi, safi_t safi,
                   struct bgp_table *table, int rsclient)
{
  struct bgp_node *rn;

  if (! table)
    table = (rsclient) ? peer->rib[afi][safi] : peer->bgp->rib[afi][safi];

  if ((safi != SAFI_MPLS_VPN)
      && (peer->af_flags[afi][safi] & PEER_FLAG_DEFAULT_ORIGINATE))
    bgp_default_originate (peer, afi, safi, false);

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next(rn))
    {
      struct bgp_info *ri;

      for (ri = rn->info; ri; ri = ri->info_next)
        {
          struct attr* attr ;

          /* We do not announce to the source peer.
           */
          if (ri->peer == peer)
            continue ;

          /* Announce the selected route.
           *
           * This is slightly less than than satisfactory...  this may announce
           * routes which are not Valid and/or Stale and/or Removed :-(
           *
           * The problem is that the process logic assumes that if it
           * reselects the selected route, it does not need to announce it.
           * Which is generally a good thing.  In this case, however, suppose
           * the currently selected route has been Removed.  If we did not
           * announce that route, then between now and the processing loop,
           * the route might be restored, and at that point be reselected
           * and hence not announced !  On the other hand, what will now
           * happen is that the route will be announced, and at some
           * future date (soon, one hopes) withdrawn or replaced !
           *
           * What is a way to force an update for a subset of all peers.
           */
          if (!(ri->flags & BGP_INFO_SELECTED))
            continue ;

          if (!rsclient)
            attr = bgp_announce_check (ri, peer, &rn->p, afi, safi) ;
          else
            attr = bgp_announce_check_rsclient (ri, peer, &rn->p, afi, safi) ;

          if (attr != NULL)
            bgp_adj_out_set (rn, peer, &rn->p, attr, afi, safi, ri);
          else
            bgp_adj_out_unset (rn, peer, &rn->p, afi, safi);
        } ;
    } ;
} ;

void
bgp_announce_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

  if (peer->state != bgp_peer_pEstablished)
    return;

  if (! peer->afc_nego[afi][safi])
    return;

  /* First update is deferred until ORF or ROUTE-REFRESH is received
   */
  if (peer->af_sflags[afi][safi] & PEER_STATUS_ORF_WAIT_REFRESH)
    return;

  if (safi != SAFI_MPLS_VPN)
    bgp_announce_table (peer, afi, safi, NULL, 0);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
         rn = bgp_route_next(rn))
      if ((table = (rn->info)) != NULL)
       bgp_announce_table (peer, afi, safi, table, 0);

  if (peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)
    bgp_announce_table (peer, afi, safi, NULL, 1);
}

void
bgp_announce_route_all (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_announce_route (peer, afi, safi);
}

static void
bgp_soft_reconfig_table_rsclient (struct peer *rsclient, afi_t afi,
        safi_t safi, struct bgp_table *table)
{
  struct bgp_node *rn;
  struct bgp_adj_in *ain;
  struct rs_route rt_s ;

  if (! table)
    table = rsclient->bgp->rib[afi][safi];

  /* Prepare the rs_route object, setting all the parts common to all routes
   * which are about to announce to the rs client.
   */
  bgp_rs_route_init(&rt_s, afi, safi, NULL, NULL, NULL,
                                ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL) ;

  /* Announce everything in the table.
   */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->adj_next)
      {
        rt_s.orig_attr = ain->attr ;
        rt_s.peer      = ain->peer ;
        rt_s.p         = &rn->p ;

        bgp_update_rsclient (rsclient, &rt_s, true /* soft_reconfig */) ;

        /* Reset the rs_route object -- which discards any interned rs_in_attr
         * which may have been created and clears the rs_in_applied flag.
         *
         * Leaves everything else !
         */
        bgp_rs_route_reset(&rt_s) ;
      } ;
}

void
bgp_soft_reconfig_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;

  if (safi != SAFI_MPLS_VPN)
    bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, NULL);

  else
    for (rn = bgp_table_top (rsclient->bgp->rib[afi][safi]); rn;
            rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        bgp_soft_reconfig_table_rsclient (rsclient, afi, safi, table);
}

static void
bgp_soft_reconfig_table (struct peer *peer, afi_t afi, safi_t safi,
                         struct bgp_table *table)
{
  int ret;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  if (! table)
    table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain; ain = ain->adj_next)
      {
        if (ain->peer == peer)
          {
            ret = bgp_update (peer, &rn->p, ain->attr, afi, safi,
                              ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
                              NULL, NULL, true /* soft_reconfig */);
            if (ret < 0)
              {
                bgp_unlock_node (rn);
                return;
              }
            continue;
          }
      }
}

void
bgp_soft_reconfig_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_table *table;

  if (peer->state != bgp_peer_pEstablished)
    return;

  if (safi != SAFI_MPLS_VPN)
    bgp_soft_reconfig_table (peer, afi, safi, NULL);
  else
    for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
         rn = bgp_route_next (rn))
      if ((table = rn->info) != NULL)
        bgp_soft_reconfig_table (peer, afi, safi, table);
}

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
 * Normal clearing of a a given peer's routes.
 *
 * The following lists are processed:
 *
 *   * struct bgp_info* routes_head
 *
 *     Walks this and clears each route.
 *
 *   * struct bgp_adj_in* adj_in_head
 *   * struct bgp_adj_out* adj_out_head
 *
 *     These two are simply emptied out.
 *
 * NB: in the latest scheme of things this is completed immediately...
 *
 *     ...however, retain the ability for this to kick off background or other
 *     activity.
 *
 * Returns:  true <=> clearing has completed
 *
 */
extern bool
bgp_clear_routes(struct peer *peer, afi_t afi, safi_t safi, bool nsf)
{
  struct bgp_info*     ri ;
  struct bgp_info*     next_ri ;
  struct bgp_adj_in*   adj_in ;
  struct bgp_adj_out*  adj_out ;
  struct bgp_adj_in**  adj_in_head ;
  struct bgp_adj_out** adj_out_head ;

  next_ri = peer->routes_head[afi][safi] ;

  /* If NSF requested and nsf configured for this afi/safi, do nsf and
   * set flag to indicate that at least one afi/safi may have stale routes.
   */
  nsf = nsf && peer->nsf[afi][safi] ;
  if (nsf)
    SET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT) ;

  /* TODO: fix bgp_clear_route_normal() so can clear an MPLS VPN table....  */
  if (next_ri != NULL)
    assert(safi != SAFI_MPLS_VPN) ;

  while (next_ri != NULL)
    {
      /* The current bgp_info object may vanish, so bank the next       */
      ri = next_ri ;
      next_ri = ri->routes_next ;

      assert (peer == ri->peer) ;

      if (nsf && !(ri->flags & (BGP_INFO_STALE | BGP_INFO_UNUSEABLE)))
        bgp_info_set_flag (ri->rn, ri, BGP_INFO_STALE);
      else
        bgp_rib_remove (ri->rn, ri, peer, afi, safi);
    } ;

  /* Empty out all adjacencies
   */
  adj_in_head = &(peer->adj_in_head[afi][safi]) ;
  while ((adj_in = *adj_in_head) != NULL)
    {
      assert(adj_in->route_prev == NULL) ;
      bgp_adj_in_remove (adj_in->rn, adj_in) ;
      assert(adj_in != *adj_in_head) ;
    } ;

  adj_out_head = &(peer->adj_out_head[afi][safi]) ;
  while ((adj_out = *adj_out_head) != NULL)
    {
      assert(adj_out->route_prev == NULL) ;
      bgp_adj_out_remove (adj_out->rn, adj_out, peer, afi, safi) ;
      assert(adj_out != *adj_out_head) ;
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Normal clearing of given peer for all AFI/SAFI -- respecting NSF if required.
 *
 * NB: in the latest scheme of things this is completed immediately...
 *
 *     ...however, retain the ability to run this in the background with the
 *        peer in bgp_peer_pClearing.
 *
 * Returns: true <=> all clearing completed
 *          so false => something running in the background.
 */
extern bool
bgp_clear_all_routes (struct peer *peer, bool nsf)
{
  bool completed ;
  afi_t afi;
  safi_t safi;

  assert(peer->state == bgp_peer_pClearing) ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT) ;

  completed = true ;
  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      if (!bgp_clear_routes(peer, afi, safi, nsf))
        completed = false ;

  return completed ;
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
bgp_clear_rsclient_rib(struct peer* rsclient, afi_t afi, safi_t safi)
{
  struct bgp_node *rn ;
  struct bgp_table* table ;

  table = rsclient->rib[afi][safi] ;

  if (table == NULL)
    return ;            /* Ignore unconfigured afi/safi or similar      */

  /* TODO: fix bgp_clear_rsclient_rib() so that will clear an MPLS VPN table. */
  passert(table->safi != SAFI_MPLS_VPN) ;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_info    *ri;
      struct bgp_info    *next_ri ;
      struct bgp_adj_in  *ain;
      struct bgp_adj_out *aout;

      next_ri = rn->info ;
      while(next_ri != NULL)
        {
          ri = next_ri ;
          next_ri = ri->info_next ;     /* bank this    */

          bgp_rib_remove (rn, ri, rsclient, table->afi, table->safi);
        } ;

      while ((ain = rn->adj_in) != NULL)
        {
          assert(ain->adj_prev == NULL) ;
          bgp_adj_in_remove (rn, ain);
          assert(ain != rn->adj_in) ;
        } ;

      while ((aout = rn->adj_out) != NULL)
        {
          assert(aout->adj_prev == NULL) ;
          bgp_adj_out_remove (rn, aout, aout->peer, table->afi, table->safi) ;
          assert(aout != rn->adj_out) ;
        } ;
    }
  return ;
}

/*------------------------------------------------------------------------------
 * Walk main RIB and remove any adj_in for given peer.
 *
 * TODO: walk peer->bgp_adj_in_head[afi][safi] -- but check which table ?
 */
void
bgp_clear_adj_in (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_table *table;
  struct bgp_node *rn;
  struct bgp_adj_in *ain;

  table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    for (ain = rn->adj_in; ain ; ain = ain->adj_next)
      if (ain->peer == peer)
        {
          bgp_adj_in_remove (rn, ain);
          break;
        }
} ;

/*------------------------------------------------------------------------------
 * Walk main RIB and remove all stale routes for the given peer.
 *
 * NB: is required to complete immediately !
 *
 * TODO: walk peer->routes_head[afi][safi]
 */
void
bgp_clear_stale_route (struct peer *peer, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = peer->bgp->rib[afi][safi];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->info_next)
        if (ri->peer == peer)
          {
            if (ri->flags & BGP_INFO_STALE)
              bgp_rib_remove (rn, ri, peer, afi, safi);
            break;
          }
    }
}

#if 0

struct bgp_clear_node_queue
{
  struct bgp_node *rn;
  enum bgp_clear_route_type purpose;
};

WQ_ARGS_SIZE_OK(bgp_clear_node_queue) ;

static wq_item_status
bgp_clear_route_node (struct work_queue *wq, work_queue_item item)
{
  struct bgp_clear_node_queue *cnq = work_queue_item_args(item) ;
  struct bgp_node *rn = cnq->rn;
  struct peer *peer = wq->spec.data;
  struct bgp_info *ri;
  afi_t afi = rn->table->afi;
  safi_t safi = rn->table->safi;

  assert (rn && peer);

  for (ri = rn->info; ri; ri = ri->info_next)
    if (ri->peer == peer || cnq->purpose == BGP_CLEAR_ROUTE_MY_RSCLIENT)
      {
        /* graceful restart STALE flag set. */
        if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT)
            && peer->nsf[afi][safi]
            && ! CHECK_FLAG (ri->flags, BGP_INFO_STALE)
            && ! CHECK_FLAG (ri->flags, BGP_INFO_UNUSEABLE))
          bgp_info_set_flag (rn, ri, BGP_INFO_STALE);
        else
          bgp_rib_remove (rn, ri, peer, afi, safi);
        break;
      }
  return WQ_SUCCESS;
}

static void
bgp_clear_node_queue_del (struct work_queue *wq, work_queue_item item)
{
  struct bgp_clear_node_queue *cnq = work_queue_item_args(item) ;
  struct bgp_node *rn = cnq->rn;
  struct bgp_table *table = rn->table;

  bgp_unlock_node (rn);
  bgp_table_unlock (table);
}

static void
bgp_clear_node_complete (struct work_queue *wq)
{
  struct peer *peer = wq->spec.data;

  /* Flush the event queue and ensure the peer is shut down */
  bgp_peer_stop(peer);
  BGP_EVENT_FLUSH (peer);
  if (peer->state == bgp_peer_pClearing)
    {
      peer_change_status (peer, bgp_peer_pIdle);
      /* enable peer if required */
      bgp_peer_enable(peer);
    }

  bgp_peer_unlock (peer); /* bgp_clear_route */
}

static void
bgp_clear_node_queue_init (struct peer *peer)
{
  char wname[sizeof("clear xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx")];

  snprintf (wname, sizeof(wname), "clear %s", peer->host);
#undef CLEAR_QUEUE_NAME_LEN

  if ( (peer->clear_node_queue = work_queue_new (bm->master, wname)) == NULL)
    {
      zlog_err ("%s: Failed to allocate work queue", __func__);
      exit (1);
    }
  peer->clear_node_queue->spec.hold = 10;
  peer->clear_node_queue->spec.workfunc = &bgp_clear_route_node;
  peer->clear_node_queue->spec.del_item_data = &bgp_clear_node_queue_del;
  peer->clear_node_queue->spec.completion_func = &bgp_clear_node_complete;
  peer->clear_node_queue->spec.max_retries = 0;

  /* we only 'lock' this peer reference when the queue is actually active */
  peer->clear_node_queue->spec.data = peer;
}

void
bgp_clear_route (struct peer *peer, afi_t afi, safi_t safi)
{
//struct bgp_node *rn;
//struct bgp_table *table;
//struct peer *rsclient;
//struct listnode *node, *nnode;

//if (peer->clear_node_queue == NULL)
//  bgp_clear_node_queue_init (peer);

  /* bgp_fsm.c keeps sessions in state Clearing, not transitioning to
   * Idle until it receives a Clearing_Completed event. This protects
   * against peers which flap faster than we can we clear, which could
   * lead to:
   *
   * a) race with routes from the new session being installed before
   *    clear_route_node visits the node (to delete the route of that
   *    peer)
   * b) resource exhaustion, clear_route_node likely leads to an entry
   *    on the process_main queue. Fast-flapping could cause that queue
   *    to grow and grow.
   */
//if (!peer->clear_node_queue->thread)
  bgp_peer_lock (peer); /* bgp_clear_node_complete */

  switch (purpose)
    {
    case BGP_CLEAR_ROUTE_NORMAL:
      if (peer->routes_head[afi][safi] == NULL)
        break ;

      if (safi != SAFI_MPLS_VPN)
        bgp_clear_route_normal(peer, afi, safi) ;
      else
/* TODO: how to deal with SAFI_MPLS_VPN in bgp_clear_route ??   */
        passert(0) ;
#if 0
        for (rn = bgp_table_top (peer->bgp->rib[afi][safi]); rn;
             rn = bgp_route_next (rn))
          if ((table = rn->info) != NULL)
            bgp_clear_route_table (peer, afi, safi, table, NULL, purpose);
#endif
#if 0
      for (ALL_LIST_ELEMENTS (peer->bgp->rsclient, node, nnode, rsclient))
        if (CHECK_FLAG(rsclient->af_flags[afi][safi],
                       PEER_FLAG_RSERVER_CLIENT))
          bgp_clear_route_table (peer, afi, safi, NULL, rsclient, purpose);
#endif
      break;

    case BGP_CLEAR_ROUTE_MY_RSCLIENT:
      bgp_clear_route_table (peer, peer->rib[afi][safi]) ;
      break;

    default:
      assert (0);
      break;
    }

  /* If no routes were cleared, nothing was added to workqueue, the
   * completion function won't be run by workqueue code - call it here.
   * XXX: Actually, this assumption doesn't hold, see
   * bgp_clear_route_table(), we queue all non-empty nodes.
   *
   * Additionally, there is a presumption in FSM that clearing is only
   * really needed if peer state is Established - peers in
   * pre-Established states shouldn't have any route-update state
   * associated with them (in or out).
   *
   * We still can get here in pre-Established though, through
   * peer_delete -> bgp_fsm_change_status, so this is a useful sanity
   * check to ensure the assumption above holds.
   *
   * At some future point, this check could be move to the top of the
   * function, and do a quick early-return when state is
   * pre-Established, avoiding above list and table scans. Once we're
   * sure it is safe..
   */

  /* The following was in bgp_clear_node_complete               */

  bgp_peer_unlock (peer); /* bgp_clear_route */
}
#endif

/*============================================================================*/

#if 0
/* Delete all kernel routes.                            */
void
bgp_cleanup_routes (void)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      table = bgp->rib[AFI_IP][SAFI_UNICAST];

      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        for (ri = rn->info; ri; ri = ri->info_next)
          if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
              && ri->type == ZEBRA_ROUTE_BGP
              && ri->sub_type == BGP_ROUTE_NORMAL)
            bgp_zebra_withdraw (&rn->p, ri,SAFI_UNICAST);

      table = bgp->rib[AFI_IP6][SAFI_UNICAST];

      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        for (ri = rn->info; ri; ri = ri->info_next)
          if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
              && ri->type == ZEBRA_ROUTE_BGP
              && ri->sub_type == BGP_ROUTE_NORMAL)
            bgp_zebra_withdraw (&rn->p, ri,SAFI_UNICAST);
    }
}
#endif

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
  access_list_reset ();
  prefix_list_reset (keep_it);
}

/*------------------------------------------------------------------------------
 * Parse NLRI stream.  Withdraw NLRI is recognized by NULL attr value.
 *
 * The given attr may not be interned, but all the sub-attr MUST be.  (In
 * route-maps etc, where the sub-attr may change, uses ref_count == 0 to
 * detect new values.)
 */
extern int
bgp_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  struct prefix p;
  int psize;
  int ret;

  qassert(bgp_sub_attr_are_interned(attr)) ;

  /* Check peer status.
   */
  if (peer->state != bgp_peer_pEstablished)
    return 0;

  pnt = packet->nlri;
  lim = pnt + packet->length;

  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure.
       */
      memset (&p, 0, sizeof (struct prefix));

      /* Fetch prefix length.
       */
      p.prefixlen = *pnt++;
      p.family = afi2family (packet->afi);

      /* Already checked in nlri_sanity_check().  We do double check here.
       */
      if ( ((packet->afi == AFI_IP)  && (p.prefixlen >  32)) ||
           ((packet->afi == AFI_IP6) && (p.prefixlen > 128)) )
        return -1;

      /* Packet size overflow check.
       */
      psize = PSIZE (p.prefixlen);

      /* When packet overflow occur return immediately.
       */
      if (pnt + psize > lim)
        return -1;

      /* Fetch prefix from NLRI packet.
       */
      memcpy (&p.u.prefix, pnt, psize);

      /* Check address.
       */
      if ((packet->afi == AFI_IP) && (packet->safi == SAFI_UNICAST))
        {
          if (IN_CLASSD (ntohl (p.u.prefix4.s_addr)))
            {
             /*
              * From draft-ietf-idr-bgp4-22, Section 6.3:
              * If a BGP router receives an UPDATE message with a
              * semantically incorrect NLRI field, in which a prefix is
              * semantically incorrect (eg. an unexpected multicast IP
              * address), it should ignore the prefix.
              */
              zlog (peer->log, LOG_ERR,
                    "IPv4 unicast NLRI is multicast address %s",
                    safe_inet_ntoa (p.u.prefix4));

              return -1;
            }
        }

#ifdef HAVE_IPV6
      /* Check address.
       */
      if ((packet->afi == AFI_IP6) && (packet->safi == SAFI_UNICAST))
        {
          if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
            {
              char buf[BUFSIZ];

              zlog (peer->log, LOG_WARNING,
                    "IPv6 link-local NLRI received %s ignore this NLRI",
                    inet_ntop (AF_INET6, &p.u.prefix6, buf, BUFSIZ));

              continue;
            }
        }
#endif /* HAVE_IPV6 */

      /* Normal process.
       */
      if (attr)
        ret = bgp_update (peer, &p, attr, packet->afi, packet->safi,
                          ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL,
                                                    false /* !soft_reconfig */);
      else
        ret = bgp_withdraw (peer, &p, NULL, packet->afi, packet->safi,
                            ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL);

      /* Address family configuration mismatch or maximum-prefix count
       * overflow.
       */
      if (ret < 0)
        return -1;
    }

  /* Packet length consistency check.
   */
  if (pnt != lim)
    return -1;

  return 0;
}

/* NLRI encode syntax check routine. */
int
bgp_nlri_sanity_check (struct peer *peer, int afi, u_char *pnt,
                                                   bgp_size_t length)
{
  size_t offset ;
  u_char prefixlen_max ;

  switch (afi)
    {
      case AFI_IP:
        prefixlen_max =  32 ;
        break ;

      case AFI_IP6:
        prefixlen_max = 128 ;
        break ;

      default:
        prefixlen_max = 255 ;   /* it's a byte, guys    */
        break ;
    } ;

  /* RFC1771 6.3 The NLRI field in the UPDATE message is checked for
     syntactic validity.  If the field is syntactically incorrect,
     then the Error Subcode is set to Invalid Network Field. */

  offset = 0 ;
  while (offset < length)
    {
      u_char  prefixlen;

      prefixlen = pnt[offset] ;

      /* Prefix length check.
       */
      if (prefixlen > prefixlen_max)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error: prefix length %u > %u "
                                                                  "for %s NLRI",
                    peer->host, prefixlen, prefixlen_max,
                                        map_direct(bgp_afi_name_map, afi).str) ;
          bgp_peer_down_error(peer, BGP_NOTIFY_UPDATE_ERR,
                                    BGP_NOTIFY_UPDATE_INVAL_NETWORK);
          return -1;
        }

      /* Step and check remains within total length.
       */
      offset += PSIZE(prefixlen) + 1 ;

      if (offset > length)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error: prefix length %u overruns"
                                                       " total size of %s NLRI",
                    peer->host, prefixlen,
                                         map_direct(bgp_afi_name_map, afi).str);
          bgp_peer_down_error(peer, BGP_NOTIFY_UPDATE_ERR,
                                    BGP_NOTIFY_UPDATE_INVAL_NETWORK);
          return -1;
        }
    } ;

  return 0;
}

static struct bgp_static *
bgp_static_new (void)
{
  return XCALLOC (MTYPE_BGP_STATIC, sizeof (struct bgp_static));
}

static void
bgp_static_free (struct bgp_static *bgp_static)
{
  if (bgp_static->rmap.name)
    free (bgp_static->rmap.name);
  XFREE (MTYPE_BGP_STATIC, bgp_static);
}

static void
bgp_static_withdraw_rsclient (struct bgp *bgp, struct peer *rsclient,
        struct prefix *p, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  /* Check selected route and self inserted route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == bgp->peer_self) && (ri->type == ZEBRA_ROUTE_BGP)
                                     && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  /* Withdraw static BGP route from routing table.
   */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_rsclient (struct peer *rsclient, struct prefix *p,
                            struct bgp_static *bgp_static,
                            afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct attr static_attr_s ;
  struct attr* static_attr ;
  struct rs_route rt_s ;
  struct bgp *bgp;
  char buf[SU_ADDRSTRLEN];

  bgp = rsclient->bgp;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (rsclient->rib[afi][safi], afi, safi, p, NULL);

  /* Construct the static route attributes.
   *
   * The static_attr contains no interned sub-attr, so can be passed through
   * the route-map directly.
   */
  static_attr = bgp_attr_default_set (&static_attr_s, BGP_ORIGIN_IGP,
                                                          false /* !intern */) ;

  static_attr->nexthop = bgp_static->igpnexthop;
  static_attr->med     = bgp_static->igpmetric;
  static_attr->flag   |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (bgp_static->atomic)
    static_attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  /* Apply network route-map for export to this rsclient.
   *
   * Create interned attributes client_attr, either from route-map result, or
   * from the static_attr.
   */
  if (bgp_static->rmap.name)
    {
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      info_s.peer = rsclient ;
      info_s.attr = static_attr ;
      info_s.peer->rmap_type = PEER_RMAP_TYPE_EXPORT | PEER_RMAP_TYPE_NETWORK ;
      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
        {
          /* Discard the manufactured static_attr, and anything which the
           * route-map has added.
           *
           * Note that we start with an interned aspath.
           *
           * NB: if anything else were to be added
           */
          bgp_attr_flush (static_attr);

          bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);

          return;
        } ;
    } ;

  static_attr = bgp_attr_intern_temp(static_attr) ;

  /* run the import route-map for the rsclient.
   */
  bgp_rs_route_init(&rt_s, afi, safi, NULL, bgp->peer_self, p,
                                ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL, NULL) ;

  static_attr = bgp_import_modifier (rsclient, &rt_s, static_attr,
                                                       PEER_RMAP_TYPE_NETWORK) ;

  if (static_attr == NULL)
    {
      /* This BGP update is filtered.  Log the reason then update BGP entry.
       */
      if (BGP_DEBUG (update, UPDATE_IN))
            zlog (rsclient->log, LOG_DEBUG,
            "Static UPDATE about %s/%d -- DENIED for RS-client %s due to: "
                                                                "import-policy",
            inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
            p->prefixlen, rsclient->host);

      bgp_static_withdraw_rsclient (bgp, rsclient, p, afi, safi);

      return;
    }

  /* Apply the client_attr
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == bgp->peer_self) && (ri->type == ZEBRA_ROUTE_BGP)
                                     && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  if (ri)
    {
      if (attrhash_cmp (ri->attr, static_attr) &&
                                               !(ri->flags & BGP_INFO_REMOVED))
        {
          /* No point duplicating
           */
          bgp_attr_unintern (static_attr);
        }
      else
        {
          /* The attribute is changed.
           */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information.
           */
          if (ri->flags & BGP_INFO_REMOVED)
            bgp_info_restore(rn, ri);

          bgp_attr_unintern (ri->attr);
          ri->attr   = static_attr ;
          ri->uptime = bgp_clock ();

          /* Process change.
           */
          bgp_process (bgp, rn, afi, safi);
        }

      bgp_unlock_node (rn);
      return ;
    } ;

  /* Make new BGP info.
   */
  ri = bgp_info_new ();
  ri->type     = rt_s.type ;
  ri->sub_type = rt_s.sub_type ;
  ri->peer     = rt_s.peer ;
  ri->attr     = static_attr ;
  ri->uptime   = bgp_clock ();

  SET_FLAG (ri->flags, BGP_INFO_VALID);

  /* Register new BGP information.
   */
  bgp_info_add (rn, ri);

  /* Process change.
   */
  bgp_process (bgp, rn, afi, safi);

  /* route_node_get lock
   */
  bgp_unlock_node (rn);
}

static void
bgp_static_update_main (struct bgp *bgp, struct prefix *p,
                   struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_info *new;
  struct attr static_attr_s ;
  struct attr* static_attr ;

  assert (bgp_static);
  if (!bgp_static)
    return;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);

  static_attr = bgp_attr_default_set (&static_attr_s, BGP_ORIGIN_IGP,
                                                          false /* !intern */) ;

  static_attr->nexthop = bgp_static->igpnexthop;
  static_attr->med = bgp_static->igpmetric;
  static_attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  if (bgp_static->atomic)
    static_attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  /* Apply route-map.
   */
  if (bgp_static->rmap.name)
    {
      struct bgp_info info_s = { 0 } ;
      route_map_result_t ret;

      info_s.peer = bgp->peer_self;
      info_s.attr = static_attr ;

      info_s.peer->rmap_type = PEER_RMAP_TYPE_NETWORK ;
      ret = route_map_apply (bgp_static->rmap.map, p, RMAP_BGP, &info_s);

      if (ret == RMAP_DENYMATCH)
        {
          /* Discard temporary attributes
           */
          bgp_attr_flush (static_attr);

          bgp_static_withdraw (bgp, p, afi, safi);
          return;
        } ;
    } ;

  static_attr = bgp_attr_intern_temp(static_attr);

  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == bgp->peer_self) && (ri->type == ZEBRA_ROUTE_BGP)
                                     && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  if (ri)
    {
      if (attrhash_cmp (ri->attr, static_attr) &&
                                                !(ri->flags & BGP_INFO_REMOVED))
        {
          bgp_unlock_node (rn);
          bgp_attr_unintern (static_attr);
          return;
        }
      else
        {
          /* The attribute is changed.
           */
          bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);

          /* Rewrite BGP route information.
           */
          if (ri->flags & BGP_INFO_REMOVED)
            bgp_info_restore(rn, ri);
          else
            bgp_aggregate_decrement (bgp, p, ri, afi, safi);
          bgp_attr_unintern (ri->attr);
          ri->attr = static_attr;
          ri->uptime = bgp_clock ();

          /* Process change.
           */
          bgp_aggregate_increment (bgp, p, ri, afi, safi);
          bgp_process (bgp, rn, afi, safi);
          bgp_unlock_node (rn);
          return;
        }
    }

  /* Make new BGP info.
   */
  new = bgp_info_new ();
  new->type = ZEBRA_ROUTE_BGP;
  new->sub_type = BGP_ROUTE_STATIC;
  new->peer = bgp->peer_self;
  SET_FLAG (new->flags, BGP_INFO_VALID);
  new->attr = static_attr;
  new->uptime = bgp_clock ();

  /* Aggregate address increment.
   */
  bgp_aggregate_increment (bgp, p, new, afi, safi);

  /* Register new BGP information.
   */
  bgp_info_add (rn, new);

  /* route_node_get lock
   */
  bgp_unlock_node (rn);

  /* Process change.
   */
  bgp_process (bgp, rn, afi, safi);
}

void
bgp_static_update (struct bgp *bgp, struct prefix *p,
                  struct bgp_static *bgp_static, afi_t afi, safi_t safi)
{
  struct peer *rsclient;
  struct listnode *node, *nnode;

  bgp_static_update_main (bgp, p, bgp_static, afi, safi);

  for (ALL_LIST_ELEMENTS (bgp->rsclient, node, nnode, rsclient))
    {
      if (rsclient->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT)
        bgp_static_update_rsclient (rsclient, p, bgp_static, afi, safi);
    }
}

static void
bgp_static_update_vpnv4 (struct bgp *bgp, struct prefix *p, afi_t afi,
                         safi_t safi, struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *new;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Make new BGP info.
   */
  new = bgp_info_new ();
  new->type = ZEBRA_ROUTE_BGP;
  new->sub_type = BGP_ROUTE_STATIC;
  new->peer = bgp->peer_self;
  new->attr = bgp_attr_default_intern (BGP_ORIGIN_IGP);
  SET_FLAG (new->flags, BGP_INFO_VALID);
  new->uptime = bgp_clock ();
  new->extra = bgp_info_extra_new();
  memcpy (new->extra->tag, tag, 3);

  /* Aggregate address increment.
   */
  bgp_aggregate_increment (bgp, p, new, afi, safi);

  /* Register new BGP information.
   */
  bgp_info_add (rn, new);

  /* route_node_get lock
   */
  bgp_unlock_node (rn);

  /* Process change.
   */
  bgp_process (bgp, rn, afi, safi);
}

void
bgp_static_withdraw (struct bgp *bgp, struct prefix *p, afi_t afi,
                     safi_t safi)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, NULL);

  /* Check selected route and self inserted route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == bgp->peer_self) && (ri->type == ZEBRA_ROUTE_BGP)
                                     && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  /* Withdraw static BGP route from routing table.
   */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (rn);
}

void
bgp_check_local_routes_rsclient (struct peer *rsclient, afi_t afi, safi_t safi)
{
  struct bgp_static *bgp_static;
  struct bgp *bgp;
  struct bgp_node *rn;
  struct prefix *p;

  bgp = rsclient->bgp;

  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        bgp_static_update_rsclient (rsclient, p, bgp_static, afi, safi);
      }
}

static void
bgp_static_withdraw_vpnv4 (struct bgp *bgp, struct prefix *p, afi_t afi,
                           safi_t safi, struct prefix_rd *prd, u_char *tag)
{
  struct bgp_node *rn;
  struct bgp_info *ri;

  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi, p, prd);

  /* Check selected route and self inserted route.
   */
  for (ri = rn->info; ri; ri = ri->info_next)
    if ((ri->peer == bgp->peer_self) && (ri->type == ZEBRA_ROUTE_BGP)
                                     && (ri->sub_type == BGP_ROUTE_STATIC))
      break;

  /* Withdraw static BGP route from routing table.
   */
  if (ri)
    {
      bgp_aggregate_decrement (bgp, p, ri, afi, safi);
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (rn);
}

/* Configure static BGP network.  When user don't run zebra, static
 * route should be installed as valid.
 */
static int
bgp_static_set (struct vty *vty, struct bgp *bgp, const char *ip_str,
                afi_t afi, safi_t safi, const char *rmap, int backdoor)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;
  u_char need_update = 0;

  /* Convert IP prefix string to struct prefix.
   */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&p);

  /* Set BGP static route configuration.
   */
  rn = bgp_node_get (bgp->route[afi][safi], &p);

  if (rn->info)
    {
      /* Configuration change.
       */
      bgp_static = rn->info;

      /* Check previous routes are installed into BGP.
       */
      if (bgp_static->valid && (bgp_static->backdoor != backdoor))
        need_update = 1;

      bgp_static->backdoor = backdoor;

      if (rmap)
        {
          if (bgp_static->rmap.name)
            free (bgp_static->rmap.name);
          bgp_static->rmap.name = strdup (rmap);
          bgp_static->rmap.map = route_map_lookup_by_name (rmap);
        }
      else
        {
          if (bgp_static->rmap.name)
            free (bgp_static->rmap.name);
          bgp_static->rmap.name = NULL;
          bgp_static->rmap.map = NULL;
          bgp_static->valid = 0;
        }
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration.
       */
      bgp_static = bgp_static_new ();
      bgp_static->backdoor = backdoor;
      bgp_static->valid = 0;
      bgp_static->igpmetric = 0;
      bgp_static->igpnexthop.s_addr = 0;

      if (rmap)
        {
          if (bgp_static->rmap.name)
            free (bgp_static->rmap.name);
          bgp_static->rmap.name = strdup (rmap);
          bgp_static->rmap.map = route_map_lookup_by_name (rmap);
        }
      rn->info = bgp_static;
    }

  /* If BGP scan is not enabled, we should install this route here.
   */
  if (! bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
    {
      bgp_static->valid = 1;

      if (need_update)
        bgp_static_withdraw (bgp, &p, afi, safi);

      if (! bgp_static->backdoor)
        bgp_static_update (bgp, &p, bgp_static, afi, safi);
    }

  return CMD_SUCCESS;
}

/* Configure static BGP network.
 */
static int
bgp_static_unset (struct vty *vty, struct bgp *bgp, const char *ip_str,
                  afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_static *bgp_static;
  struct bgp_node *rn;

  /* Convert IP prefix string to struct prefix.
   */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#ifdef HAVE_IPV6
  if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    {
      vty_out (vty, "%% Malformed prefix (link-local address)%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif /* HAVE_IPV6 */

  apply_mask (&p);

  rn = bgp_node_lookup (bgp->route[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% Can't find specified static route configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_static = rn->info;

  /* Update BGP RIB.
   */
  if (! bgp_static->backdoor)
    bgp_static_withdraw (bgp, &p, afi, safi);

  /* Clear configuration.
   */
  bgp_static_free (bgp_static);
  rn->info = NULL;
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

/* Called from bgp_delete().  Delete all static routes from the BGP instance.
 */
void
bgp_static_delete (struct bgp *bgp)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_table *table;
  struct bgp_static *bgp_static;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      for (rn = bgp_table_top (bgp->route[afi][safi]); rn;
                                                       rn = bgp_route_next (rn))
        if (rn->info != NULL)
          {
            if (safi == SAFI_MPLS_VPN)
              {
                table = rn->info;

                for (rm = bgp_table_top (table); rm; rm = bgp_route_next (rm))
                  {
                    bgp_static = rn->info;
                    bgp_static_withdraw_vpnv4 (bgp, &rm->p,
                                               AFI_IP, SAFI_MPLS_VPN,
                                               (struct prefix_rd *)&rn->p,
                                               bgp_static->tag);
                    bgp_static_free (bgp_static);
                    rn->info = NULL;
                    bgp_unlock_node (rn);
                  }
              }
            else
              {
                bgp_static = rn->info;
                bgp_static_withdraw (bgp, &rn->p, afi, safi);
                bgp_static_free (bgp_static);
                rn->info = NULL;
                bgp_unlock_node (rn);
              }
          }
}

int
bgp_static_set_vpnv4 (struct vty *vty, const char *ip_str, const char *rd_str,
                      const char *tag_str)
{
  int ret;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp *bgp;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

  bgp = vty->index;

  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[AFI_IP][SAFI_MPLS_VPN],
                        (struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, SAFI_MPLS_VPN);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_get (table, &p);

  if (rn->info)
    {
      vty_out (vty, "%% Same network configuration exists%s", VTY_NEWLINE);
      bgp_unlock_node (rn);
    }
  else
    {
      /* New configuration.
       */
      bgp_static = bgp_static_new ();
      bgp_static->valid = 1;
      memcpy (bgp_static->tag, tag, 3);
      rn->info = bgp_static;

      bgp_static_update_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);
    }

  return CMD_SUCCESS;
}

/* Configure static BGP network.
 */
int
bgp_static_unset_vpnv4 (struct vty *vty, const char *ip_str,
                        const char *rd_str, const char *tag_str)
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct prefix_rd prd;
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct bgp_static *bgp_static;
  u_char tag[3];

  bgp = vty->index;

  /* Convert IP prefix string to struct prefix.
   */
  ret = str2prefix (ip_str, &p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  ret = str2prefix_rd (rd_str, &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed rd%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2tag (tag_str, tag);
  if (! ret)
    {
      vty_out (vty, "%% Malformed tag%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  prn = bgp_node_get (bgp->route[AFI_IP][SAFI_MPLS_VPN],
                        (struct prefix *)&prd);
  if (prn->info == NULL)
    prn->info = bgp_table_init (AFI_IP, SAFI_MPLS_VPN);
  else
    bgp_unlock_node (prn);
  table = prn->info;

  rn = bgp_node_lookup (table, &p);

  if (rn)
    {
      bgp_static_withdraw_vpnv4 (bgp, &p, AFI_IP, SAFI_MPLS_VPN, &prd, tag);

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

DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0],
                         AFI_IP, bgp_node_safi (vty), NULL, 0);
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
                         AFI_IP, bgp_node_safi (vty), argv[1], 0);
}

DEFUN (bgp_network_backdoor,
       bgp_network_backdoor_cmd,
       "network A.B.C.D/M backdoor",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify a BGP backdoor route\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP, SAFI_UNICAST,
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
                         AFI_IP, bgp_node_safi (vty), NULL, 0);
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
                         AFI_IP, bgp_node_safi (vty), argv[2], 0);
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

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
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
                         AFI_IP, bgp_node_safi (vty), NULL, 0);
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
                         AFI_IP, bgp_node_safi (vty), argv[1], 0);
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

  return bgp_static_set (vty, vty->index, prefix_str, AFI_IP, SAFI_UNICAST,
                         NULL, 1);
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP,
                           bgp_node_safi (vty));
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

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP,
                           bgp_node_safi (vty));
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

  return bgp_static_unset (vty, vty->index, prefix_str, AFI_IP,
                           bgp_node_safi (vty));
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
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty),
                         NULL, 0);
}

DEFUN (ipv6_bgp_network_route_map,
       ipv6_bgp_network_route_map_cmd,
       "network X:X::X:X/M route-map WORD",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n"
       "Route-map to modify the attributes\n"
       "Name of the route map\n")
{
  return bgp_static_set (vty, vty->index, argv[0], AFI_IP6,
                         bgp_node_safi (vty), argv[1], 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_unset (vty, vty->index, argv[0], AFI_IP6, bgp_node_safi(vty));
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

/* Aggregate address:

  advertise-map  Set condition to advertise attribute
  as-set         Generate AS set path information
  attribute-map  Set attributes of aggregate
  route-map      Set parameters of aggregate
  summary-only   Filter more specific routes from updates
  suppress-map   Conditionally filter more specific routes from updates
  <cr>
 */
struct bgp_aggregate
{
  /* Summary-only flag. */
  u_char summary_only;

  /* AS set generation. */
  u_char as_set;

  /* Route-map for aggregated route. */
  struct route_map *map;

  /* Suppress-count. */
  unsigned long count;

  /* SAFI configuration. */
  safi_t safi;
};

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

static void
bgp_aggregate_route (struct bgp *bgp, struct prefix *p, struct bgp_info *rinew,
                     afi_t afi, safi_t safi, struct bgp_info *del,
                     struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  u_char origin;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;
  struct in_addr nexthop;
  u_int32_t med = 0;
  struct bgp_info *ri;
  struct bgp_info *new;
  int first = 1;
  unsigned long match = 0;

  /* Record adding route's nexthop and med. */
  if (rinew)
    {
      nexthop = rinew->attr->nexthop;
      med = rinew->attr->med;
    }

  /* ORIGIN attribute: If at least one route among routes that are
     aggregated has ORIGIN with the value INCOMPLETE, then the
     aggregated route must have the ORIGIN attribute with the value
     INCOMPLETE. Otherwise, if at least one route among routes that
     are aggregated has ORIGIN with the value EGP, then the aggregated
     route must have the origin attribute with the value EGP. In all
     other case the value of the ORIGIN attribute of the aggregated
     route is INTERNAL. */
  origin = BGP_ORIGIN_IGP;

  table = bgp->rib[afi][safi];

  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
        match = 0;

        for (ri = rn->info; ri; ri = ri->info_next)
          {
            if (BGP_INFO_HOLDDOWN (ri))
              continue;

            if (del && ri == del)
              continue;

            if (! rinew && first)
              {
                nexthop = ri->attr->nexthop;
                med = ri->attr->med;
                first = 0;
              }
enum
  {
    aggregate_next_hop_check
#ifdef AGGREGATE_NEXTHOP_CHECK
      = true
#else
      = false
#endif
  } ;

  if (aggregate_next_hop_check)
    {
            if (! IPV4_ADDR_SAME (&ri->attr->nexthop, &nexthop)
                || ri->attr->med != med)
              {
                if (aspath)
                  aspath_free (aspath);
                if (community)
                  community_free (community);
                bgp_unlock_node (rn);
                bgp_unlock_node (top);
                return;
              }
    } ;

            if (ri->sub_type != BGP_ROUTE_AGGREGATE)
              {
                if (aggregate->summary_only)
                  {
                    (bgp_info_extra_get (ri))->suppress++;
                    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
                    match++;
                  }

                aggregate->count++;

                if (aggregate->as_set)
                  {
                    if (origin < ri->attr->origin)
                      origin = ri->attr->origin;

                    if (aspath)
                      {
                        asmerge = aspath_aggregate (aspath, ri->attr->aspath);
                        aspath_free (aspath);
                        aspath = asmerge;
                      }
                    else
                      aspath = aspath_dup (ri->attr->aspath);

                    if (ri->attr->community)
                      {
                        if (community)
                          {
                            commerge = community_merge (community,
                                                        ri->attr->community);
                            community = community_uniq_sort (commerge);
                            community_free (commerge);
                          }
                        else
                          community = community_dup (ri->attr->community);
                      }
                  }
              }
          }
        if (match)
          bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  if (rinew)
    {
      aggregate->count++;

      if (aggregate->summary_only)
        (bgp_info_extra_get (rinew))->suppress++;

      if (aggregate->as_set)
        {
          if (origin < rinew->attr->origin)
            origin = rinew->attr->origin;

          if (aspath)
            {
              asmerge = aspath_aggregate (aspath, rinew->attr->aspath);
              aspath_free (aspath);
              aspath = asmerge;
            }
          else
            aspath = aspath_dup (rinew->attr->aspath);

          if (rinew->attr->community)
            {
              if (community)
                {
                  commerge = community_merge (community,
                                              rinew->attr->community);
                  community = community_uniq_sort (commerge);
                  community_free (commerge);
                }
              else
                community = community_dup (rinew->attr->community);
            }
        }
    }

  if (aggregate->count > 0)
    {
      rn = bgp_node_get (table, p);
      new = bgp_info_new ();
      new->type = ZEBRA_ROUTE_BGP;
      new->sub_type = BGP_ROUTE_AGGREGATE;
      new->peer = bgp->peer_self;
      SET_FLAG (new->flags, BGP_INFO_VALID);
      new->attr = bgp_attr_aggregate_intern (bgp, origin, aspath, community,
                                                             aggregate->as_set);
      new->uptime = bgp_clock ();

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);
      bgp_process (bgp, rn, afi, safi);
    }
  else
    {
      if (aspath)
        aspath_free (aspath);
      if (community)
        community_free (community);
    }
}

void bgp_aggregate_delete (struct bgp *, struct prefix *, afi_t, safi_t,
                           struct bgp_aggregate *);

void
bgp_aggregate_increment (struct bgp *bgp, struct prefix *p,
                         struct bgp_info *ri, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;

  /* MPLS-VPN aggregation is not yet supported.
   */
  if (safi == SAFI_MPLS_VPN)
    return;

  if (p->prefixlen == 0)
    return;

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  child = bgp_node_get (bgp->aggregate[afi][safi], p);

  /* Aggregate address configuration check.
   */
  for (rn = child; rn; rn = rn->parent)
    if (((aggregate = rn->info) != NULL) && (rn->p.prefixlen < p->prefixlen))
      {
        bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
        bgp_aggregate_route (bgp, &rn->p, ri, afi, safi, NULL, aggregate);
      }
  bgp_unlock_node (child);
}

void
bgp_aggregate_decrement (struct bgp *bgp, struct prefix *p,
                         struct bgp_info *del, afi_t afi, safi_t safi)
{
  struct bgp_node *child;
  struct bgp_node *rn;
  struct bgp_aggregate *aggregate;

  /* MPLS-VPN aggregation is not yet supported.
   */
  if (safi == SAFI_MPLS_VPN)
    return;

  if (p->prefixlen == 0)
    return;

  child = bgp_node_get (bgp->aggregate[afi][safi], p);

  /* Aggregate address configuration check.
   */
  for (rn = child; rn; rn = rn->parent)
    if ((aggregate = rn->info) != NULL && rn->p.prefixlen < p->prefixlen)
      {
        bgp_aggregate_delete (bgp, &rn->p, afi, safi, aggregate);
        bgp_aggregate_route (bgp, &rn->p, NULL, afi, safi, del, aggregate);
      }
  bgp_unlock_node (child);
}

static void
bgp_aggregate_add (struct bgp *bgp, struct prefix *p, afi_t afi, safi_t safi,
                   struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *new;
  struct bgp_info *ri;
  unsigned long match;
  u_char origin = BGP_ORIGIN_IGP;
  struct aspath *aspath = NULL;
  struct aspath *asmerge = NULL;
  struct community *community = NULL;
  struct community *commerge = NULL;

  table = bgp->rib[afi][safi];

  /* Sanity check. */
  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;

  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
        match = 0;

        for (ri = rn->info; ri; ri = ri->info_next)
          {
            if (BGP_INFO_HOLDDOWN (ri))
              continue;

            if (ri->sub_type != BGP_ROUTE_AGGREGATE)
              {
                /* summary-only aggregate route suppress aggregated
                   route announcement.  */
                if (aggregate->summary_only)
                  {
                    (bgp_info_extra_get (ri))->suppress++;
                    bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
                    match++;
                  }
                /* as-set aggregate route generate origin, as path,
                   community aggregation.  */
                if (aggregate->as_set)
                  {
                    if (origin < ri->attr->origin)
                      origin = ri->attr->origin;

                    if (aspath)
                      {
                        asmerge = aspath_aggregate (aspath, ri->attr->aspath);
                        aspath_free (aspath);
                        aspath = asmerge;
                      }
                    else
                      aspath = aspath_dup (ri->attr->aspath);

                    if (ri->attr->community)
                      {
                        if (community)
                          {
                            commerge = community_merge (community,
                                                        ri->attr->community);
                            community = community_uniq_sort (commerge);
                            community_free (commerge);
                          }
                        else
                          community = community_dup (ri->attr->community);
                      }
                  }
                aggregate->count++;
              }
          }

        /* If this node is suppressed, process the change. */
        if (match)
          bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Add aggregate route to BGP table. */
  if (aggregate->count)
    {
      rn = bgp_node_get (table, p);

      new = bgp_info_new ();
      new->type = ZEBRA_ROUTE_BGP;
      new->sub_type = BGP_ROUTE_AGGREGATE;
      new->peer = bgp->peer_self;
      SET_FLAG (new->flags, BGP_INFO_VALID);
      new->attr = bgp_attr_aggregate_intern (bgp, origin, aspath, community,
                                                             aggregate->as_set);
      new->uptime = bgp_clock ();

      bgp_info_add (rn, new);
      bgp_unlock_node (rn);

      /* Process change. */
      bgp_process (bgp, rn, afi, safi);
    }
}

void
bgp_aggregate_delete (struct bgp *bgp, struct prefix *p, afi_t afi,
                      safi_t safi, struct bgp_aggregate *aggregate)
{
  struct bgp_table *table;
  struct bgp_node *top;
  struct bgp_node *rn;
  struct bgp_info *ri;
  unsigned long match;

  table = bgp->rib[afi][safi];

  if (afi == AFI_IP && p->prefixlen == IPV4_MAX_BITLEN)
    return;
  if (afi == AFI_IP6 && p->prefixlen == IPV6_MAX_BITLEN)
    return;

  /* If routes exists below this node, generate aggregate routes. */
  top = bgp_node_get (table, p);
  for (rn = bgp_node_get (table, p); rn; rn = bgp_route_next_until (rn, top))
    if (rn->p.prefixlen > p->prefixlen)
      {
        match = 0;

        for (ri = rn->info; ri; ri = ri->info_next)
          {
            if (BGP_INFO_HOLDDOWN (ri))
              continue;

            if (ri->sub_type != BGP_ROUTE_AGGREGATE)
              {
                if (aggregate->summary_only && ri->extra)
                  {
                    ri->extra->suppress--;

                    if (ri->extra->suppress == 0)
                      {
                        bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
                        match++;
                      }
                  }
                aggregate->count--;
              }
          }

        /* If this node was suppressed, process the change. */
        if (match)
          bgp_process (bgp, rn, afi, safi);
      }
  bgp_unlock_node (top);

  /* Delete aggregate route from BGP table. */
  rn = bgp_node_get (table, p);

  for (ri = rn->info; ri; ri = ri->info_next)
    if (ri->peer == bgp->peer_self
        && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_AGGREGATE)
      break;

  /* Withdraw static BGP route from routing table. */
  if (ri)
    {
      bgp_info_delete (rn, ri);
      bgp_process (bgp, rn, afi, safi);
    }

  /* Unlock bgp_node_lookup. */
  bgp_unlock_node (rn);
}

/* Aggregate route attribute. */
#define AGGREGATE_SUMMARY_ONLY 1
#define AGGREGATE_AS_SET       1

static int
bgp_aggregate_unset (struct vty *vty, const char *prefix_str,
                     afi_t afi, safi_t safi)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_lookup (bgp->aggregate[afi][safi], &p);
  if (! rn)
    {
      vty_out (vty, "%% There is no aggregate-address configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  aggregate = rn->info;
  if (aggregate->safi & SAFI_UNICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (aggregate->safi & SAFI_MULTICAST)
    bgp_aggregate_delete (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  /* Unlock aggregate address configuration. */
  rn->info = NULL;
  bgp_aggregate_free (aggregate);
  bgp_unlock_node (rn);
  bgp_unlock_node (rn);

  return CMD_SUCCESS;
}

static int
bgp_aggregate_set (struct vty *vty, const char *prefix_str,
                   afi_t afi, safi_t safi,
                   u_char summary_only, u_char as_set)
{
  int ret;
  struct prefix p;
  struct bgp_node *rn;
  struct bgp *bgp;
  struct bgp_aggregate *aggregate;

  /* Convert string to prefix structure. */
  ret = str2prefix (prefix_str, &p);
  if (!ret)
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  apply_mask (&p);

  /* Get BGP structure. */
  bgp = vty->index;

  /* Old configuration check. */
  rn = bgp_node_get (bgp->aggregate[afi][safi], &p);

  if (rn->info)
    {
      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);
      /* try to remove the old entry */
      ret = bgp_aggregate_unset (vty, prefix_str, afi, safi);
      if (ret)
        {
          vty_out (vty, "Error deleting aggregate.%s", VTY_NEWLINE);
          bgp_unlock_node (rn);
          return CMD_WARNING;
        }
    }

  /* Make aggregate address structure. */
  aggregate = bgp_aggregate_new ();
  aggregate->summary_only = summary_only;
  aggregate->as_set = as_set;
  aggregate->safi = safi;
  rn->info = aggregate;

  /* Aggregate address insert into BGP routing table. */
  if (safi & SAFI_UNICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_UNICAST, aggregate);
  if (safi & SAFI_MULTICAST)
    bgp_aggregate_add (bgp, &p, afi, SAFI_MULTICAST, aggregate);

  return CMD_SUCCESS;
}

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty), 0, 0);
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

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
                            0, 0);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
                            AGGREGATE_SUMMARY_ONLY, 0);
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

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
                            AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (aggregate_address_as_set,
       aggregate_address_as_set_cmd,
       "aggregate-address A.B.C.D/M as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
                            0, AGGREGATE_AS_SET);
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

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
                            0, AGGREGATE_AS_SET);
}


DEFUN (aggregate_address_as_set_summary,
       aggregate_address_as_set_summary_cmd,
       "aggregate-address A.B.C.D/M as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP, bgp_node_safi (vty),
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

  return bgp_aggregate_set (vty, prefix_str, AFI_IP, bgp_node_safi (vty),
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
  return bgp_aggregate_unset (vty, argv[0], AFI_IP, bgp_node_safi (vty));
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

  return bgp_aggregate_unset (vty, prefix_str, AFI_IP, bgp_node_safi (vty));
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
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST, 0, 0);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "aggregate-address X:X::X:X/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], AFI_IP6, SAFI_UNICAST,
                            AGGREGATE_SUMMARY_ONLY, 0);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no aggregate-address X:X::X:X/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], AFI_IP6, SAFI_UNICAST);
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

/* Redistribute route treatment.
 */
void
bgp_redistribute_add (struct prefix *p, const struct in_addr *nexthop,
                      const struct in6_addr *nexthop6,
                      u_int32_t metric, u_char type)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  struct bgp_info *bi;
  struct bgp_node *bn;
  struct attr  attr_s;
  struct attr* attr ;
  struct attr  attr_new_s ;
  struct attr* attr_new ;
  afi_t afi;

  /* Make default attribute.
   *
   * NB: the attr itself is not interned, but all sub-attr are.  So, when
   *     we are finished with the attr, we can uninterm same.
   */
  attr = bgp_attr_default_set (&attr_s, BGP_ORIGIN_INCOMPLETE,
                                                           true /* !intern */) ;
  if (nexthop)
    attr->nexthop = *nexthop;

#ifdef HAVE_IPV6
  if (nexthop6)
    {
      struct attr_extra *extra = bgp_attr_extra_get(attr);
      extra->mp_nexthop_global = *nexthop6;
      extra->mp_nexthop_len = 16;
    }
#endif

  attr->med = metric;
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
        {
          /* Copy attribute for modification.
           */
          attr_new = bgp_attr_dup (&attr_new_s, attr);

          if (bgp->redist_metric_flag[afi][type])
            attr_new->med = bgp->redist_metric[afi][type];

          /* Apply route-map.
           */
          if (bgp->rmap[afi][type].map)
            {
              struct bgp_info info_s = { 0 } ;
              route_map_result_t ret;

              info_s.peer = bgp->peer_self;
              info_s.attr = attr_new;
              info_s.peer->rmap_type = PEER_RMAP_TYPE_REDISTRIBUTE ;
              ret = route_map_apply (bgp->rmap[afi][type].map, p, RMAP_BGP,
                                                                       &info_s);

              if (ret == RMAP_DENYMATCH)
                {
                  /* Free temporary attribute.
                   */
                  bgp_attr_flush (attr_new);

                  bgp_redistribute_delete (p, type);
                  continue ;
                }
            }

          attr_new = bgp_attr_intern_temp(attr_new);

          bn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST],
                                 afi, SAFI_UNICAST, p, NULL);

          for (bi = bn->info; bi; bi = bi->info_next)
            if (bi->peer == bgp->peer_self
                && bi->sub_type == BGP_ROUTE_REDISTRIBUTE)
              break;

          if (bi)
            {
              if (attrhash_cmp (bi->attr, attr_new) &&
                  !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
                {
                  bgp_attr_unintern (attr_new);
                }
              else
                {
                  /* The attribute is changed.
                   */
                  bgp_info_set_flag (bn, bi, BGP_INFO_ATTR_CHANGED);

                  /* Rewrite BGP route information.
                   */
                  if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
                    bgp_info_restore(bn, bi);
                  else
                    bgp_aggregate_decrement (bgp, p, bi, afi, SAFI_UNICAST);
                  bgp_attr_unintern (bi->attr);
                  bi->attr = attr_new;
                  bi->uptime = bgp_clock ();

                  /* Process change.
                   */
                  bgp_aggregate_increment (bgp, p, bi, afi, SAFI_UNICAST);
                  bgp_process (bgp, bn, afi, SAFI_UNICAST);
                }
            }
          else
            {
              struct bgp_info *new;

              new = bgp_info_new ();
              new->type = type;
              new->sub_type = BGP_ROUTE_REDISTRIBUTE;
              new->peer = bgp->peer_self;
              SET_FLAG (new->flags, BGP_INFO_VALID);
              new->attr = attr_new;
              new->uptime = bgp_clock ();

              bgp_aggregate_increment (bgp, p, new, afi, SAFI_UNICAST);
              bgp_info_add (bn, new);
              bgp_process (bgp, bn, afi, SAFI_UNICAST);
            } ;

          bgp_unlock_node (bn);
        }
    }

  /* Unintern original.
   */
  qassert(attr->refcnt == 0) ;
  attr->refcnt = 0 ;                    /* belt-and-braces      */
  bgp_attr_unintern(attr) ;
}

void
bgp_redistribute_delete (struct prefix *p, u_char type)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;
  afi_t afi;
  struct bgp_node *rn;
  struct bgp_info *ri;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      afi = family2afi (p->family);

      if (bgp->redist[afi][type])
        {
         rn = bgp_afi_node_get (bgp->rib[afi][SAFI_UNICAST], afi, SAFI_UNICAST, p, NULL);

          for (ri = rn->info; ri; ri = ri->info_next)
            if (ri->peer == bgp->peer_self
                && ri->type == type)
              break;

          if (ri)
            {
              bgp_aggregate_decrement (bgp, p, ri, afi, SAFI_UNICAST);
              bgp_info_delete (rn, ri);
              bgp_process (bgp, rn, afi, SAFI_UNICAST);
            }
          bgp_unlock_node (rn);
        }
    }
}

/* Withdraw specified route type's route. */
void
bgp_redistribute_withdraw (struct bgp *bgp, afi_t afi, int type)
{
  struct bgp_node *rn;
  struct bgp_info *ri;
  struct bgp_table *table;

  table = bgp->rib[afi][SAFI_UNICAST];

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    {
      for (ri = rn->info; ri; ri = ri->info_next)
        if (ri->peer == bgp->peer_self
            && ri->type == type)
          break;

      if (ri)
        {
          bgp_aggregate_decrement (bgp, &rn->p, ri, afi, SAFI_UNICAST);
          bgp_info_delete (rn, ri);
          bgp_process (bgp, rn, afi, SAFI_UNICAST);
        }
    }
}

/* Static function to display route. */
static void
route_vty_out_route (struct prefix *p, struct vty *vty)
{
  int len;
  u_int32_t destination;
  char buf[BUFSIZ];

  if (p->family == AF_INET)
    {
      len = vty_out (vty, "%s", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ));
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
    len = vty_out (vty, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
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
route_vty_short_status_out (struct vty *vty, struct bgp_info *binfo)
{
 /* Route status display. */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
    vty_out (vty, "R");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
    vty_out (vty, "S");
  else if (binfo->extra && binfo->extra->suppress)
    vty_out (vty, "s");
  else if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected */
  if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "h");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
    vty_out (vty, "d");
  else if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route. */
    if ((binfo->peer->as) && (binfo->peer->as == binfo->peer->local_as))
      vty_out (vty, "i");
    else
      vty_out (vty, " ");
}

/* called from terminal list command */
void
route_vty_out (struct vty *vty, struct prefix *p,
               struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);

  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      if (p->family == AF_INET)
        {
          if (safi == SAFI_MPLS_VPN)
            vty_out (vty, "%-16s",
                     safe_inet_ntoa (attr->extra->mp_nexthop_global_in));
          else
            vty_out (vty, "%-16s", safe_inet_ntoa (attr->nexthop));
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          int len;
          char buf[BUFSIZ];

          len = vty_out (vty, "%s",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                         buf, BUFSIZ));
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));

      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str) ;
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* called from terminal list command */
void
route_vty_out_tmp (struct vty *vty, struct prefix *p,
                   struct attr *attr, safi_t safi)
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
          if (safi == SAFI_MPLS_VPN)
            vty_out (vty, "%-16s",
                     safe_inet_ntoa (attr->extra->mp_nexthop_global_in));
          else
            vty_out (vty, "%-16s", safe_inet_ntoa (attr->nexthop));
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          int len;
          char buf[BUFSIZ];

          assert (attr->extra);

          len = vty_out (vty, "%s",
                         inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                         buf, BUFSIZ));
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "%s%*s", VTY_NEWLINE, 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", (attr->extra ? attr->extra->weight : 0));

      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    }

  vty_out (vty, "%s", VTY_NEWLINE);
}

void
route_vty_out_tag (struct vty *vty, struct prefix *p,
                   struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  u_int32_t label = 0;

  if (!binfo->extra)
    return;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);

  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      if (p->family == AF_INET)
        {
          if (safi == SAFI_MPLS_VPN)
            vty_out (vty, "%-16s",
                     safe_inet_ntoa (attr->extra->mp_nexthop_global_in));
          else
            vty_out (vty, "%-16s", safe_inet_ntoa (attr->nexthop));
        }
#ifdef HAVE_IPV6
      else if (p->family == AF_INET6)
        {
          assert (attr->extra);
          char buf[BUFSIZ];
          char buf1[BUFSIZ];
          if (attr->extra->mp_nexthop_len == 16)
            vty_out (vty, "%s",
                     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                     buf, BUFSIZ));
          else if (attr->extra->mp_nexthop_len == 32)
            vty_out (vty, "%s(%s)",
                     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                                buf, BUFSIZ),
                     inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                                buf1, BUFSIZ));

        }
#endif /* HAVE_IPV6 */
    }

  label = decode_label (binfo->extra->tag);

  vty_out (vty, "notag/%d", label);

  vty_out (vty, "%s", VTY_NEWLINE);
}

/* dampening route */
static void
damp_route_vty_out (struct vty *vty, struct prefix *p,
                    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  int len;
  char timebuf[BGP_UPTIME_LEN];

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);

  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
  len = 17 - len;
  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 34, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (struct vty *vty, struct prefix *p,
                    struct bgp_info *binfo, int display, safi_t safi)
{
  struct attr *attr;
  struct bgp_damp_info *bdi;
  char timebuf[BGP_UPTIME_LEN];
  int len;

  if (!binfo->extra)
    return;

  bdi = binfo->extra->damp_info;

  /* short status lead text */
  route_vty_short_status_out (vty, binfo);

  /* print prefix and mask */
  if (! display)
    route_vty_out_route (p, vty);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", binfo->peer->host);
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

  if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, binfo, timebuf, BGP_UPTIME_LEN));
  else
    vty_out (vty, "%*s ", 8, " ");

  /* Print attribute */
  attr = binfo->attr;
  if (attr)
    {
      /* Print aspath */
      if (attr->aspath)
        aspath_print_vty (vty, "%s", attr->aspath, " ");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
route_vty_out_detail (struct vty *vty, struct bgp *bgp, struct prefix *p,
                      struct bgp_info *binfo, afi_t afi, safi_t safi)
{
  char buf[SU_ADDRSTRLEN];
  struct attr *attr;
  int sockunion_vty_out (struct vty *, union sockunion *);
  time_t tbuf ;

  attr = binfo->attr;

  if (attr)
    {
      /* Line1 display AS-path, Aggregator */
      if (attr->aspath)
        {
          vty_out (vty, "  ");
          if (aspath_count_hops (attr->aspath) == 0)
            vty_out (vty, "Local");
          else
            aspath_print_vty (vty, "%s", attr->aspath, "");
        }

      if (CHECK_FLAG (binfo->flags, BGP_INFO_REMOVED))
        vty_out (vty, ", (removed)");
      if (CHECK_FLAG (binfo->flags, BGP_INFO_STALE))
        vty_out (vty, ", (stale)");
      if (CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR)))
        vty_out (vty, ", (aggregated by %u %s)",
                 attr->extra->aggregator_as,
                 safe_inet_ntoa (attr->extra->aggregator_addr));
      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi],
                                                    PEER_FLAG_REFLECTOR_CLIENT))
        vty_out (vty, ", (Received from a RR-client)");
      if (CHECK_FLAG (binfo->peer->af_flags[afi][safi],
                                                      PEER_FLAG_RSERVER_CLIENT))
        vty_out (vty, ", (Received from a RS-client)");
      if (CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        vty_out (vty, ", (history entry)");
      else if (CHECK_FLAG (binfo->flags, BGP_INFO_DAMPED))
        vty_out (vty, ", (suppressed due to dampening)");
      vty_out (vty, "%s", VTY_NEWLINE);

      /* Line2 display Next-hop, Neighbor, Router-id */
      if (p->family == AF_INET)
        {
          vty_out (vty, "    %s", safi == SAFI_MPLS_VPN ?
                   safe_inet_ntoa (attr->extra->mp_nexthop_global_in) :
                   safe_inet_ntoa (attr->nexthop));
        }
#ifdef HAVE_IPV6
      else
        {
          assert (attr->extra);
          vty_out (vty, "    %s",
                   inet_ntop (AF_INET6, &attr->extra->mp_nexthop_global,
                              buf, INET6_ADDRSTRLEN));
        }
#endif /* HAVE_IPV6 */

      if (binfo->peer == bgp->peer_self)
        {
          vty_out (vty, " from %s ",
                   p->family == AF_INET ? "0.0.0.0" : "::");
          vty_out (vty, "(%s)", safe_inet_ntoa(bgp->router_id));
        }
      else
        {
          if (! CHECK_FLAG (binfo->flags, BGP_INFO_VALID))
            vty_out (vty, " (inaccessible)");
          else if (binfo->extra && binfo->extra->igpmetric)
            vty_out (vty, " (metric %d)", binfo->extra->igpmetric);
          vty_out (vty, " from %s",
                           sockunion2str (&binfo->peer->su, buf, sizeof(buf)));
          if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
            vty_out (vty, " (%s)", safe_inet_ntoa (attr->extra->originator_id));
          else
            vty_out (vty, " (%s)",
                inet_ntop (AF_INET, &binfo->peer->remote_id, buf, sizeof(buf)));
        }
      vty_out (vty, "%s", VTY_NEWLINE);

#ifdef HAVE_IPV6
      /* display nexthop local */
      if (attr->extra && attr->extra->mp_nexthop_len == 32)
        {
          vty_out (vty, "    (%s)%s",
                   inet_ntop (AF_INET6, &attr->extra->mp_nexthop_local,
                                                             buf, sizeof(buf)),
                   VTY_NEWLINE);
        }
#endif /* HAVE_IPV6 */

      /* Line 3 display:
       *  Origin, Med, Locpref, Weight, valid, Int/Ext/Local, Atomic, best */
      vty_out (vty, "      Origin %s",
                            map_direct(bgp_origin_long_map, attr->origin).str) ;

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
        vty_out (vty, ", metric %u", attr->med);

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
        vty_out (vty, ", localpref %u", attr->local_pref);
      else
        vty_out (vty, ", localpref %u", bgp->default_local_pref);

      if (attr->extra && attr->extra->weight != 0)
        vty_out (vty, ", weight %u", attr->extra->weight);

      if (! CHECK_FLAG (binfo->flags, BGP_INFO_HISTORY))
        vty_out (vty, ", valid");

      if (binfo->peer != bgp->peer_self)
        {
          if (binfo->peer->as == binfo->peer->local_as)
            vty_out (vty, ", internal");
          else
            vty_out (vty, ", %s",
                     (bgp_confederation_peers_check(bgp, binfo->peer->as)
                                            ? "confed-external" : "external"));
        }
      else if (binfo->sub_type == BGP_ROUTE_AGGREGATE)
        vty_out (vty, ", aggregated, local");
      else if (binfo->type != ZEBRA_ROUTE_BGP)
        vty_out (vty, ", sourced");
      else
        vty_out (vty, ", sourced, local");

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE))
        vty_out (vty, ", atomic-aggregate");

      if (CHECK_FLAG (binfo->flags, BGP_INFO_SELECTED))
        vty_out (vty, ", best");

      vty_out (vty, "%s", VTY_NEWLINE);

      /* Line 4 display Community */
      if (attr->community)
        vty_out (vty, "      Community: %s%s", attr->community->str,
                 VTY_NEWLINE);

      /* Line 5 display Extended-community */
      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))
        vty_out (vty, "      Extended Community: %s%s",
                 attr->extra->ecommunity->str, VTY_NEWLINE);

      /* Line 6 display Originator, Cluster-id */
      if ((attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID)) ||
          (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST)))
        {
          assert (attr->extra);
          if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
            vty_out (vty, "      Originator: %s",
                     safe_inet_ntoa (attr->extra->originator_id));

          if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_CLUSTER_LIST))
            {
              int i;
              vty_out (vty, ", Cluster list: ");
              for (i = 0; i < attr->extra->cluster->length / 4; i++)
                vty_out (vty, "%s ",
                         safe_inet_ntoa (attr->extra->cluster->list[i]));
            }
          vty_out (vty, "%s", VTY_NEWLINE);
        }

      if (binfo->extra && binfo->extra->damp_info)
        bgp_damp_info_vty (vty, binfo);

      /* Line 7 display Uptime */
      tbuf = bgp_wall_clock(binfo->uptime);
      vty_out (vty, "      Last update: %s", ctime(&tbuf));
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

#define BGP_SHOW_SCODE_HEADER "Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,%s              r RIB-failure, S Stale, R Removed%s"
#define BGP_SHOW_OCODE_HEADER "Origin codes: i - IGP, e - EGP, ? - incomplete%s%s"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path%s"
#define BGP_SHOW_DAMP_HEADER "   Network          From             Reuse    Path%s"
#define BGP_SHOW_FLAP_HEADER "   Network          From            Flaps Duration Reuse    Path%s"

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
  bgp_show_type_dampend_paths,
  bgp_show_type_damp_neighbor
};

static int
bgp_show_table (struct vty *vty, struct bgp_table *table, struct in_addr *router_id,
          enum bgp_show_type type, void *output_arg)
{
  struct bgp_info *ri;
  struct bgp_node *rn;
  int header = 1;
  int display;
  unsigned long output_count;

  /* This is first entry point, so reset total line. */
  output_count = 0;

  /* Start processing of routes. */
  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (rn->info != NULL)
      {
        display = 0;

        for (ri = rn->info; ri; ri = ri->info_next)
          {
            if (type == bgp_show_type_flap_statistics
                || type == bgp_show_type_flap_address
                || type == bgp_show_type_flap_prefix
                || type == bgp_show_type_flap_cidr_only
                || type == bgp_show_type_flap_regexp
                || type == bgp_show_type_flap_filter_list
                || type == bgp_show_type_flap_prefix_list
                || type == bgp_show_type_flap_prefix_longer
                || type == bgp_show_type_flap_route_map
                || type == bgp_show_type_flap_neighbor
                || type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              {
                if (!(ri->extra && ri->extra->damp_info))
                  continue;
              }
            if (type == bgp_show_type_regexp
                || type == bgp_show_type_flap_regexp)
              {
                regex_t *regex = output_arg;

                if (bgp_regexec (regex, ri->attr->aspath) == REG_NOMATCH)
                  continue;
              }
            if (type == bgp_show_type_prefix_list
                || type == bgp_show_type_flap_prefix_list)
              {
                struct prefix_list *plist = output_arg;

                if (prefix_list_apply (plist, &rn->p) != PREFIX_PERMIT)
                  continue;
              }
            if (type == bgp_show_type_filter_list
                || type == bgp_show_type_flap_filter_list)
              {
                struct as_list *as_list = output_arg;

                if (as_list_apply (as_list, ri->attr->aspath) != AS_FILTER_PERMIT)
                  continue;
              }
            if ( (type == bgp_show_type_route_map) ||
                 (type == bgp_show_type_flap_route_map) )
              {
                struct route_map *rmap = output_arg;
                struct attr dummy_attr ;
                struct bgp_info info_s = { 0 } ;
                route_map_result_t ret;

                bgp_attr_dup (&dummy_attr, ri->attr);
                info_s.peer = ri->peer;
                info_s.attr = &dummy_attr;

                ri->peer->rmap_type = 0 ;
                ret = route_map_apply (rmap, &rn->p, RMAP_BGP, &info_s);
                bgp_attr_flush(&dummy_attr);

                if (ret == RMAP_DENYMATCH)
                  continue;
              }
            if (type == bgp_show_type_neighbor
                || type == bgp_show_type_flap_neighbor
                || type == bgp_show_type_damp_neighbor)
              {
                union sockunion *su = output_arg;

                if (ri->peer->su_remote == NULL || ! sockunion_same(ri->peer->su_remote, su))
                  continue;
              }
            if (type == bgp_show_type_cidr_only
                || type == bgp_show_type_flap_cidr_only)
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
            if (type == bgp_show_type_prefix_longer
                || type == bgp_show_type_flap_prefix_longer)
              {
                struct prefix *p = output_arg;

                if (! prefix_match (p, &rn->p))
                  continue;
              }
            if (type == bgp_show_type_community_all)
              {
                if (! ri->attr->community)
                  continue;
              }
            if (type == bgp_show_type_community)
              {
                struct community *com = output_arg;

                if (! ri->attr->community ||
                    ! community_match (ri->attr->community, com))
                  continue;
              }
            if (type == bgp_show_type_community_exact)
              {
                struct community *com = output_arg;

                if (! ri->attr->community ||
                    ! community_cmp (ri->attr->community, com))
                  continue;
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
            if (type == bgp_show_type_flap_address
                || type == bgp_show_type_flap_prefix)
              {
                struct prefix *p = output_arg;

                if (! prefix_match (&rn->p, p))
                  continue;

                if (type == bgp_show_type_flap_prefix)
                  if (p->prefixlen != rn->p.prefixlen)
                    continue;
              }
            if (type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              {
                if (! CHECK_FLAG (ri->flags, BGP_INFO_DAMPED)
                    || CHECK_FLAG (ri->flags, BGP_INFO_HISTORY))
                  continue;
              }

            if (header)
              {
                vty_out (vty, "BGP table version is 0, local router ID is %s%s", safe_inet_ntoa (*router_id), VTY_NEWLINE);
                vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                if (type == bgp_show_type_dampend_paths
                    || type == bgp_show_type_damp_neighbor)
                  vty_out (vty, BGP_SHOW_DAMP_HEADER, VTY_NEWLINE);
                else if (type == bgp_show_type_flap_statistics
                         || type == bgp_show_type_flap_address
                         || type == bgp_show_type_flap_prefix
                         || type == bgp_show_type_flap_cidr_only
                         || type == bgp_show_type_flap_regexp
                         || type == bgp_show_type_flap_filter_list
                         || type == bgp_show_type_flap_prefix_list
                         || type == bgp_show_type_flap_prefix_longer
                         || type == bgp_show_type_flap_route_map
                         || type == bgp_show_type_flap_neighbor)
                  vty_out (vty, BGP_SHOW_FLAP_HEADER, VTY_NEWLINE);
                else
                  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                header = 0;
              }

            if (type == bgp_show_type_dampend_paths
                || type == bgp_show_type_damp_neighbor)
              damp_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST);
            else if (type == bgp_show_type_flap_statistics
                     || type == bgp_show_type_flap_address
                     || type == bgp_show_type_flap_prefix
                     || type == bgp_show_type_flap_cidr_only
                     || type == bgp_show_type_flap_regexp
                     || type == bgp_show_type_flap_filter_list
                     || type == bgp_show_type_flap_prefix_list
                     || type == bgp_show_type_flap_prefix_longer
                     || type == bgp_show_type_flap_route_map
                     || type == bgp_show_type_flap_neighbor)
              flap_route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST);
            else
              route_vty_out (vty, &rn->p, ri, display, SAFI_UNICAST);
            display++;
          }
        if (display)
          output_count++;
      }

  /* No route is displayed */
  if (output_count == 0)
    {
      if (type == bgp_show_type_normal)
        vty_out (vty, "No BGP network exists%s", VTY_NEWLINE);
    }
  else
    vty_out (vty, "%sTotal number of prefixes %ld%s",
             VTY_NEWLINE, output_count, VTY_NEWLINE);

  return CMD_SUCCESS;
}

static int
bgp_show (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
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


  table = bgp->rib[afi][safi];

  return bgp_show_table (vty, table, &bgp->router_id, type, output_arg);
}

/* Header of detailed BGP route information */
static void
route_vty_out_detail_header (struct vty *vty, struct bgp *bgp,
                             struct bgp_node *rn,
                             struct prefix_rd *prd, afi_t afi, safi_t safi)
{
  struct bgp_info *ri;
  struct prefix *p;
  struct peer *peer;
  struct listnode *node, *nnode;
  char buf[SU_ADDRSTRLEN];
  char buf_rd[RD_ADDRSTRLEN];
  int count = 0;
  int best = 0;
  int suppress = 0;
  int no_export = 0;
  int no_advertise = 0;
  int local_as = 0;
  int first = 0;

  p = &rn->p;
  vty_out (vty, "BGP routing table entry for %s%s%s/%d%s",
           (safi == SAFI_MPLS_VPN ?
           prefix_rd2str (prd, buf_rd, sizeof(buf_rd)) : ""),
           safi == SAFI_MPLS_VPN ? ":" : "",
           inet_ntop (p->family, &p->u.prefix, buf, sizeof(buf)),
           p->prefixlen, VTY_NEWLINE);

  for (ri = rn->info; ri; ri = ri->info_next)
    {
      count++;
      if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED))
        {
          best = count;
          if (ri->extra && ri->extra->suppress)
            suppress = 1;
          if (ri->attr->community != NULL)
            {
              if (community_include (ri->attr->community, COMMUNITY_NO_ADVERTISE))
                no_advertise = 1;
              if (community_include (ri->attr->community, COMMUNITY_NO_EXPORT))
                no_export = 1;
              if (community_include (ri->attr->community, COMMUNITY_LOCAL_AS))
                local_as = 1;
            }
        }
    }

  vty_out (vty, "Paths: (%d available", count);
  if (best)
    {
      vty_out (vty, ", best #%d", best);
      if (safi == SAFI_UNICAST)
        vty_out (vty, ", table Default-IP-Routing-Table");
    }
  else
    vty_out (vty, ", no best path");
  if (no_advertise)
    vty_out (vty, ", not advertised to any peer");
  else if (no_export)
    vty_out (vty, ", not advertised to EBGP peer");
  else if (local_as)
    vty_out (vty, ", not advertised outside local AS");
  if (suppress)
    vty_out (vty, ", Advertisements suppressed by an aggregate.");
  vty_out (vty, ")%s", VTY_NEWLINE);

  /* advertised peer */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (bgp_adj_out_lookup (peer, p, afi, safi, rn))
        {
          if (! first)
            vty_out (vty, "  Advertised to non peer-group peers:%s ",
                                                                   VTY_NEWLINE);
          vty_out (vty, " %s", sutoa(&peer->su).str);
          first = 1;
        }
    }
  if (! first)
    vty_out (vty, "  Not advertised to any peer");
  vty_out (vty, "%s", VTY_NEWLINE);
}

/* Display specified route of BGP table. */
static int
bgp_show_route_in_table (struct vty *vty, struct bgp *bgp,
                         struct bgp_table *rib, const char *ip_str,
                         afi_t afi, safi_t safi, struct prefix_rd *prd,
                         int prefix_check)
{
  int ret;
  int header;
  int display = 0;
  struct prefix match;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_table *table;

  /* Check IP address argument. */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  match.family = afi2family (afi);

  if (safi == SAFI_MPLS_VPN)
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
                      for (ri = rm->info; ri; ri = ri->info_next)
                        {
                          if (header)
                            {
                              route_vty_out_detail_header (vty, bgp, rm,
                                                  (struct prefix_rd *)&rn->p,
                                                         AFI_IP, SAFI_MPLS_VPN);

                              header = 0;
                            }
                          display++;
                          route_vty_out_detail (vty, bgp, &rm->p, ri, AFI_IP,
                                                                 SAFI_MPLS_VPN);
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
              for (ri = rn->info; ri; ri = ri->info_next)
                {
                  if (header)
                    {
                      route_vty_out_detail_header (vty, bgp, rn, NULL, afi, safi);
                      header = 0;
                    }
                  display++;
                  route_vty_out_detail (vty, bgp, &rn->p, ri, afi, safi);
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

/* Display specified route of Main RIB */
static int
bgp_show_route (struct vty *vty, const char *view_name, const char *ip_str,
                afi_t afi, safi_t safi, struct prefix_rd *prd,
                int prefix_check)
{
  struct bgp *bgp;

  /* BGP structure lookup. */
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

  return bgp_show_route_in_table (vty, bgp, bgp->rib[afi][safi], ip_str,
                                   afi, safi, prd, prefix_check);
}

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

ALIAS (show_ip_bgp_ipv4,
       show_bgp_ipv4_safi_cmd,
       "show bgp ipv4 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 0);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 0);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 0);
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
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 0);
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
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 0);
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_UNICAST, NULL, 1);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MULTICAST, NULL, 1);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_UNICAST, NULL, 1);
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
  return bgp_show_route (vty, NULL, argv[0], AFI_IP, SAFI_MPLS_VPN, NULL, 1);
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
  int ret;
  struct prefix_rd prd;

  ret = str2prefix_rd (argv[0], &prd);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Route Distinguisher%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_show_route (vty, NULL, argv[1], AFI_IP, SAFI_MPLS_VPN, &prd, 1);
}

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

  return bgp_show (vty, bgp, AFI_IP, SAFI_UNICAST, bgp_show_type_normal, NULL);
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
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 0);
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
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP, SAFI_UNICAST, NULL, 1);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp,
       show_bgp_cmd,
       "show bgp",
       SHOW_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                     NULL);

  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

/* old command */
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal,
                   NULL);
}

DEFUN (show_bgp_route,
       show_bgp_route_cmd,
       "show bgp X:X::X:X",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 0);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0);
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
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 0);
}

DEFUN (show_bgp_prefix,
       show_bgp_prefix_cmd,
       "show bgp X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_MULTICAST, NULL, 1);

  return bgp_show_route (vty, NULL, argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1);
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
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_UNICAST, NULL, 1);
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

  return bgp_show (vty, bgp, AFI_IP6, SAFI_UNICAST, bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view,
       show_bgp_view_ipv6_cmd,
       "show bgp view WORD ipv6",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n")

DEFUN (show_bgp_view_route,
       show_bgp_view_route_cmd,
       "show bgp view WORD X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 0);
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
  return bgp_show_route (vty, argv[0], argv[1], AFI_IP6, SAFI_UNICAST, NULL, 1);
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
DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp",
       SHOW_STR
       IP_STR
       MBGP_STR)
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST, bgp_show_type_normal,
                   NULL);
}

/* old command */
DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")
{
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 0);
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
  return bgp_show_route (vty, NULL, argv[0], AFI_IP6, SAFI_MULTICAST, NULL, 1);
}
#endif


static int
bgp_show_regexp (struct vty *vty, int argc, argv_t argv, afi_t afi,
                 safi_t safi, enum bgp_show_type type)
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

  rc = bgp_show (vty, NULL, afi, safi, type, regex);
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
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
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
  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_MULTICAST,
                            bgp_show_type_regexp);

  return bgp_show_regexp (vty, argc, argv, AFI_IP, SAFI_UNICAST,
                          bgp_show_type_regexp);
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
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_regexp (vty, argc, argv, AFI_IP6, SAFI_MULTICAST,
                          bgp_show_type_regexp);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_prefix_list (struct vty *vty, const char *prefix_list_str, afi_t afi,
                      safi_t safi, enum bgp_show_type type)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (afi, prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, plist);
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
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_prefix_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
                                 bgp_show_type_prefix_list);

  return bgp_show_prefix_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
                               bgp_show_type_prefix_list);
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
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_prefix_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
                               bgp_show_type_prefix_list);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_filter_list (struct vty *vty, const char *filter, afi_t afi,
                      safi_t safi, enum bgp_show_type type)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name%s", filter, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, as_list);
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
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_filter_list (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_MULTICAST,
                                 bgp_show_type_filter_list);

  return bgp_show_filter_list (vty, argv[1], AFI_IP, SAFI_UNICAST,
                               bgp_show_type_filter_list);
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
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_filter_list (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
                               bgp_show_type_filter_list);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_route_map (struct vty *vty, const char *rmap_str, afi_t afi,
                    safi_t safi, enum bgp_show_type type)
{
  struct route_map *rmap;

  rmap = route_map_lookup_by_name (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name%s",
               rmap_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi, type, rmap);
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
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_route_map (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_MULTICAST,
                               bgp_show_type_route_map);

  return bgp_show_route_map (vty, argv[1], AFI_IP, SAFI_UNICAST,
                             bgp_show_type_route_map);
}

DEFUN (show_bgp_route_map,
       show_bgp_route_map_cmd,
       "show bgp route-map WORD",
       SHOW_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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

DEFUN (show_ip_bgp_cidr_only,
       show_ip_bgp_cidr_only_cmd,
       "show ip bgp cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
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
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                     bgp_show_type_cidr_only, NULL);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
                     bgp_show_type_cidr_only, NULL);
}

DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show (vty, NULL, AFI_IP, SAFI_MULTICAST,
                     bgp_show_type_community_all, NULL);

  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
                   bgp_show_type_community_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_all,
       show_bgp_community_all_cmd,
       "show bgp community",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
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
  return bgp_show (vty, NULL, AFI_IP6, SAFI_UNICAST,
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
  return bgp_show (vty, NULL, AFI_IP6, SAFI_MULTICAST,
                   bgp_show_type_community_all, NULL);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_community (struct vty *vty, const char *view_name,
                                          int argc, argv_t argv,
                                             int exact, afi_t afi, safi_t safi)
{
  struct community *com;
  struct buffer *b;
  struct bgp *bgp;
  int i;
  char *str;
  int first = 0;

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

  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
        {
          if (  (strcmp (argv[i], "unicast") == 0)
             || (strcmp (argv[i], "multicast") == 0)  )
            continue;
          first = 1;
        }

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  str = buffer_getstr (b);
  buffer_free (b);

  com = community_str2com (str);
  XFREE (MTYPE_TMP, str);
  if (! com)
    {
      vty_out (vty, "%% Community malformed: %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, bgp, afi, safi,
                   (exact ? bgp_show_type_community_exact :
                            bgp_show_type_community), com);
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
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
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
  safi_t safi ;

  safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST ;

  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP, safi);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
  int afi;
  int safi;
  struct bgp *bgp;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
    {
      vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
#endif
  return bgp_show (vty, bgp, afi, safi, bgp_show_type_community_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export)",
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
  int afi;
  int safi;

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show_community (vty, argv[0], argc-3, &argv[3], 0, afi, safi);
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  return bgp_show_community (vty, argv[0], argc-2, &argv[2], 0, afi, safi);
#endif
}

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp view WORD ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, SAFI_UNICAST);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  safi_t safi ;

  safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST ;

  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP, safi);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ip bgp ipv4 (unicast|multicast) community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_UNICAST);
}

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  return bgp_show_community (vty, NULL, argc, argv, 0, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export)",
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
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
  return bgp_show_community (vty, NULL, argc, argv, 1, AFI_IP6, SAFI_MULTICAST);
}

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) (AA:NN|local-AS|no-advertise|no-export) exact-match",
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

static int
bgp_show_community_list (struct vty *vty, const char *com, int exact,
                         afi_t afi, safi_t safi)
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, com, COMMUNITY_LIST_MASTER);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, NULL, afi, safi,
                   (exact ? bgp_show_type_community_list_exact :
                            bgp_show_type_community_list), list);
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
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP, SAFI_UNICAST);
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_MULTICAST);

  return bgp_show_community_list (vty, argv[1], 0, AFI_IP, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP, SAFI_UNICAST);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) exact-match",
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_MULTICAST);

  return bgp_show_community_list (vty, argv[1], 1, AFI_IP, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 0, AFI_IP6, SAFI_MULTICAST);
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
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_UNICAST);
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
  return bgp_show_community_list (vty, argv[0], 1, AFI_IP6, SAFI_MULTICAST);
}
#endif /* HAVE_IPV6 */

static int
bgp_show_prefix_longer (struct vty *vty, const char *prefix, afi_t afi,
                        safi_t safi, enum bgp_show_type type)
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

  ret = bgp_show (vty, NULL, afi, safi, type, p);
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_MULTICAST,
                                   bgp_show_type_prefix_longer);

  return bgp_show_prefix_longer (vty, argv[1], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_UNICAST,
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
  return bgp_show_prefix_longer (vty, argv[0], AFI_IP6, SAFI_MULTICAST,
                                 bgp_show_type_prefix_longer);
}
#endif /* HAVE_IPV6 */

static struct peer *
peer_lookup_in_view (struct vty *vty, const char *view_name,
                     const char *ip_str)
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  union sockunion su;

  /* BGP structure lookup. */
  if (view_name)
    {
      bgp = bgp_lookup_by_name (view_name);
      if (! bgp)
        {
          vty_out (vty, "Can't find BGP view %s%s", view_name, VTY_NEWLINE);
          return NULL;
        }
    }
  else
    {
      bgp = bgp_get_default ();
      if (! bgp)
        {
          vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
          return NULL;
        }
    }

  /* Get peer sockunion. */
  ret = str2sockunion (ip_str, &su);
  if (ret < 0)
    {
      vty_out (vty, "Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return NULL;
    }

  /* Peer structure lookup. */
  peer = peer_lookup (bgp, &su);
  if (! peer)
    {
      vty_out (vty, "No such neighbor%s", VTY_NEWLINE);
      return NULL;
    }

  return peer;
}

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
  unsigned long long counts[BGP_STATS_MAX];
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

      for (ri = rn->info; ri; ri = ri->info_next)
        {
          rinum++;
          ts->counts[BGP_STATS_RIB]++;

          if (ri->attr &&
              (CHECK_FLAG (ri->attr->flag,
                           ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))))
            ts->counts[BGP_STATS_AGGREGATES]++;

          /* as-path stats */
          if (ri->attr && ri->attr->aspath)
            {
              unsigned int hops = aspath_count_hops (ri->attr->aspath);
              unsigned int size = aspath_size (ri->attr->aspath);
              as_t highest = aspath_highest (ri->attr->aspath);

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
bgp_table_stats (struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi)
{
  struct bgp_table_stats ts;
  unsigned int i;

  if (!bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No RIB exist for the AFI/SAFI%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&ts, 0, sizeof (ts));
  ts.table = bgp->rib[afi][safi];
  thread_execute (bm->master, bgp_table_stats_walker, &ts, 0);

  vty_out (vty, "BGP %s RIB statistics%s%s",
           afi_safi_print (afi, safi), VTY_NEWLINE, VTY_NEWLINE);

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
            vty_out (vty, "%12llu", ts.counts[i]);
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
  afi_t afi;
  safi_t safi;

 if (name)
    bgp = bgp_lookup_by_name (name);
  else
    bgp = bgp_get_default ();

  if (!bgp)
    {
      vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  if (strncmp (afi_str, "ipv", 3) == 0)
    {
      if (strncmp (afi_str, "ipv4", 4) == 0)
        afi = AFI_IP;
      else if (strncmp (afi_str, "ipv6", 4) == 0)
        afi = AFI_IP6;
      else
        {
          vty_out (vty, "%% Invalid address family %s%s",
                   afi_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
      if (strncmp (safi_str, "m", 1) == 0)
        safi = SAFI_MULTICAST;
      else if (strncmp (safi_str, "u", 1) == 0)
        safi = SAFI_UNICAST;
      else if (strncmp (safi_str, "vpnv4", 5) == 0 || strncmp (safi_str, "vpnv6", 5) == 0)
        safi = SAFI_MPLS_LABELED_VPN;
      else
        {
          vty_out (vty, "%% Invalid subsequent address family %s%s",
                   safi_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  else
    {
      vty_out (vty, "%% Invalid address family %s%s",
               afi_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_table_stats (vty, bgp, afi, safi);
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
  struct bgp_node *rn;
  struct peer_pcounts *pc = THREAD_ARG (t);
  const struct peer *peer = pc->peer;

  for (rn = bgp_table_top (pc->table); rn; rn = bgp_route_next (rn))
    {
      struct bgp_adj_in *ain;
      struct bgp_info *ri;

      for (ain = rn->adj_in; ain; ain = ain->adj_next)
        if (ain->peer == peer)
          pc->count[PCOUNT_ADJ_IN]++;

      for (ri = rn->info; ri; ri = ri->info_next)
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
bgp_peer_counts (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi)
{
  struct peer_pcounts pcounts = { .peer = peer };
  unsigned int i;

  if (!peer || !peer->bgp || !peer->afc[afi][safi]
      || !peer->bgp->rib[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.peer = peer;
  pcounts.table = peer->bgp->rib[afi][safi];

  /* in-place call via thread subsystem so as to record execution time
   * stats for the thread-walk (i.e. ensure this can't be blamed on
   * on just vty_read()).
   */
  thread_execute (bm->master, bgp_peer_count_walker, &pcounts, 0);

  vty_out (vty, "Prefix counts for %s, %s%s",
           peer->host, afi_safi_print (afi, safi), VTY_NEWLINE);
  vty_out (vty, "PfxCt: %ld%s", peer->pcount[afi][safi], VTY_NEWLINE);
  vty_out (vty, "%sCounts from RIB table walk:%s%s",
           VTY_NEWLINE, VTY_NEWLINE, VTY_NEWLINE);

  for (i = 0; i < PCOUNT_MAX; i++)
      vty_out (vty, "%20s: %-10d%s",
               pcount_strs[i], pcounts.count[i], VTY_NEWLINE);

  if (pcounts.count[PCOUNT_PFCNT] != peer->pcount[afi][safi])
    {
      vty_out (vty, "%s [pcount] PfxCt drift!%s",
               peer->host, VTY_NEWLINE);
      vty_out (vty, "Please report this bug, with the above command output%s",
              VTY_NEWLINE);
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

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
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

  return bgp_peer_counts (vty, peer, AFI_IP6, SAFI_UNICAST);
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

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MULTICAST);

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_UNICAST);
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

  return bgp_peer_counts (vty, peer, AFI_IP, SAFI_MPLS_VPN);
}


static void
show_adj_route (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi,
                int in)
{
  struct bgp_table *table;
  struct bgp_adj_in *ain;
  struct bgp_adj_out *adj;
  unsigned long output_count;
  struct bgp_node *rn;
  int header1 = 1;
  struct bgp *bgp;
  int header2 = 1;

  bgp = peer->bgp;

  if (! bgp)
    return;

  table = bgp->rib[afi][safi];

  output_count = 0;

  if (! in && CHECK_FLAG (peer->af_sflags[afi][safi],
                          PEER_STATUS_DEFAULT_ORIGINATE))
    {
      vty_out (vty, "BGP table version is 0, local router ID is %s%s", safe_inet_ntoa (bgp->router_id), VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
      vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);

      vty_out (vty, "Originating default network 0.0.0.0%s%s",
               VTY_NEWLINE, VTY_NEWLINE);
      header1 = 0;
    }

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if (in)
      {
        for (ain = rn->adj_in; ain; ain = ain->adj_next)
          if (ain->peer == peer)
            {
              if (header1)
                {
                  vty_out (vty, "BGP table version is 0, local router ID is %s%s", safe_inet_ntoa (bgp->router_id), VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                  header1 = 0;
                }
              if (header2)
                {
                  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                  header2 = 0;
                }
              if (ain->attr)
                {
                  route_vty_out_tmp (vty, &rn->p, ain->attr, safi);
                  output_count++;
                }
            }
      }
    else
      {
        for (adj = rn->adj_out; adj; adj = adj->adj_next)
          if (adj->peer == peer)
            {
              if (header1)
                {
                  vty_out (vty, "BGP table version is 0, local router ID is %s%s", safe_inet_ntoa (bgp->router_id), VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_SCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                  vty_out (vty, BGP_SHOW_OCODE_HEADER, VTY_NEWLINE, VTY_NEWLINE);
                  header1 = 0;
                }
              if (header2)
                {
                  vty_out (vty, BGP_SHOW_HEADER, VTY_NEWLINE);
                  header2 = 0;
                }
              if (adj->attr)
                {
                  route_vty_out_tmp (vty, &rn->p, adj->attr, safi);
                  output_count++;
                }
            }
      }

  if (output_count != 0)
    vty_out (vty, "%sTotal number of prefixes %ld%s",
             VTY_NEWLINE, output_count, VTY_NEWLINE);
}

static int
peer_adj_routes (struct vty *vty, struct peer *peer, afi_t afi, safi_t safi, int in)
{
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (in && ! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SOFT_RECONFIG))
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  show_adj_route (vty, peer, afi, safi, in);

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

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0);
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

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 0);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 0);
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

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 0);
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

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_UNICAST, 1);
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

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 0);
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

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1);
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

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return peer_adj_routes (vty, peer, AFI_IP, SAFI_MULTICAST, 1);

  return peer_adj_routes (vty, peer, AFI_IP, SAFI_UNICAST, 1);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
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
       "show bgp view WORD ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
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
  int afi;
  int safi;
  int in;
  struct peer *peer;

#ifdef HAVE_IPV6
    peer = peer_lookup_in_view (vty, argv[0], argv[3]);
#else
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
#endif

  if (! peer)
    return CMD_WARNING;

#ifdef HAVE_IPV6
  afi = (strncmp (argv[1], "ipv6", 4) == 0) ? AFI_IP6 : AFI_IP;
  safi = (strncmp (argv[2], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  in = (strncmp (argv[4], "r", 1) == 0) ? 1 : 0;
#else
  afi = AFI_IP;
  safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  in = (strncmp (argv[3], "r", 1) == 0) ? 1 : 0;
#endif

  return peer_adj_routes (vty, peer, afi, safi, in);
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
  char name[BUFSIZ];
  union sockunion *su;
  struct peer *peer;
  int count;

  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    return CMD_WARNING;

  peer = peer_lookup (NULL, su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_neighbor_received_prefix_filter,
       show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
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
  char name[BUFSIZ];
  union sockunion *su;
  struct peer *peer;
  int count;

  su = sockunion_str2su (argv[1]);
  if (su == NULL)
    return CMD_WARNING;

  peer = peer_lookup (NULL, su);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_MULTICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
        {
          vty_out (vty, "Address family: IPv4 Multicast%s", VTY_NEWLINE);
          prefix_bgp_show_prefix_list (vty, AFI_IP, name);
        }
    }
  else
    {
      sprintf (name, "%s.%d.%d", peer->host, AFI_IP, SAFI_UNICAST);
      count =  prefix_bgp_show_prefix_list (NULL, AFI_IP, name);
      if (count)
        {
          vty_out (vty, "Address family: IPv4 Unicast%s", VTY_NEWLINE);
          prefix_bgp_show_prefix_list (vty, AFI_IP, name);
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
  char name[BUFSIZ];
  union sockunion *su;
  struct peer *peer;
  int count;

  su = sockunion_str2su (argv[0]);
  if (su == NULL)
    return CMD_WARNING;

  peer = peer_lookup (NULL, su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
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

  return peer_adj_routes (vty, peer, AFI_IP6, SAFI_MULTICAST, 1);
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
  char name[BUFSIZ];
  union sockunion *su;
  struct peer *peer;
  struct bgp *bgp;
  int count;

  /* BGP structure lookup. */
  bgp = bgp_lookup_by_name (argv[0]);
  if (bgp == NULL)
  {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
          return CMD_WARNING;
        }

  su = sockunion_str2su (argv[1]);
  if (su == NULL)
    return CMD_WARNING;

  peer = peer_lookup (bgp, su);
  if (! peer)
    return CMD_WARNING;

  sprintf (name, "%s.%d.%d", peer->host, AFI_IP6, SAFI_UNICAST);
  count =  prefix_bgp_show_prefix_list (NULL, AFI_IP6, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast%s", VTY_NEWLINE);
      prefix_bgp_show_prefix_list (vty, AFI_IP6, name);
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
bgp_show_neighbor_route (struct vty *vty, struct peer *peer, afi_t afi,
                         safi_t safi, enum bgp_show_type type)
{
  if (! peer || ! peer->afc[afi][safi])
    {
      vty_out (vty, "%% No such neighbor or address family%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show (vty, peer->bgp, afi, safi, type, &peer->su);
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
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

  peer = peer_lookup_in_view (vty, NULL, argv[1]);
  if (! peer)
    return CMD_WARNING;

  if (strncmp (argv[0], "m", 1) == 0)
    return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_MULTICAST,
                                    bgp_show_type_neighbor);

  return bgp_show_neighbor_route (vty, peer, AFI_IP, SAFI_UNICAST,
                                  bgp_show_type_neighbor);
}

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

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL);
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
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
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
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL);
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
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 0);
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
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
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
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 0);
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
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP, SAFI_UNICAST, NULL, 1);
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
       "show bgp view WORD ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
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
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP, safi, NULL, 1);
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_ipv4_safi_rsclient_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

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

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_UNICAST,
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

  return bgp_show_neighbor_route (vty, peer, AFI_IP6, SAFI_MULTICAST,
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
  struct peer *peer;

  if (argc == 2)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][SAFI_UNICAST];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL);
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
  safi_t safi;

  if (argc == 3) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  table = peer->rib[AFI_IP6][safi];

  return bgp_show_table (vty, table, &peer->remote_id, bgp_show_type_normal, NULL);
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
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 0);
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
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
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
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 0);
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
  struct bgp *bgp;
  struct peer *peer;

  /* BGP structure lookup. */
  if (argc == 3)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 3)
    peer = peer_lookup_in_view (vty, argv[0], argv[1]);
  else
    peer = peer_lookup_in_view (vty, NULL, argv[0]);

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][SAFI_UNICAST])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][SAFI_UNICAST],
              PEER_FLAG_RSERVER_CLIENT))
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][SAFI_UNICAST],
                                  (argc == 3) ? argv[2] : argv[1],
                                  AFI_IP6, SAFI_UNICAST, NULL, 1);
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
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
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
  struct bgp *bgp;
  struct peer *peer;
  safi_t safi;

  /* BGP structure lookup. */
  if (argc == 4)
    {
      bgp = bgp_lookup_by_name (argv[0]);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", argv[0], VTY_NEWLINE);
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

  if (argc == 4) {
    peer = peer_lookup_in_view (vty, argv[0], argv[2]);
    safi = (strncmp (argv[1], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  } else {
    peer = peer_lookup_in_view (vty, NULL, argv[1]);
    safi = (strncmp (argv[0], "m", 1) == 0) ? SAFI_MULTICAST : SAFI_UNICAST;
  }

  if (! peer)
    return CMD_WARNING;

  if (! peer->afc[AFI_IP6][safi])
    {
      vty_out (vty, "%% Activate the neighbor for the address family first%s",
            VTY_NEWLINE);
      return CMD_WARNING;
}

  if ( ! CHECK_FLAG (peer->af_flags[AFI_IP6][safi],
              PEER_FLAG_RSERVER_CLIENT))
{
      vty_out (vty, "%% Neighbor is not a Route-Server client%s",
            VTY_NEWLINE);
    return CMD_WARNING;
    }

  return bgp_show_route_in_table (vty, bgp, peer->rib[AFI_IP6][safi],
                                  (argc == 4) ? argv[3] : argv[2],
                                  AFI_IP6, safi, NULL, 1);
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_ipv6_safi_rsclient_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")

#endif /* HAVE_IPV6 */

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

/* Apply BGP information to distance method. */
u_char
bgp_distance_apply (struct prefix *p, struct bgp_info *rinfo, struct bgp *bgp)
{
  struct bgp_node *rn;
  struct prefix_ipv4 q;
  struct peer *peer;
  struct bgp_distance *bdistance;
  struct access_list *alist;
  struct bgp_static *bgp_static;

  if (! bgp)
    return 0;

  if (p->family != AF_INET)
    return 0;

  peer = rinfo->peer;

  if (peer->su.sa.sa_family != AF_INET)
    return 0;

  memset (&q, 0, sizeof (struct prefix_ipv4));
  q.family = AF_INET;
  q.prefix = peer->su.sin.sin_addr;
  q.prefixlen = IPV4_MAX_BITLEN;

  /* Check source address. */
  rn = bgp_node_match (bgp_distance_table, (struct prefix *) &q);
  if (rn)
    {
      bdistance = rn->info;
      bgp_unlock_node (rn);

      if (bdistance->access_list)
        {
          alist = access_list_lookup (AFI_IP, bdistance->access_list);
          if (alist && access_list_apply (alist, p) == FILTER_PERMIT)
            return bdistance->distance;
        }
      else
        return bdistance->distance;
    }

  /* Backdoor check. */
  rn = bgp_node_lookup (bgp->route[AFI_IP][SAFI_UNICAST], p);
  if (rn)
    {
      bgp_static = rn->info;
      bgp_unlock_node (rn);

      if (bgp_static->backdoor)
        {
          if (bgp->distance_local)
            return bgp->distance_local;
          else
            return ZEBRA_IBGP_DISTANCE_DEFAULT;
        }
    }

  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      if (bgp->distance_ebgp)
        return bgp->distance_ebgp;
      return ZEBRA_EBGP_DISTANCE_DEFAULT;
    }
  else
    {
      if (bgp->distance_ibgp)
        return bgp->distance_ibgp;
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

  bgp->distance_ebgp = atoi (argv[0]);
  bgp->distance_ibgp = atoi (argv[1]);
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

  bgp->distance_ebgp= 0;
  bgp->distance_ibgp = 0;
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
  return bgp_damp_enable (bgp, bgp_node_afi (vty), bgp_node_safi (vty),
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
  return bgp_damp_disable (bgp, bgp_node_afi (vty), bgp_node_safi (vty));
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
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST, bgp_show_type_dampend_paths,
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
  return bgp_show (vty, NULL, AFI_IP, SAFI_UNICAST,
                   bgp_show_type_flap_statistics, NULL);
}

/* Display specified route of BGP table. */
static int
bgp_clear_damp_route (struct vty *vty, const char *view_name,
                      const char *ip_str, afi_t afi, safi_t safi,
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

  match.family = afi2family (afi);

  if (safi == SAFI_MPLS_VPN)
    {
      for (rn = bgp_table_top (bgp->rib[AFI_IP][SAFI_MPLS_VPN]); rn;
                                                      rn = bgp_route_next (rn))
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
                            ri_temp = ri->info_next;
                            bgp_damp_info_free (ri->extra->damp_info, 1);
                            ri = ri_temp;
                          }
                        else
                          ri = ri->info_next;
                      }
                  }
                bgp_unlock_node (rm);
              }
        }
    }
  else
    {
      if ((rn = bgp_node_match (bgp->rib[afi][safi], &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              ri = rn->info;
              while (ri)
                {
                  if (ri->extra && ri->extra->damp_info)
                    {
                      ri_temp = ri->info_next;
                      bgp_damp_info_free (ri->extra->damp_info, 1);
                      ri = ri_temp;
                    }
                  else
                    ri = ri->info_next;
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
bgp_config_write_network_vpnv4 (struct vty *vty, struct bgp *bgp,
                                afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct prefix_rd *prd;
  struct bgp_static *bgp_static;
  u_int32_t label;
  char buf[SU_ADDRSTRLEN];
  char rdbuf[RD_ADDRSTRLEN];

  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[afi][safi]); prn; prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        if ((bgp_static = rn->info) != NULL)
          {
            p = &rn->p;
            prd = (struct prefix_rd *) &prn->p;

            /* "address-family" display.  */
            bgp_config_write_family_header (vty, afi, safi, write);

            /* "network" configuration display.  */
            prefix_rd2str (prd, rdbuf, RD_ADDRSTRLEN);
            label = decode_label (bgp_static->tag);

            vty_out (vty, " network %s/%d rd %s tag %d",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     p->prefixlen,
                     rdbuf, label);
            vty_out (vty, "%s", VTY_NEWLINE);
          }
  return 0;
}

/* Configuration of static route announcement and aggregate
   information. */
int
bgp_config_write_network (struct vty *vty, struct bgp *bgp,
                          afi_t afi, safi_t safi, int *write)
{
  struct bgp_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  struct bgp_aggregate *bgp_aggregate;
  char buf[SU_ADDRSTRLEN];

  if (afi == AFI_IP && safi == SAFI_MPLS_VPN)
    return bgp_config_write_network_vpnv4 (vty, bgp, afi, safi, write);

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, afi, safi, write);

        /* "network" configuration display.  */
        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
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

  /* Aggregate-address configuration. */
  for (rn = bgp_table_top (bgp->aggregate[afi][safi]); rn; rn = bgp_route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, afi, safi, write);

        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && afi == AFI_IP)
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
  if (bgp->distance_ebgp
      && bgp->distance_ibgp
      && bgp->distance_local
      && (bgp->distance_ebgp != ZEBRA_EBGP_DISTANCE_DEFAULT
          || bgp->distance_ibgp != ZEBRA_IBGP_DISTANCE_DEFAULT
          || bgp->distance_local != ZEBRA_IBGP_DISTANCE_DEFAULT))
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
  bgp_distance_table = bgp_table_init (AFI_IP, SAFI_UNICAST);
} ;

void
bgp_route_finish (void)
{
  bgp_table_unlock (bgp_distance_table);
  bgp_distance_table = NULL;
}
