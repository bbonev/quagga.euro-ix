/* BGP static routes
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
#include <misc.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_route_static.h"
#include "bgpd/bgp_vty.h"

#include "command.h"

/*==============================================================================
 * Static Route Stuff -- TODO !!!!!!!!
 */

extern void
bgp_static_delete (bgp_inst bgp)
{
  // TODO
} ;

extern void
bgp_static_update(bgp_inst bgp, prefix pfx, struct bgp_static* sroute,
                                                                    qafx_t qafx)
{
  // TODO
} ;

extern void
bgp_static_withdraw (bgp_inst bgp, prefix pfx, qafx_t qafx)
{
  // TODO
} ;

static cmd_ret_t
bgp_static_set_vpnv4 (vty vty, const char *ip_str, const char *rd_str,
                                                           const char *tag_str)
{
  vty_out(vty, "%% static routes not currently supported") ;    // TODO
  return CMD_WARNING ;
} ;

static cmd_ret_t
bgp_static_unset_vpnv4 (vty vty, const char* ip_str,
                                       const char* rd_str, const char* tag_str)
{
  vty_out(vty, "%% static routes not currently supported") ;    // TODO
  return CMD_WARNING ;
}

#if 0

static void bgp_static_withdraw_main (bgp_inst bgp, prefix p, qafx_t qafx) ;
static void bgp_static_withdraw_rsclient (bgp_inst bgp, bgp_peer rsclient,
                                                        prefix p, qafx_t qafx) ;
static bool bgp_static_make_attributes(bgp_inst bgp, prefix p,
                  attr_pair attrs, qafx_t qafx, struct bgp_static *bgp_static,
                                                bgp_prun prun, uint rmap_type) ;

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
bgp_static_update_main (bgp_inst bgp, prefix p,
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
bgp_static_withdraw_main (bgp_inst bgp, prefix p, qafx_t qafx)
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
bgp_static_update_rsclient (bgp_inst bgp, bgp_peer rsclient, prefix p,
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
bgp_static_withdraw_rsclient (bgp_inst bgp, bgp_peer rsclient, prefix p,
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
bgp_static_update_vpnv4 (bgp_inst bgp, prefix p, qafx_t qafx,
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
bgp_static_withdraw_vpnv4 (bgp_inst bgp, prefix p, qafx_t qafx,
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
  bgp_prun prun ;
  struct listnode *node, *nnode;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    return ;

  bgp_static_update_main (bgp, p, bgp_static, qafx);

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      bgp_prib prib ;

      prib = peer->prib[qafx] ;

      if ((prib == NULL) || !prib->route_server_client)
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
  bgp_prun prun;
  struct listnode *node, *nnode;

  qassert(!qafx_is_mpls_vpn(qafx)) ;
  if (qafx_is_mpls_vpn(qafx))
    return ;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      bgp_prib prib ;

      prib = peer->prib[qafx] ;

      if ((prib == NULL) || !prib->route_server_client)
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
  bgp_inst bgp;
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
bgp_static_set (struct vty *vty, bgp_inst bgp, const char *ip_str,
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
bgp_static_unset (struct vty *vty, bgp_inst bgp, const char *ip_str,
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
extern cmd_ret_t
bgp_static_set_vpnv4 (struct vty *vty, const char *ip_str, const char *rd_str,
                      const char *tag_str)
{
  int ret;
  prefix_t p[1] ;
  struct prefix_rd prd;
  bgp_inst bgp;
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
extern cmd_ret_t
bgp_static_unset_vpnv4 (struct vty *vty, const char *ip_str,
                        const char *rd_str, const char *tag_str)
{
  int ret;
  bgp_inst bgp;
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
bgp_static_delete (bgp_inst bgp)
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
bgp_static_make_attributes(bgp_inst bgp, prefix p, attr_pair attrs,
                                 qafx_t qafx, struct bgp_static *bgp_static,
                                                  bgp_prun prun, uint rmap_type)
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

#endif

/*------------------------------------------------------------------------------
 * The static route configuration stuff -- TODO !!
 */
static cmd_ret_t
bgp_static_todo_warning(vty vty)
{
  vty_out (vty, "%% Static Routes are disabled -- pro tem\n");
  return CMD_WARNING;
} ;

static cmd_ret_t
bgp_static_set(struct vty *vty, bgp_inst bgp, const char *ip_str,
                                   qafx_t qafx, const char *rmap, bool backdoor)
{
  return bgp_static_todo_warning(vty) ;
} ;

static cmd_ret_t
bgp_static_unset(struct vty *vty, bgp_inst bgp, const char *ip_str,
                                                                   qafx_t qafx)
{
  return bgp_static_todo_warning(vty) ;
} ;


DEFUN (bgp_network,
       bgp_network_cmd,
       "network A.B.C.D/M",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_static_set (vty, vty->index, argv[0], bgp_node_qafx(vty), NULL, 0);
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
                          qafx_from_q(qAFI_IPv6, bgp_node_safi(vty)), NULL, 0);
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
                       qafx_from_q(qAFI_IPv6, bgp_node_safi(vty)), argv[1], 0);
}

DEFUN (no_ipv6_bgp_network,
       no_ipv6_bgp_network_cmd,
       "no network X:X::X:X/M",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_static_unset (vty, vty->index, argv[0],
                                   qafx_from_q(qAFI_IPv6, bgp_node_safi(vty)));
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
 * MPLS CLI stuff.
 */

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

/*==============================================================================
 * Table of bgp static route commands
 */
CMD_INSTALL_TABLE(static, bgp_static_cmd_table, BGPD) =
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

#ifdef HAVE_IPV6
  /* New config IPv6 BGP commands.  */
  { BGP_IPV6_NODE,   &ipv6_bgp_network_cmd                              },
  { BGP_IPV6_NODE,   &ipv6_bgp_network_route_map_cmd                    },
  { BGP_IPV6_NODE,   &no_ipv6_bgp_network_cmd                           },
  { BGP_IPV6_NODE,   &no_ipv6_bgp_network_route_map_cmd                 },

  { BGP_IPV6M_NODE,  &ipv6_bgp_network_cmd                              },
  { BGP_IPV6M_NODE,  &no_ipv6_bgp_network_cmd                           },

  /* Old config IPv6 BGP commands.  */
  { BGP_NODE,        &old_ipv6_bgp_network_cmd                          },
  { BGP_NODE,        &old_no_ipv6_bgp_network_cmd                       },
#endif /* HAVE_IPV6 */

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

  { BGP_VPNV4_NODE,  &vpnv4_network_cmd                                 },
  { BGP_VPNV4_NODE,  &no_vpnv4_network_cmd                              },

  CMD_INSTALL_END
} ;

extern void
bgp_static_cmd_init (void)
{
  cmd_install_table(bgp_static_cmd_table) ;
}


