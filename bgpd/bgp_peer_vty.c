/* BGP Peer Command Support
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Restructured: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#include "bgpd/bgp_peer_vty.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_route.h"

#include "command.h"
#include "vty.h"

/*==============================================================================
 * Output of peer configuration
 */
static void bgp_config_write_filter (vty vty, bgp_peer peer, qafx_t qafx) ;


/*------------------------------------------------------------------------------
 * BGP peer configuration display function.
 */
extern void
bgp_config_write_peer (vty vty, bgp_inst bgp, bgp_peer peer, qafx_t qafx)
{
  bgp_peer  g_conf ;
  peer_rib  prib, g_prib ;
  bool pgm, agm ;
  char*     name;
  bgp_peer_sort_t sort ;

  name = peer->host;            /* for group this is the group name     */
  sort = peer_sort(peer) ;

  if (peer->group_membership == qafx_set_empty)
    {
      pgm    = false ;          /* not a group member at all            */
      agm    = false ;          /* not a group member in the family     */

      g_conf = NULL ;           /* no group configuration               */
    }
  else
    {
      qassert(peer->type == PEER_TYPE_REAL) ;
      qassert((peer->group != NULL) && (peer->group->conf != NULL)) ;

      pgm    = true ;           /* group member in at least one family  */
      agm    = peer->group_membership & qafx_bit(qafx) ;
                                /* whether group member in the family   */

      g_conf = peer->group->conf ;
    } ;

  if (qafx == qafx_ipv4_unicast)
    {
      /* ipv4_unicast implicitly includes stuff which is global to the
       * neighbor or group
       */
      if (!pgm)
        {
          /* Not a peer group member, so:
           *
           *   * may be a peer group -- so start with its name, followed
           *                            by an AS, if any.
           *
           *   * otherwise must be a real peer, with an explicit AS
           */
          if (peer->type == PEER_TYPE_GROUP_CONF)
            vty_out (vty, " neighbor %s peer-group\n", name);
          else
            qassert(peer->type == PEER_TYPE_REAL) ;

          if (peer->as != BGP_ASN_NULL)
            vty_out (vty, " neighbor %s remote-as %u\n", name, peer->as) ;
          else
            qassert(peer->type == PEER_TYPE_GROUP_CONF) ;
        }
      else
        {
          /* Is a peer group member, so must be a real peer.
           *
           * If the group has an AS, then the real peer will inherit that.
           */
          qassert(peer->type == PEER_TYPE_REAL) ;

          if (g_conf->as == BGP_ASN_NULL)
            vty_out (vty, " neighbor %s remote-as %u\n", name, peer->as) ;
          else
            qassert(agm) ;

          if (agm)
            vty_out (vty, " neighbor %s peer-group %s\n", name,
                                                            peer->group->name) ;
        } ;

      if (peer->change_local_as)
        if (!pgm)
          vty_out (vty, " neighbor %s local-as %u%s%s", name,
                    peer->change_local_as,
                     (peer->flags & PEER_FLAG_LOCAL_AS_NO_PREPEND)
                                            ? " no-prepend" : "", VTY_NEWLINE);

      if (peer->desc)
        vty_out (vty, " neighbor %s description %s%s", name, peer->desc,
                                                                  VTY_NEWLINE);

      if (peer->flags & PEER_FLAG_SHUTDOWN)
        if (!pgm || !(g_conf->flags & PEER_FLAG_SHUTDOWN))
          vty_out (vty, " neighbor %s shutdown%s", name, VTY_NEWLINE);

      if (peer->password)
        if (!pgm || (g_conf->password == NULL)
                 || (strcmp (peer->password, g_conf->password) != 0))
          vty_out (vty, " neighbor %s password %s%s", name, peer->password,
                                                                  VTY_NEWLINE);

      if (peer->port != BGP_PORT_DEFAULT)
        vty_out (vty, " neighbor %s port %d%s", name, peer->port, VTY_NEWLINE);

      if (peer->ifname)
        vty_out (vty, " neighbor %s interface %s%s", name, peer->ifname,
                                                                  VTY_NEWLINE);

      if (peer->flags & PEER_FLAG_PASSIVE)
        if (!pgm || !(g_conf->flags & PEER_FLAG_PASSIVE))
          vty_out (vty, " neighbor %s passive%s", name, VTY_NEWLINE);

      if (sort != BGP_PEER_IBGP)
        {
          if (peer->gtsm)
            {
              /* ttl-security hops                              */
              if (!pgm || ! g_conf->gtsm)
                vty_out (vty, " neighbor %s ttl-security hops %d%s", name,
                                                      peer->ttl, VTY_NEWLINE) ;
            }
          else if (peer->ttl != 1)
            {
              /* eBGP multihop                                  */
              if (!pgm || (g_conf->ttl != peer->ttl))
                vty_out (vty, " neighbor %s ebgp-multihop %d%s", name,
                                                      peer->ttl, VTY_NEWLINE) ;
            } ;
        } ;

      if (peer->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK)
        if (!pgm ||
            !(g_conf->flags & PEER_FLAG_DISABLE_CONNECTED_CHECK))
          vty_out (vty, " neighbor %s disable-connected-check%s", name,
                                                                  VTY_NEWLINE);

      if (peer->update_if)
        if (!pgm || ! g_conf->update_if
                 || (strcmp (g_conf->update_if, peer->update_if) != 0))
          vty_out (vty, " neighbor %s update-source %s%s", name,
                                                 peer->update_if, VTY_NEWLINE);
      if (peer->update_source)
        if (!pgm || ! g_conf->update_source
           || (sockunion_cmp (g_conf->update_source, peer->update_source) != 0))
          vty_out (vty, " neighbor %s update-source %s%s", name,
                                               sutoa(peer->update_source).str,
                                                                   VTY_NEWLINE);

      if (!pgm && (peer->config & PEER_CONFIG_MRAI))
        vty_out (vty, " neighbor %s advertisement-interval %u\n", name,
                                                            peer->config_mrai) ;

      if (!pgm && (peer->config & PEER_CONFIG_TIMER))
        vty_out (vty, " neighbor %s timers %u %u\n", name,
                                peer->config_keepalive, peer->config_holdtime) ;

      if (!pgm && (peer->config & PEER_CONFIG_CONNECT))
        vty_out (vty, " neighbor %s timers connect %u\n", name,
                                                         peer->config_connect) ;

      if (peer->config & PEER_CONFIG_WEIGHT)
        vty_out (vty, " neighbor %s weight %u\n", name, peer->weight);

      if (peer->flags & PEER_FLAG_DYNAMIC_CAPABILITY)
        if (!pgm || !(g_conf->flags & PEER_FLAG_DYNAMIC_CAPABILITY))
          vty_out (vty, " neighbor %s capability dynamic%s", name,
                                                                  VTY_NEWLINE);

      if (peer->flags & PEER_FLAG_DONT_CAPABILITY)
        if (!pgm || !(g_conf->flags & PEER_FLAG_DONT_CAPABILITY))
          vty_out (vty, " neighbor %s dont-capability-negotiate%s", name,
                                                                  VTY_NEWLINE);

      if (peer->flags & PEER_FLAG_OVERRIDE_CAPABILITY)
        if (!pgm || !(g_conf->flags & PEER_FLAG_OVERRIDE_CAPABILITY))
          vty_out (vty, " neighbor %s override-capability%s", name,
                                                                  VTY_NEWLINE);

      if (peer->flags & PEER_FLAG_STRICT_CAP_MATCH)
        if (!pgm || !(g_conf->flags & PEER_FLAG_STRICT_CAP_MATCH))
          vty_out (vty, " neighbor %s strict-capability-match%s", name,
                                                                 VTY_NEWLINE);

      if (!pgm)
        {
          if (bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4))
            {
              if (peer_family_is_active(peer, qafx_ipv4_unicast))
                vty_out (vty, " neighbor %s activate%s", name, VTY_NEWLINE);
            }
          else
            {
              if (!peer_family_is_active(peer, qafx_ipv4_unicast))
                vty_out (vty, " no neighbor %s activate%s", name, VTY_NEWLINE);

              return ;
            }
        } ;
    }
  else
    {
      /* All other address-families -- do nothing if not active !
       */
      if (!peer_family_is_active(peer, qafx))
        return ;

      if (agm)
        vty_out (vty, " neighbor %s peer-group %s\n", name, peer->group->name);
      else
        vty_out (vty, " neighbor %s activate\n", name);
    } ;

  /*--------------------------------------------------------------------
   * From now on we are dealing with the particular address family.
   */
  prib = peer->prib[qafx] ;

  qassert(peer_family_is_active(peer, qafx) && (prib != NULL)) ;

  if (prib == NULL)
    return ;

  if (agm)
    {
      qassert(prib->af_group_member) ;
      g_prib = g_conf->prib[qafx] ;

      qassert(g_prib != NULL) ;

      if (g_prib == NULL)
        return ;
   }
  else
    {
      qassert(!prib->af_group_member) ;
      g_prib = NULL ;
    } ;

  if ( (prib->af_flags & PEER_AFF_ORF_PFX_SM) ||
       (prib->af_flags & PEER_AFF_ORF_PFX_RM) )
    if (!agm)
    {
      vty_out (vty, " neighbor %s capability orf prefix-list", name);

      if ((prib->af_flags & PEER_AFF_ORF_PFX_SM)
          && (prib->af_flags & PEER_AFF_ORF_PFX_RM))
        vty_out (vty, " both");
      else if (prib->af_flags & PEER_AFF_ORF_PFX_SM)
        vty_out (vty, " send");
      else
        vty_out (vty, " receive");
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  if (!agm && (prib->af_flags & PEER_AFF_REFLECTOR_CLIENT))
    vty_out (vty, " neighbor %s route-reflector-client\n", name);

  if (!agm && (prib->af_flags & PEER_AFF_NEXTHOP_SELF))
    vty_out (vty, " neighbor %s next-hop-self\n", name);

  if (!agm && (prib->af_flags & PEER_AFF_REMOVE_PRIVATE_AS))
    vty_out (vty, " neighbor %s remove-private-AS%s", name, VTY_NEWLINE);

  if (!agm)
    {
      if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
        {
          if ((prib->af_flags & PEER_AFF_SEND_COMMUNITY)
              && (prib->af_flags & PEER_AFF_SEND_EXT_COMMUNITY))
            vty_out (vty, " neighbor %s send-community both%s", name, VTY_NEWLINE);
          else if (prib->af_flags & PEER_AFF_SEND_EXT_COMMUNITY)
            vty_out (vty, " neighbor %s send-community extended%s",
                     name, VTY_NEWLINE);
          else if (prib->af_flags & PEER_AFF_SEND_COMMUNITY)
            vty_out (vty, " neighbor %s send-community%s", name, VTY_NEWLINE);
        }
      else
        {
          if (! (prib->af_flags & PEER_AFF_SEND_COMMUNITY)
              && ! (prib->af_flags & PEER_AFF_SEND_EXT_COMMUNITY))
            vty_out (vty, " no neighbor %s send-community both%s",
                     name, VTY_NEWLINE);
          else if (! (prib->af_flags & PEER_AFF_SEND_EXT_COMMUNITY))
            vty_out (vty, " no neighbor %s send-community extended%s",
                     name, VTY_NEWLINE);
          else if (! (prib->af_flags & PEER_AFF_SEND_COMMUNITY))
            vty_out (vty, " no neighbor %s send-community%s",
                     name, VTY_NEWLINE);
        }
    }

  if (!agm && (prib->af_flags & PEER_AFF_DEFAULT_ORIGINATE))
    {
      vty_out (vty, " neighbor %s default-originate", name);
      if (prib->default_rmap->name)
        vty_out (vty, " route-map %s", prib->default_rmap->name);
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  if (prib->af_flags & PEER_AFF_SOFT_RECONFIG)
    if (!agm ||
        !(g_prib->af_flags & PEER_AFF_SOFT_RECONFIG))
    vty_out (vty, " neighbor %s soft-reconfiguration inbound\n", name);

  if (prib->pmax.set)
    if ( !agm
        || (g_prib->pmax.limit     != prib->pmax.limit)
        || (g_prib->pmax.thresh_pc != prib->pmax.thresh_pc)
        || (g_prib->pmax.warning   != prib->pmax.warning) )
      {
        vty_out (vty, " neighbor %s maximum-prefix %u", name,
                                                       prib->pmax.limit);
        if (prib->pmax.thresh_pc != MAXIMUM_PREFIX_THRESHOLD_DEFAULT)
          vty_out (vty, " %d", prib->pmax.thresh_pc);
        if (prib->pmax.warning)
          vty_out (vty, " warning-only");
        if (prib->pmax.restart)
          vty_out (vty, " restart %d", prib->pmax.restart);
        vty_out (vty, "%s", VTY_NEWLINE);
      }

  if (!agm && (prib->af_flags & PEER_AFF_RSERVER_CLIENT))
    vty_out (vty, " neighbor %s route-server-client%s", name, VTY_NEWLINE);

  if ((prib->af_flags & PEER_AFF_NEXTHOP_LOCAL_UNCHANGED) && ! prib->af_group_member)
    vty_out (vty, " neighbor %s nexthop-local unchanged\n", name);

  if (prib->af_flags & PEER_AFF_ALLOWAS_IN)
    if (!pgm || ! (g_prib->af_flags & PEER_AFF_ALLOWAS_IN)
             || (prib->allowas_in != g_prib->allowas_in))
      {
        if (prib->allowas_in == 3)
          vty_out (vty, " neighbor %s allowas-in\n", name);
        else
          vty_out (vty, " neighbor %s allowas-in %d\n", name, prib->allowas_in);
      }

  bgp_config_write_filter (vty, peer, qafx);

  if ( !agm && (prib->af_flags & (PEER_AFF_AS_PATH_UNCHANGED |
                                  PEER_AFF_NEXTHOP_UNCHANGED |
                                  PEER_AFF_MED_UNCHANGED) ) )
    {
      if ( (prib->af_flags & PEER_AFF_AS_PATH_UNCHANGED) &&
           (prib->af_flags & PEER_AFF_NEXTHOP_UNCHANGED) &&
           (prib->af_flags & PEER_AFF_MED_UNCHANGED) )
        vty_out (vty, " neighbor %s attribute-unchanged\n", name);
      else
        vty_out (vty, " neighbor %s attribute-unchanged%s%s%s\n", name,
             (prib->af_flags & PEER_AFF_AS_PATH_UNCHANGED) ? " as-path" : "",
             (prib->af_flags & PEER_AFF_NEXTHOP_UNCHANGED) ? " next-hop" : "",
             (prib->af_flags & PEER_AFF_MED_UNCHANGED)     ? " med" : "");
    } ;
}

static void
bgp_config_write_filter (struct vty *vty, struct peer *peer, qafx_t qafx)
{
  enum
  {
    in  = FILTER_IN,
    out = FILTER_OUT
  } ;

  peer_rib      prib, g_prib ;
  access_list   dlist ;
  prefix_list   plist ;
  route_map     rmap ;
  as_list       flist ;
  char *addr;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return ;

  g_prib = NULL ;
  if (prib->af_group_member)
    {
      qassert(peer->group != NULL) ;
      g_prib = peer->group->conf->prib[qafx] ;
      qassert(g_prib != NULL) ;
    } ;

  addr = peer->host;

  /* distribute-list.
   */
  dlist = prib->dlist[FILTER_IN] ;
  if ((dlist != NULL) &&
                 ( (g_prib == NULL) || (dlist != g_prib->dlist[FILTER_IN]) ))
    vty_out (vty, " neighbor %s distribute-list %s in%s", addr,
                                     access_list_get_name(dlist), VTY_NEWLINE);

  dlist = prib->dlist[FILTER_OUT] ;
  if ((dlist != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s distribute-list %s out%s", addr,
                                     access_list_get_name(dlist), VTY_NEWLINE);

  /* prefix-list.
   */
  plist = prib->plist[FILTER_IN] ;
  if ((plist != NULL) &&
                  ( (g_prib == NULL) || (plist != g_prib->plist[FILTER_IN]) ))
    vty_out (vty, " neighbor %s prefix-list %s in%s", addr,
                                     prefix_list_get_name(plist), VTY_NEWLINE);

  plist = prib->plist[FILTER_OUT] ;
  if ((plist != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s prefix-list %s in%s", addr,
                                     prefix_list_get_name(plist), VTY_NEWLINE);

  /* route-map.
   */
  rmap = prib->rmap[RMAP_IN] ;
  if ((rmap != NULL) &&
                      ( (g_prib == NULL) || (rmap != g_prib->rmap[RMAP_IN]) ))
    vty_out (vty, " neighbor %s route-map %s in%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  rmap = prib->rmap[RMAP_OUT] ;
  if ((rmap != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s route-map %s out%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  rmap = prib->rmap[RMAP_RS_IN] ;
  if ((rmap != NULL) &&
                   ( (g_prib == NULL) || (rmap != g_prib->rmap[RMAP_RS_IN]) ))
    vty_out (vty, " neighbor %s route-map %s rs-in%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  rmap = prib->rmap[RMAP_EXPORT] ;
  if ((rmap != NULL) &&
                  ( (g_prib == NULL) || (rmap != g_prib->rmap[RMAP_EXPORT]) ))
    vty_out (vty, " neighbor %s route-map %s export%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  rmap = prib->rmap[RMAP_IMPORT] ;
  if ((rmap != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s route-map %s import%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  /* unsuppress-map             */
  rmap = prib->us_rmap ;
  if ((rmap != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s unsuppress-map %s import%s", addr,
                                        route_map_get_name(rmap), VTY_NEWLINE);

  /* filter-list.       */
  flist = prib->flist[FILTER_IN] ;
  if ((flist != NULL) &&
                 ( (g_prib == NULL) || (flist != g_prib->flist[FILTER_IN]) ))
    vty_out (vty, " neighbor %s filter-list %s in%s", addr,
                                         as_list_get_name(flist), VTY_NEWLINE);

  flist = prib->flist[FILTER_OUT] ;
  if ((flist != NULL) && (g_prib == NULL))
    vty_out (vty, " neighbor %s filter-list %s out%s", addr,
                                         as_list_get_name(flist), VTY_NEWLINE);
} ;

/*==============================================================================
 *
 */


/*------------------------------------------------------------------------------
 * eBGP multihop configuration set -- Confed is eBGP for this purpose.
 *
 * This is simply ignored if iBGP.  For iBGP peer->ttl is set to MAXTTL, and
 * peer->gtsm is always false.
 *
 * For eBGP and for Confed, peer->ttl is set to 1, and peer->gtsm is also
 * set false -- until either ebgp-multihop or ttl-security is seen.
 *
 * NB: cannot set ebgp-multihop if ttl-security (GTSM) is set.
 *
 * NB: setting ebgp-multihop of 1 is the same as unsetting it.
 *
 *     setting any value < 1 also unsets ebgp-multihop (sets ttl = 1)
 *
 * For a peer-group we set the ttl and gtsm flags, and those will be used for
 * any peer which is not iBGP.
 *
 * Note that for peer-group the group settings take precedence.
 */
extern bgp_ret_t
peer_ebgp_multihop_set (bgp_peer peer, ttl_t ttl)
{
  if (peer->type == PEER_TYPE_REAL)
    {
      if (peer->group != NULL)
        return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER ;

      if (peer->sort == BGP_PEER_IBGP)
        return BGP_SUCCESS ;
    } ;

  if (peer->gtsm)
    return BGP_ERR_NO_EBGP_MULTIHOP_WITH_GTSM;

  if    (ttl < 1)
    ttl = 1 ;
  else if (ttl > TTL_MAX)
    ttl = TTL_MAX ;

  peer->ttl = ttl ;     /* 1..TTL_MAX           */
  qassert(!peer->gtsm) ;

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      bgp_session_set_ttl (peer->session, peer->ttl, peer->gtsm);
    }
  else
    {
      struct listnode *node, *nnode;
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if (peer_sort (member) == BGP_PEER_IBGP)
            continue;

          member->ttl  = ttl ;
          member->gtsm = false ;
          bgp_session_set_ttl (member->session, member->ttl, member->gtsm);
        }
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * eBGP multihop configuration unset -- Confed is eBGP for this purpose.
 *
 * Implemented by setting the ttl to 0 !
 */
extern bgp_ret_t
peer_ebgp_multihop_unset (bgp_peer peer)
{
  return peer_ebgp_multihop_set (peer, 0) ;
}

/*------------------------------------------------------------------------------
 * eBGP ttl-security hops configuration set -- Confed is eBGP for this purpose.
 *
 * Setting ttl-security hops is equivalent to setting eBGP multi-hop, except
 * that it also enables the GTSM -- if available.
 *
 * This is simply ignored if iBGP.  For iBGP peer->ttl is set to MAXTTL, and
 * peer->gtsm is always false.
 *
 * For eBGP and for Confed, peer->ttl is set to 1, and peer->gtsm is also
 * set false -- until either ebgp-multihop or ttl-security is seen.
 *
 * NB: cannot set ttl-security (GTSM) if eBGP multi-hop is set.
 *
 *     cannot set ttl-security (GTSM) on a group if eBGP multi-hop is set on any
 *     group member.
 *
 * NB: setting ebgp-multihop of < 1 is unsets it (sets ttl = 1, and gtsm false)
 */
extern bgp_ret_t
peer_ttl_security_hops_set (bgp_peer peer, ttl_t ttl)
{
  struct listnode *node, *nnode;
  bool gtsm ;

  zlog_debug ("peer_ttl_security_hops_set: set gtsm_hops to %d for %s",
                                                              ttl, peer->host) ;

  if (peer_sort (peer) == BGP_PEER_IBGP)
    return BGP_ERR_NO_IBGP_WITH_TTLHACK ;

  if (!peer->gtsm && (peer->ttl > 1))
    return BGP_ERR_NO_EBGP_MULTIHOP_WITH_GTSM;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if (peer_sort(member) == BGP_PEER_IBGP)
            continue;

          if (!member->gtsm && (member->ttl > 1))
            return BGP_ERR_NO_EBGP_MULTIHOP_WITH_GTSM;
        }
    } ;


  if (ttl >= 1)
    {
      gtsm = true ;
      if (ttl > TTL_MAX)
        ttl = TTL_MAX ;
    }
  else
    {
      gtsm = false ;
      ttl  = 1 ;
    } ;

  peer->ttl  = ttl ;            /* 1..TTL_MAX   */
  peer->gtsm = gtsm ;

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      bgp_session_set_ttl (peer->session, peer->ttl, peer->gtsm);
    }
  else
    {
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if (peer_sort (member) == BGP_PEER_IBGP)
            continue;

          member->ttl  = ttl;
          member->gtsm = gtsm ;
          bgp_session_set_ttl (member->session, member->ttl, member->gtsm);
        } ;
    }
  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * eBGP ttl-security hops configuration unset -- Confed is eBGP for this purpose.
 *
 * Implemented by setting the ttl to 0 !
 */
extern bgp_ret_t
peer_ttl_security_hops_unset (bgp_peer peer)
{
  return peer_ttl_security_hops_set(peer, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Neighbor description.
 */
extern bgp_ret_t
peer_description_set (bgp_peer peer, const char* desc)
{
  if (peer->desc != NULL)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  peer->desc = XSTRDUP (MTYPE_PEER_DESC, desc);

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_description_unset (bgp_peer peer)
{
  if (peer->desc != NULL)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  peer->desc = NULL;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Neighbor update-source.
 */
extern bgp_ret_t
peer_update_source_if_set (bgp_peer peer, const char *ifname)
{
  bgp_peer member ;
  struct listnode *node, *nnode;

  if (peer->update_if)
    {
      if ((peer->type != PEER_TYPE_GROUP_CONF)
          && strcmp (peer->update_if, ifname) == 0)
        return BGP_SUCCESS ;

      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  if (peer->update_source)
    {
      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }

  peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, ifname);

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      bgp_peer_down(peer, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
      return BGP_SUCCESS ;
    }

  /* peer-group member updates. */
  for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
    {
      if (member->update_if)
        {
          if (strcmp (member->update_if, ifname) == 0)
            continue;

          XFREE (MTYPE_PEER_UPDATE_SOURCE, member->update_if);
          member->update_if = NULL;
        }

      if (member->update_source)
        {
          sockunion_free (member->update_source);
          peer->update_source = NULL;
        }

      member->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, ifname);

      bgp_peer_down(member, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
    } ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_update_source_addr_set (bgp_peer peer, sockunion su)
{
  bgp_peer member ;
  struct listnode *node, *nnode;

  if (peer->update_source)
    {
      if ((peer->type != PEER_TYPE_GROUP_CONF)
          && sockunion_cmp (peer->update_source, su) == 0)
        return BGP_SUCCESS ;

      sockunion_free (peer->update_source);
      peer->update_source = NULL;
    }

  if (peer->update_if)
    {
      XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = NULL;
    }

  peer->update_source = sockunion_dup (su);

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      bgp_peer_down(peer, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
      return BGP_SUCCESS ;
    }

  /* peer-group member updates
   */
  for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
    {
      if (member->update_source)
        {
          if (sockunion_cmp (member->update_source, su) == 0)
            continue;

          sockunion_free (member->update_source);
          member->update_source = NULL;
        }

      if (member->update_if)
        {
          XFREE (MTYPE_PEER_UPDATE_SOURCE, member->update_if);
          member->update_if = NULL;
        }

      member->update_source = sockunion_dup (su);

      bgp_peer_down(member, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Unset update_source and update_if
 *
 * For group members, inherit the group setting.
 *
 * For groups, unset the group and all members.
 */
extern bgp_ret_t
peer_update_source_unset (bgp_peer peer)
{
  /* Need do nothing if this is not a group and it has neither update_source
   * nor update_if.
   */
  if ( (peer->type != PEER_TYPE_GROUP_CONF) && (peer->update_source != NULL)
                                            && (peer->update_if != NULL) )
    return BGP_SUCCESS ;

  /* Unset values -- for all types of peer.
   */
  if (peer->update_source != NULL)
    peer->update_source = sockunion_free (peer->update_source);

  if (peer->update_if != NULL)
    XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if) ;
                                        /* sets peer->update_if = NULL  */

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer   member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if ((member->update_source == NULL) && (member->update_if == NULL))
            continue;

          if (member->update_source != NULL)
            member->update_source = sockunion_free (member->update_source);

          if (member->update_if != NULL)
            XFREE (MTYPE_PEER_UPDATE_SOURCE, member->update_if) ;
                                        /* sets member->update_if = NULL */

          bgp_peer_down(member, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
        } ;
    }
  else
    {
      if (peer->group_membership != qafx_set_empty)
        {
          bgp_peer gconf ;

          gconf = peer->group->conf ;

          if (gconf->update_source != NULL)
            peer->update_source = sockunion_dup (gconf->update_source) ;
          else if (gconf->update_if != NULL)
            peer->update_if =
                           XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, gconf->update_if);
        } ;

      bgp_peer_down(peer, PEER_DOWN_UPDATE_SOURCE_CHANGE) ;
    } ;

  return BGP_SUCCESS ;
}

static void
peer_default_originate_set_prib (peer_rib prib, const char* rmap_name)
{
  prib->af_flags |= PEER_AFF_DEFAULT_ORIGINATE ;
  if (rmap_name != NULL)
    {
      route_map_clear_ref(prib->default_rmap) ;
      prib->default_rmap = route_map_get_ref(rmap_name) ;
    } ;
} ;

extern bgp_ret_t
peer_default_originate_set (bgp_peer peer, qafx_t qafx, const char* rmap_name)
{
  peer_rib   prib ;

  /* Address family must be activated.
   */
  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  /* Default originate can't be used for peer group member
   */
  if (prib->af_group_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Change the peer or peer-group.
   */
  peer_default_originate_set_prib (prib, rmap_name) ;

  prib->af_flags |= PEER_AFF_DEFAULT_ORIGINATE ;
  if (rmap_name != NULL)
    {
      route_map_clear_ref(prib->default_rmap) ;
      prib->default_rmap = route_map_get_ref(rmap_name) ;
    } ;

  /* Update peer-group members or the given peer.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer   member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || !prib->af_group_member)
            continue ;

          prib->af_flags |= PEER_AFF_DEFAULT_ORIGINATE ;

          if (rmap_name != NULL)
            {
              route_map_clear_ref(prib->default_rmap) ;
              prib->default_rmap = route_map_get_ref(rmap_name) ;
            } ;

          if (prib->af_session_up)
            bgp_default_originate (member, qafx, false /* originate */);
        } ;
    }
  else
    {
      if (prib->af_session_up)
        bgp_default_originate (peer, qafx, false /* originate */);

      return BGP_SUCCESS ;
    }

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_default_originate_unset (bgp_peer peer, qafx_t qafx)
{
  peer_rib  prib ;
  bgp_peer  member ;
  struct listnode *node, *nnode;

  /* Address family must be activated.
   */
  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  /* Default originate can't be used for peer group member.
   */
  if (prib->af_group_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  UNSET_FLAG (prib->af_flags, PEER_AFF_DEFAULT_ORIGINATE);
  prib->default_rmap = route_map_clear_ref(prib->default_rmap) ;

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      if (prib->af_session_up)
        bgp_default_originate (peer, qafx, true /* withdraw */);

      return BGP_SUCCESS;
    }

  /* peer-group member updates.
   */
  for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
    {
      prib = peer_family_prib(member, qafx) ;
      if ((prib == NULL) || !prib->af_group_member)
        continue ;

      UNSET_FLAG (prib->af_flags, PEER_AFF_DEFAULT_ORIGINATE);

      prib->default_rmap = route_map_clear_ref(prib->default_rmap) ;

      if (prib->af_session_up)
        bgp_default_originate (member, qafx, true /* withdraw */);
    } ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_port_set (bgp_peer peer, uint16_t port)
{
  peer->port = port;
  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_port_unset (bgp_peer peer)
{
  peer->port = BGP_PORT_DEFAULT;
  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * set neighbor weight.
 *
 * The weight given will override any weight inherited from a group.
 *
 * Setting the weight for a group, overrides any weight set for all members
 * of the group.
 *
 * The PEER_CONFIG_WEIGHT flag means that an explicit weight has been set.
 */
extern bgp_ret_t
peer_weight_set (bgp_peer peer, uint weight)
{
  if (weight > 65535)
    return BGP_ERR_INVALID_VALUE;

  /* Set weight for peer or group -- overrides any value inherited from group.
   */
  peer->weight  = weight;
  peer->config |= PEER_CONFIG_WEIGHT ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->weight  = weight ;
          member->config &= ~PEER_CONFIG_WEIGHT ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * unset neighbor weight.
 *
 * Unsetting the weight for a group sets it zero and similarly unsets the
 * weight set for all members of the group.
 *
 * Unsetting the weight for a group member sets it to whatever the group is
 * set to (if anything).
 *
 * The PEER_CONFIG_WEIGHT flag means that an explicit weight has been set,
 * either directly in the peer or inheritted from the group.
 */
extern bgp_ret_t
peer_weight_unset (bgp_peer peer)
{
  /* Set default weight and unset explicit weight set.
   *
   * At this stage the peer may be any type of peer.
   */
  peer->weight  = 0;
  peer->config &= ~PEER_CONFIG_WEIGHT ;

  /* Update all peer-group members, or revert to group setting, as required.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if (member->config & PEER_CONFIG_WEIGHT)
            continue ;                  /* member has own weight        */

          member->weight  = 0 ;         /* revert to default            */
        } ;
    }
  else if (peer->group_membership != qafx_set_empty)
    {
      if (peer->group->conf->config & PEER_CONFIG_WEIGHT)
        peer->weight  = peer->group->conf->weight;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set the config_keepalive and holdtime for given peer or group
 *
 * Cannot override any setting inherited from a group.
 *
 * Setting the times for a group, overrides any times set for all members
 * of the group.
 *
 * The PEER_CONFIG_TIMER flag means that explicit times have been set.
 *
 * NB: will set whatever keepalive time the administrator asks for, whether
 *     or not that is more or less than holdtime, and whether or not it is
 *     zero and/or holdtime is.
 *
 *     When the HoldTime for a session is, finally, negotiated then (and only
 *     then) with the configured KeepAlive be taken into account.
 *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_timers_set (bgp_peer peer, uint keepalive, uint holdtime)
{
  /* Check for valid values
   */
  if (keepalive > 65535)
    return BGP_ERR_INVALID_VALUE;

  if (holdtime > 65535)
    return BGP_ERR_INVALID_VALUE;

  if ((holdtime < 3) && (holdtime != 0))
    return BGP_ERR_INVALID_VALUE;

  /* Not for peer group member -- group setting overrides
   */
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Set configured values -- may be real peer or group config.
   */
  peer->config_holdtime  = holdtime;
  peer->config_keepalive = keepalive;
  peer->config          |= PEER_CONFIG_TIMER ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_holdtime  = holdtime ;
          member->config_keepalive = keepalive ;
          member->config          |= PEER_CONFIG_TIMER ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Unset the keepalive and holdtime for given peer or group -- mark unset
 *
 * Cannot override any setting inherited from a group.
 *
 * Unsetting the times for a group, unsets times set for all members of the
 * group -- returning them to the default.
 *
 * The PEER_CONFIG_TIMER flag means that explicit times have been set, so this
 * unsets that flag for the affected peer or group and all members.
 *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_timers_unset (bgp_peer peer)
{
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear configuration.
   *
   * Clearing PEER_CONFIG_TIMER is sufficient, but we zeroize anyway.
   */
  peer->config_keepalive = 0;
  peer->config_holdtime  = 0;
  peer->config          &= ~PEER_CONFIG_TIMER ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_holdtime  = 0;
          member->config_keepalive = 0;
          member->config          &= ~PEER_CONFIG_TIMER ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set the config_connect time for given peer or group
 *
 * Cannot override any setting inherited from a group.
 *
 * Setting the time for a group, overrides any time set for all members
 * of the group.
 *
 * The PEER_CONFIG_CONNECT flag means that explicit time have been set.
  *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_timers_connect_set (bgp_peer peer, uint32_t connect)
{
  qassert(peer->type != PEER_TYPE_GROUP_CONF) ;

  if (connect > 65535)
    return BGP_ERR_INVALID_VALUE;

  /* Not for peer group member -- group setting overrides
   */
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Set configured value -- may be real peer or group config.
   */
  peer->config_connect = connect;
  peer->config        |= PEER_CONFIG_CONNECT ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_connect = connect;
          member->config        |= PEER_CONFIG_CONNECT ;
        } ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Unset the connect time for given peer or group
 *
 * Cannot override any setting inherited from a group.
 *
 * Unsetting the time for a group, unsets any time set for all members of the
 * group -- returning them to the default.
 *
 * The PEER_CONFIG_CONNECT flag means that explicit time has been set, so this
 * unsets that flag for the affected peer or group and all members.
 *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_timers_connect_unset (bgp_peer peer)
{
  qassert(peer->type != PEER_TYPE_GROUP_CONF) ;

  /* Not for peer group member -- group setting overrides
   */
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear configuration -- may be real peer or group config.
   *
   * Clearing PEER_CONFIG_CONNECT is sufficient, but we zeroize anyway.
   */
  peer->config_connect = 0;
  peer->config        &= ~PEER_CONFIG_CONNECT ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_connect = 0;
          member->config        &= ~PEER_CONFIG_CONNECT ;
        } ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Set the given peer's or group's route advertisement interval.
 *
 * Cannot override any setting inherited from a group.
 *
 * Setting the interval for a group, overrides any interval set for all members
 * of the group.
 *
 * The PEER_CONFIG_MRAI flag means that explicit interval has been set.
  *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_advertise_interval_set (bgp_peer peer, uint32_t mrai)
{
  qassert(peer->type == PEER_TYPE_REAL) ;

  if (mrai > 600)
    return BGP_ERR_INVALID_VALUE;

  /* Not for peer group member -- group setting overrides
   */
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Set configured value -- may be real peer or group config.
   */
  peer->config_mrai = mrai;
  peer->config     |= PEER_CONFIG_MRAI ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_mrai = mrai;
          member->config     |= PEER_CONFIG_MRAI ;
        } ;
    } ;

  return BGP_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Clear the given peer's or group's route advertisement interval.
 *
 * Cannot override any setting inherited from a group.
 *
 * Unsetting the interval for a group, unsets any interval set for all members
 * of the group -- returning them to the default.
 *
 * The PEER_CONFIG_CONNECT flag means that explicit time has been set, so this
 * unsets that flag for the affected peer or group and all members.
 *
 * TODO ... update running sessions ? ..............................................
 */
extern bgp_ret_t
peer_advertise_interval_unset (bgp_peer peer)
{
  /* Not for peer group member -- group setting overrides
   */
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear configuration -- may be real peer or group config.
   *
   * Clearing PEER_CONFIG_CONNECT is sufficient, but we zeroize anyway.
   */
  if (peer_sort (peer) == BGP_PEER_IBGP)
    peer->config_mrai = BGP_DEFAULT_IBGP_MRAI;
  else
    peer->config_mrai = BGP_DEFAULT_EBGP_MRAI;

  peer->config &= ~PEER_CONFIG_MRAI ;

  /* peer-group member updates.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->config_mrai = 0;
          member->config     &= ~PEER_CONFIG_MRAI ;
        } ;
    } ;

  return BGP_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Set neighbor interface for given *real* peer.
 *
 * NB: it does not appear to be possible to set this for a Group.
 */
extern bgp_ret_t
peer_interface_set (bgp_peer peer, const char* ifname)
{
  if (peer->ifname)
    free (peer->ifname);

  peer->ifname = strdup (ifname);

  return BGP_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Unset neighbor interface for given *real* peer.
 *
 * NB: it does not appear to be possible to set this for a Group.
 */
extern bgp_ret_t
peer_interface_unset (bgp_peer peer)
{
  if (peer->ifname)
    free (peer->ifname);
  peer->ifname = NULL;

  return BGP_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Allow-as in.
 */
extern bgp_ret_t
peer_allowas_in_set (bgp_peer peer, qafx_t qafx, uint allow_num)
{
  peer_rib    prib ;
  struct listnode *node, *nnode;

  if (allow_num < 1 || allow_num > 10)
    return BGP_ERR_INVALID_VALUE;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_SUCCESS ;

  if (prib->allowas_in != allow_num)
    {
      /* Set the changed allowas_in, and then force the flag false so that
       * the flag setting (below) will pick up the change and deal with side
       * effects.
       */
      prib->allowas_in = allow_num;
      prib->af_flags &= ~PEER_AFF_ALLOWAS_IN ;
    }

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer    group_member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, group_member))
        {
          prib = peer_family_prib(group_member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          if (prib->allowas_in != allow_num)
            {
              /* Set the changed allowas_in, and then force the flag false so
               * that the flag setting (below) will pick up the change and deal
               * with side effects.
               */
              prib->allowas_in = allow_num;
              prib->af_flags  &= ~PEER_AFF_ALLOWAS_IN ;
            } ;
        } ;
    } ;

  peer_af_flag_set (peer, qafx, PEER_AFF_ALLOWAS_IN);

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_allowas_in_unset (bgp_peer peer, qafx_t qafx)
{
  peer_rib    prib ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_SUCCESS ;

  prib->allowas_in = 0;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer    group_member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, group_member))
        {
          prib = peer_family_prib(group_member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue;

          prib->allowas_in = 0;
        } ;
    } ;

  peer_af_flag_unset (peer, qafx, PEER_AFF_ALLOWAS_IN);

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set neighbor nnn local-as <ASN> [no-prepend]
 *
 * The <ASN> may not be the same as the bgp->as or the bgp->confed_id !
 *
 * The neighbor may be a peer or a peer-group.
 *
 * For a real peer, can set this iff it is an eBGP peer -- which *excludes*
 * Confederation neighbors.
 *
 * For a peer-group, we remember the state, and apply it to all group members
 * which are eBGP peers -- which *excludes* Confederation neighbors.
 */
extern bgp_ret_t
peer_local_as_set (bgp_peer peer, as_t as, bool no_prepend)
{
  bgp_inst   bgp ;
  peer_flag_bits_t no_prepend_flag ;

  bgp = peer->bgp;

  if (bgp->as == as)
    return BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS;

  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      if (peer->sort != BGP_PEER_EBGP)
        return BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP;

      if (peer->group_membership != qafx_set_empty)
        return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
    } ;

  no_prepend_flag = no_prepend ? PEER_FLAG_LOCAL_AS_NO_PREPEND : 0 ;

  /* Quit now if no change.
   */
  if ( (peer->change_local_as == as) &&
            ((peer->flags & PEER_FLAG_LOCAL_AS_NO_PREPEND) == no_prepend_flag) )
    return BGP_SUCCESS ;

  /* Set the new state and reset peer(s) as required.
   */
  peer->change_local_as = as;
  peer->flags = (peer->flags & ~PEER_FLAG_LOCAL_AS_NO_PREPEND)
                                                             | no_prepend_flag ;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      struct listnode *node, *nnode;
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          if (member->sort != BGP_PEER_EBGP)
            continue ;

          member->change_local_as = as;
          member->flags = (member->flags & ~PEER_FLAG_LOCAL_AS_NO_PREPEND)
                                                             | no_prepend_flag ;
          bgp_peer_down(member, PEER_DOWN_LOCAL_AS_CHANGE) ;
        } ;
    }
  else
    bgp_peer_down(peer, PEER_DOWN_LOCAL_AS_CHANGE) ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Unset neighbor nnn local-as <ASN> [no-prepend]
 *
 * The neighbor may be a peer or a peer-group.
 *
 * For a real peer, can set this iff it is an eBGP peer -- which *excludes*
 * Confederation neighbors.  So, we unset the value, but only push the peer
 * down if is eBGP (!).
 *
 * For a peer-group, we remember the state, and apply it to all group members
 * which are eBGP peers -- which *excludes* Confederation neighbors.
 */
extern bgp_ret_t
peer_local_as_unset (bgp_peer peer)
{
  if (peer->group_membership != qafx_set_empty)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  peer->flags &= ~PEER_FLAG_LOCAL_AS_NO_PREPEND ;

  if (peer->change_local_as == BGP_ASN_NULL)
    return BGP_SUCCESS ;                /* no change    */

  peer->change_local_as = BGP_ASN_NULL ;

  /* For peer-group, need to update all members.
   *
   * All members should be either iBGP or not iBGP (Confed or eBGP).  We run
   * along the member list and ensure that the change_local_as is cleared
   * (which should only affect eBGP).
   */
  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          member->flags &= ~PEER_FLAG_LOCAL_AS_NO_PREPEND ;

          if (member->change_local_as == BGP_ASN_NULL)
            continue ;

          member->change_local_as = BGP_ASN_NULL ;

          if (member->sort == BGP_PEER_EBGP)
            bgp_peer_down(member, PEER_DOWN_LOCAL_AS_CHANGE) ;
        } ;
    }
  else
    {
      if (peer->sort == BGP_PEER_EBGP)
        bgp_peer_down(peer, PEER_DOWN_LOCAL_AS_CHANGE) ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Set password for authenticating with the peer.
 */
extern bgp_ret_t
peer_password_set (bgp_peer peer, const char* password)
{
  size_t len ;

  len = (password != NULL) ? strlen(password) : 0 ;

  if ((len < BGP_PASSWORD_MIN_LEN) || (len > BGP_PASSWORD_MAX_LEN))
    return BGP_ERR_INVALID_VALUE;

  if (peer->password != NULL)
    {
      if ( (strcmp (peer->password, password) == 0) &&
                                          (peer->type != PEER_TYPE_GROUP_CONF) )
        return BGP_SUCCESS ;

      XFREE (MTYPE_PEER_PASSWORD, peer->password);
    } ;

  peer->password = XSTRDUP (MTYPE_PEER_PASSWORD, password);

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *nn, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, nn, nnode, member))
        {
          if (member->password != NULL)
            {
              if (strcmp (member->password, password) == 0)
                continue;

              XFREE (MTYPE_PEER_PASSWORD, member->password);
            } ;

          member->password = XSTRDUP(MTYPE_PEER_PASSWORD, password);

          bgp_peer_down(member, PEER_DOWN_PASSWORD_CHANGE) ;
        }
    }
  else
    bgp_peer_down(peer, PEER_DOWN_PASSWORD_CHANGE) ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_password_unset (bgp_peer peer)
{
  if (peer->type != PEER_TYPE_GROUP_CONF)
    {
      /* Need do nothing for real peer if no password is currently set.
       */
      if (peer->password == NULL)
        return BGP_SUCCESS ;

      /* Can do nothing if password is set by the group
       *
       * NB: is set by the group if the member's password is the same as the
       *     group password.
       *
       * NB: if the member's password is not the same as the group password,
       *     it is *cleared* -- ie it is *not* set to the group value !
       */
      if (peer->group_membership != qafx_set_empty)
        {
          const char* group_password ;

          group_password = peer->group->conf->password ;
          if ((group_password != NULL)
                              && (strcmp (group_password, peer->password) == 0))
            return BGP_ERR_PEER_GROUP_HAS_THE_FLAG;
        } ;
    } ;

  if (peer->password != NULL)
    XFREE (MTYPE_PEER_PASSWORD, peer->password);
                                        /* sets peer->password NULL     */

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      struct listnode *nn, *nnode;
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, nn, nnode, member))
        {
          if (member->password == NULL)
            continue;

          XFREE (MTYPE_PEER_PASSWORD, member->password);
                                        /* sets member->password NULL */
          bgp_peer_down(member, PEER_DOWN_PASSWORD_CHANGE) ;
        } ;
    }
  else
    bgp_peer_down(peer, PEER_DOWN_PASSWORD_CHANGE) ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set distribute list to the peer.
 */
extern bgp_ret_t
peer_distribute_set (bgp_peer peer, qafx_t qafx, int direct, const char* name)
{
  peer_rib     prib ;
  access_list* p_dlist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  if (prib->plist[direct] != NULL)
    return BGP_ERR_PEER_FILTER_CONFLICT;

  p_dlist = &prib->dlist[direct] ;
  access_list_clear_ref(*p_dlist) ;
  *p_dlist = access_list_get_ref(get_qAFI(qafx), name) ;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      struct listnode *node, *nnode ;
      bgp_peer    member ;
      access_list group_dlist ;

      group_dlist = *p_dlist ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_dlist = &prib->dlist[direct] ;
          access_list_clear_ref(*p_dlist) ;
          *p_dlist = access_list_set_ref(group_dlist) ;
        }
    } ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_distribute_unset (bgp_peer peer, qafx_t qafx, int direct)
{
  peer_rib     prib ;
  access_list* p_dlist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Clear any existing filter
   */
  p_dlist = &prib->dlist[direct] ;
  *p_dlist = access_list_clear_ref(*p_dlist) ;

  /* If is a group, process all relevant members.
   *
   * If is a group member, apply the peer-group filter
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      struct listnode *node, *nnode;
      bgp_peer member ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_dlist = &prib->dlist[direct] ;
          *p_dlist = access_list_clear_ref(*p_dlist) ;
        }
    }
  else if (prib->af_group_member)
    {
      *p_dlist =
           access_list_set_ref(peer->group->conf->prib[qafx]->dlist[direct]) ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * This is the call-back used when a distribute-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * distribute-list...  but that is for another day !
 */
extern void
peer_distribute_update (access_list alist)
{
}

/* Set prefix list to the peer.
 */
extern bgp_ret_t
peer_prefix_list_set (bgp_peer peer, qafx_t qafx, int direct, const char* name)
{
  peer_rib prib ;
  prefix_list* p_plist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  if (prib->dlist[direct] != NULL)
    return BGP_ERR_PEER_FILTER_CONFLICT;

  /* Clear any existing reference and set the new one.
   */
  p_plist = &prib->plist[direct] ;
  prefix_list_clear_ref(*p_plist) ;
  *p_plist = prefix_list_get_ref(get_qAFI(qafx), name) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      prefix_list group_plist ;
      bgp_peer member ;
      struct listnode *node, *nnode ;

      group_plist = *p_plist ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_plist = &prib->plist[direct] ;

          prefix_list_clear_ref(*p_plist) ;
          *p_plist = prefix_list_set_ref(group_plist) ;
        }
    } ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_prefix_list_unset (bgp_peer peer, qafx_t qafx, int direct)
{
  peer_rib prib ;
  prefix_list* p_plist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Unset the prefix-list reference (if any)
   *
   * Replace by the peer-group prefix-list, if any
   */
  p_plist = &prib->plist[direct] ;
  *p_plist = prefix_list_clear_ref(*p_plist) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   *
   * If this is a member of a peer-group, replace the setting by the group
   * setting.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_plist = &prib->plist[direct] ;
          *p_plist = prefix_list_clear_ref(*p_plist) ;
        }
    }
  else if (prib->af_group_member)
    {
      *p_plist =
             prefix_list_set_ref(peer->group->conf->prib[qafx]->plist[direct]) ;
    }

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * This is the all-back used when a prefix-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * prefix-list...  but that is for another day !
 */
extern void
peer_prefix_list_update (struct prefix_list *plist)
{
}

extern bgp_ret_t
peer_aslist_set (bgp_peer peer, qafx_t qafx, int direct, const char* name)
{
  peer_rib prib ;
  as_list* p_flist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Clear any existing reference and set the new one.
   */
  p_flist = &prib->flist[direct] ;
  as_list_clear_ref(*p_flist) ;
  *p_flist = as_list_get_ref(name) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      as_list group_aslist ;
      bgp_peer member ;
      struct listnode *node, *nnode;

      group_aslist = *p_flist ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_flist = &prib->flist[direct] ;
          as_list_clear_ref(*p_flist) ;
          *p_flist = as_list_set_ref(group_aslist) ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
peer_aslist_unset (bgp_peer peer, qafx_t qafx, int direct)
{
  peer_rib prib ;
  as_list* p_flist ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case FILTER_IN:
        break ;

      case FILTER_OUT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Unset the as-list reference (if any)
   *
   * Replace by the peer-group as-list, if any
   */
  p_flist = &prib->flist[direct] ;
  *p_flist = as_list_clear_ref(*p_flist) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   *
   * If this is a peer group member, change the setting to the group setting.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_flist = &prib->flist[direct] ;
          *p_flist = as_list_clear_ref(*p_flist) ;
        }
    }
  else if (prib->af_group_member)
    {
      *p_flist = as_list_set_ref(peer->group->conf->prib[qafx]->flist[direct]) ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * This is the all-back used when an as-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * as-list...  but that is for another day !
 */
extern void
peer_aslist_update (void)
{
}

/*------------------------------------------------------------------------------
 * Set route-map to the peer.
 */
extern bgp_ret_t
peer_route_map_set (bgp_peer peer, qafx_t qafx, int direct, const char* name)
{
  peer_rib prib ;
  route_map* p_rmap ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case RMAP_IN:
      case RMAP_RS_IN:
      case RMAP_EXPORT:
        break ;

      case RMAP_OUT:
      case RMAP_IMPORT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Clear any existing reference and set the new one.
   */
  p_rmap = &prib->rmap[direct] ;
  route_map_clear_ref(*p_rmap) ;
  *p_rmap = route_map_get_ref(name) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      route_map group_rmap ;
      bgp_peer member ;
      struct listnode *node, *nnode ;

      group_rmap = *p_rmap ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_rmap = &prib->rmap[direct] ;

          route_map_clear_ref(*p_rmap) ;
          *p_rmap = route_map_set_ref(group_rmap) ;
        }
    } ;

  return BGP_SUCCESS ;
}

/* Unset route-map from the peer.
 */
extern bgp_ret_t
peer_route_map_unset (bgp_peer peer, qafx_t qafx, int direct)
{
  peer_rib prib ;
  route_map* p_rmap ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  switch (direct)
    {
      case RMAP_IN:
      case RMAP_RS_IN:
      case RMAP_EXPORT:
        break ;

      case RMAP_OUT:
      case RMAP_IMPORT:
        if (prib->af_group_member)
          return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  /* Unset the route-map reference (if any)
   *
   * Replace by the peer-group route-map, if any
   */
  p_rmap = &prib->rmap[direct] ;
  *p_rmap = route_map_clear_ref(*p_rmap) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   *
   * If this is a peer group member, change the setting to the group setting.
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_rmap = &prib->rmap[direct] ;
          *p_rmap = route_map_clear_ref(*p_rmap) ;
        }
    }
  else if (prib->af_group_member)
    {
      *p_rmap = route_map_set_ref(peer->group->conf->prib[qafx]->rmap[direct]) ;
    } ;

  return BGP_SUCCESS ;
}

/* Set unsuppress-map to the peer.
 */
extern bgp_ret_t
peer_unsuppress_map_set (bgp_peer peer, qafx_t qafx, const char* name)
{
  peer_rib prib ;
  route_map* p_rmap ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  if (prib->af_group_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Clear any existing reference and set the new one.
   */
  p_rmap = &prib->us_rmap ;
  route_map_clear_ref(*p_rmap) ;
  *p_rmap = route_map_get_ref(name) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      route_map group_rmap ;
      bgp_peer member ;
      struct listnode *node, *nnode ;

      group_rmap = *p_rmap ;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_rmap = &prib->us_rmap ;

          route_map_clear_ref(*p_rmap) ;
          *p_rmap = route_map_set_ref(group_rmap) ;
        }
    } ;

  return BGP_SUCCESS ;
}

/* Unset route-map from the peer.
 */
extern bgp_ret_t
peer_unsuppress_map_unset (bgp_peer peer, qafx_t qafx)
{
  peer_rib prib ;
  route_map* p_rmap ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  if (prib->af_group_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Unset the route-map reference (if any)
   *
   * Replace by the peer-group route-map, if any
   */
  p_rmap = &prib->us_rmap ;
  *p_rmap = route_map_clear_ref(*p_rmap) ;

  /* If this is a peer-group, hit all the peers which are in the group for
   * the given afi/safi
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || ! prib->af_group_member)
            continue ;

          p_rmap = &prib->us_rmap ;
          *p_rmap = route_map_clear_ref(*p_rmap) ;
        }
    }
  else if (prib->af_group_member)
    {
      *p_rmap = route_map_set_ref(peer->group->conf->prib[qafx]->us_rmap) ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set maximum prefix parameters.
 *
 * Setting a peer overrides any setting inherited from a peer-group.
 *
 * Setting a peer-group sets all members.
 */
extern bgp_ret_t
peer_maximum_prefix_set (bgp_peer peer, qafx_t qafx, uint32_t max,
                                byte thresh_pc, bool warning, uint16_t restart)
{
  peer_rib    prib ;
  prefix_max  pmax ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE ;

  /* Set value for peer or peer-group.
   */
  pmax = &prib->pmax ;
  memset(pmax, 0, sizeof(prefix_max_t)) ;

  prib->pmax.set       = true ;
  prib->pmax.warning   = warning ;

  prib->pmax.limit     = max ;
  prib->pmax.threshold = ((urlong)max * thresh_pc) / 100 ; ;
  prib->pmax.thresh_pc = thresh_pc ;
  prib->pmax.restart   = restart ;

  /* Update peer-group members
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || !prib->af_group_member)
            continue;

          prib->pmax = *pmax ;
        } ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Unset maximum prefix parameters.
 *
 * Unsetting a peer which is a member of a peer-group, sets the peer-group's
 * values.
 *
 * Unsetting a peer-group unsets all members.
 */
extern bgp_ret_t
peer_maximum_prefix_unset (bgp_peer peer, qafx_t qafx)
{
  peer_rib    prib ;
  prefix_max  pmax ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  /* For peer-group member, set the current peer-group values
   */
  if (prib->af_group_member)
    {
      prib->pmax = peer->group->conf->prib[qafx]->pmax ;
      return BGP_SUCCESS ;
    } ;

  /* Unset value for peer or peer-group.
   */
  pmax = &prib->pmax ;
  memset(pmax, 0, sizeof(prefix_max_t)) ;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      bgp_peer  member ;
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (peer->group->members, node, nnode, member))
        {
          prib = peer_family_prib(member, qafx) ;
          if ((prib == NULL) || !prib->af_group_member)
            continue;

          prib->pmax = *pmax ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

