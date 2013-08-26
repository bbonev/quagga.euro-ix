/* zebra client
   Copyright (C) 1997, 98, 99 Kunihiro Ishiguro

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
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "network.h"
#include "prefix.h"
#include "log.h"
#include "sockunion.h"
#include "zclient.h"
#include "routemap.h"
#include "thread.h"
#include "pthread_safe.h"
#include "qafi_safi.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_debug.h"

/*------------------------------------------------------------------------------
 * All information about zebra.
 */
struct zclient *zclient = NULL;
struct in_addr router_id_zebra;

/*------------------------------------------------------------------------------
 * Router-id update message from zebra.
 *
 * Updates the default router-id, and the router-id of any bgp instances for
 * which no explicit router-id has been set.
 */
static int
bgp_router_id_update (int command, struct zclient *zclient, zebra_size_t length)
{
  struct prefix router_id;
  struct listnode *node, *nnode;
  struct bgp *bgp;

  zebra_router_id_update_read(zclient->ibuf,&router_id);

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: router id update %s", spfxtoa(&router_id).str);

  router_id_zebra = router_id.u.prefix4;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      if (!(bgp->config & BGP_CONFIG_ROUTER_ID))
        bgp_router_id_set (bgp, 0, false /* unset */);
    } ;

  return 0;
}

/* Inteface addition message from zebra. */
static int
bgp_interface_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  if (BGP_DEBUG(zebra, ZEBRA) && ifp)
    zlog_debug("Zebra rcvd: interface add %s", ifp->name);

  return 0;
}

static int
bgp_interface_delete (int command, struct zclient *zclient,
                      zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);
  ifp->ifindex = IFINDEX_INTERNAL;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface delete %s", ifp->name);

  return 0;
}

static int
bgp_interface_up (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct listnode *node, *nnode;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);

  if (! ifp)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s up", ifp->name);

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_add (c);

  return 0;
}

static int
bgp_interface_down (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct interface *ifp;
  struct connected *c;
  struct listnode *node, *nnode;

  s = zclient->ibuf;
  ifp = zebra_interface_state_read (s);
  if (! ifp)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s down", ifp->name);

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, c))
    bgp_connected_delete (c);

  /* Fast external-failover (Currently IPv4 only) */
  {
    struct listnode *mnode;
    struct bgp *bgp;
    struct peer *peer;
    struct interface *peer_if;

    for (ALL_LIST_ELEMENTS_RO (bm->bgp, mnode, bgp))
      {
        if (CHECK_FLAG (bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER))
          continue;

        for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
          {
            if (peer->cops.ttl != 1)
              continue;

            if (peer->su_name->sa.sa_family == AF_INET)
              peer_if = if_lookup_by_ipv4 (&peer->su_name->sin.sin_addr);
            else
              continue;

            if (ifp == peer_if)
              bgp_peer_down(peer, PEER_DOWN_INTERFACE_DOWN);
          }
      }
  }

  return 0;
}

static int
bgp_interface_address_add (int command, struct zclient *zclient,
                           zebra_size_t length)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf);

  if (ifc == NULL)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s address add %s",
                                     ifc->ifp->name, spfxtoa(ifc->address).str);

  if (if_is_operative (ifc->ifp))
    bgp_connected_add (ifc);

  return 0;
}

static int
bgp_interface_address_delete (int command, struct zclient *zclient,
                              zebra_size_t length)
{
  struct connected *ifc;

  ifc = zebra_interface_address_read (command, zclient->ibuf);

  if (ifc == NULL)
    return 0;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra rcvd: interface %s address delete %s",
                                     ifc->ifp->name, spfxtoa(ifc->address).str);

  if (if_is_operative (ifc->ifp))
    bgp_connected_delete (ifc);

  connected_free (ifc);

  return 0;
}

/* Zebra route add and delete treatment. */
static int
zebra_read_ipv4 (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv4 api;
  ip_union_t  nexthop;
  struct prefix p;

  s = zclient->ibuf;
  nexthop.ipv4 = 0;

  /* Type, flags, message. */
  api.type    = stream_getc (s);
  api.flags   = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv4 prefix. */
  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_INET;
  p.prefixlen = stream_getc (s);
  stream_get (&p.u.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      nexthop.ipv4 = stream_get_ipv4 (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      stream_getl (s); /* ifindex, unused */
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (command == ZEBRA_IPV4_ROUTE_ADD)
    {
      if (BGP_DEBUG(zebra, ZEBRA))
        {
          zlog_debug("Zebra rcvd: IPv4 route add %s %s nexthop %s metric %u",
                     zebra_route_string(api.type),
                     spfxtoa(&p).str, siptoa(AF_INET, &nexthop).str,
                     api.metric);
        }
      bgp_redistribute_add(&p, &nexthop, api.metric, api.type);
    }
  else
    {
      if (BGP_DEBUG(zebra, ZEBRA))
        {
          zlog_debug("Zebra rcvd: IPv4 route delete %s %s "
                     "nexthop %s metric %u",
                     zebra_route_string(api.type),
                     spfxtoa(&p).str, siptoa(AF_INET, &nexthop).str,
                     api.metric);
        }
      bgp_redistribute_delete(&p, api.type);
    }

  return 0;
}

#ifdef HAVE_IPV6
/* Zebra route add and delete treatment. */
static int
zebra_read_ipv6 (int command, struct zclient *zclient, zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv6 api;
  ip_union_t nexthop;
  struct prefix p;

  s = zclient->ibuf;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv6 prefix. */
  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.u.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get (&nexthop.ipv6, s, 16);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      stream_getl (s); /* ifindex, unused */
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  /* Simply ignore link-local address. */
  if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
    return 0;

  if (command == ZEBRA_IPV6_ROUTE_ADD)
    {
      if (BGP_DEBUG(zebra, ZEBRA))
        {
          zlog_debug("Zebra rcvd: IPv6 route add %s %s nexthop %s metric %u",
                     zebra_route_string(api.type),
                     spfxtoa(&p).str, siptoa(AF_INET6, &nexthop).str,
                     api.metric);
        }
      bgp_redistribute_add (&p, &nexthop, api.metric, api.type);
    }
  else
    {
      if (BGP_DEBUG(zebra, ZEBRA))
        {
          zlog_debug("Zebra rcvd: IPv6 route delete %s %s "
                     "nexthop %s metric %u",
                     zebra_route_string(api.type),
                     spfxtoa(&p).str, siptoa(AF_INET6, &nexthop).str,
                     api.metric);
        }
      bgp_redistribute_delete (&p, api.type);
    }

  return 0;
}
#endif /* HAVE_IPV6 */

struct interface *
if_lookup_by_ipv4 (struct in_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv4 p;
  struct prefix *cp;

  p.family = AF_INET;
  p.prefix = *addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
          cp = connected->address;

          if (cp->family == AF_INET)
            if (prefix_match (cp, (struct prefix *)&p))
              return ifp;
        }
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv4_exact (struct in_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
          cp = connected->address;

          if (cp->family == AF_INET)
            if (IPV4_ADDR_SAME (&cp->u.prefix4, addr))
              return ifp;
        }
    }
  return NULL;
}

#ifdef HAVE_IPV6
struct interface *
if_lookup_by_ipv6 (struct in6_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix_ipv6 p;
  struct prefix *cp;

  p.family = AF_INET6;
  p.prefix = *addr;
  p.prefixlen = IPV6_MAX_BITLEN;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
          cp = connected->address;

          if (cp->family == AF_INET6)
            if (prefix_match (cp, (struct prefix *)&p))
              return ifp;
        }
    }
  return NULL;
}

struct interface *
if_lookup_by_ipv6_exact (struct in6_addr *addr)
{
  struct listnode *ifnode;
  struct listnode *cnode;
  struct interface *ifp;
  struct connected *connected;
  struct prefix *cp;

  for (ALL_LIST_ELEMENTS_RO (iflist, ifnode, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
        {
          cp = connected->address;

          if (cp->family == AF_INET6)
            if (IPV6_ADDR_SAME (&cp->u.prefix6, addr))
              return ifp;
        }
    }
  return NULL;
}

static int
if_get_ipv6_global (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp;

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;

      if (cp->family == AF_INET6)
        if (! IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
          {
            memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
            return 1;
          }
    }
  return 0;
}

static int
if_get_ipv6_local (struct interface *ifp, struct in6_addr *addr)
{
  struct listnode *cnode;
  struct connected *connected;
  struct prefix *cp;

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, cnode, connected))
    {
      cp = connected->address;

      if (cp->family == AF_INET6)
        if (IN6_IS_ADDR_LINKLOCAL (&cp->u.prefix6))
          {
            memcpy (addr, &cp->u.prefix6, IPV6_MAX_BYTELEN);
            return 1;
          }
    }
  return 0;
}
#endif /* HAVE_IPV6 */

int
bgp_nexthop_set (sockunion local, sockunion remote,
                 bgp_nexthop nexthop, struct peer *peer)
{
  int ret = 0;
  struct interface *ifp = NULL;

  memset (nexthop, 0, sizeof (bgp_nexthop_t));

  if (!local)
    return -1;
  if (!remote)
    return -1;

  if (local->sa.sa_family == AF_INET)
    {
      nexthop->v4 = local->sin.sin_addr;
      ifp = if_lookup_by_ipv4 (&local->sin.sin_addr);
    }
#ifdef HAVE_IPV6
  if (local->sa.sa_family == AF_INET6)
    {
      if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
        {
          if (peer->cops.ifname)
            ifp = if_lookup_by_index (
                                    if_nametoindex (peer->cops.ifname));
        }
      else
        ifp = if_lookup_by_ipv6 (&local->sin6.sin6_addr);
    }
#endif /* HAVE_IPV6 */

  if (!ifp)
    return -1;

  nexthop->ifp = ifp;

  /* IPv4 connection. */
  if (local->sa.sa_family == AF_INET)
    {
#ifdef HAVE_IPV6
      /* IPv6 nexthop*/
      ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

      /* There is no global nexthop. */
      if (!ret)
        if_get_ipv6_local (ifp, &nexthop->v6_global);
      else
        if_get_ipv6_local (ifp, &nexthop->v6_local);
#endif /* HAVE_IPV6 */
    }

#ifdef HAVE_IPV6
  /* IPv6 connection. */
  if (local->sa.sa_family == AF_INET6)
    {
      struct interface *direct = NULL;

      /* IPv4 nexthop.  I don't care about it.
       */
      if (peer->args.local_id != 0)
        nexthop->v4.s_addr = peer->args.local_id;

      /* Global address*/
      if (! IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr))
        {
          memcpy (&nexthop->v6_global, &local->sin6.sin6_addr,
                  IPV6_MAX_BYTELEN);

          /* If directory connected set link-local address. */
          direct = if_lookup_by_ipv6 (&remote->sin6.sin6_addr);
          if (direct)
            if_get_ipv6_local (ifp, &nexthop->v6_local);
        }
      else
        /* Link-local address. */
        {
          ret = if_get_ipv6_global (ifp, &nexthop->v6_global);

          /* If there is no global address.  Set link-local address as
             global.  I know this break RFC specification... */
          if (!ret)
            memcpy (&nexthop->v6_global, &local->sin6.sin6_addr,
                    IPV6_MAX_BYTELEN);
          else
            memcpy (&nexthop->v6_local, &local->sin6.sin6_addr,
                    IPV6_MAX_BYTELEN);
        }
    }

  if (IN6_IS_ADDR_LINKLOCAL (&local->sin6.sin6_addr) ||
      if_lookup_by_ipv6 (&remote->sin6.sin6_addr))
    peer->shared_network = true;
  else
    peer->shared_network = false ;

  /* KAME stack specific treatment.  */
#ifdef KAME
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_global)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_global))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_global, 0);
    }
  if (IN6_IS_ADDR_LINKLOCAL (&nexthop->v6_local)
      && IN6_LINKLOCAL_IFINDEX (nexthop->v6_local))
    {
      SET_IN6_LINKLOCAL_IFINDEX (nexthop->v6_local, 0);
    }
#endif /* KAME */
#endif /* HAVE_IPV6 */
  return ret;
}

/*------------------------------------------------------------------------------
 * Set given route_zebra -- allocating one if required.
 *
 * Sets:
 *
 *   * safi       -- per ri->qafx
 *   * flags      -- per peer->sort, ->ttl & ->flags as required
 *
 *   * med        -- per ri->attr->med
 *
 *   * next_hop   -- zero
 *   * ifindex    -- zero;
 */
static route_zebra
bgp_zebra_route_set(route_zebra zr, bgp_peer peer, route_info ri)
{
  if (zr == NULL)
    zr = XCALLOC(0, sizeof(route_zebra_t)) ;
  else
    zr = memset(zr, 0, sizeof(route_zebra_t)) ;

  zr->safi = get_iSAFI(ri->qafx) ;

  switch (peer->sort)
    {
      case BGP_PEER_IBGP:
      case BGP_PEER_CBGP:
        zr->flags |= ZEBRA_FLAG_IBGP | ZEBRA_FLAG_INTERNAL ;
        break ;

      case BGP_PEER_EBGP:
        if ((peer->cops.ttl != 1) || (peer->disable_connected_check))
          zr->flags |= ZEBRA_FLAG_INTERNAL ;
        break ;

      default:
        qassert(false) ;
        break ;
    } ;

  zr->med  = ri->attr->med ;

  return zr ;
}

/*------------------------------------------------------------------------------
 * Announce the given route to Zebra.
 *
 * Automatically withdraws any existing route for the given prefix.
 */
extern route_zebra
bgp_zebra_announce (route_zebra zr, bgp_rib_node rn, prefix_c p)
{
  route_info    ri ;
  bgp_peer      peer ;
  attr_next_hop nh ;
  bool          ok ;

  if ((zclient->sock < 0) || !zclient->redist[ZEBRA_ROUTE_BGP])
    return bgp_zebra_discard(zr, p) ;

  ok = false ;

  ri = rn->selected ;
  nh = &ri->attr->next_hop ;

  peer  = ri->prib->peer;
  qassert(peer->type == PEER_TYPE_REAL) ;

  switch (p->family)
    {
      case AF_INET:
        {
          struct zapi_ipv4 api;
          struct in_addr*  nexthop[1] ;

          if ( (ri->qafx != qafx_ipv4_unicast) &&
               (ri->qafx != qafx_ipv4_multicast) )
            break ;

          if (nh->type != nh_ipv4)
            break ;             /* not an IPv5 next-hop         */

          ok = true ;
          zr = bgp_zebra_route_set(zr, peer, ri) ;

          zr->next_hop.ipv4 = nh->ip.v4 ;

          memset(&api, 0, sizeof(struct zapi_ipv4)) ;
          nexthop[0] = (struct in_addr*)&zr->next_hop.ipv4 ;

          api.flags        = zr->flags ;
          api.type         = ZEBRA_ROUTE_BGP;
          api.safi         = zr->safi ;

          api.message     |= ZAPI_MESSAGE_NEXTHOP ;
          api.nexthop_num  = 1;
          api.nexthop      = nexthop ;

          api.ifindex_num  = 0;

          api.message     |= ZAPI_MESSAGE_METRIC ;
          api.metric       = zr->med;

          api.distance     = bgp_distance_apply (peer, p) ;
          if (api.distance != 0)
            api.message   |= ZAPI_MESSAGE_DISTANCE ;

          if (BGP_DEBUG(zebra, ZEBRA))
            {
              zlog_debug("Zebra send: IPv4 route add %s/%d nexthop %s metric %u",
                         siptoa(AF_INET, &p->u.prefix4).str,
                         p->prefixlen,
                         siptoa(AF_INET, nexthop[0]).str,
                         api.metric);
            }

          zapi_ipv4_route (ZEBRA_IPV4_ROUTE_ADD, zclient,
                                       (const struct prefix_ipv4 *)p, &api);
        } ;
        break ;

#ifdef HAVE_IPV6
      case AF_INET6:
        {
          /* We have to think about a IPv6 link-local address curse.
           */
          struct in6_addr* nexthop[1] ;
          struct zapi_ipv6 api ;

          if ( (ri->qafx != qafx_ipv6_unicast) &&
               (ri->qafx != qafx_ipv6_multicast) )
            break ;

          if ( (nh->type != nh_ipv6_1) &&
               (nh->type != nh_ipv6_2) )
            break ;

          ok = true ;
          zr = bgp_zebra_route_set(zr, peer, ri) ;

          if (nh->type == nh_ipv6_1)
            {
              /* Only global address nexthop exists.
               */
              zr->next_hop.ipv6.addr = nh->ip.v6[in6_global].addr ;
            }
          else
            {
              /* Both global and link-local address present.
               *
               * Workaround for Cisco's nexthop bug.
               */
              if (IN6_IS_ADDR_UNSPECIFIED(&nh->ip.v6[in6_global])
                 && (peer->session->cops->su_remote.sa.sa_family == AF_INET6))
                zr->next_hop.ipv6.addr =
                                peer->session->cops->su_remote.sin6.sin6_addr ;
              else
                zr->next_hop.ipv6.addr = nh->ip.v6[in6_link_local].addr ;

              if (peer->nexthop.ifp)
                zr->ifindex = peer->nexthop.ifp->ifindex;
            } ;

          if ((zr->ifindex != 0) && IN6_IS_ADDR_LINKLOCAL (nexthop[0]))
            {
              if (peer->cops.ifname)
                zr->ifindex = if_nametoindex (peer->cops.ifname);
              else if (peer->nexthop.ifp)
                zr->ifindex = peer->nexthop.ifp->ifindex;
            } ;

          memset(&api, 0, sizeof(struct zapi_ipv6)) ;
          nexthop[0] = &zr->next_hop.ipv6.addr ;

          /* Make Zebra API structure.
           */
          api.flags       = zr->flags;
          api.type        = ZEBRA_ROUTE_BGP;
          api.safi        = zr->safi;

          api.message    |= ZAPI_MESSAGE_NEXTHOP ;
          api.nexthop_num = 1;
          api.nexthop     = nexthop ;

          api.message    |= ZAPI_MESSAGE_IFINDEX ;
          api.ifindex_num = 1;
          api.ifindex     = &zr->ifindex ;

          api.message    |= ZAPI_MESSAGE_METRIC ;
          api.metric      = zr->med ;

          if (BGP_DEBUG(zebra, ZEBRA))
            {
              zlog_debug("Zebra send: IPv6 route add %s/%d nexthop %s metric %u",
                         siptoa(AF_INET6, &p->u.prefix6).str,
                         p->prefixlen,
                         siptoa(AF_INET6, nexthop[0]).str,
                         api.metric);
            }

          zapi_ipv6_route (ZEBRA_IPV6_ROUTE_ADD, zclient,
                           (const struct prefix_ipv6 *) p, &api);
        } ;
        break ;
#endif /* HAVE_IPV6 */

      default:
        break ;
    } ;

  /* If we failed to set the new zebra_route, withdraw the old one, if it is
   * set !
   */
  if (!ok)
    bgp_zebra_withdraw(zr, p) ;

  return zr ;
} ;

/*------------------------------------------------------------------------------
 * Tell Zebra that no longer have a route for the given prefix.
 */
extern route_zebra
bgp_zebra_discard (route_zebra zr, prefix_c p)
{
  if (zr != NULL)
    {
      bgp_zebra_withdraw(zr, p) ;

      XFREE(0, zr) ;
    } ;

  return NULL ;
}

/*------------------------------------------------------------------------------
 * Tell Zebra that no longer have a route for the given prefix.
 */
extern void
bgp_zebra_withdraw (route_zebra zr, prefix_c p)
{
  if ((zr == NULL) || (zr->safi == iSAFI_Reserved))
    return ;

  if (zclient->sock >= 0)
    switch (p->family)
      {
        case AF_INET:
          {
            struct zapi_ipv4 api;
            struct in_addr* nexthop[1] ;

            memset(&api, 0, sizeof(struct zapi_ipv4)) ;
            nexthop[0] = (struct in_addr*)&zr->next_hop.ipv4 ;

            api.flags       = zr->flags ;
            api.type        = ZEBRA_ROUTE_BGP;
            api.safi        = zr->safi;

            api.message    |= ZAPI_MESSAGE_NEXTHOP ;
            api.nexthop_num = 1;
            api.nexthop     = nexthop;
            api.ifindex_num = 0;

            api.message    |= ZAPI_MESSAGE_METRIC ;
            api.metric      = zr->med ;

            if (BGP_DEBUG(zebra, ZEBRA))
              {
                zlog_debug("Zebra send: IPv4 route delete %s/%d "
                                                        "nexthop %s metric %u",
                       siptoa(AF_INET, &p->u.prefix4).str,
                       p->prefixlen,
                       siptoa(AF_INET, nexthop[1]).str,
                       api.metric);
              }

            zapi_ipv4_route (ZEBRA_IPV4_ROUTE_DELETE, zclient,
                                         (const struct prefix_ipv4 *) p, &api) ;
          } ;
          break ;

  #ifdef HAVE_IPV6
        case AF_INET6:
          {
            struct zapi_ipv6 api ;
            struct in6_addr* nexthop[1] ;

            memset(&api, 0, sizeof(struct zapi_ipv6)) ;
            nexthop[0] = &zr->next_hop.ipv6.addr ;

            api.flags       = zr->flags;
            api.type        = ZEBRA_ROUTE_BGP;
            api.safi        = zr->safi;

            api.message    |= ZAPI_MESSAGE_NEXTHOP ;
            api.nexthop_num = 1;
            api.nexthop     = nexthop ;

            api.message    |= ZAPI_MESSAGE_IFINDEX ;
            api.ifindex_num = 1;

            api.ifindex     = &zr->ifindex ;

            api.message    |= ZAPI_MESSAGE_METRIC ;
            api.metric      = zr->med;

            if (BGP_DEBUG(zebra, ZEBRA))
              {
                zlog_debug("Zebra send: IPv6 route delete %s/%d "
                                                        "nexthop %s metric %u",
                           siptoa(AF_INET6, &p->u.prefix6).str,
                           p->prefixlen,
                           siptoa(AF_INET6, nexthop[0]).str,
                           api.metric);
              }

            zapi_ipv6_route (ZEBRA_IPV6_ROUTE_DELETE, zclient,
                                        (const struct prefix_ipv6 *) p, &api);
          } ;
          break ;
#endif /* HAVE_IPV6 */

        default:
          break ;
      } ;

  zr->safi = iSAFI_Reserved ;
} ;

/* Other routes redistribution into BGP. */
int
bgp_redistribute_set (struct bgp *bgp, afi_t afi, int type)
{
  /* Set flag to BGP instance. */
  bgp->redist[afi][type] = true ;

  /* Return if already redistribute flag is set. */
  if (zclient->redist[type])
    return CMD_WARNING;

  zclient->redist[type] = true ;

  /* Return if zebra connection is not established. */
  if (zclient->sock < 0)
    return CMD_WARNING;

  if (BGP_DEBUG(zebra, ZEBRA))
    zlog_debug("Zebra send: redistribute add %s", zebra_route_string(type));

  /* Send distribute add message to zebra. */
  zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient, type);

  return CMD_SUCCESS;
}

/* Redistribute with route-map specification.  */
int
bgp_redistribute_rmap_set (struct bgp *bgp, afi_t afi, int type,
                           const char *name)
{
  if (bgp->rmap[afi][type].name
      && (strcmp (bgp->rmap[afi][type].name, name) == 0))
    return 0;

  if (bgp->rmap[afi][type].name)
    free (bgp->rmap[afi][type].name);
  bgp->rmap[afi][type].name = strdup (name);
  bgp->rmap[afi][type].map = route_map_lookup (name);

  return 1;
}

/* Redistribute with metric specification.  */
int
bgp_redistribute_metric_set (struct bgp *bgp, afi_t afi, int type,
                             u_int32_t metric)
{
  if (bgp->redist_metric_set[afi][type]
      && bgp->redist_metric[afi][type] == metric)
    return 0;

  bgp->redist_metric_set[afi][type] = true ;
  bgp->redist_metric[afi][type] = metric;

  return 1;
}

/*------------------------------------------------------------------------------
 * Unset redistribution.
 */
extern cmd_ret_t
bgp_redistribute_unset (struct bgp *bgp, qAFI_t q_afi, int type)
{
  /* Unset flag from BGP instance. */
  bgp->redist[q_afi][type] = false ;

  /* Unset route-map. */
  if (bgp->rmap[q_afi][type].name)
    free (bgp->rmap[q_afi][type].name);
  bgp->rmap[q_afi][type].name = NULL;
  bgp->rmap[q_afi][type].map = NULL;

  /* Unset metric. */
  bgp->redist_metric_set[q_afi][type] = false;
  bgp->redist_metric[q_afi][type] = 0;

  /* Return if zebra connection is disabled. */
  if (! zclient->redist[type])
    return CMD_WARNING;
  zclient->redist[type] = 0 ;

  if (!bgp->redist[qAFI_IP][type] && !bgp->redist[qAFI_IP6][type]
                                                        && (zclient->sock >= 0))
    {
      /* Send distribute delete message to zebra. */
      if (BGP_DEBUG(zebra, ZEBRA))
        zlog_debug("Zebra send: redistribute delete %s",
                   zebra_route_string(type));
      zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, type);
    }

  /* Withdraw redistributed routes from current BGP's routing table. */
  bgp_redistribute_withdraw_all (bgp, q_afi, type);

  return CMD_SUCCESS;
}

/* Unset redistribution route-map configuration.  */
int
bgp_redistribute_routemap_unset (struct bgp *bgp, afi_t afi, int type)
{
  if (! bgp->rmap[afi][type].name)
    return 0;

  /* Unset route-map. */
  free (bgp->rmap[afi][type].name);
  bgp->rmap[afi][type].name = NULL;
  bgp->rmap[afi][type].map = NULL;

  return 1;
}

/* Unset redistribution metric configuration.  */
int
bgp_redistribute_metric_unset (struct bgp *bgp, afi_t afi, int type)
{
  if (! bgp->redist_metric_set[afi][type])
    return 0;

  /* Unset metric. */
  bgp->redist_metric_set[afi][type] = false ;
  bgp->redist_metric[afi][type] = 0;

  return 1;
}

void
bgp_zclient_reset (void)
{
  zclient_reset (zclient);
}

void
bgp_zebra_init (void)
{
  /* Set default values. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_BGP);
  zclient->router_id_update = bgp_router_id_update;
  zclient->interface_add = bgp_interface_add;
  zclient->interface_delete = bgp_interface_delete;
  zclient->interface_address_add = bgp_interface_address_add;
  zclient->interface_address_delete = bgp_interface_address_delete;
  zclient->ipv4_route_add = zebra_read_ipv4;
  zclient->ipv4_route_delete = zebra_read_ipv4;
  zclient->interface_up = bgp_interface_up;
  zclient->interface_down = bgp_interface_down;
#ifdef HAVE_IPV6
  zclient->ipv6_route_add = zebra_read_ipv6;
  zclient->ipv6_route_delete = zebra_read_ipv6;
#endif /* HAVE_IPV6 */

  /* Interface related init. */
  if_init ();
}
