/* BGP nexthop scan
   Copyright (C) 2000 Kunihiro Ishiguro

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

#include "command.h"
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_damp.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"        /* For ZEBRA_SERV_PATH. */

struct bgp_nexthop_cache *zlookup_query (struct in_addr);
#ifdef HAVE_IPV6
struct bgp_nexthop_cache *zlookup_query_ipv6 (struct in6_addr *);
#endif /* HAVE_IPV6 */

/* Only one BGP scan thread are activated at the same time. */
static struct thread *bgp_scan_thread = NULL;

/* BGP import thread */
static struct thread *bgp_import_thread = NULL;

/* BGP scan interval. */
static int bgp_scan_interval;

/* BGP import interval. */
static int bgp_import_interval;

/* Route table for next-hop lookup cache. */
static struct bgp_table *bgp_nexthop_cache_table[qAFI_count];
static struct bgp_table *cache1_table[qAFI_count];
static struct bgp_table *cache2_table[qAFI_count];

/* Route table for connected route. */
static struct bgp_table *bgp_connected_table[qAFI_count];

/* BGP nexthop lookup query client. */
struct zclient *zlookup = NULL;

/* Add nexthop to the end of the list.  */
static void
bnc_nexthop_add (struct bgp_nexthop_cache *bnc, struct nexthop *nexthop)
{
  struct nexthop *last;

  for (last = bnc->nexthop; last && last->next; last = last->next)
    ;
  if (last)
    last->next = nexthop;
  else
    bnc->nexthop = nexthop;
  nexthop->prev = last;
}

static void
bnc_nexthop_free (struct bgp_nexthop_cache *bnc)
{
  struct nexthop *nexthop;
  struct nexthop *next = NULL;

  for (nexthop = bnc->nexthop; nexthop; nexthop = next)
    {
      next = nexthop->next;
      XFREE (MTYPE_NEXTHOP, nexthop);
    }
}

static struct bgp_nexthop_cache *
bnc_new (void)
{
  return XCALLOC (MTYPE_BGP_NEXTHOP_CACHE, sizeof (struct bgp_nexthop_cache));
}

static void
bnc_free (struct bgp_nexthop_cache *bnc)
{
  bnc_nexthop_free (bnc);
  XFREE (MTYPE_BGP_NEXTHOP_CACHE, bnc);
}

static int
bgp_nexthop_same (struct nexthop *next1, struct nexthop *next2)
{
  if (next1->type != next2->type)
    return 0;

  switch (next1->type)
    {
    case ZEBRA_NEXTHOP_IPV4:
      if (! IPV4_ADDR_SAME (&next1->gate.ipv4, &next2->gate.ipv4))
        return 0;
      break;
    case ZEBRA_NEXTHOP_IFINDEX:
    case ZEBRA_NEXTHOP_IFNAME:
      if (next1->ifindex != next2->ifindex)
        return 0;
      break;
#ifdef HAVE_IPV6
    case ZEBRA_NEXTHOP_IPV6:
      if (! IPV6_ADDR_SAME (&next1->gate.ipv6, &next2->gate.ipv6))
        return 0;
      break;
    case ZEBRA_NEXTHOP_IPV6_IFINDEX:
    case ZEBRA_NEXTHOP_IPV6_IFNAME:
      if (! IPV6_ADDR_SAME (&next1->gate.ipv6, &next2->gate.ipv6))
        return 0;
      if (next1->ifindex != next2->ifindex)
        return 0;
      break;
#endif /* HAVE_IPV6 */
    default:
      /* do nothing */
      break;
    }
  return 1;
}

static int
bgp_nexthop_cache_different (struct bgp_nexthop_cache *bnc1,
                           struct bgp_nexthop_cache *bnc2)
{
  int i;
  struct nexthop *next1, *next2;

  if (bnc1->nexthop_num != bnc2->nexthop_num)
    return 1;

  next1 = bnc1->nexthop;
  next2 = bnc2->nexthop;

  for (i = 0; i < bnc1->nexthop_num; i++)
    {
      if (! bgp_nexthop_same (next1, next2))
        return 1;

      next1 = next1->next;
      next2 = next2->next;
    }
  return 0;
}

/*------------------------------------------------------------------------------
 * If nexthop exists on connected network return true.
 */
extern bool
bgp_nexthop_onlink (qAFI_t q_afi, attr_next_hop next_hop)
{
  struct bgp_node *rn;

  /* If zebra is not enabled return */
  if (zlookup->sock < 0)
    return true ;

  /* Lookup the address is onlink or not. */
  if (q_afi == qAFI_IP)
    {
      rn = bgp_node_match_ipv4 (bgp_connected_table[qAFI_IP],
                                                    &next_hop->ip.in_addr);
      if (rn)
        {
          bgp_unlock_node (rn);
          return true ;
        }
    }
#ifdef HAVE_IPV6
  else if (q_afi == qAFI_IP6)
    {
      if (next_hop->type == nh_ipv6_2)
        return true ;
      else if (next_hop->type == nh_ipv6_1)
        {
          if (IN6_IS_ADDR_LINKLOCAL (&next_hop->ip.v6[in6_global]))
            return true ;

          rn = bgp_node_match_ipv6 (bgp_connected_table[qAFI_IP6],
                                        &next_hop->ip.v6[in6_global].addr);
          if (rn)
            {
              bgp_unlock_node (rn);
              return true ;
            }
        }
    }
#endif /* HAVE_IPV6 */
  return 0;
}

#ifdef HAVE_IPV6
/*------------------------------------------------------------------------------
 * Check specified next-hop is reachable or not.
 *
 * Returns:  true <=> is reachable (or no zebra connection)
 */
static int
bgp_nexthop_lookup_ipv6 (bgp_peer peer, route_info ri, bool* changed,
                                                           bool* metricchanged)
{
  struct bgp_node *rn;
  struct prefix p;
  struct bgp_nexthop_cache *bnc;
  attr_set attr ;

  ri->igp_metric = 0 ;
  *changed = *metricchanged = false ;

  /* If lookup is not enabled, return valid. */
  if (zlookup->sock < 0)
    return true ;

  /* Only check IPv6 global address only nexthop.
   */
  attr = ri->attr;

  if ((attr->next_hop.type != nh_ipv6_1)
                   || IN6_IS_ADDR_LINKLOCAL (&attr->next_hop.ip.v6[in6_global]))
    return true ;

  memset (&p, 0, sizeof (struct prefix));
  p.family    = AF_INET6;
  p.prefixlen = IPV6_MAX_BITLEN;
  p.u.prefix6 = attr->next_hop.ip.v6[in6_global].addr;

  /* IBGP or ebgp-multihop
   */
  rn = bgp_node_get(bgp_nexthop_cache_table[qAFI_IP6], &p);

  if (rn->info != NULL)
    {
      bnc = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      bnc = zlookup_query_ipv6 (&attr->next_hop.ip.v6[in6_global].addr) ;

      if (bnc == NULL)
        bnc = bnc_new ();
      else
        {
          if (changed)
            {
              struct bgp_table *old;
              struct bgp_node *oldrn;

              if (bgp_nexthop_cache_table[qAFI_IP6] == cache1_table[qAFI_IP6])
                old = cache2_table[qAFI_IP6];
              else
                old = cache1_table[qAFI_IP6];

              oldrn = bgp_node_lookup (old, &p);
              if (oldrn)
                {
                  struct bgp_nexthop_cache *oldbnc = oldrn->info;

                  bnc->changed = bgp_nexthop_cache_different (bnc, oldbnc);

                  if (bnc->metric != oldbnc->metric)
                    bnc->metricchanged = 1;

                  bgp_unlock_node (oldrn);
                }
            }
        }
      rn->info = bnc;
    }

  if (changed)
    *changed = bnc->changed;

  if (metricchanged)
    *metricchanged = bnc->metricchanged;

  if (bnc->valid && bnc->metric)
    ri->igp_metric = bnc->metric;

  return bnc->valid;
}
#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * Check specified next-hop is reachable or not.
 *
 * Returns:  true <=> is reachable (or no zebra connection)
 */
extern bool
bgp_nexthop_lookup (qAFI_t q_afi, bgp_peer peer, route_info ri,
                                             bool* changed, bool* metricchanged)
{
  struct bgp_node *rn;
  struct prefix p;
  struct bgp_nexthop_cache *bnc;
  struct in_addr addr;

#ifdef HAVE_IPV6
  if (q_afi == qAFI_IP6)
    return bgp_nexthop_lookup_ipv6 (peer, ri, changed, metricchanged);
#endif /* HAVE_IPV6 */

  /* If lookup is not enabled, return valid.
   */
  *changed = *metricchanged = false ;
  ri->igp_metric = 0;

  if (zlookup->sock < 0)
    return true ;

  addr = ri->attr->next_hop.ip.in_addr ;

  memset (&p, 0, sizeof (struct prefix));
  p.family = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;
  p.u.prefix4 = addr;

  /* IBGP or ebgp-multihop
   */
  rn = bgp_node_get (bgp_nexthop_cache_table[qAFI_IP], &p);

  if (rn->info)
    {
      bnc = rn->info;
      bgp_unlock_node (rn);
    }
  else
    {
      if (NULL == (bnc = zlookup_query (addr)))
        bnc = bnc_new ();
      else
        {
          if (changed)
            {
              struct bgp_table *old;
              struct bgp_node *oldrn;

              if (bgp_nexthop_cache_table[qAFI_IP] == cache1_table[qAFI_IP])
                old = cache2_table[qAFI_IP];
              else
                old = cache1_table[qAFI_IP];

              oldrn = bgp_node_lookup (old, &p);
              if (oldrn)
                {
                  struct bgp_nexthop_cache *oldbnc = oldrn->info;

                  bnc->changed = bgp_nexthop_cache_different (bnc, oldbnc);

                  if (bnc->metric != oldbnc->metric)
                    bnc->metricchanged = 1;

                  bgp_unlock_node (oldrn);
                }
            }
        }
      rn->info = bnc;
    }

  if (changed)
    *changed = bnc->changed;

  if (metricchanged)
    *metricchanged = bnc->metricchanged;

  if (bnc->valid && bnc->metric)
    ri->igp_metric = bnc->metric;

  return bnc->valid;
}

/* Reset and free all BGP nexthop cache. */
static void
bgp_nexthop_cache_reset (struct bgp_table *table)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;

  for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
    if ((bnc = rn->info) != NULL)
      {
        bnc_free (bnc);
        rn->info = NULL;
        bgp_unlock_node (rn);
      }
}

static void
bgp_scan (qAFI_t q_afi)
{
  bgp_inst     bgp;
  bgp_rib      rib ;
  bgp_peer     peer;
  bgp_rib_node rn;
  qafx_t       qafx ;
  ihash_walker_t walk[1] ;
  struct listnode *node, *nnode;

  /* Change cache.
   */
  if (bgp_nexthop_cache_table[q_afi] == cache1_table[q_afi])
    bgp_nexthop_cache_table[q_afi] = cache2_table[q_afi];
  else
    bgp_nexthop_cache_table[q_afi] = cache1_table[q_afi];

  /* Get default bgp.
   */
  bgp = bgp_get_default ();
  if (bgp == NULL)
    return;

  /* Maximum prefix check
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      qSAFI_t q_safi ;

      if (peer->state != bgp_pEstablished)
        continue;

      for (q_safi = qSAFI_first ; q_safi <= qSAFI_last ; q_safi++)
        {
          peer_rib prib ;

          qafx = qafx_from_q(q_afi, q_safi) ;

          if ((qafx < qafx_first) || (qafx >  qafx_last))
            continue ;

          prib = peer_family_prib(peer, qafx) ;

          if ((prib != NULL) && (prib->af_session_up))
            bgp_maximum_prefix_overflow (prib, true /* always */) ;
        } ;
    } ;

  qafx = qafx_from_q(q_afi, qSAFI_Unicast) ;
  rib = bgp->rib[qafx][rib_main] ;

  ihash_walk_start((rib != NULL) ? rib->nodes_table : NULL, walk) ;

  while ((rn = ihash_walk_next(walk, NULL)) != NULL)
    {
      route_info next ;

      next = ddl_head(rn->routes) ;

      while (next != NULL)
        {
          route_info ri ;

          ri = next ;
          next = ddl_next(ri, route_list) ;

          if (ri->route_type ==
                              bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL))
            {
              bgp_peer peer ;
              bool valid, current, changed, metricchanged ;

              changed       = false;
              metricchanged = false ;

              peer = ri->prib->peer ;

              if ((peer->sort == BGP_PEER_EBGP) && (peer->cops.ttl == 1))
                valid = bgp_nexthop_onlink (q_afi, &ri->attr->next_hop);
              else
                valid = bgp_nexthop_lookup (q_afi, peer, ri,
                                                      &changed, &metricchanged);

              current = (ri->flags & BGP_INFO_VALID) != 0 ;

              if (changed)
                SET_FLAG (ri->flags, BGP_INFO_IGP_CHANGED);
              else
                UNSET_FLAG (ri->flags, BGP_INFO_IGP_CHANGED);

#if 0
              if (valid != current)
                {
                  if (CHECK_FLAG (ri->flags, BGP_INFO_VALID))
                    {
                      bgp_aggregate_decrement (bgp, &rn->p, ri, qafx) ;
                      bgp_info_unset_flag (rn, ri, BGP_INFO_VALID);
                    }
                  else
                    {
                      bgp_info_set_flag (rn, ri, BGP_INFO_VALID);
                      bgp_aggregate_increment (bgp, &rn->p, ri, qafx);
                    }
                }

              if (CHECK_FLAG (bgp->af_flags[qafx], BGP_CONFIG_DAMPING)
                  && ri->extra && ri->extra->damp_info )
                {
                  if (bgp_damp_scan (ri, qafx))
                    bgp_aggregate_increment (bgp, &rn->p, ri, qafx) ;
                } ;
#endif
            }
        } ;

      bgp_process_dispatch (bgp, rn);
    }

  /* Flash old cache.
   */
  if (bgp_nexthop_cache_table[q_afi] == cache1_table[q_afi])
    bgp_nexthop_cache_reset (cache2_table[q_afi]);
  else
    bgp_nexthop_cache_reset (cache1_table[q_afi]);

  if (BGP_DEBUG (events, EVENTS))
    {
      if (q_afi == qAFI_IP)
        zlog_debug ("scanning IPv4 Unicast routing tables");
      else if (q_afi == qAFI_IP6)
        zlog_debug ("scanning IPv6 Unicast routing tables");
    }
} ;

/* BGP scan thread.  This thread check nexthop reachability. */
static int
bgp_scan_timer (struct thread *t)
{
  bgp_scan_thread =
    thread_add_timer (master, bgp_scan_timer, NULL, bgp_scan_interval);

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("Performing BGP general scanning");

  bgp_scan (qAFI_IP);

#ifdef HAVE_IPV6
  bgp_scan (qAFI_IP6);
#endif /* HAVE_IPV6 */

  return 0;
}

struct bgp_connected_ref
{
  unsigned int refcnt;
};

void
bgp_connected_add (struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct interface *ifp;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;

  ifp = ifc->ifp;

  if (! ifp)
    return;

  if (if_is_loopback (ifp))
    return;

  addr = ifc->address;

  if (addr->family == AF_INET)
    {
      prefix_copy_ipv4(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
        return;

      rn = bgp_node_get (bgp_connected_table[qAFI_IP], (struct prefix *) &p);
      if (rn->info)
        {
          bc = rn->info;
          bc->refcnt++;
        }
      else
        {
          bc = XCALLOC (MTYPE_BGP_CONN, sizeof (struct bgp_connected_ref));
          bc->refcnt = 1;
          rn->info = bc;
        }
    }
#ifdef HAVE_IPV6
  else if (addr->family == AF_INET6)
    {
      prefix_copy_ipv6(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
        return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return;

      rn = bgp_node_get (bgp_connected_table[qAFI_IP6], (struct prefix *) &p);
      if (rn->info)
        {
          bc = rn->info;
          bc->refcnt++;
        }
      else
        {
          bc = XCALLOC (MTYPE_BGP_CONN, sizeof (struct bgp_connected_ref));
          bc->refcnt = 1;
          rn->info = bc;
        }
    }
#endif /* HAVE_IPV6 */
}

void
bgp_connected_delete (struct connected *ifc)
{
  struct prefix p;
  struct prefix *addr;
  struct interface *ifp;
  struct bgp_node *rn;
  struct bgp_connected_ref *bc;

  ifp = ifc->ifp;

  if (if_is_loopback (ifp))
    return;

  addr = ifc->address;

  if (addr->family == AF_INET)
    {
      prefix_copy_ipv4(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv4 ((struct prefix_ipv4 *) &p);

      if (prefix_ipv4_any ((struct prefix_ipv4 *) &p))
        return;

      rn = bgp_node_lookup (bgp_connected_table[qAFI_IP], &p);
      if (! rn)
        return;

      bc = rn->info;
      bc->refcnt--;
      if (bc->refcnt == 0)
        {
          XFREE (MTYPE_BGP_CONN, bc);
          rn->info = NULL;
        }
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
#ifdef HAVE_IPV6
  else if (addr->family == AF_INET6)
    {
      prefix_copy_ipv6(&p, CONNECTED_PREFIX(ifc));
      apply_mask_ipv6 ((struct prefix_ipv6 *) &p);

      if (IN6_IS_ADDR_UNSPECIFIED (&p.u.prefix6))
        return;

      if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
        return;

      rn = bgp_node_lookup (bgp_connected_table[qAFI_IP6], (struct prefix *) &p);
      if (! rn)
        return;

      bc = rn->info;
      bc->refcnt--;
      if (bc->refcnt == 0)
        {
          XFREE (MTYPE_BGP_CONN, bc);
          rn->info = NULL;
        }
      bgp_unlock_node (rn);
      bgp_unlock_node (rn);
    }
#endif /* HAVE_IPV6 */
}

/*------------------------------------------------------------------------------
 * Is the given IPv4 address one of ours ?
 */
extern bool
bgp_nexthop_self (in_addr_t ip)
{
  struct listnode *node;
  struct listnode *node2;
  struct interface *ifp;
  struct connected *ifc;
  struct prefix *p;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
    {
      for (ALL_LIST_ELEMENTS_RO (ifp->connected, node2, ifc))
        {
          p = ifc->address;

          if ((p != NULL) && (p->family == AF_INET)
                          && (p->u.prefix4.s_addr == ip))
            return true ;
        }
    } ;

  return false ;
}

static struct bgp_nexthop_cache *
zlookup_read (void)
{
  struct stream *s;
  uint16_t length;
  uint32_t metric ;
  u_char marker;
  u_char version;
  int i;
  u_char nexthop_num;
  struct nexthop *nexthop;
  struct bgp_nexthop_cache *bnc;

  s = zlookup->ibuf;
  stream_reset (s);

  stream_read (s, zlookup->sock, 2);
  length = stream_getw (s);

  stream_read (s, zlookup->sock, length - 2);
  marker = stream_getc (s);
  version = stream_getc (s);

  if (version != ZSERV_VERSION || marker != ZEBRA_HEADER_MARKER)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, zlookup->sock, marker, version);
      return NULL;
    }

  stream_getw (s);              /* Skip "command"       */

  stream_get_ipv4 (s);          /* Skip address         */
  metric = stream_getl (s);
  nexthop_num = stream_getc (s);

  if (nexthop_num)
    {
      bnc = bnc_new ();
      bnc->valid = 1;
      bnc->metric = metric;
      bnc->nexthop_num = nexthop_num;

      for (i = 0; i < nexthop_num; i++)
        {
          nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
          nexthop->type = stream_getc (s);
          switch (nexthop->type)
            {
            case ZEBRA_NEXTHOP_IPV4:
              nexthop->gate.ipv4.s_addr = stream_get_ipv4 (s);
              break;
            case ZEBRA_NEXTHOP_IFINDEX:
            case ZEBRA_NEXTHOP_IFNAME:
              nexthop->ifindex = stream_getl (s);
              break;
            default:
              /* do nothing */
              break;
            }
          bnc_nexthop_add (bnc, nexthop);
        }
    }
  else
    return NULL;

  return bnc;
}

struct bgp_nexthop_cache *
zlookup_query (struct in_addr addr)
{
  int ret;
  struct stream *s;

  /* Check socket. */
  if (zlookup->sock < 0)
    return NULL;

  s = zlookup->obuf;
  stream_reset (s);
  zclient_create_header (s, ZEBRA_IPV4_NEXTHOP_LOOKUP);
  stream_put_in_addr (s, &addr);

  stream_putw_at (s, 0, stream_get_endp (s));

  ret = writen (zlookup->sock, s->data, stream_get_endp (s));
  if (ret < 0)
    {
      zlog_err ("can't write to zlookup->sock");
      zclient_stop(zlookup);
      return NULL;
    }
  if (ret == 0)
    {
      zlog_err ("zlookup->sock connection closed");
      zclient_stop(zlookup);
      return NULL;
    }

  return zlookup_read ();
}

#ifdef HAVE_IPV6
static struct bgp_nexthop_cache *
zlookup_read_ipv6 (void)
{
  struct stream *s;
  uint16_t length;
  u_char version, marker;
  struct in6_addr raddr;
  uint32_t metric;
  int i;
  u_char nexthop_num;
  struct nexthop *nexthop;
  struct bgp_nexthop_cache *bnc;

  s = zlookup->ibuf;
  stream_reset (s);

  stream_read (s, zlookup->sock, 2);
  length = stream_getw (s);

  stream_read (s, zlookup->sock, length - 2);
  marker = stream_getc (s);
  version = stream_getc (s);

  if (version != ZSERV_VERSION || marker != ZEBRA_HEADER_MARKER)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, zlookup->sock, marker, version);
      return NULL;
    }

  stream_getw (s);              /* Skip "command"       */

  stream_get (&raddr, s, 16);

  metric = stream_getl (s);
  nexthop_num = stream_getc (s);

  if (nexthop_num)
    {
      bnc = bnc_new ();
      bnc->valid = 1;
      bnc->metric = metric;
      bnc->nexthop_num = nexthop_num;

      for (i = 0; i < nexthop_num; i++)
        {
          nexthop = XCALLOC (MTYPE_NEXTHOP, sizeof (struct nexthop));
          nexthop->type = stream_getc (s);
          switch (nexthop->type)
            {
            case ZEBRA_NEXTHOP_IPV6:
              stream_get (&nexthop->gate.ipv6, s, 16);
              break;
            case ZEBRA_NEXTHOP_IPV6_IFINDEX:
            case ZEBRA_NEXTHOP_IPV6_IFNAME:
              stream_get (&nexthop->gate.ipv6, s, 16);
              nexthop->ifindex = stream_getl (s);
              break;
            case ZEBRA_NEXTHOP_IFINDEX:
            case ZEBRA_NEXTHOP_IFNAME:
              nexthop->ifindex = stream_getl (s);
              break;
            default:
              /* do nothing */
              break;
            }
          bnc_nexthop_add (bnc, nexthop);
        }
    }
  else
    return NULL;

  return bnc;
}

struct bgp_nexthop_cache *
zlookup_query_ipv6 (struct in6_addr *addr)
{
  int ret;
  struct stream *s;

  /* Check socket. */
  if (zlookup->sock < 0)
    return NULL;

  s = zlookup->obuf;
  stream_reset (s);
  zclient_create_header (s, ZEBRA_IPV6_NEXTHOP_LOOKUP);
  stream_put (s, addr, 16);
  stream_putw_at (s, 0, stream_get_endp (s));

  ret = writen (zlookup->sock, s->data, stream_get_endp (s));
  if (ret < 0)
    {
      zlog_err ("can't write to zlookup->sock");
      zclient_stop(zlookup);
      return NULL;
    }
  if (ret == 0)
    {
      zlog_err ("zlookup->sock connection closed");
      zclient_stop(zlookup);
      return NULL;
    }

  return zlookup_read_ipv6 ();
}
#endif /* HAVE_IPV6 */

static bool
bgp_import_check (struct prefix *p, u_int32_t *igpmetric,
                  struct in_addr *igpnexthop)
{
  struct stream *s;
  int ret;
  u_int16_t length ;
  u_char version, marker;
  struct in_addr nexthop;
  u_int32_t metric = 0;
  u_char nexthop_num;
  u_char nexthop_type;

  /* If lookup connection is not available return valid. */
  if (zlookup->sock < 0)
    {
      if (igpmetric)
        *igpmetric = 0;
      return true ;
    }

  /* Send query to the lookup connection */
  s = zlookup->obuf;
  stream_reset (s);
  zclient_create_header (s, ZEBRA_IPV4_IMPORT_LOOKUP);

  stream_putc (s, p->prefixlen);
  stream_put_in_addr (s, &p->u.prefix4);

  stream_putw_at (s, 0, stream_get_endp (s));

  /* Write the packet. */
  ret = writen (zlookup->sock, s->data, stream_get_endp (s));

  if (ret < 0)
    {
      zlog_err ("can't write to zlookup->sock");
      zclient_stop(zlookup);
      return true ;
    }
  if (ret == 0)
    {
      zlog_err ("zlookup->sock connection closed");
      zclient_stop(zlookup);
      return true ;
    }

  /* Get result. */
  stream_reset (s);

  /* Fetch length. */
  stream_read (s, zlookup->sock, 2);
  length = stream_getw (s);

  /* Fetch whole data. */
  stream_read (s, zlookup->sock, length - 2);
  marker = stream_getc (s);
  version = stream_getc (s);

  if (version != ZSERV_VERSION || marker != ZEBRA_HEADER_MARKER)
    {
      zlog_err("%s: socket %d version mismatch, marker %d, version %d",
               __func__, zlookup->sock, marker, version);
      return false ;
    }

  stream_getw (s);      /* Skip the "command"   */
  stream_get_ipv4 (s);  /* Skip the address     */

  metric = stream_getl (s);
  nexthop_num = stream_getc (s);

  /* Set IGP metric value. */
  if (igpmetric)
    *igpmetric = metric;

  /* If there is nexthop then this is active route. */
  if (nexthop_num)
    {
      nexthop.s_addr = 0;
      nexthop_type = stream_getc (s);
      if (nexthop_type == ZEBRA_NEXTHOP_IPV4)
        {
          nexthop.s_addr = stream_get_ipv4 (s);
          if (igpnexthop)
            *igpnexthop = nexthop;
        }
      else
        *igpnexthop = nexthop;

      return true ;
    }
  else
    return false ;
}

/* Scan all configured BGP route then check the route exists in IGP or not.
 */
static int
bgp_import (struct thread *t)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;

  bgp_import_thread =
    thread_add_timer (master, bgp_import, NULL, bgp_import_interval);

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("Import timer expired.");

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    {
      qafx_t qafx ;

      for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
        {
          bgp_node rn ;
          struct bgp_static *bgp_static;
          int valid;
          u_int32_t metric;
          struct in_addr nexthop;

          if (qafx_is_mpls_vpn(qafx))
            continue ;

          for (rn = bgp_table_top (bgp->route[qafx]); rn;
                                                      rn = bgp_route_next (rn))
            if ((bgp_static = rn->info) != NULL)
              {
                if (bgp_static->backdoor)
                  continue;

                valid   = bgp_static->valid;
                metric  = bgp_static->igpmetric;
                nexthop = bgp_static->igpnexthop;

                if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK)
                                                      && qafx_is_unicast(qafx))
                  {
                    bgp_static->valid = bgp_import_check (&rn->p,
                                                      &bgp_static->igpmetric,
                                                      &bgp_static->igpnexthop);
                  }
                else
                  {
                    bgp_static->valid             = true ;
                    bgp_static->igpmetric         = 0;
                    bgp_static->igpnexthop.s_addr = 0;
                  }

                if (bgp_static->valid != valid)
                  {
                    if (bgp_static->valid)
                      bgp_static_update (bgp, &rn->p, bgp_static, qafx);
                    else
                      bgp_static_withdraw (bgp, &rn->p, qafx);
                  }
                else if (bgp_static->valid)
                  {
                    if (bgp_static->igpmetric != metric
                        || bgp_static->igpnexthop.s_addr != nexthop.s_addr
                        || bgp_static->rmap.name)
                      bgp_static_update (bgp, &rn->p, bgp_static, qafx);
                  }
              }
        } ;
    } ;

  return 0;
}

/* Check specified multiaccess next-hop. */
extern int
bgp_multiaccess_check_v4 (in_addr_t nexthop, sockunion su)
{
  struct bgp_node *rn1;
  struct bgp_node *rn2;
  struct prefix p;

  /* If bgp scan is not enabled, return invalid. */
  if (zlookup->sock < 0)
    return 0;

  if (sockunion_family(su) != AF_INET)
    return 0;

  memset (&p, 0, sizeof (struct prefix));
  p.family    = AF_INET;
  p.prefixlen = IPV4_MAX_BITLEN;

  p.u.prefix4.s_addr = nexthop;
  rn1 = bgp_node_match (bgp_connected_table[qAFI_IP], &p);
  if (! rn1)
    return 0;
  bgp_unlock_node (rn1);

  p.u.prefix4 = su->sin.sin_addr;

  rn2 = bgp_node_match (bgp_connected_table[qAFI_IP], &p);
  if (! rn2)
    return 0;
  bgp_unlock_node (rn2);

  /* This is safe, even with above unlocks, since we are just
     comparing pointers to the objects, not the objects themselves. */
  if (rn1 == rn2)
    return 1;

  return 0;
}

DEFUN (bgp_scan_time,
       bgp_scan_time_cmd,
       "bgp scan-time <5-60>",
       "BGP specific commands\n"
       "Configure background scanner interval\n"
       "Scanner interval (seconds)\n")
{
  bgp_scan_interval = atoi (argv[0]);

  if (bgp_scan_thread)
    {
      thread_cancel (bgp_scan_thread);
      bgp_scan_thread =
        thread_add_timer (master, bgp_scan_timer, NULL, bgp_scan_interval);
    }

  return CMD_SUCCESS;
}

DEFUN (no_bgp_scan_time,
       no_bgp_scan_time_cmd,
       "no bgp scan-time",
       NO_STR
       "BGP specific commands\n"
       "Configure background scanner interval\n")
{
  bgp_scan_interval = BGP_SCAN_INTERVAL_DEFAULT;

  if (bgp_scan_thread)
    {
      thread_cancel (bgp_scan_thread);
      bgp_scan_thread =
        thread_add_timer (master, bgp_scan_timer, NULL, bgp_scan_interval);
    }

  return CMD_SUCCESS;
}

ALIAS (no_bgp_scan_time,
       no_bgp_scan_time_val_cmd,
       "no bgp scan-time <5-60>",
       NO_STR
       "BGP specific commands\n"
       "Configure background scanner interval\n"
       "Scanner interval (seconds)\n")

static int
show_ip_bgp_scan_tables (struct vty *vty, const bool detail)
{
  struct bgp_node *rn;
  struct bgp_nexthop_cache *bnc;
  u_char i;

  if (bgp_scan_thread)
    vty_out (vty, "BGP scan is running%s", VTY_NEWLINE);
  else
    vty_out (vty, "BGP scan is not running%s", VTY_NEWLINE);

  vty_out (vty, "BGP scan interval is %d%s", bgp_scan_interval, VTY_NEWLINE);

  vty_out (vty, "Current BGP nexthop cache:%s", VTY_NEWLINE);
  for (rn = bgp_table_top (bgp_nexthop_cache_table[qAFI_IP]); rn;
                                                       rn = bgp_route_next (rn))
    if ((bnc = rn->info) != NULL)
      {
        if (bnc->valid)
          {
            vty_out (vty, " %s valid [IGP metric %d]\n",
                        siptoa(AF_INET, &rn->p.u.prefix4).str, bnc->metric);
            if (detail)
              for (i = 0; i < bnc->nexthop_num; i++)
                switch (bnc->nexthop[i].type)
                  {
                    case NEXTHOP_TYPE_IPV4:
                      vty_out (vty, "  gate %s\n",
                               siptoa(AF_INET, &bnc->nexthop[i].gate.ipv4).str);
                      break;
                    case NEXTHOP_TYPE_IFINDEX:
                      vty_out (vty, "  ifidx %u\n", bnc->nexthop[i].ifindex);
                      break;
                    default:
                      vty_out (vty, "  invalid nexthop type %u\n",
                                                          bnc->nexthop[i].type);
                  }
          }
        else
          vty_out (vty, " %s invalid\n", safe_inet_ntoa (rn->p.u.prefix4));
      }

#ifdef HAVE_IPV6
  {
    for (rn = bgp_table_top (bgp_nexthop_cache_table[qAFI_IP6]);
         rn;
         rn = bgp_route_next (rn))
      if ((bnc = rn->info) != NULL)
        {
          if (bnc->valid)
          {
            vty_out (vty, " %s valid [IGP metric %d]\n",
                           siptoa(AF_INET6, &rn->p.u.prefix6).str, bnc->metric);
            if (detail)
              for (i = 0; i < bnc->nexthop_num; i++)
                switch (bnc->nexthop[i].type)
                {
                case NEXTHOP_TYPE_IPV6:
                  vty_out (vty, "  gate %s\n",
                              siptoa(AF_INET6, &bnc->nexthop[i].gate.ipv6).str);
                  break;
                case NEXTHOP_TYPE_IFINDEX:
                  vty_out (vty, "  ifidx %u\n", bnc->nexthop[i].ifindex);
                  break;
                default:
                  vty_out (vty, "  invalid nexthop type %u\n",
                                                          bnc->nexthop[i].type);
                }
          }
          else
            vty_out (vty, " %s invalid\n",
                                        siptoa(AF_INET6, &rn->p.u.prefix6).str);
        }
  }
#endif /* HAVE_IPV6 */

  vty_out (vty, "BGP connected route:%s", VTY_NEWLINE);
  for (rn = bgp_table_top (bgp_connected_table[qAFI_IP]);
       rn;
       rn = bgp_route_next (rn))
    if (rn->info != NULL)
      vty_out (vty, " %s\n", spfxtoa(&rn->p).str);

#ifdef HAVE_IPV6
  for (rn = bgp_table_top (bgp_connected_table[qAFI_IP6]);
       rn;
       rn = bgp_route_next (rn))
    if (rn->info != NULL)
      vty_out (vty, " %s\n", spfxtoa(&rn->p).str);
#endif /* HAVE_IPV6 */

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_scan,
       show_ip_bgp_scan_cmd,
       "show ip bgp scan",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP scan status\n")
{
  return show_ip_bgp_scan_tables (vty, false /* not detail */);
}

DEFUN (show_ip_bgp_scan_detail,
       show_ip_bgp_scan_detail_cmd,
       "show ip bgp scan detail",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP scan status\n"
       "More detailed output\n")
{
  return show_ip_bgp_scan_tables (vty, true /* detail */);
}

int
bgp_config_write_scan_time (struct vty *vty)
{
  if (bgp_scan_interval != BGP_SCAN_INTERVAL_DEFAULT)
    vty_out (vty, " bgp scan-time %d%s", bgp_scan_interval, VTY_NEWLINE);
  return CMD_SUCCESS;
}

CMD_INSTALL_TABLE(static, bgp_nexthop_cmd_table, BGPD) =
{
  { BGP_NODE,        &bgp_scan_time_cmd                                 },
  { BGP_NODE,        &no_bgp_scan_time_cmd                              },
  { BGP_NODE,        &no_bgp_scan_time_val_cmd                          },
  { VIEW_NODE,       &show_ip_bgp_scan_cmd                              },
  { RESTRICTED_NODE, &show_ip_bgp_scan_cmd                              },
  { ENABLE_NODE,     &show_ip_bgp_scan_cmd                              },

  { VIEW_NODE,       &show_ip_bgp_scan_detail_cmd                       },
  { ENABLE_NODE, &show_ip_bgp_scan_detail_cmd                           },

  CMD_INSTALL_END
} ;

extern void
bgp_scan_cmd_init (void)
{
  cmd_install_table(bgp_nexthop_cmd_table) ;
} ;

void
bgp_scan_init (void)
{
  zlookup = zclient_new ();

  /* enable zebra client and schedule connection */
  zlookup->enable = 1 ;
  zlookup_schedule(zlookup);

  bgp_scan_interval = BGP_SCAN_INTERVAL_DEFAULT;
  bgp_import_interval = BGP_IMPORT_INTERVAL_DEFAULT;

  cache1_table[qAFI_IP] = bgp_table_init (qafx_ipv4_unicast);
  cache2_table[qAFI_IP] = bgp_table_init (qafx_ipv4_unicast);
  bgp_nexthop_cache_table[qAFI_IP] = cache1_table[qAFI_IP];

  bgp_connected_table[qAFI_IP] = bgp_table_init (qafx_ipv4_unicast);

#ifdef HAVE_IPV6
  cache1_table[qAFI_IP6] = bgp_table_init (qafx_ipv6_unicast);
  cache2_table[qAFI_IP6] = bgp_table_init (qafx_ipv6_unicast);
  bgp_nexthop_cache_table[qAFI_IP6] = cache1_table[qAFI_IP6];
  bgp_connected_table[qAFI_IP6] = bgp_table_init (qafx_ipv6_unicast);
#endif /* HAVE_IPV6 */

  /* Make BGP scan thread. */
  bgp_scan_thread = thread_add_timer (master, bgp_scan_timer,
                                      NULL, bgp_scan_interval);
  /* Make BGP import there. */
  bgp_import_thread = thread_add_timer (master, bgp_import, NULL, 0);
}

void
bgp_scan_finish (void)
{
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp_nexthop_cache_table[qAFI_IP]);

  bgp_table_unlock (cache1_table[qAFI_IP]);
  cache1_table[qAFI_IP] = NULL;

  bgp_table_unlock (cache2_table[qAFI_IP]);
  cache2_table[qAFI_IP] = NULL;

  bgp_table_unlock (bgp_connected_table[qAFI_IP]);
  bgp_connected_table[qAFI_IP] = NULL;

#ifdef HAVE_IPV6
  /* Only the current one needs to be reset. */
  bgp_nexthop_cache_reset (bgp_nexthop_cache_table[qAFI_IP6]);

  bgp_table_unlock (cache1_table[qAFI_IP6]);
  cache1_table[qAFI_IP6] = NULL;

  bgp_table_unlock (cache2_table[qAFI_IP6]);
  cache2_table[qAFI_IP6] = NULL;

  bgp_table_unlock (bgp_connected_table[qAFI_IP6]);
  bgp_connected_table[qAFI_IP6] = NULL;
#endif /* HAVE_IPV6 */
}
