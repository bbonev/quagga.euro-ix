/* Route map function of bgpd.
   Copyright (C) 1998, 1999 Kunihiro Ishiguro

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

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_routemap.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vty.h"

#include "prefix.h"
#include "filter.h"
#include "routemap.h"
#include "command.h"
#include "linklist.h"
#include "plist.h"
#include "memory.h"
#include "log.h"
#ifdef HAVE_LIBPCREPOSIX
# include <pcreposix.h>
#else
# ifdef HAVE_GNU_REGEX
#  include <regex.h>
# else
#  include "regex-gnu.h"
# endif /* HAVE_GNU_REGEX */
#endif /* HAVE_LIBPCREPOSIX */
#include "buffer.h"
#include "sockunion.h"

/* Memo of route-map commands.

o Cisco route-map

 match as-path          :  Done
       community        :  Done
       interface        :  Not yet
       ip address       :  Done
       ip next-hop      :  Done
       ip route-source  :  Done
       ip prefix-list   :  Done
       ipv6 address     :  Done
       ipv6 next-hop    :  Done
       ipv6 route-source:  (This will not be implemented by bgpd)
       ipv6 prefix-list :  Done
       length           :  (This will not be implemented by bgpd)
       metric           :  Done
       route-type       :  (This will not be implemented by bgpd)
       tag              :  (This will not be implemented by bgpd)

 set  as-path prepend   :  Done
      as-path tag       :  Not yet
      automatic-tag     :  (This will not be implemented by bgpd)
      community         :  Done
      comm-list         :  Not yet
      dampning          :  Not yet
      default           :  (This will not be implemented by bgpd)
      interface         :  (This will not be implemented by bgpd)
      ip default        :  (This will not be implemented by bgpd)
      ip next-hop       :  Done
      ip precedence     :  (This will not be implemented by bgpd)
      ip tos            :  (This will not be implemented by bgpd)
      level             :  (This will not be implemented by bgpd)
      local-preference  :  Done
      metric            :  Done
      metric-type       :  Not yet
      origin            :  Done
      tag               :  (This will not be implemented by bgpd)
      weight            :  Done

o Local extention

  set ipv6 next-hop global: Done
  set ipv6 next-hop local : Done
  set as-path exclude     : Done

*/

/*------------------------------------------------------------------------------
 * Generic Route-Map rule "compiled" value new and free
 */
static char bgp_route_map_value_empty[1] = { '\0' } ;

static void*
bgp_route_map_value_new(uint size)
{
  return XCALLOC(MTYPE_ROUTE_MAP_COMPILED, size);
} ;

static void
bgp_route_map_value_free(void* value)
{
  if ((value != NULL) && (value != bgp_route_map_value_empty))
    XFREE(MTYPE_ROUTE_MAP_COMPILED, value) ;
} ;

/*==============================================================================
 * 'match peer (A.B.C.D|X:X::X:X)' or 'match peer local'
 *
 * Compares the peer specified in the 'match peer' clause with the peer
 * received in bgp_info->peer. If it is the same, or if the peer structure
 * received is a peer_group containing it, returns RMAP_MATCH.
 */
static route_map_result_t
route_match_peer(void* value, prefix_c pfx, route_map_object_t type,
                                                                   void* object)
{
  bgp_route_map brm ;
  union sockunion *su;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;

  if (!(brm->rmap_type & (BGP_RMAP_TYPE_IMPORT | BGP_RMAP_TYPE_EXPORT)))
    return RMAP_NOT_MATCH;

  /* If value=bgp_route_map_value_empty (command 'match peer local'),
   * and it's a NETWORK, REDISTRIBUTE or DEFAULT_GENERATED route
   * => return RMAP_MATCH
   */
  if (value == bgp_route_map_value_empty)
    {
      if (brm->rmap_type & (BGP_RMAP_TYPE_NETWORK |
                            BGP_RMAP_TYPE_REDISTRIBUTE |
                            BGP_RMAP_TYPE_DEFAULT) )
        return RMAP_MATCH ;
      else
        return RMAP_NOT_MATCH;
    } ;

  /* value must be a sockunion -- we look for a match to the given peer.
   */
  su = value ;
  if (sockunion_same (su, brm->prun->su_name))
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 * If the arg is NULL or empty, then this is match peer local.
 * Otherwise arg is (A.B.C.D|X:X::X:X)
 */
static void *
route_match_peer_compile (const char *arg)
{
  union sockunion* su ;

  if ((arg == NULL) || (*arg == '\0'))
    return bgp_route_map_value_empty ;

  su = bgp_route_map_value_new(sizeof(union sockunion)) ;

  if (str2sockunion (arg, su) < 0)
    {
      bgp_route_map_value_free(su) ;
      su = NULL ;
    } ;

  return su;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_peer_cmd =
{
  "peer",
  route_match_peer,
  route_match_peer_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 * 'match ip address IP_ACCESS_LIST'
 */
static route_map_result_t
route_match_ip_address (void* value, prefix_c pfx, route_map_object_t type,
                                                                  void* object)
{
  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  if (pfx->family != AF_INET)
    return RMAP_NOT_MATCH ;

  if (access_list_apply (*(access_list*)value, pfx) != FILTER_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 * Compile reference to the ip access-list with name 'arg'.
 *
 * Sets up a reference to the ip access-list of the given name.  The list may
 * not have any value (yet).
 */
static void *
route_match_ip_access_list_compile (const char *arg)
{
  access_list* p_access_list ;

  if ((arg == NULL) || (*arg == '\0'))
    return NULL ;

  p_access_list = bgp_route_map_value_new(sizeof(access_list)) ;

  *p_access_list = access_list_get_ref(qAFI_IP, arg) ;

  return p_access_list ;
}

/*------------------------------------------------------------------------------
 * Release reference to an ip access-list.
 */
static void
route_match_access_list_free (void* value)
{
  access_list_clear_ref(*(access_list*)value) ;
  bgp_route_map_value_free(value);
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_address_cmd =
{
  "ip address",
  route_match_ip_address,
  route_match_ip_access_list_compile,
  route_match_access_list_free,
};

/*==============================================================================
 * 'match ip address prefix-list PREFIX_LIST'
 */
static route_map_result_t
route_match_ip_address_prefix_list (void* value, prefix_c pfx,
                                         route_map_object_t type, void* object)
{
  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  if (pfx->family != AF_INET)
    return RMAP_NOT_MATCH ;

  if (prefix_list_apply(*(prefix_list*)value, pfx) == PREFIX_PERMIT)
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 * Compile reference to the ip prefix-list with name 'arg'.
 *
 * Sets up a reference to the ip prefix-list of the given name.  The list may
 * not have any value (yet).
 */
static void *
route_match_ip_prefix_list_compile (const char *arg)
{
  prefix_list* p_prefix_list ;

  if ((arg == NULL) || (*arg == '\0'))
    return NULL ;

  p_prefix_list = bgp_route_map_value_new(sizeof(prefix_list)) ;

  *p_prefix_list = prefix_list_get_ref(qAFI_IP, arg) ;

  return p_prefix_list ;
}

/*------------------------------------------------------------------------------
 * Release reference to a prefix-list.
 */
static void
route_match_prefix_list_free (void *value)
{
  prefix_list_clear_ref(*(prefix_list*)value) ;
  bgp_route_map_value_free(value);
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_address_prefix_list_cmd =
{
  "ip address prefix-list",
  route_match_ip_address_prefix_list,
  route_match_ip_prefix_list_compile,
  route_match_prefix_list_free
};

/*==============================================================================
 * 'match ip next-hop ACCESS-LIST'
 *
 * TODO should there be a match to an IP Address -- same like IPv6 ?
 */
static route_map_result_t
route_match_ip_next_hop (void* value, prefix_c pfx, route_map_object_t type,
                                                                   void* object)
{
  bgp_route_map  brm ;
  attr_set        working ;
  struct prefix_ipv4 p;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;

  working = brm->attrs->working ;

  if (working->next_hop.type != nh_ipv4)
    return RMAP_NOT_MATCH ;

  p.family        = AF_INET;
  p.prefix.s_addr = working->next_hop.ip.v4 ;
  p.prefixlen     = IPV4_MAX_BITLEN;

  if (access_list_apply (*(access_list*)value, &p) != FILTER_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_next_hop_cmd =
{
  "ip next-hop",
  route_match_ip_next_hop,
  route_match_ip_access_list_compile,
  route_match_access_list_free,
};

/*==============================================================================
 * 'match ip next-hop prefix-list PREFIX_LIST'
 */
static route_map_result_t
route_match_ip_next_hop_prefix_list (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set        working ;
  struct prefix_ipv4 p;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;

  working = brm->attrs->working ;

  if (working->next_hop.type != nh_ipv4)
    return RMAP_NOT_MATCH ;

  p.family        = AF_INET;
  p.prefix.s_addr = working->next_hop.ip.v4 ;
  p.prefixlen     = IPV4_MAX_BITLEN;

  if (prefix_list_apply (*(prefix_list*)value, &p) == PREFIX_PERMIT)
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_next_hop_prefix_list_cmd =
{
  "ip next-hop prefix-list",
  route_match_ip_next_hop_prefix_list,
  route_match_ip_prefix_list_compile,
  route_match_prefix_list_free
};

/*==============================================================================
 * 'match ip route-source ACCESS-LIST'
 */
static route_map_result_t
route_match_ip_route_source (void* value, prefix_c pfx, route_map_object_t type,
                                                                   void* object)
{
  struct prefix_ipv4 p;
  bgp_route_map  brm ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;

  if ((brm->prun == NULL) || (sockunion_family(brm->prun->su_name) != AF_INET))
    return RMAP_NOT_MATCH;

  p.family    = AF_INET;
  p.prefix    = brm->prun->su_name->sin.sin_addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  if (access_list_apply (*(access_list*)value, &p) == FILTER_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_route_source_cmd =
{
  "ip route-source",
  route_match_ip_route_source,
  route_match_ip_access_list_compile,
  route_match_access_list_free,
};

/*==============================================================================
 * 'match ip route-source prefix-list PREFIX_LIST'
 */
static route_map_result_t
route_match_ip_route_source_prefix_list (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  struct prefix_ipv4 p;
  bgp_route_map  brm ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;

  if ((brm->prun == NULL) || (sockunion_family(brm->prun->su_name) != AF_INET))
    return RMAP_NOT_MATCH;

  p.family    = AF_INET;
  p.prefix    = brm->prun->su_name->sin.sin_addr;
  p.prefixlen = IPV4_MAX_BITLEN;

  if (prefix_list_apply (*(prefix_list*)value, &p) == PREFIX_PERMIT)
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ip_route_source_prefix_list_cmd =
{
  "ip route-source prefix-list",
  route_match_ip_route_source_prefix_list,
  route_match_ip_prefix_list_compile,
  route_match_prefix_list_free
};

/*==============================================================================
 * 'match metric METRIC'
 */
static route_map_result_t
route_match_metric (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set        working ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  working = brm->attrs->working ;

  if ((working->have & atb_med) && (working->med == *((uint32_t*)value)))
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH ;
} ;

/*------------------------------------------------------------------------------
 * Route map 'match metric' match statement. 'arg' is MED value
 */
static void *
route_match_metric_compile (const char *arg)
{
  uint32_t* p_med;
  strtox_t tox ;
  const char* end ;
  uint32_t tmp;

  tmp = strtoul_xr(arg, &tox, &end, 0, UINT32_MAX) ;

  if ((tox != strtox_ok) || (*end != '\0'))
    return NULL ;

  p_med = bgp_route_map_value_new(sizeof (uint32_t));

  *p_med = tmp;
  return p_med;
}

/*------------------------------------------------------------------------------
 * Route map commands for metric matching.
 */
static const route_map_rule_cmd_t  route_match_metric_cmd =
{
  "metric",
  route_match_metric,
  route_match_metric_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 * 'match as-path ASPATH'
 */
static route_map_result_t
route_match_aspath (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set       working ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  working = brm->attrs->working ;

  if (working->asp == NULL)
    return RMAP_NOT_MATCH ;

  if (as_list_apply(*(as_list*)value, working->asp) == AS_FILTER_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 * Compile reference to the as-list with name 'arg'.
 *
 * Sets up a reference to the as-list of the given name.  The list may not
 * have any value (yet).
 */
static void *
route_match_aspath_compile (const char *arg)
{
  as_list* p_as_list ;

  if ((arg == NULL) || (*arg == '\0'))
    return NULL ;

  p_as_list = bgp_route_map_value_new(sizeof(as_list)) ;

  *p_as_list = as_list_get_ref(arg) ;

  return p_as_list ;
}

/*------------------------------------------------------------------------------
 * Release reference to an as-list.
 */
static void
route_match_aspath_free (void* value)
{
  as_list_clear_ref(*(as_list*)value) ;
  bgp_route_map_value_free(value);
}

/*------------------------------------------------------------------------------
 * Route map commands for aspath matching.
 */
static const route_map_rule_cmd_t  route_match_aspath_cmd =
{
  "as-path",
  route_match_aspath,
  route_match_aspath_compile,
  route_match_aspath_free
};

/*==============================================================================
 * match as-origin ASN
 */
static route_map_result_t
route_match_as_origin (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set        working ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  working = brm->attrs->working ;

  if (working->asp == NULL)
    return RMAP_NOT_MATCH ;

  if (*((as_t*)value) == as_path_first_simple_asn(working->asp))
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 * Compile a single ASN value
 */
static void *
route_match_as_origin_compile (const char *arg)
{
  as_t* p_asn;
  strtox_t tox ;
  const char* end ;
  uint32_t tmp;

  tmp = strtoul_xr(arg, &tox, &end, BGP_ASN_FIRST, BGP_ASN_LAST) ;

  if ((tox != strtox_ok) || (*end != '\0'))
    return NULL ;

  p_asn = bgp_route_map_value_new(sizeof(as_t));

  *p_asn = tmp ;
  return p_asn ;
} ;

/*------------------------------------------------------------------------------
 */
/* Route map commands for as-origin matching. */
static const route_map_rule_cmd_t  route_match_as_origin_cmd =
{
  "as-origin",
  route_match_as_origin,
  route_match_as_origin_compile,
  bgp_route_map_value_free
} ;

/*==============================================================================
 * 'match community COMMUNIY'
 */
struct rmap_community
{
  community_list list ;
  bool           exact;
};

static route_map_result_t
route_match_community (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map   brm ;
  struct rmap_community* rcom;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  rcom = value ;

  if (rcom->exact)
    {
      if (community_list_exact_match (brm->attrs->working->community,
                                                                    rcom->list))
        return RMAP_MATCH;
    }
  else
    {
      if (community_list_match (brm->attrs->working->community, rcom->list))
        return RMAP_MATCH;
    }

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 * Parse "name" or "name exact..."
 */
static void *
route_match_community_compile (const char *arg)
{
  struct rmap_community *rcom;
  char *p;
  char *n;

  rcom = bgp_route_map_value_new(sizeof(struct rmap_community));

  n = strdup(arg) ;
  p = strchr (n, ' ');
  if (p != NULL)
    {
      *p = '\0' ;               /* Discard the "exact"  */
      rcom->exact = true ;
    }
  else
    {
      rcom->exact = false ;
    } ;

  rcom->list = community_list_get_ref(bgp_clist, COMMUNITY_LIST, n) ;

  free(n) ;

  return rcom;
}

/*------------------------------------------------------------------------------
 * Release reference to community-list
 */
static void
route_match_community_free (void* value)
{
  struct rmap_community *rcom = value;

  community_list_clear_ref(rcom->list) ;
  bgp_route_map_value_free(rcom);
} ;

/*------------------------------------------------------------------------------
 * Route map commands for community matching.
 */
static const route_map_rule_cmd_t  route_match_community_cmd =
{
  "community",
  route_match_community,
  route_match_community_compile,
  route_match_community_free
};

/*==============================================================================
 * Match function for extcommunity match.
 */
static route_map_result_t
route_match_ecommunity (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set       working ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  working = brm->attrs->working ;

  if (working->ecommunity == NULL)
    return RMAP_NOT_MATCH ;

  if (ecommunity_list_match (working->ecommunity, *(community_list*)value))
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 * Compile name of extcommunity-list to symbol reference.
 */
static void *
route_match_ecommunity_compile (const char* arg)
{
  community_list* rcom ;

  rcom = bgp_route_map_value_new(sizeof(community_list)) ;

  *rcom = community_list_get_ref(bgp_clist, ECOMMUNITY_LIST, arg) ;

  return rcom ;
}

/*------------------------------------------------------------------------------
 * Release reference to symbol for extcommunity-list
 */
static void
route_match_ecommunity_free (void* value)
{
  community_list_clear_ref(*(community_list*)value) ;

  bgp_route_map_value_free(value);
}

/*------------------------------------------------------------------------------
 * Route map commands for community matching.
 */
static const route_map_rule_cmd_t  route_match_ecommunity_cmd =
{
  "extcommunity",
  route_match_ecommunity,
  route_match_ecommunity_compile,
  route_match_ecommunity_free
};

/*==============================================================================
 * 'match nlri' and 'set nlri' are replaced by 'address-family ipv4'
 * and 'address-family vpnv4'.
 */

/*==============================================================================
 * 'match origin'
 */
static route_map_result_t
route_match_origin (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_set        working ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm = object ;
  working = brm->attrs->working ;

  if (working->origin == *(byte*)value)
    return RMAP_MATCH ;

  return RMAP_NOT_MATCH ;
} ;

/*------------------------------------------------------------------------------
 * Set ORIGIN to match to -- only sets a valid origin
 */
static void*
route_match_origin_compile (const char *arg)
{
  byte*  origin;

  origin = bgp_route_map_value_new(sizeof(byte));

  if      (strncmp (arg, "igp", 2) == 0)
    *origin = BGP_ATT_ORG_IGP ;
  else if (strncmp (arg, "egp", 1) == 0)
    *origin = BGP_ATT_ORG_IGP ;
  else if (strncmp (arg, "incomplete", 2) == 0)
    *origin = BGP_ATT_ORG_INCOMP ;
  else
    {
      bgp_route_map_value_free(origin) ;
      origin = NULL ;
    } ;

  return origin;
} ;

/*------------------------------------------------------------------------------
 * Route map commands for origin matching.
 */
static const route_map_rule_cmd_t  route_match_origin_cmd =
{
  "origin",
  route_match_origin,
  route_match_origin_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 * match probability
 */
static route_map_result_t
route_match_probability (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  uint thresh ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  thresh = *((uint*)value) ;

  if (thresh == 0)
    return RMAP_NOT_MATCH ;

  if (thresh > (uint)RAND_MAX)
    return RMAP_MATCH ;

  if ((uint)rand() <= thresh)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 */
static void *
route_match_probability_compile (const char *arg)
{
  uint* p_thresh ;
  strtox_t tox ;
  const char* end ;
  urlong tmp;

  tmp = strtoul_xr(arg, &tox, &end, 0, 100) ;

  if ((tox != strtox_ok) || (*end != '\0'))
    return NULL ;

  confirm(RAND_MAX >= INT32_MAX) ;
  confirm((sizeof(urlong) > sizeof(uint))
                             && (URLONG_MAX >= (((ulong)RAND_MAX + 1) * 100))) ;

  tmp = (((urlong)RAND_MAX + 1) * tmp) / 100 ;

  p_thresh = bgp_route_map_value_new(sizeof(uint));

  *p_thresh = tmp ;
  return p_thresh ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_probability_cmd =
{
  "probability",
  route_match_probability,
  route_match_probability_compile,
  bgp_route_map_value_free
};

#ifdef HAVE_IPV6 /* <-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-< */

/*==============================================================================
 * 'match ipv6 address IP_ACCESS_LIST'
 */
static route_map_result_t
route_match_ipv6_address (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  if (pfx->family != AF_INET6)
    return RMAP_NOT_MATCH ;

  if (access_list_apply (*(access_list*)value, pfx) != FILTER_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 * Compile reference to the ipv6 access-list with name 'arg'.
 *
 * Sets up a reference to the ipv6 access-list of the given name.  The list may
 * not have any value (yet).
 */
static void *
route_match_ipv6_access_list_compile (const char *arg)
{
  access_list* p_access_list ;

  if ((arg == NULL) || (*arg == '\0'))
    return NULL ;

  p_access_list = bgp_route_map_value_new(sizeof(access_list)) ;

  *p_access_list = access_list_get_ref(qAFI_IP6, arg) ;

  return p_access_list ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ipv6_address_cmd =
{
  "ipv6 address",
  route_match_ipv6_address,
  route_match_ipv6_access_list_compile,
  route_match_access_list_free
};

/*==============================================================================
 * 'match ipv6 address prefix-list PREFIX_LIST'
 */
static route_map_result_t
route_match_ipv6_address_prefix_list (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  if (pfx->family != AF_INET6)
    return RMAP_NOT_MATCH ;

  if (prefix_list_apply (*(prefix_list*)value, pfx) != PREFIX_PERMIT)
    return RMAP_MATCH;

  return RMAP_NOT_MATCH;
}

/*------------------------------------------------------------------------------
 * Compile reference to the ipv6 prefix-list with name 'arg'.
 *
 * Sets up a reference to the ipv6 prefix-list of the given name.  The list may
 * not have any value (yet).
 */
static void *
route_match_ipv6_prefix_list_compile (const char *arg)
{
  prefix_list* p_prefix_list ;

  if ((arg == NULL) || (*arg == '\0'))
    return NULL ;

  p_prefix_list = bgp_route_map_value_new(sizeof(prefix_list)) ;

  *p_prefix_list = prefix_list_get_ref(qAFI_IP6, arg) ;

  return p_prefix_list ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ipv6_address_prefix_list_cmd =
{
  "ipv6 address prefix-list",
  route_match_ipv6_address_prefix_list,
  route_match_ipv6_prefix_list_compile,
  route_match_prefix_list_free
};

/*==============================================================================
 * 'match ipv6 next-hop IP_ADDRESS' -- not a Cisco command
 */
static route_map_result_t
route_match_ipv6_next_hop (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map   brm ;
  attr_set         working ;
  struct in6_addr* ipv6 ;

  if (type != RMAP_BGP)
    return RMAP_NOT_MATCH ;

  brm  = object ;
  ipv6 = value ;

  working = brm->attrs->working ;

  switch (working->next_hop.type)
    {
      case nh_ipv6_2:
        if (IPV6_ADDR_SAME (&working->next_hop.ip.v6[in6_link_local], ipv6))
          return RMAP_MATCH ;

        fall_through ;

      case nh_ipv6_1:
        if (IPV6_ADDR_SAME (&working->next_hop.ip.v6[in6_global], ipv6))
          return RMAP_MATCH ;
        break ;

      default:
        break ;
    } ;

  return RMAP_NOT_MATCH;
} ;

/*------------------------------------------------------------------------------
 * Parse an ipv6 address
 */
static void *
route_match_ipv6_next_hop_compile (const char *arg)
{
  struct in6_addr* ipv6 ;

  ipv6 = bgp_route_map_value_new(sizeof(struct in6_addr)) ;

  if (inet_pton (AF_INET6, arg, ipv6) <= 0)
    {
      bgp_route_map_value_free(ipv6);
      ipv6 = NULL ;
    }

  return ipv6 ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_match_ipv6_next_hop_cmd =
{
  "ipv6 next-hop",
  route_match_ipv6_next_hop,
  route_match_ipv6_next_hop_compile,
  bgp_route_map_value_free
};


#endif /* HAVE_IPV6 >->->->->->->->->->->->->->->->->->->->->->->->->->->->-> */

/*==============================================================================
 * 'set ip next-hop IP_ADDRESS'
 *
 * NB: if the route is not IPv4, does nothing.
 */
struct rmap_ip_nexthop_set
{
  in_addr_t ipv4 ;
  bool      peer_address;
};

static route_map_result_t
route_set_ip_nexthop (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  struct rmap_ip_nexthop_set *rins ;
  in_addr_t* p_ip ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  if (!qafx_is_ipv4(brm->qafx))
    return RMAP_OKAY ;

  rins = value ;

  if (rins->peer_address)
    {
      sockunion su ;

      if (brm->rmap_type & (BGP_RMAP_TYPE_IN | BGP_RMAP_TYPE_RS_IN
                                             | BGP_RMAP_TYPE_IMPORT) )
        su = &brm->prun->session->cops->su_remote ;
      else if (brm->rmap_type & BGP_RMAP_TYPE_OUT)
        su = &brm->prun->session->cops->su_local ;
      else
        return RMAP_OKAY ;

      if (sockunion_family(su) != AF_INET)
        return RMAP_OKAY ;

      p_ip = &su->sin.sin_addr.s_addr ;
    }
  else
    p_ip = &rins->ipv4 ;

  bgp_attr_pair_set_next_hop(brm->attrs, nh_ipv4, p_ip) ;

  return RMAP_OKAY ;
}

/*------------------------------------------------------------------------------
 * If given string is "peer-address", set peer_address in rmap_ip_nexthop_set
 * structure.
 *
 * Otherwise, clear peer_address and set ipv4 in rmap_ip_nexthop_set structure.
 */
static void *
route_set_ip_nexthop_compile (const char *arg)
{
  struct rmap_ip_nexthop_set* rins ;

  rins = bgp_route_map_value_new(sizeof(struct rmap_ip_nexthop_set));

  if (strcmp (arg, "peer-address") == 0)
    rins->peer_address = true ;
  else
    {
      rins->peer_address = false ;

      if (inet_pton (AF_INET, arg, &rins->ipv4) <= 0)
        {
          bgp_route_map_value_free(rins);
          rins = NULL;
        }
    }

  return rins;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_ip_nexthop_cmd =
{
  "ip next-hop",
  route_set_ip_nexthop,
  route_set_ip_nexthop_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 * 'set local-preference LOCAL_PREF'
 */
static route_map_result_t
route_set_local_pref (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  bgp_attr_pair_set_local_pref(brm->attrs, *((uint32_t*)value)) ;

  return RMAP_OKAY;
}

/*------------------------------------------------------------------------------
 * local_pref is a 32-but unsigned
 */
static void *
route_set_local_pref_compile (const char *arg)
{
  uint32_t* p_local_pref;
  strtox_t tox ;
  const char* end ;
  uint32_t tmp;

  tmp = strtoul_xr(arg, &tox, &end, 0, UINT32_MAX) ;

  if ((tox != strtox_ok) || (*end != '\0'))
    return NULL ;

  p_local_pref = bgp_route_map_value_new(sizeof(uint32_t));

  *p_local_pref = tmp ;
  return p_local_pref ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_local_pref_cmd =
{
  "local-preference",
  route_set_local_pref,
  route_set_local_pref_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 *'set weight WEIGHT'
 */
static route_map_result_t
route_set_weight (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  bgp_attr_pair_set_weight(brm->attrs, *((uint16_t*)value)) ;

  return RMAP_OKAY;
}

/*------------------------------------------------------------------------------
 * weight is an unsigned 16-bit integer
 */
static void *
route_set_weight_compile (const char *arg)
{
  uint16_t* p_weight ;
  strtox_t tox ;
  const char* end ;
  uint16_t tmp;

  tmp = strtoul_xr(arg, &tox, &end, 0, UINT16_MAX) ;

  if ((tox != strtox_ok) || (*end != '\0'))
    return NULL ;

  p_weight = bgp_route_map_value_new(sizeof(uint16_t));

  *p_weight = tmp ;
  return p_weight ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_weight_cmd =
{
  "weight",
  route_set_weight,
  route_set_weight_compile,
  bgp_route_map_value_free,
};

/*==============================================================================
 * 'set metric METRIC'
 *
 * The METRIC may be an unsigned 32-bit integer or +/- same.
 *
 * Underlying MED is unsigned 32-bit integer, so if is +/-:
 *
 *   * the delta may be -UINT32_MAX..+UINT32_MAX
 *
 *   * if no med is set, treat as med == 0
 *
 *   * result is clamped to 0..UINT32_MAX.
 */
struct rmap_med_set
{
  int64_t med ;
  bool    delta ;
} ;

static route_map_result_t
route_set_metric (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  struct rmap_med_set* rmed ;
  int64_t  med ;

  confirm(INT64_MAX > UINT32_MAX) ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  rmed = value ;
  med  = rmed->med ;

  brm = object ;

  if ((rmed->delta) && (brm->attrs->working->have & atb_med))
    med += brm->attrs->working->med ;

  if (med < 0)
    med = 0 ;
  if (med > UINT32_MAX)
    med = UINT32_MAX ;

  bgp_attr_pair_set_med(brm->attrs, med) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 * med is an unsigned 32-bit integer
 *
 * But we here allow for a 'delta' med of +/- UINT32_MAX
 */
static void *
route_set_metric_compile (const char *arg)
{
  struct rmap_med_set* rmed ;
  strtox_t tox ;
  const char* end ;
  rlong  tmp;

  confirm(RLONG_MAX > (rlong)UINT32_MAX) ;

  tmp = strtol_xr(arg, &tox, &end, -(urlong)UINT32_MAX, +(urlong)UINT32_MAX) ;

  if (((tox != strtox_ok) && (tox != strtox_signed)) || (*end != '\0'))
    return NULL ;

  rmed = bgp_route_map_value_new(sizeof(struct rmap_med_set)) ;

  rmed->med   = tmp ;
  rmed->delta = tox == strtox_signed ;

  return rmed ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_metric_cmd =
{
  "metric",
  route_set_metric,
  route_set_metric_compile,
  bgp_route_map_value_free,
};

/*==============================================================================
 * 'set as-path prepend ASPATH'
 *
 * The as_path to be prepended may contain Confed stuff, but that will be
 * at the front of the as_path only.
 *
 * The as_path to be prepended to may also contain Confed stuff, and we expect
 * that will also be at the front of the as_path only.
 *
 * Whatever the result of the prepend, we here ensure that any Confed stuff is
 * at the front of the path, by moving Confed segments where necessary.
 */
static route_map_result_t
route_set_aspath_prepend (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  as_path       asp ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  asp = as_path_prepend_path(brm->attrs->working->asp, (as_path)value) ;
  asp = as_path_confed_sweep(asp) ;

  bgp_attr_pair_set_as_path(brm->attrs, asp) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 * Get an as_path from the given string
 *
 * NB: accepts any and all forms of AS_PATH -- so can, if minded to, prepend
 *     all kinds of invalid nonsense.
 *
 *     However, will reject anything where there are "out of place" Confed
 *     segments.
 */
static void *
route_set_aspath_prepend_compile (const char *arg)
{
  as_path asp ;

  asp = as_path_from_str(arg) ;

  if ((asp != NULL) && !as_path_confed_ok(asp))
    asp = as_path_free(asp) ;

  return asp ;
} ;

/*------------------------------------------------------------------------------
 */
static void
route_set_aspath_prepend_free (void* value)
{
  as_path_free((as_path)value);
} ;

/* Set metric rule structure. */
static const route_map_rule_cmd_t  route_set_aspath_prepend_cmd =
{
  "as-path prepend",
  route_set_aspath_prepend,
  route_set_aspath_prepend_compile,
  route_set_aspath_prepend_free,
};

/*==============================================================================
 * 'set as-path exclude ASn'
 */
static route_map_result_t
route_set_aspath_exclude (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  as_path        asp ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  if (brm->attrs->working->asp == NULL)
    return RMAP_OKAY ;

  asp = as_path_exclude_asns(brm->attrs->working->asp, (asn_set)value) ;

  bgp_attr_pair_set_as_path(brm->attrs, asp) ;

  return RMAP_OKAY;
}

/*------------------------------------------------------------------------------
 * Take string and convert to asn_set for use by as_path_exclude_asns()
 */
static void *
route_set_aspath_exclude_compile (const char *arg)
{
  return asn_set_from_str(arg) ;
} ;

/*------------------------------------------------------------------------------
 */
static void
route_set_aspath_exclude_free (void* value)
{
  asn_set_free((asn_set)value);
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_aspath_exclude_cmd =
{
  "as-path exclude",
  route_set_aspath_exclude,
  route_set_aspath_exclude_compile,
  route_set_aspath_exclude_free,
};

/*==============================================================================
 * 'set community COMMUNITY'
 */
struct rmap_comm_set
{
  attr_community comm ;
  attr_community_type_t act ;
};

static route_map_result_t
route_set_community (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  struct rmap_comm_set* rcs;
  bgp_route_map brm ;
  attr_community comm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;
  comm = brm->attrs->working->community ;

  rcs = value ;

  switch (rcs->act)
    {
      case act_none:
      default:
        comm = NULL ;                   /* discard communities  */
        break ;

      case act_additive:
        comm = attr_community_add_list(comm, rcs->comm) ;
        break ;

      case act_simple:
        comm = attr_community_replace_list(comm, rcs->comm) ;
        break ;
    } ;

  bgp_attr_pair_set_community(brm->attrs, comm) ;

  return RMAP_OKAY;
}

/*------------------------------------------------------------------------------
 * Process string to extract communities:
 *
 *   <community>... ["additive"]
 *   "none"
 *
 * Where each <community> is:
 *
 *   9999|999:999|no-export|no-advertise|local-AS
 */
static void *
route_set_community_compile (const char *arg)
{
  struct rmap_comm_set *rcs;
  attr_community comm ;
  attr_community_type_t act ;

  comm = attr_community_from_str(arg, &act) ;

  switch (act)
    {
      case act_none:
      case act_simple:
      case act_additive:
        break ;

      default:
        comm = attr_community_free(comm) ;
        return NULL ;
    } ;

  rcs = bgp_route_map_value_new(sizeof (struct rmap_comm_set));

  rcs->comm = attr_community_store(comm) ;
  rcs->act  = act ;

  return rcs;
}

/*------------------------------------------------------------------------------
 */
static void
route_set_community_free (void* value)
{
  struct rmap_comm_set* rcs = value ;

  if (rcs->comm != NULL)
    attr_community_release(rcs->comm);

  bgp_route_map_value_free(rcs);
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_community_cmd =
{
  "community",
  route_set_community,
  route_set_community_compile,
  route_set_community_free,
};

/*==============================================================================
 * 'set comm-list (<1-99>|<100-500>|WORD) delete'
 */
static route_map_result_t
route_set_community_delete (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  attr_community comm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  comm = brm->attrs->working->community ;
  if (comm == NULL)
    return RMAP_OKAY ;

  comm = community_list_match_delete(comm, *(community_list*)value);

  bgp_attr_pair_set_community(brm->attrs, comm) ;

  return RMAP_OKAY;
}

/*------------------------------------------------------------------------------
 * Collect name of community-list from arg string.
 */
static void *
route_set_community_delete_compile (const char *arg)
{
  community_list* rcom;
  char *p;
  char *n;

  n = strdup(arg) ;
  p = strchr(n, ' ');
  if (p == NULL)
    return NULL ;

  *p = '\0' ;           /* chop at end of name/number   */

  rcom = bgp_route_map_value_new(sizeof(community_list));

  *rcom = community_list_get_ref(bgp_clist, COMMUNITY_LIST, n) ;

  free(n) ;

  return rcom;
} ;

/*------------------------------------------------------------------------------
 * Release reference to symbol for community-list
 */
static void
route_set_community_delete_free (void* value)
{
  community_list_clear_ref(*(community_list*)value) ;

  bgp_route_map_value_free(value);
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_community_delete_cmd =
{
  "comm-list",
  route_set_community_delete,
  route_set_community_delete_compile,
  route_set_community_delete_free,
};

/*==============================================================================
 * 'set extcommunity rt COMMUNITY'
 * 'set extcommunity soo COMMUNITY'
 */
static route_map_result_t
route_set_ecommunity(void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  attr_ecommunity ecomm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;
  ecomm = brm->attrs->working->ecommunity ;

  ecomm = attr_ecommunity_add_list(ecomm, (attr_ecommunity)value) ;

  bgp_attr_pair_set_ecommunity(brm->attrs, ecomm) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 * Take string and construct attr_ecommunity assuming these are all 'rt'
 * extended communities.
 */
static void *
route_set_ecommunity_rt_compile (const char *arg)
{
  return attr_ecommunity_from_str(arg, false /* no prefix */,
                                                           BGP_EXCS_R_TARGET) ;
} ;

/*------------------------------------------------------------------------------
 * Take string and construct attr_ecommunity assuming these are all 'soo'
 * extended communities.
 */
static void *
route_set_ecommunity_soo_compile (const char *arg)
{
  return attr_ecommunity_from_str(arg, false /* no prefix */,
                                                           BGP_EXCS_R_ORIGIN) ;
} ;

/*------------------------------------------------------------------------------
 */
static void
route_set_ecommunity_free (void* value)
{
  attr_ecommunity_free(value) ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_ecommunity_rt_cmd =
{
  "extcommunity rt",
  route_set_ecommunity,
  route_set_ecommunity_rt_compile,
  route_set_ecommunity_free,
};

static const route_map_rule_cmd_t  route_set_ecommunity_soo_cmd =
{
  "extcommunity soo",
  route_set_ecommunity,
  route_set_ecommunity_soo_compile,
  route_set_ecommunity_free,
};

/*------------------------------------------------------------------------------
 * 'set origin ORIGIN'
 */
static route_map_result_t
route_set_origin (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  bgp_attr_pair_set_origin(brm->attrs, *((byte*)value)) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 */
static void *
route_set_origin_compile (const char *arg)
{
 byte *origin;

  origin = bgp_route_map_value_new(sizeof (byte));

  if (strcmp (arg, "igp") == 0)
    *origin = 0;
  else if (strcmp (arg, "egp") == 0)
    *origin = 1;
  else
    *origin = 2;

  return origin;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_origin_cmd =
{
  "origin",
  route_set_origin,
  route_set_origin_compile,
  bgp_route_map_value_free,
};

/*==============================================================================
 * 'set atomic-aggregate'
 */
static route_map_result_t
route_set_atomic_aggregate(void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;
  brm->attrs->working->have  |= atb_atomic_aggregate ;

  bgp_attr_pair_set_atomic_aggregate(brm->attrs, true) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 */
static void *
route_set_atomic_aggregate_compile (const char *arg)
{
  return bgp_route_map_value_empty ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_atomic_aggregate_cmd =
{
  "atomic-aggregate",
  route_set_atomic_aggregate,
  route_set_atomic_aggregate_compile,
  bgp_route_map_value_free,
};

/*==============================================================================
 * 'set aggregator as AS A.B.C.D'
 */
struct rmap_aggregator_set
{
  as_t      as ;
  in_addr_t ip ;
};

static route_map_result_t
route_set_aggregator_as (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;
  struct rmap_aggregator_set* ras ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;
  ras = value ;

  bgp_attr_pair_set_aggregator(brm->attrs, ras->as, ras->ip) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 * Parse: "9999 A.B.C.D" into struct rmap_aggregator_set
 */
static void *
route_set_aggregator_as_compile (const char *arg)
{
  struct rmap_aggregator_set* ras ;
  strtox_t  tox ;
  const char* p ;
  as_t      tmp ;
  in_addr_t ip ;

  confirm(LONG_MAX > UINT32_MAX) ;

  tmp = strtoul_xr(arg, &tox, &p, 0, BGP_AS4_MAX) ;

  if ((tox != strtox_ok) || (*p != ' '))
    return NULL ;

  while (*p == ' ')
    ++p ;

  if (inet_pton(AF_INET, p, &ip) <= 0)
    return NULL ;

  ras = bgp_route_map_value_new(sizeof(struct rmap_aggregator_set));

  ras->as = tmp ;
  ras->ip = ip ;

  return ras ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_aggregator_as_cmd =
{
  "aggregator as",
  route_set_aggregator_as,
  route_set_aggregator_as_compile,
  bgp_route_map_value_free,
};

#ifdef HAVE_IPV6 /* <-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-< */

/*==============================================================================
 * 'set ipv6 nexthop global IP_ADDRESS'
 * 'set ipv6 nexthop local  IP_ADDRESS'
 *
 * NB: when setting 'global' does not change any existing 'local'.
 * NB: when setting 'local' does not change any existing 'global'.
 * NB: when setting 'local' will set empty global if none is set.
 */
struct rmap_ipv6_nexthop_set
{
  nh_type_t  type ;
  in6_addr_t ip ;
};

static route_map_result_t
route_set_ipv6_nexthop(void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map  brm ;
  struct rmap_ipv6_nexthop_set* rnhs ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm  = object ;

  if (!qafx_is_ipv6(brm->qafx))
    return RMAP_OKAY ;

  rnhs = value ;

  bgp_attr_pair_set_next_hop(brm->attrs, rnhs->type, &rnhs->ip) ;

  return RMAP_OKAY;
} ;

/*------------------------------------------------------------------------------
 * Parse "XX:XX::XX:XX" for setting next_hop of given type
 */
static void *
route_set_ipv6_nexthop_compile (const char *arg, nh_type_t type)
{
  struct rmap_ipv6_nexthop_set* rnhs ;
  bool ok ;

  rnhs = bgp_route_map_value_new(sizeof(struct rmap_ipv6_nexthop_set)) ;
  rnhs->type = type ;

  ok = inet_pton (AF_INET6, arg, &rnhs->ip) > 0 ;

  if (ok)
    {
      if (IN6_IS_ADDR_LINKLOCAL(&rnhs->ip))
        ok = (type == nh_ipv6_2) ;
      else
        ok = (type == nh_ipv6_1) ;
    } ;

  if (ok)
    return rnhs ;

  bgp_route_map_value_free(rnhs);
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Parse "XX:XX::XX:XX" for setting next_hop 'global'
 */
static void *
route_set_ipv6_nexthop_global_compile (const char *arg)
{
  return route_set_ipv6_nexthop_compile (arg, nh_ipv6_1) ;
} ;

/*------------------------------------------------------------------------------
 * Parse "XX:XX::XX:XX" for setting next_hop 'local'
 */
static void *
route_set_ipv6_nexthop_local_compile (const char *arg)
{
  return route_set_ipv6_nexthop_compile (arg, nh_ipv6_2) ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_ipv6_nexthop_global_cmd =
{
  "ipv6 next-hop global",
  route_set_ipv6_nexthop,
  route_set_ipv6_nexthop_global_compile,
  bgp_route_map_value_free
};

static const route_map_rule_cmd_t  route_set_ipv6_nexthop_local_cmd =
{
  "ipv6 next-hop local",
  route_set_ipv6_nexthop,
  route_set_ipv6_nexthop_local_compile,
  bgp_route_map_value_free
};

#endif /* HAVE_IPV6 >->->->->->->->->->->->->->->->->->->->->->->->->->->->-> */

/*==============================================================================
 * 'set vpnv4 nexthop A.B.C.D'
 */
static route_map_result_t
route_set_vpnv4_nexthop (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  if (brm->qafx != qafx_ipv4_mpls_vpn)
    return RMAP_OKAY ;

  bgp_attr_pair_set_next_hop(brm->attrs, nh_ipv4, (in_addr_t*)value) ;

  return RMAP_OKAY ;
}

/*------------------------------------------------------------------------------
 * Parse "A.B.C.D" to an in_addr_t
 */
static void *
route_set_vpnv4_nexthop_compile (const char *arg)
{
  struct in_addr* ip ;

  ip = bgp_route_map_value_new(sizeof(in_addr_t));

  if (inet_pton(AF_INET, arg, ip) <= 0)
    {
      bgp_route_map_value_free(ip);
      ip = NULL;
    }

  return ip ;
}

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_vpnv4_nexthop_cmd =
{
  "vpnv4 next-hop",
  route_set_vpnv4_nexthop,
  route_set_vpnv4_nexthop_compile,
  bgp_route_map_value_free
};

/*==============================================================================
 * 'set originator-id'
 */
static route_map_result_t
route_set_originator_id (void* value, prefix_c pfx,
                                          route_map_object_t type, void* object)
{
  bgp_route_map brm ;

  if (type != RMAP_BGP)
    return RMAP_OKAY ;

  brm = object ;

  bgp_attr_pair_set_originator_id(brm->attrs, *(bgp_id_t*)value) ;

  return RMAP_OKAY ;
} ;

/*------------------------------------------------------------------------------
 * Parse "A.B.C.D" to an in_addr_t
 */
static void *
route_set_originator_id_compile (const char *arg)
{
  struct in_addr* ip ;

  ip = bgp_route_map_value_new(sizeof(in_addr_t));

  if (inet_pton(AF_INET, arg, ip) <= 0)
    {
      bgp_route_map_value_free(ip);
      return NULL;
    }

  return ip ;
} ;

/*------------------------------------------------------------------------------
 */
static const route_map_rule_cmd_t  route_set_originator_id_cmd =
{
  "originator-id",
  route_set_originator_id,
  route_set_originator_id_compile,
  bgp_route_map_value_free,
} ;

/*==============================================================================
 *
 */

/* Add bgp route map rule. */
static int
bgp_route_match_add (struct vty *vty, struct route_map_entry *index,
                     const char *command, const char *arg)
{
  int ret;

  ret = route_map_add_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
          case RMAP_RULE_MISSING:
            vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
            return CMD_WARNING;

          case RMAP_COMPILE_ERROR:
            vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
            return CMD_WARNING;

          default:
            vty_out (vty, "%% Route map *internal* error %d.%s", ret,
                                                                   VTY_NEWLINE);
            return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

/* Delete bgp route map rule. */
static int
bgp_route_match_delete (struct vty *vty, struct route_map_entry *index,
                        const char *command, const char *arg)
{
  int ret;

  ret = route_map_delete_match (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;

        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;

        default:
          vty_out (vty, "%% Route map *internal* error %d.%s", ret,
                                                                 VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

/* Add bgp route map rule. */
static int
bgp_route_set_add (struct vty *vty, struct route_map_entry *index,
                   const char *command, const char *arg)
{
  int ret;

  ret = route_map_add_set (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;

        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;

        default:
          vty_out (vty, "%% Route map *internal* error %d.%s", ret,
                                                                 VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

/* Delete bgp route map rule. */
static int
bgp_route_set_delete (struct vty *vty, struct route_map_entry *index,
                      const char *command, const char *arg)
{
  int ret;

  ret = route_map_delete_set (index, command, arg);
  if (ret)
    {
      switch (ret)
        {
        case RMAP_RULE_MISSING:
          vty_out (vty, "%% Can't find rule.%s", VTY_NEWLINE);
          return CMD_WARNING;

        case RMAP_COMPILE_ERROR:
          vty_out (vty, "%% Argument is malformed.%s", VTY_NEWLINE);
          return CMD_WARNING;

        default:
          vty_out (vty, "%% Route map *internal* error %d.%s", ret,
                                                                 VTY_NEWLINE);
          return CMD_WARNING;
        }
    }
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Hook function for updating route_map assignment.
 *
 * This used to worry about mapping of names to route-maps, but that is now
 * taken care of by the reference mechanics.
 *
 * Arguably this should worry about what depends on the route-map....
 */
static void
bgp_route_map_update (const char *unused)
{
}

/*==============================================================================
 * CLI for match/set for BGP.
 */
DEFUN (match_peer,
       match_peer_cmd,
       "match peer (A.B.C.D|X:X::X:X)",
       MATCH_STR
       "Match peer address\n"
       "IPv6 address of peer\n"
       "IP address of peer\n")
{
  return bgp_route_match_add (vty, vty->index, "peer", argv[0]);
}

DEFUN (match_peer_local,
        match_peer_local_cmd,
        "match peer local",
        MATCH_STR
        "Match peer address\n"
        "Static or Redistributed routes\n")
{
  return bgp_route_match_add (vty, vty->index, "peer", NULL);
}

DEFUN (no_match_peer,
       no_match_peer_cmd,
       "no match peer",
       NO_STR
       MATCH_STR
       "Match peer address\n")
{
  return bgp_route_match_delete (vty, vty->index, "peer",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_peer,
       no_match_peer_val_cmd,
       "no match peer (A.B.C.D|X:X::X:X)",
       NO_STR
       MATCH_STR
       "Match peer address\n"
       "IPv6 address of peer\n"
       "IP address of peer\n")

ALIAS (no_match_peer,
       no_match_peer_local_cmd,
       "no match peer local",
       NO_STR
       MATCH_STR
       "Match peer address\n"
       "Static or Redistributed routes\n")

DEFUN (match_ip_address,
       match_ip_address_cmd,
       "match ip address (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip address", argv[0]);
}

DEFUN (no_match_ip_address,
       no_match_ip_address_cmd,
       "no match ip address",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip address",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_address,
       no_match_ip_address_val_cmd,
       "no match ip address (<1-199>|<1300-2699>|WORD)",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")

DEFUN (match_ip_next_hop,
       match_ip_next_hop_cmd,
       "match ip next-hop (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (no_match_ip_next_hop,
       no_match_ip_next_hop_cmd,
       "no match ip next-hop",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip next-hop",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_next_hop,
       no_match_ip_next_hop_val_cmd,
       "no match ip next-hop (<1-199>|<1300-2699>|WORD)",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")

/* match probability { */

DEFUN (match_probability,
       match_probability_cmd,
       "match probability <0-100>",
       MATCH_STR
       "Match portion of routes defined by percentage value\n"
       "Percentage of routes\n")
{
  return bgp_route_match_add (vty, vty->index, "probability", argv[0]);
}

DEFUN (no_match_probability,
       no_match_probability_cmd,
       "no match probability",
       NO_STR
       MATCH_STR
       "Match portion of routes defined by percentage value\n")
{
  return bgp_route_match_delete (vty, vty->index, "probability",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_probability,
       no_match_probability_val_cmd,
       "no match probability <1-99>",
       NO_STR
       MATCH_STR
       "Match portion of routes defined by percentage value\n"
       "Percentage of routes\n")

/* } */

DEFUN (match_ip_route_source,
       match_ip_route_source_cmd,
       "match ip route-source (<1-199>|<1300-2699>|WORD)",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP standard access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip route-source", argv[0]);
}

DEFUN (no_match_ip_route_source,
       no_match_ip_route_source_cmd,
       "no match ip route-source",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip route-source",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_route_source,
       no_match_ip_route_source_val_cmd,
       "no match ip route-source (<1-199>|<1300-2699>|WORD)",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP standard access-list name\n")

DEFUN (match_ip_address_prefix_list,
       match_ip_address_prefix_list_cmd,
       "match ip address prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip address prefix-list",
                                                                      argv[0]) ;
}

DEFUN (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_cmd,
       "no match ip address prefix-list",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip address prefix-list",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_val_cmd,
       "no match ip address prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFUN (match_ip_next_hop_prefix_list,
       match_ip_next_hop_prefix_list_cmd,
       "match ip next-hop prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip next-hop prefix-list",
                                                                      argv[0]) ;
}

DEFUN (no_match_ip_next_hop_prefix_list,
       no_match_ip_next_hop_prefix_list_cmd,
       "no match ip next-hop prefix-list",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip next-hop prefix-list",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_next_hop_prefix_list,
       no_match_ip_next_hop_prefix_list_val_cmd,
       "no match ip next-hop prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFUN (match_ip_route_source_prefix_list,
       match_ip_route_source_prefix_list_cmd,
       "match ip route-source prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ip route-source prefix-list",
                                                                      argv[0]) ;
}

DEFUN (no_match_ip_route_source_prefix_list,
       no_match_ip_route_source_prefix_list_cmd,
       "no match ip route-source prefix-list",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "Match entries of prefix-lists\n")
{
  return bgp_route_match_delete (vty, vty->index, "ip route-source prefix-list",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_ip_route_source_prefix_list,
       no_match_ip_route_source_prefix_list_val_cmd,
       "no match ip route-source prefix-list WORD",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")

DEFUN (match_metric,
       match_metric_cmd,
       "match metric <0-4294967295>",
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
  return bgp_route_match_add (vty, vty->index, "metric", argv[0]);
}

DEFUN (no_match_metric,
       no_match_metric_cmd,
       "no match metric",
       NO_STR
       MATCH_STR
       "Match metric of route\n")
{
  return bgp_route_match_delete (vty, vty->index, "metric",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_match_metric,
       no_match_metric_val_cmd,
       "no match metric <0-4294967295>",
       NO_STR
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")

DEFUN (match_community,
       match_community_cmd,
       "match community (<1-99>|<100-500>|WORD)",
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "community", argv[0]);
}

DEFUN (match_community_exact,
       match_community_exact_cmd,
       "match community (<1-99>|<100-500>|WORD) exact-match",
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Do exact matching of communities\n")
{
  int ret;
  char *argstr;

  argstr = bgp_route_map_value_new(strlen (argv[0])
                                                 + strlen ("exact-match") + 2) ;

  sprintf (argstr, "%s exact-match", argv[0]);

  ret = bgp_route_match_add (vty, vty->index, "community", argstr);

  bgp_route_map_value_free(argstr);

  return ret;
}

DEFUN (no_match_community,
       no_match_community_cmd,
       "no match community",
       NO_STR
       MATCH_STR
       "Match BGP community list\n")
{
  return bgp_route_match_delete (vty, vty->index, "community", NULL);
}

ALIAS (no_match_community,
       no_match_community_val_cmd,
       "no match community (<1-99>|<100-500>|WORD)",
       NO_STR
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n")

ALIAS (no_match_community,
       no_match_community_exact_cmd,
       "no match community (<1-99>|<100-500>|WORD) exact-match",
       NO_STR
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Do exact matching of communities\n")

DEFUN (match_ecommunity,
       match_ecommunity_cmd,
       "match extcommunity (<1-99>|<100-500>|WORD)",
       MATCH_STR
       "Match BGP/VPN extended community list\n"
       "Extended community-list number (standard)\n"
       "Extended community-list number (expanded)\n"
       "Extended community-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "extcommunity", argv[0]);
}

DEFUN (no_match_ecommunity,
       no_match_ecommunity_cmd,
       "no match extcommunity",
       NO_STR
       MATCH_STR
       "Match BGP/VPN extended community list\n")
{
  return bgp_route_match_delete (vty, vty->index, "extcommunity", NULL);
}

ALIAS (no_match_ecommunity,
       no_match_ecommunity_val_cmd,
       "no match extcommunity (<1-99>|<100-500>|WORD)",
       NO_STR
       MATCH_STR
       "Match BGP/VPN extended community list\n"
       "Extended community-list number (standard)\n"
       "Extended community-list number (expanded)\n"
       "Extended community-list name\n")

DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path WORD",
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "as-path", argv[0]);
}

DEFUN (no_match_aspath,
       no_match_aspath_cmd,
       "no match as-path",
       NO_STR
       MATCH_STR
       "Match BGP AS path list\n")
{
  return bgp_route_match_delete (vty, vty->index, "as-path", NULL);
}

ALIAS (no_match_aspath,
       no_match_aspath_val_cmd,
       "no match as-path WORD",
       NO_STR
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")

/*------------------------------------------------------------------------------
 * match as-origin 9999
 * no match as-origin
 * no match as-origin 9999
 */

DEFUN (match_as_origin,
       match_as_origin_cmd,
       "match as-origin " CMD_AS_RANGE,
       MATCH_STR
       "Match BGP AS path origin ASN\n"
       "AS path origin ASN\n")
{
  return bgp_route_match_add (vty, vty->index, "as-origin", argv[0]);
}

DEFUN (no_match_as_origin,
       no_match_as_origin_cmd,
       "no match as-origin",
       NO_STR
       MATCH_STR
       "Match BGP AS path origin ASN\n")
{
  return bgp_route_match_delete (vty, vty->index, "as-origin", NULL);
}

ALIAS (no_match_as_origin,
       no_match_as_origin_val_cmd,
       "no match as-origin " CMD_AS_RANGE,
       NO_STR
       MATCH_STR
       "Match BGP AS path origin ASN\n"
       "AS path origin ASN\n")

/*----------------------------------------------------------------------------*/

DEFUN (match_origin,
       match_origin_cmd,
       "match origin (egp|igp|incomplete)",
       MATCH_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
  if (strncmp (argv[0], "igp", 2) == 0)
    return bgp_route_match_add (vty, vty->index, "origin", "igp");
  if (strncmp (argv[0], "egp", 1) == 0)
    return bgp_route_match_add (vty, vty->index, "origin", "egp");
  if (strncmp (argv[0], "incomplete", 2) == 0)
    return bgp_route_match_add (vty, vty->index, "origin", "incomplete");

  return CMD_WARNING;
}

DEFUN (no_match_origin,
       no_match_origin_cmd,
       "no match origin",
       NO_STR
       MATCH_STR
       "BGP origin code\n")
{
  return bgp_route_match_delete (vty, vty->index, "origin", NULL);
}

ALIAS (no_match_origin,
       no_match_origin_val_cmd,
       "no match origin (egp|igp|incomplete)",
       NO_STR
       MATCH_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")

DEFUN (set_ip_nexthop,
       set_ip_nexthop_cmd,
       "set ip next-hop A.B.C.D",
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
  union sockunion su;
  int ret;

  ret = str2sockunion (argv[0], &su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed Next-hop address%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_route_set_add (vty, vty->index, "ip next-hop", argv[0]);
}

DEFUN (set_ip_nexthop_peer,
       set_ip_nexthop_peer_cmd,
       "set ip next-hop peer-address",
       SET_STR
       IP_STR
       "Next hop address\n"
       "Use peer address (for BGP only)\n")
{
  return bgp_route_set_add (vty, vty->index, "ip next-hop", "peer-address");
}

#if 0
DEFUN_DEPRECATED (no_set_ip_nexthop_peer,
       no_set_ip_nexthop_peer_cmd,
       "no set ip next-hop peer-address",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "Use peer address (for BGP only)\n")
{
  return bgp_route_set_delete (vty, vty->index, "ip next-hop", NULL);
}
#endif

DEFUN (no_set_ip_nexthop,
       no_set_ip_nexthop_cmd,
       "no set ip next-hop",
       NO_STR
       SET_STR
       "Next hop address\n")
{
  return bgp_route_set_delete (vty, vty->index, "ip next-hop",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_ip_nexthop,
       no_set_ip_nexthop_val_cmd,
       "no set ip next-hop A.B.C.D",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")

DEFUN (set_metric,
       set_metric_cmd,
       "set metric <0-4294967295>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
  return bgp_route_set_add (vty, vty->index, "metric", argv[0]);
}

ALIAS (set_metric,
       set_metric_addsub_cmd,
       "set metric <-2147483647-+2147483647>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Add or subtract metric\n")

DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n")
{
  return bgp_route_set_delete (vty, vty->index, "metric",
                                                (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_metric,
       no_set_metric_val_cmd,
       "no set metric <0-4294967295>",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")

DEFUN (set_local_pref,
       set_local_pref_cmd,
       "set local-preference <0-4294967295>",
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")
{
  return bgp_route_set_add (vty, vty->index, "local-preference", argv[0]);
}

DEFUN (no_set_local_pref,
       no_set_local_pref_cmd,
       "no set local-preference",
       NO_STR
       SET_STR
       "BGP local preference path attribute\n")
{
  return bgp_route_set_delete (vty, vty->index, "local-preference",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_local_pref,
       no_set_local_pref_val_cmd,
       "no set local-preference <0-4294967295>",
       NO_STR
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")

DEFUN (set_weight,
       set_weight_cmd,
       "set weight <0-65535>",
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")
{
  return bgp_route_set_add (vty, vty->index, "weight", argv[0]);
}

DEFUN (no_set_weight,
       no_set_weight_cmd,
       "no set weight",
       NO_STR
       SET_STR
       "BGP weight for routing table\n")
{
  return bgp_route_set_delete (vty, vty->index, "weight",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_weight,
       no_set_weight_val_cmd,
       "no set weight <0-65535>",
       NO_STR
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")

DEFUN (set_aspath_prepend,
       set_aspath_prepend_cmd,
       "set as-path prepend .AS_PATH",
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_add (vty, vty->index, "as-path prepend", str);
  XFREE (MTYPE_TMP, str);

  return ret;
}

DEFUN (no_set_aspath_prepend,
       no_set_aspath_prepend_cmd,
       "no set as-path prepend",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n")
{
  int ret;
  char *str;

  if (argc == 0)
    return bgp_route_set_delete (vty, vty->index, "as-path prepend", NULL);

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_delete (vty, vty->index, "as-path prepend", str);
  XFREE (MTYPE_TMP, str);
  return ret;
}

ALIAS (no_set_aspath_prepend,
       no_set_aspath_prepend_val_cmd,
       "no set as-path prepend .AS_PATH",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")

DEFUN (set_aspath_exclude,
       set_aspath_exclude_cmd,
       "set as-path exclude .ASNs",
       SET_STR
       "Transform BGP AS-path attribute\n"
       "Exclude from the as-path\n"
       "AS number\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_add (vty, vty->index, "as-path exclude", str);
  XFREE (MTYPE_TMP, str);
  return ret;
}

DEFUN (no_set_aspath_exclude,
       no_set_aspath_exclude_cmd,
       "no set as-path exclude",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Exclude from the as-path\n")
{
  int ret;
  char *str;

  if (argc == 0)
    return bgp_route_set_delete (vty, vty->index, "as-path exclude", NULL);

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_delete (vty, vty->index, "as-path exclude", str);
  XFREE (MTYPE_TMP, str);
  return ret;
}

ALIAS (no_set_aspath_exclude,
       no_set_aspath_exclude_val_cmd,
       "no set as-path exclude .ASNs",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Exclude from the as-path\n"
       "AS number\n")

DEFUN (set_community,
       set_community_cmd,
       "set community .AA:NN",
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or "
                     "local-AS|no-advertise|no-export or additive\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_add (vty, vty->index, "community", str) ;
  XFREE (MTYPE_TMP, str);

  return ret;
}

DEFUN (set_community_none,
       set_community_none_cmd,
       "set community none",
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")
{
  return bgp_route_set_add (vty, vty->index, "community", "none");
}

DEFUN (no_set_community,
       no_set_community_cmd,
       "no set community",
       NO_STR
       SET_STR
       "BGP community attribute\n")
{
  return bgp_route_set_delete (vty, vty->index, "community", NULL);
}

ALIAS (no_set_community,
       no_set_community_val_cmd,
       "no set community .AA:NN",
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "Community number in aa:nn format or "
                       "local-AS|no-advertise|no-export|internet or additive\n")

ALIAS (no_set_community,
       no_set_community_none_cmd,
       "no set community none",
       NO_STR
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")

DEFUN (set_community_delete,
       set_community_delete_cmd,
       "set comm-list (<1-99>|<100-500>|WORD) delete",
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Communitly-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")
{
  char *str;

  str = XCALLOC (MTYPE_TMP, strlen (argv[0]) + strlen (" delete") + 1);
  strcpy (str, argv[0]);
  strcat (str, " delete");

  bgp_route_set_add (vty, vty->index, "comm-list", str);

  XFREE (MTYPE_TMP, str);
  return CMD_SUCCESS;
}

DEFUN (no_set_community_delete,
       no_set_community_delete_cmd,
       "no set comm-list",
       NO_STR
       SET_STR
       "set BGP community list (for deletion)\n")
{
  return bgp_route_set_delete (vty, vty->index, "comm-list", NULL);
}

ALIAS (no_set_community_delete,
       no_set_community_delete_val_cmd,
       "no set comm-list (<1-99>|<100-500>|WORD) delete",
       NO_STR
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Communitly-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")

DEFUN (set_ecommunity_rt,
       set_ecommunity_rt_cmd,
       "set extcommunity rt .ASN:nn_or_IP-address:nn",
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extended community\n"
       "VPN extended community\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_add (vty, vty->index, "extcommunity rt", str);
  XFREE (MTYPE_TMP, str);

  return ret;
}

DEFUN (no_set_ecommunity_rt,
       no_set_ecommunity_rt_cmd,
       "no set extcommunity rt",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extended community\n")
{
  return bgp_route_set_delete (vty, vty->index, "extcommunity rt", NULL);
}

ALIAS (no_set_ecommunity_rt,
       no_set_ecommunity_rt_val_cmd,
       "no set extcommunity rt .ASN:nn_or_IP-address:nn",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extended community\n"
       "VPN extended community\n")

DEFUN (set_ecommunity_soo,
       set_ecommunity_soo_cmd,
       "set extcommunity soo .ASN:nn_or_IP-address:nn",
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")
{
  int ret;
  char *str;

  str = argv_concat (argv, argc, 0);
  ret = bgp_route_set_add (vty, vty->index, "extcommunity soo", str);
  XFREE (MTYPE_TMP, str);
  return ret;
}

DEFUN (no_set_ecommunity_soo,
       no_set_ecommunity_soo_cmd,
       "no set extcommunity soo",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n")
{
  return bgp_route_set_delete (vty, vty->index, "extcommunity soo", NULL);
}

ALIAS (no_set_ecommunity_soo,
       no_set_ecommunity_soo_val_cmd,
       "no set extcommunity soo .ASN:nn_or_IP-address:nn",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")

DEFUN (set_origin,
       set_origin_cmd,
       "set origin (egp|igp|incomplete)",
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
  if (strncmp (argv[0], "igp", 2) == 0)
    return bgp_route_set_add (vty, vty->index, "origin", "igp");
  if (strncmp (argv[0], "egp", 1) == 0)
    return bgp_route_set_add (vty, vty->index, "origin", "egp");
  if (strncmp (argv[0], "incomplete", 2) == 0)
    return bgp_route_set_add (vty, vty->index, "origin", "incomplete");

  return CMD_WARNING;
}

DEFUN (no_set_origin,
       no_set_origin_cmd,
       "no set origin",
       NO_STR
       SET_STR
       "BGP origin code\n")
{
  return bgp_route_set_delete (vty, vty->index, "origin", NULL);
}

ALIAS (no_set_origin,
       no_set_origin_val_cmd,
       "no set origin (egp|igp|incomplete)",
       NO_STR
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")

DEFUN (set_atomic_aggregate,
       set_atomic_aggregate_cmd,
       "set atomic-aggregate",
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
  return bgp_route_set_add (vty, vty->index, "atomic-aggregate", NULL);
}

DEFUN (no_set_atomic_aggregate,
       no_set_atomic_aggregate_cmd,
       "no set atomic-aggregate",
       NO_STR
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
  return bgp_route_set_delete (vty, vty->index, "atomic-aggregate", NULL);
}

DEFUN (set_aggregator_as,
       set_aggregator_as_cmd,
       "set aggregator as " CMD_AS_RANGE " A.B.C.D",
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")
{
  int ret;
  as_t as;
  struct in_addr address;
  char *argstr;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], 1, BGP_AS4_MAX);

  ret = inet_aton (argv[1], &address);
  if (ret == 0)
    {
      vty_out (vty, "Aggregator IP address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  argstr = bgp_route_map_value_new(strlen (argv[0]) + strlen (argv[1]) + 2);

  sprintf (argstr, "%u %s", as, argv[1]);

  ret = bgp_route_set_add (vty, vty->index, "aggregator as", argstr);

  bgp_route_map_value_free(argstr);

  return ret;
}

DEFUN (no_set_aggregator_as,
       no_set_aggregator_as_cmd,
       "no set aggregator as",
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n")
{
  int ret;
  as_t as;
  struct in_addr address;
  char *argstr;

  if (argv == 0)
    return bgp_route_set_delete (vty, vty->index, "aggregator as", NULL);

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], 1, BGP_AS4_MAX);

  ret = inet_aton (argv[1], &address);
  if (ret == 0)
    {
      vty_out (vty, "Aggregator IP address is invalid%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  argstr = bgp_route_map_value_new(strlen (argv[0]) + strlen (argv[1]) + 2);

  sprintf (argstr, "%u %s", as, argv[1]);

  ret = bgp_route_set_delete (vty, vty->index, "aggregator as", argstr);

  bgp_route_map_value_free(argstr);

  return ret;
}

ALIAS (no_set_aggregator_as,
       no_set_aggregator_as_val_cmd,
       "no set aggregator as " CMD_AS_RANGE " A.B.C.D",
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")


#ifdef HAVE_IPV6
DEFUN (match_ipv6_address,
       match_ipv6_address_cmd,
       "match ipv6 address WORD",
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 address", argv[0]);
}

DEFUN (no_match_ipv6_address,
       no_match_ipv6_address_cmd,
       "no match ipv6 address WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 address", argv[0]);
}

DEFUN (match_ipv6_next_hop,
       match_ipv6_next_hop_cmd,
       "match ipv6 next-hop X:X::X:X",
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 next-hop", argv[0]);
}

DEFUN (no_match_ipv6_next_hop,
       no_match_ipv6_next_hop_cmd,
       "no match ipv6 next-hop X:X::X:X",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 next-hop", argv[0]);
}

DEFUN (match_ipv6_address_prefix_list,
       match_ipv6_address_prefix_list_cmd,
       "match ipv6 address prefix-list WORD",
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_add (vty, vty->index, "ipv6 address prefix-list",
                                                                      argv[0]);
}

DEFUN (no_match_ipv6_address_prefix_list,
       no_match_ipv6_address_prefix_list_cmd,
       "no match ipv6 address prefix-list WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
  return bgp_route_match_delete (vty, vty->index, "ipv6 address prefix-list",
                                                                      argv[0]);
}

DEFUN (set_ipv6_nexthop_global,
       set_ipv6_nexthop_global_cmd,
       "set ipv6 next-hop global X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 next-hop global", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_global,
       no_set_ipv6_nexthop_global_cmd,
       "no set ipv6 next-hop global",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n")
{
  return bgp_route_set_delete (vty, vty->index, "ipv6 next-hop global",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_ipv6_nexthop_global,
       no_set_ipv6_nexthop_global_val_cmd,
       "no set ipv6 next-hop global X:X::X:X",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")

DEFUN (set_ipv6_nexthop_local,
       set_ipv6_nexthop_local_cmd,
       "set ipv6 next-hop local X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "ipv6 next-hop local", argv[0]);
}

DEFUN (no_set_ipv6_nexthop_local,
       no_set_ipv6_nexthop_local_cmd,
       "no set ipv6 next-hop local",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n")
{
  return bgp_route_set_delete (vty, vty->index, "ipv6 next-hop local",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_ipv6_nexthop_local,
       no_set_ipv6_nexthop_local_val_cmd,
       "no set ipv6 next-hop local X:X::X:X",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
#endif /* HAVE_IPV6 */

DEFUN (set_vpnv4_nexthop,
       set_vpnv4_nexthop_cmd,
       "set vpnv4 next-hop A.B.C.D",
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n"
       "IP address of next hop\n")
{
  return bgp_route_set_add (vty, vty->index, "vpnv4 next-hop", argv[0]);
}

DEFUN (no_set_vpnv4_nexthop,
       no_set_vpnv4_nexthop_cmd,
       "no set vpnv4 next-hop",
       NO_STR
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n")
{
  return bgp_route_set_delete (vty, vty->index, "vpnv4 next-hop",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_vpnv4_nexthop,
       no_set_vpnv4_nexthop_val_cmd,
       "no set vpnv4 next-hop A.B.C.D",
       NO_STR
       SET_STR
       "VPNv4 information\n"
       "VPNv4 next-hop address\n"
       "IP address of next hop\n")

DEFUN (set_originator_id,
       set_originator_id_cmd,
       "set originator-id A.B.C.D",
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")
{
  return bgp_route_set_add (vty, vty->index, "originator-id", argv[0]);
}

DEFUN (no_set_originator_id,
       no_set_originator_id_cmd,
       "no set originator-id",
       NO_STR
       SET_STR
       "BGP originator ID attribute\n")
{
  return bgp_route_set_delete (vty, vty->index, "originator-id",
                                                 (argc == 1) ? argv[0] : NULL) ;
}

ALIAS (no_set_originator_id,
       no_set_originator_id_val_cmd,
       "no set originator-id A.B.C.D",
       NO_STR
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")

DEFUN_DEPRECATED (set_pathlimit_ttl,
       set_pathlimit_ttl_cmd,
       "set pathlimit ttl <1-255>",
       SET_STR
       "BGP AS-Pathlimit attribute\n"
       "Set AS-Path Hop-count TTL\n")
{
  return CMD_SUCCESS ;
}

DEFUN_DEPRECATED (no_set_pathlimit_ttl,
       no_set_pathlimit_ttl_cmd,
       "no set pathlimit ttl",
       NO_STR
       SET_STR
       "BGP AS-Pathlimit attribute\n"
       "Set AS-Path Hop-count TTL\n")
{
  return CMD_SUCCESS;
}

ALIAS (no_set_pathlimit_ttl,
       no_set_pathlimit_ttl_val_cmd,
       "no set pathlimit ttl <1-255>",
       NO_STR
       MATCH_STR
       "BGP AS-Pathlimit attribute\n"
       "Set AS-Path Hop-count TTL\n")

DEFUN_DEPRECATED (match_pathlimit_as,
       match_pathlimit_as_cmd,
       "match pathlimit as <1-65535>",
       MATCH_STR
       "BGP AS-Pathlimit attribute\n"
       "Match Pathlimit AS number\n")
{
  return CMD_SUCCESS ;
}

DEFUN_DEPRECATED (no_match_pathlimit_as,
       no_match_pathlimit_as_cmd,
       "no match pathlimit as",
       NO_STR
       MATCH_STR
       "BGP AS-Pathlimit attribute\n"
       "Match Pathlimit AS number\n")
{
  return CMD_SUCCESS ;
}

ALIAS (no_match_pathlimit_as,
       no_match_pathlimit_as_val_cmd,
       "no match pathlimit as <1-65535>",
       NO_STR
       MATCH_STR
       "BGP AS-Pathlimit attribute\n"
       "Match Pathlimit ASN\n")

/*------------------------------------------------------------------------------
 * Table of bgp_route commands
 */
CMD_INSTALL_TABLE(static, bgp_routemap_cmd_table, BGPD) =
{
  { RMAP_NODE,       &match_peer_cmd                                    },
  { RMAP_NODE,       &match_peer_local_cmd                              },
  { RMAP_NODE,       &no_match_peer_cmd                                 },
  { RMAP_NODE,       &no_match_peer_val_cmd                             },
  { RMAP_NODE,       &no_match_peer_local_cmd                           },
  { RMAP_NODE,       &match_ip_address_cmd                              },
  { RMAP_NODE,       &no_match_ip_address_cmd                           },
  { RMAP_NODE,       &no_match_ip_address_val_cmd                       },
  { RMAP_NODE,       &match_ip_next_hop_cmd                             },
  { RMAP_NODE,       &no_match_ip_next_hop_cmd                          },
  { RMAP_NODE,       &no_match_ip_next_hop_val_cmd                      },
  { RMAP_NODE,       &match_ip_route_source_cmd                         },
  { RMAP_NODE,       &no_match_ip_route_source_cmd                      },
  { RMAP_NODE,       &no_match_ip_route_source_val_cmd                  },
  { RMAP_NODE,       &match_ip_address_prefix_list_cmd                  },
  { RMAP_NODE,       &no_match_ip_address_prefix_list_cmd               },
  { RMAP_NODE,       &no_match_ip_address_prefix_list_val_cmd           },
  { RMAP_NODE,       &match_ip_next_hop_prefix_list_cmd                 },
  { RMAP_NODE,       &no_match_ip_next_hop_prefix_list_cmd              },
  { RMAP_NODE,       &no_match_ip_next_hop_prefix_list_val_cmd          },
  { RMAP_NODE,       &match_ip_route_source_prefix_list_cmd             },
  { RMAP_NODE,       &no_match_ip_route_source_prefix_list_cmd          },
  { RMAP_NODE,       &no_match_ip_route_source_prefix_list_val_cmd      },
  { RMAP_NODE,       &match_aspath_cmd                                  },
  { RMAP_NODE,       &no_match_aspath_cmd                               },
  { RMAP_NODE,       &no_match_aspath_val_cmd                           },
  { RMAP_NODE,       &match_as_origin_cmd                               },
  { RMAP_NODE,       &no_match_as_origin_cmd                            },
  { RMAP_NODE,       &no_match_as_origin_val_cmd                        },
  { RMAP_NODE,       &match_metric_cmd                                  },
  { RMAP_NODE,       &no_match_metric_cmd                               },
  { RMAP_NODE,       &no_match_metric_val_cmd                           },
  { RMAP_NODE,       &match_community_cmd                               },
  { RMAP_NODE,       &match_community_exact_cmd                         },
  { RMAP_NODE,       &no_match_community_cmd                            },
  { RMAP_NODE,       &no_match_community_val_cmd                        },
  { RMAP_NODE,       &no_match_community_exact_cmd                      },
  { RMAP_NODE,       &match_ecommunity_cmd                              },
  { RMAP_NODE,       &no_match_ecommunity_cmd                           },
  { RMAP_NODE,       &no_match_ecommunity_val_cmd                       },
  { RMAP_NODE,       &match_origin_cmd                                  },
  { RMAP_NODE,       &no_match_origin_cmd                               },
  { RMAP_NODE,       &no_match_origin_val_cmd                           },
  { RMAP_NODE,       &match_probability_cmd                             },
  { RMAP_NODE,       &no_match_probability_cmd                          },
  { RMAP_NODE,       &no_match_probability_val_cmd                      },

  { RMAP_NODE,       &set_ip_nexthop_cmd                                },
  { RMAP_NODE,       &set_ip_nexthop_peer_cmd                           },
  { RMAP_NODE,       &no_set_ip_nexthop_cmd                             },
  { RMAP_NODE,       &no_set_ip_nexthop_val_cmd                         },
  { RMAP_NODE,       &set_local_pref_cmd                                },
  { RMAP_NODE,       &no_set_local_pref_cmd                             },
  { RMAP_NODE,       &no_set_local_pref_val_cmd                         },
  { RMAP_NODE,       &set_weight_cmd                                    },
  { RMAP_NODE,       &no_set_weight_cmd                                 },
  { RMAP_NODE,       &no_set_weight_val_cmd                             },
  { RMAP_NODE,       &set_metric_cmd                                    },
  { RMAP_NODE,       &set_metric_addsub_cmd                             },
  { RMAP_NODE,       &no_set_metric_cmd                                 },
  { RMAP_NODE,       &no_set_metric_val_cmd                             },
  { RMAP_NODE,       &set_aspath_prepend_cmd                            },
  { RMAP_NODE,       &set_aspath_exclude_cmd                            },
  { RMAP_NODE,       &no_set_aspath_prepend_cmd                         },
  { RMAP_NODE,       &no_set_aspath_prepend_val_cmd                     },
  { RMAP_NODE,       &no_set_aspath_exclude_cmd                         },
  { RMAP_NODE,       &no_set_aspath_exclude_val_cmd                     },
  { RMAP_NODE,       &set_origin_cmd                                    },
  { RMAP_NODE,       &no_set_origin_cmd                                 },
  { RMAP_NODE,       &no_set_origin_val_cmd                             },
  { RMAP_NODE,       &set_atomic_aggregate_cmd                          },
  { RMAP_NODE,       &no_set_atomic_aggregate_cmd                       },
  { RMAP_NODE,       &set_aggregator_as_cmd                             },
  { RMAP_NODE,       &no_set_aggregator_as_cmd                          },
  { RMAP_NODE,       &no_set_aggregator_as_val_cmd                      },
  { RMAP_NODE,       &set_community_cmd                                 },
  { RMAP_NODE,       &set_community_none_cmd                            },
  { RMAP_NODE,       &no_set_community_cmd                              },
  { RMAP_NODE,       &no_set_community_val_cmd                          },
  { RMAP_NODE,       &no_set_community_none_cmd                         },
  { RMAP_NODE,       &set_community_delete_cmd                          },
  { RMAP_NODE,       &no_set_community_delete_cmd                       },
  { RMAP_NODE,       &no_set_community_delete_val_cmd                   },
  { RMAP_NODE,       &set_ecommunity_rt_cmd                             },
  { RMAP_NODE,       &no_set_ecommunity_rt_cmd                          },
  { RMAP_NODE,       &no_set_ecommunity_rt_val_cmd                      },
  { RMAP_NODE,       &set_ecommunity_soo_cmd                            },
  { RMAP_NODE,       &no_set_ecommunity_soo_cmd                         },
  { RMAP_NODE,       &no_set_ecommunity_soo_val_cmd                     },
  { RMAP_NODE,       &set_vpnv4_nexthop_cmd                             },
  { RMAP_NODE,       &no_set_vpnv4_nexthop_cmd                          },
  { RMAP_NODE,       &no_set_vpnv4_nexthop_val_cmd                      },
  { RMAP_NODE,       &set_originator_id_cmd                             },
  { RMAP_NODE,       &no_set_originator_id_cmd                          },
  { RMAP_NODE,       &no_set_originator_id_val_cmd                      },

#ifdef HAVE_IPV6
  { RMAP_NODE,       &match_ipv6_address_cmd                            },
  { RMAP_NODE,       &no_match_ipv6_address_cmd                         },
  { RMAP_NODE,       &match_ipv6_next_hop_cmd                           },
  { RMAP_NODE,       &no_match_ipv6_next_hop_cmd                        },
  { RMAP_NODE,       &match_ipv6_address_prefix_list_cmd                },
  { RMAP_NODE,       &no_match_ipv6_address_prefix_list_cmd             },
  { RMAP_NODE,       &set_ipv6_nexthop_global_cmd                       },
  { RMAP_NODE,       &no_set_ipv6_nexthop_global_cmd                    },
  { RMAP_NODE,       &no_set_ipv6_nexthop_global_val_cmd                },
  { RMAP_NODE,       &set_ipv6_nexthop_local_cmd                        },
  { RMAP_NODE,       &no_set_ipv6_nexthop_local_cmd                     },
  { RMAP_NODE,       &no_set_ipv6_nexthop_local_val_cmd                 },
#endif /* HAVE_IPV6 */

  /* AS-Pathlimit: functionality removed, commands kept for
   * compatibility.
   */
  { RMAP_NODE,       &set_pathlimit_ttl_cmd                             },
  { RMAP_NODE,       &no_set_pathlimit_ttl_cmd                          },
  { RMAP_NODE,       &no_set_pathlimit_ttl_val_cmd                      },
  { RMAP_NODE,       &match_pathlimit_as_cmd                            },
  { RMAP_NODE,       &no_match_pathlimit_as_cmd                         },
  { RMAP_NODE,       &no_match_pathlimit_as_val_cmd                     },

  CMD_INSTALL_END
} ;

/* Initialization of route map command handling                         */
extern void
bgp_route_map_cmd_init (void)
{
  route_map_cmd_init ();

  route_map_install_match (&route_match_peer_cmd);
  route_map_install_match (&route_match_ip_address_cmd);
  route_map_install_match (&route_match_ip_next_hop_cmd);
  route_map_install_match (&route_match_ip_route_source_cmd);
  route_map_install_match (&route_match_ip_address_prefix_list_cmd);
  route_map_install_match (&route_match_ip_next_hop_prefix_list_cmd);
  route_map_install_match (&route_match_ip_route_source_prefix_list_cmd);
  route_map_install_match (&route_match_aspath_cmd);
  route_map_install_match (&route_match_as_origin_cmd);
  route_map_install_match (&route_match_community_cmd);
  route_map_install_match (&route_match_ecommunity_cmd);
  route_map_install_match (&route_match_metric_cmd);
  route_map_install_match (&route_match_origin_cmd);
  route_map_install_match (&route_match_probability_cmd);

  route_map_install_set (&route_set_ip_nexthop_cmd);
  route_map_install_set (&route_set_local_pref_cmd);
  route_map_install_set (&route_set_weight_cmd);
  route_map_install_set (&route_set_metric_cmd);
  route_map_install_set (&route_set_aspath_prepend_cmd);
  route_map_install_set (&route_set_aspath_exclude_cmd);
  route_map_install_set (&route_set_origin_cmd);
  route_map_install_set (&route_set_atomic_aggregate_cmd);
  route_map_install_set (&route_set_aggregator_as_cmd);
  route_map_install_set (&route_set_community_cmd);
  route_map_install_set (&route_set_community_delete_cmd);
  route_map_install_set (&route_set_vpnv4_nexthop_cmd);
  route_map_install_set (&route_set_originator_id_cmd);
  route_map_install_set (&route_set_ecommunity_rt_cmd);
  route_map_install_set (&route_set_ecommunity_soo_cmd);

#ifdef HAVE_IPV6
  route_map_install_match (&route_match_ipv6_address_cmd);
  route_map_install_match (&route_match_ipv6_next_hop_cmd);
  route_map_install_match (&route_match_ipv6_address_prefix_list_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_global_cmd);
  route_map_install_set (&route_set_ipv6_nexthop_local_cmd);
#endif /* HAVE_IPV6 */

  cmd_install_table(bgp_routemap_cmd_table) ;
}

/* Initialization of route map                                          */
void
bgp_route_map_init (void)
{
  route_map_init ();
  route_map_add_hook (bgp_route_map_update);
  route_map_delete_hook (bgp_route_map_update);
}
