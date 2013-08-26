/* BGP VTY interface.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

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
#include "misc.h"

#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "plist.h"
#include "buffer.h"
#include "linklist.h"
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "hash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_peer_vty.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_names.h"

extern struct in_addr router_id_zebra;

/* Utility function to get address family from current node.
 */
extern qAFI_t
bgp_node_afi (struct vty *vty)
{
  switch (vty->node)
    {
      case BGP_NODE:
      case BGP_IPV4_NODE:
      case BGP_IPV4M_NODE:
      case BGP_VPNV4_NODE:
      default:
        return qAFI_IP ;

      case BGP_IPV6_NODE:
      case BGP_IPV6M_NODE:
        return qAFI_IP6 ;
    } ;
} ;

/* Utility function to get subsequent address family from current node.
 */
extern qSAFI_t
bgp_node_safi (struct vty *vty)
{
  switch (vty->node)
    {
      case BGP_NODE:
      case BGP_IPV4_NODE:
      case BGP_IPV6_NODE:
      default:
        return qSAFI_Unicast;

      case BGP_IPV4M_NODE:
      case BGP_IPV6M_NODE:
        return qSAFI_Multicast;

      case BGP_VPNV4_NODE:
        return qSAFI_MPLS_VPN;
    } ;
} ;

/* Utility function to get qafx from current node.
 */
extern qafx_t
bgp_node_qafx (struct vty *vty)
{
  return qafx_from_q(bgp_node_afi(vty), bgp_node_safi(vty));
}

static int
peer_address_self_check (union sockunion *su)
{
  struct interface *ifp = NULL;

  if (su->sa.sa_family == AF_INET)
    ifp = if_lookup_by_ipv4_exact (&su->sin.sin_addr);
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    ifp = if_lookup_by_ipv6_exact (&su->sin6.sin6_addr);
#endif /* HAVE IPV6 */

  if (ifp)
    return 1;

  return 0;
}

/*------------------------------------------------------------------------------
 * Utility function for looking up peer from VTY.
 *
 * Takes an IPv4 or an IPv6 (if supported) address.
 *
 * vty->index is the current bgp instance or NULL for all instances.
 *
 * Returns:  address of *real* peer (not a group) if exists in the bgp instance
 */
static bgp_peer
peer_lookup_vty_index (struct vty *vty, const char* ip_str)
{
  sockunion_t su[1] ;
  bgp_peer    peer ;

  if (str2sockunion (ip_str, su) != 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", ip_str, VTY_NEWLINE);
      return NULL;
    }

  peer = peer_lookup (vty->index, su);
  if (peer == NULL)
    vty_out (vty, "%% Specify remote-as or peer-group commands first%s",
                                                                  VTY_NEWLINE);

  return peer ;
}

/*------------------------------------------------------------------------------
 * Utility function for looking up peer or peer group from VTY.
 *
 * Takes an IPv4 or an IPv6 (if supported) address.
 *
 * vty->index is the current bgp instance or NULL for all instances.
 *
 * Returns:  address of peer or peer group if exists in the bgp instance
 */
static struct peer *
peer_and_group_lookup_vty (struct vty *vty, const char *peer_str)
{
  sockunion_t su[1] ;
  bgp_peer    peer ;

  if (str2sockunion (peer_str, su) == 0)
    {
      peer = peer_lookup (vty->index, su);
      if (peer != NULL)
        return peer;
    }
  else
    {
      struct peer_group *group;

      group = peer_group_lookup (vty->index, peer_str);
      if (group != NULL)
        return group->conf;
    }

  vty_out (vty, "%% Specify remote-as or peer-group commands first%s",
           VTY_NEWLINE);

  return NULL;
} ;

static int
bgp_vty_return (struct vty *vty, int ret)
{
  const char *str = NULL;

  switch (ret)
    {
    case BGP_ERR_BUG:
      str = "Invalid/Unknown something... report as *BUG*" ;
      break ;
    case BGP_ERR_INVALID_VALUE:
      str = "Invalid value";
      break;
    case BGP_ERR_INVALID_FLAG:
      str = "Invalid flag";
      break;
    case BGP_ERR_PEER_INACTIVE:
      str = "Activate the neighbor for the address family first";
      break;
    case BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER:
      str = "Invalid command for a peer-group member";
      break;
    case BGP_ERR_PEER_GROUP_SHUTDOWN:
      str = "Peer-group has been shutdown. Activate the peer-group first";
      break;
    case BGP_ERR_PEER_GROUP_HAS_THE_FLAG:
      str = "This peer is a peer-group member.  Please change peer-group configuration";
      break;
    case BGP_ERR_PEER_FLAG_CONFLICT_1:
      str = "Can't set strict-capability-match with dont-capability-negotiate"
                                                  "and/or override-capability";
      break;
    case BGP_ERR_PEER_FLAG_CONFLICT_2:
      str = "Can't set override-capability with strict-capability-match";
      break;
    case BGP_ERR_PEER_FLAG_CONFLICT_3:
      str = "Can't set dont-capability-negotiate with strict-capability-match";
      break;
    case BGP_ERR_PEER_GROUP_MEMBER_EXISTS:
      str = "No activate for peergroup can be given only if peer-group has no members";
      break;
    case BGP_ERR_PEER_BELONGS_TO_GROUP:
      str = "No activate for an individual peer-group member is invalid";
      break;
    case BGP_ERR_PEER_GROUP_AF_UNCONFIGURED:
      str = "Activate the peer-group for the address family first";
      break;
    case BGP_ERR_PEER_GROUP_NO_REMOTE_AS:
      str = "Specify remote-as or peer-group remote AS first";
      break;
    case BGP_ERR_PEER_GROUP_CANT_CHANGE:
      str = "Cannot change the peer-group. Deconfigure first";
      break;
    case BGP_ERR_PEER_GROUP_MISMATCH:
      str = "Cannot have different peer-group for the neighbor";
      break;
    case BGP_ERR_PEER_FILTER_CONFLICT:
      str = "Prefix/distribute list can not co-exist";
      break;
    case BGP_ERR_NOT_INTERNAL_PEER:
      str = "Invalid command. Not an internal neighbor";
      break;
    case BGP_ERR_REMOVE_PRIVATE_AS:
      str = "Private AS cannot be removed for IBGP peers";
      break;
    case BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP:
      str = "Local-AS allowed only for EBGP peers";
      break;
    case BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS:
      str = "Cannot have local-as same as BGP AS number";
      break;
    case BGP_ERR_TCPSIG_FAILED:
      str = "Error while applying TCP-Sig to session(s)";
      break;
    case BGP_ERR_PEER_EXISTS:
      str = "Cannot have the same neighbor in different bgp views";
    case BGP_ERR_NO_EBGP_MULTIHOP_WITH_GTSM:
      str = "ebgp-multihop and ttl-security cannot be configured together";
      break;
    case BGP_ERR_NO_IBGP_WITH_TTLHACK:
      str = "ttl-security only allowed for EBGP peers";
      break;
    default:
      if (ret >= 0)
        return CMD_SUCCESS ;

      vty_out (vty, "%% unknown error %d%s", ret, VTY_NEWLINE);
      return CMD_WARNING;
    } ;

  vty_out (vty, "%% %s%s", str, VTY_NEWLINE);

  return CMD_WARNING ;
}

/* BGP global configuration.  */

DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       BGP_STR
       "Enable bgp multiple instance\n")
{
  bgp_option_set (BGP_OPT_MULTIPLE_INSTANCE);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       NO_STR
       BGP_STR
       "BGP multiple instance\n")
{
  int ret;

  ret = bgp_option_unset (BGP_OPT_MULTIPLE_INSTANCE);
  if (ret < 0)
    {
      vty_out (vty, "%% There are more than two BGP instances%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (bgp_config_type,
       bgp_config_type_cmd,
       "bgp config-type (cisco|zebra)",
       BGP_STR
       "Configuration type\n"
       "cisco\n"
       "zebra\n")
{
  if (strncmp (argv[0], "c", 1) == 0)
    bgp_option_set (BGP_OPT_CONFIG_CISCO);
  else
    bgp_option_unset (BGP_OPT_CONFIG_CISCO);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_config_type,
       no_bgp_config_type_cmd,
       "no bgp config-type",
       NO_STR
       BGP_STR
       "Display configuration type\n")
{
  bgp_option_unset (BGP_OPT_CONFIG_CISCO);
  return CMD_SUCCESS;
}

DEFUN (no_synchronization,
       no_synchronization_cmd,
       "no synchronization",
       NO_STR
       "Perform IGP synchronization\n")
{
  return CMD_SUCCESS;
}

DEFUN (no_auto_summary,
       no_auto_summary_cmd,
       "no auto-summary",
       NO_STR
       "Enable automatic network number summarization\n")
{
  return CMD_SUCCESS;
}

DEFUN_DEPRECATED (neighbor_version,
                  neighbor_version_cmd,
                  NEIGHBOR_CMD "version (4|4-)",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Set the BGP version to match a neighbor\n"
                  "Neighbor's BGP version\n")
{
  return CMD_SUCCESS;
}

/* "router bgp" commands. */
DEFUN_ATTR (router_bgp,
            router_bgp_cmd,
            "router bgp " CMD_AS_RANGE,
            ROUTER_STR
            BGP_STR
            AS_STR,
            CMD_ATTR_NODE + BGP_NODE)
{
  bgp_ret_t ret;
  as_t as;
  struct bgp *bgp;
  const char *name = NULL;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);

  if (argc == 2)
    name = argv[1];

  ret = bgp_get (&bgp, &as, name);
  switch (ret)
    {
      case BGP_SUCCESS :
        break ;

      case BGP_ERR_MULTIPLE_INSTANCE_NOT_SET:
        vty_out (vty, "Please specify 'bgp multiple-instance' first%s",
                                                                  VTY_NEWLINE);
        return CMD_WARNING;

      case BGP_ERR_AS_MISMATCH:
        vty_out (vty, "BGP is already running; AS is %u%s", as, VTY_NEWLINE);
        return CMD_WARNING;

      case BGP_ERR_INSTANCE_MISMATCH:
        vty_out (vty, "BGP view name and AS number mismatch%s", VTY_NEWLINE);
        vty_out (vty, "BGP instance is already running; AS is %u%s",
                                                              as, VTY_NEWLINE);
        return CMD_WARNING;

      default:
        vty_out (vty, "%% unknown error %d%s", ret, VTY_NEWLINE);
        return CMD_WARNING ;
    }

  vty->node  = BGP_NODE ;
  vty->index = bgp;

  return CMD_SUCCESS;
}

ALIAS_ATTR (router_bgp,
            router_bgp_view_cmd,
            "router bgp " CMD_AS_RANGE " view WORD",
            ROUTER_STR
            BGP_STR
            AS_STR
            "BGP view\n"
            "view name\n",
            CMD_ATTR_NODE + BGP_NODE)

/* "no router bgp" commands. */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp " CMD_AS_RANGE,
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  as_t as;
  struct bgp *bgp;
  const char *name = NULL;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);

  if (argc == 2)
    name = argv[1];

  /* Lookup bgp structure. */
  bgp = bgp_lookup (as, name);
  if (! bgp)
    {
      vty_out (vty, "%% Can't find BGP instance%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_delete (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_router_bgp,
       no_router_bgp_view_cmd,
       "no router bgp " CMD_AS_RANGE " view WORD",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")

/* BGP router-id.  */

DEFUN (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
  int ret;
  struct in_addr id;
  struct bgp *bgp;

  bgp = vty->index;

  ret = inet_aton (argv[0], &id);
  if ((ret == 0) || IPV4_N_NET0(id.s_addr))
    {
      vty_out (vty, "%% Malformed bgp router identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_router_id_set (bgp, id.s_addr, true /* set */);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_router_id,
       no_bgp_router_id_cmd,
       "no bgp router-id",
       NO_STR
       BGP_STR
       "Override configured router identifier\n")
{
  int ret;
  struct in_addr id;
  struct bgp *bgp;

  bgp = vty->index;

  if (argc == 1)
    {
      ret = inet_aton (argv[0], &id);
      if ((ret == 0) || IPV4_N_NET0(id.s_addr))
        {
          vty_out (vty, "%% Malformed BGP router identifier%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      if (!(bgp->config & BGP_CONFIG_ROUTER_ID))
        {
          vty_out (vty, "%% BGP router-id is not set%s", VTY_NEWLINE);
          return CMD_WARNING;
        } ;

      if (bgp->router_id != id.s_addr)
        {
          vty_out (vty, "%% BGP router-id doesn't match%s", VTY_NEWLINE);
          return CMD_WARNING;
        } ;
    } ;

  bgp_router_id_set (bgp, 0, false /* unset */);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_router_id,
       no_bgp_router_id_val_cmd,
       "no bgp router-id A.B.C.D",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")

/*------------------------------------------------------------------------------
 * BGP Cluster ID.
 *
 * Where the cluster-id is defined as an integer, that is handled by inet_aton()
 * as a single part address and stored in Network Order.
 */
DEFUN (bgp_cluster_id,
       bgp_cluster_id_cmd,
       "bgp cluster-id A.B.C.D",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")
{
  struct in_addr cluster;

  if (inet_aton (argv[0], &cluster) == 0)
    {
      vty_out (vty, "%% Malformed bgp cluster identifier%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_cluster_id_set (vty->index, cluster.s_addr, true /* set */) ;

  return CMD_SUCCESS;
}

ALIAS (bgp_cluster_id,
       bgp_cluster_id32_cmd,
       "bgp cluster-id <1-4294967295>",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")

DEFUN (no_bgp_cluster_id,
       no_bgp_cluster_id_cmd,
       "no bgp cluster-id",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n")
{
  struct in_addr cluster;

  if (argc == 1)
    {
      if (inet_aton (argv[0], &cluster) == 0)
        {
          vty_out (vty, "%% Malformed bgp cluster identifier%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  bgp_cluster_id_set (vty->index, 0, false /* unset */) ;

  return CMD_SUCCESS;
}

ALIAS (no_bgp_cluster_id,
       no_bgp_cluster_id_arg_cmd,
       "no bgp cluster-id A.B.C.D",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")

DEFUN (bgp_confederation_identifier,
       bgp_confederation_identifier_cmd,
       "bgp confederation identifier " CMD_AS_RANGE,
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")
{
  struct bgp *bgp;
  as_t confed_id;

  bgp = vty->index;

  VTY_GET_INTEGER_RANGE ("AS", confed_id, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);

  bgp_confederation_id_set (bgp, confed_id);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n")
{
  struct bgp *bgp;
  as_t as  Unused ;

  bgp = vty->index;

  if (argc == 1)
    VTY_GET_INTEGER_RANGE ("AS", as, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);
  qassert(as != 0) ;            /* "use" the as to silence compiler     */

  bgp_confederation_id_unset (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_arg_cmd,
       "no bgp confederation identifier " CMD_AS_RANGE,
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")

DEFUN (bgp_confederation_peers,
       bgp_confederation_peers_cmd,
       "bgp confederation peers .ASs",
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  struct bgp *bgp;
  as_t as;
  int i;

  bgp = vty->index;

  for (i = 0; i < argc; i++)
    VTY_GET_INTEGER_RANGE ("AS", as, argv[i], BGP_ASN_FIRST, BGP_ASN_LAST);

  for (i = 0; i < argc; i++)
    {
      VTY_GET_INTEGER_RANGE ("AS", as, argv[i], BGP_ASN_FIRST, BGP_ASN_LAST);

      if (as == bgp->my_as)
        {
          vty_out (vty, "%% Local member-AS not allowed in confed peer list%s",
                   VTY_NEWLINE);
          continue;
        }

      bgp_confederation_peers_add (bgp, as);    /* update confed_peers  */
    }

  bgp_confederation_peers_scan(bgp) ;           /* complete the process */

  return CMD_SUCCESS;
}

DEFUN (no_bgp_confederation_peers,
       no_bgp_confederation_peers_cmd,
       "no bgp confederation peers .ASs",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  struct bgp *bgp;
  as_t as;
  int i;

  bgp = vty->index;

  for (i = 0; i < argc; i++)
    VTY_GET_INTEGER_RANGE ("AS", as, argv[i], BGP_ASN_FIRST, BGP_ASN_LAST);

  for (i = 0; i < argc; i++)
    {
      VTY_GET_INTEGER_RANGE ("AS", as, argv[i], BGP_ASN_FIRST, BGP_ASN_LAST);

      bgp_confederation_peers_remove (bgp, as); /* update confed_peers  */
    }

  bgp_confederation_peers_scan(bgp) ;           /* complete the process */

  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * BGP timers.
 *
 * Sets the default values for session keepalive and holdtime.  These values
 * are used where a peer does not have its own setting, or a peer is a member
 * of a group which does not have its own setting.
 *
 * NB: changing the default does not affect any existing sessions.
 */
DEFUN (bgp_timers,
       bgp_timers_cmd,
       "timers bgp <0-65535> <0-65535>",
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  bgp_inst bgp;
  uint keepalive, holdtime ;

  bgp = vty->index;

  VTY_GET_INTEGER ("keepalive", keepalive, argv[0]);
  VTY_GET_INTEGER ("holdtime",  holdtime,  argv[1]);

  /* Holdtime value check.
   */
  if ((holdtime < 3) && (holdtime != 0))
    {
      vty_out (vty, "%% hold time value must be either 0 or greater than 3%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_timers_set (bgp, keepalive, holdtime);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_timers,
       no_bgp_timers_cmd,
       "no timers bgp",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_timers_unset (bgp);

  return CMD_SUCCESS;
}

ALIAS (no_bgp_timers,
       no_bgp_timers_arg_cmd,
       "no timers bgp <0-65535> <0-65535>",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

DEFUN (bgp_client_to_client_reflection,
       bgp_client_to_client_reflection_cmd,
       "bgp client-to-client reflection",
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_client_to_client_reflection,
       no_bgp_client_to_client_reflection_cmd,
       "no bgp client-to-client reflection",
       NO_STR
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT);
  return CMD_SUCCESS;
}

/* "bgp always-compare-med" configuration. */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ALWAYS_COMPARE_MED);
  return CMD_SUCCESS;
}

/* "bgp deterministic-med" configuration. */
DEFUN (bgp_deterministic_med,
       bgp_deterministic_med_cmd,
       "bgp deterministic-med",
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_DETERMINISTIC_MED);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_deterministic_med,
       no_bgp_deterministic_med_cmd,
       "no bgp deterministic-med",
       NO_STR
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_DETERMINISTIC_MED);
  return CMD_SUCCESS;
}

/* "bgp graceful-restart" configuration. */
DEFUN (bgp_graceful_restart,
       bgp_graceful_restart_cmd,
       "bgp graceful-restart",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_GRACEFUL_RESTART);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart,
       no_bgp_graceful_restart_cmd,
       "no bgp graceful-restart",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_GRACEFUL_RESTART);
  return CMD_SUCCESS;
}

DEFUN (bgp_graceful_restart_stalepath_time,
       bgp_graceful_restart_stalepath_time_cmd,
       "bgp graceful-restart stalepath-time <1-3600>",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")
{
  struct bgp *bgp;
  u_int32_t stalepath;

  bgp = vty->index;
  if (! bgp)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("stalepath-time", stalepath, argv[0], 1, 3600);
  bgp->stalepath_time = stalepath;
  return CMD_SUCCESS;
}

DEFUN (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_cmd,
       "no bgp graceful-restart stalepath-time",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  if (! bgp)
    return CMD_WARNING;

  bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_val_cmd,
       "no bgp graceful-restart stalepath-time <1-3600>",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")

/* "bgp fast-external-failover" configuration. */
DEFUN (bgp_fast_external_failover,
       bgp_fast_external_failover_cmd,
       "bgp fast-external-failover",
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_fast_external_failover,
       no_bgp_fast_external_failover_cmd,
       "no bgp fast-external-failover",
       NO_STR
       BGP_STR
       "Immediately reset session if a link to a directly connected external peer goes down\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_FAST_EXT_FAILOVER);
  return CMD_SUCCESS;
}

/* "bgp enforce-first-as" configuration. */
DEFUN (bgp_enforce_first_as,
       bgp_enforce_first_as_cmd,
       "bgp enforce-first-as",
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ENFORCE_FIRST_AS);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_enforce_first_as,
       no_bgp_enforce_first_as_cmd,
       "no bgp enforce-first-as",
       NO_STR
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ENFORCE_FIRST_AS);
  return CMD_SUCCESS;
}

/* "bgp bestpath compare-routerid" configuration.  */
DEFUN (bgp_bestpath_compare_router_id,
       bgp_bestpath_compare_router_id_cmd,
       "bgp bestpath compare-routerid",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_COMPARE_ROUTER_ID);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_compare_router_id,
       no_bgp_bestpath_compare_router_id_cmd,
       "no bgp bestpath compare-routerid",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_COMPARE_ROUTER_ID);
  return CMD_SUCCESS;
}

/* "bgp bestpath as-path ignore" configuration.  */
DEFUN (bgp_bestpath_aspath_ignore,
       bgp_bestpath_aspath_ignore_cmd,
       "bgp bestpath as-path ignore",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ASPATH_IGNORE);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_ignore,
       no_bgp_bestpath_aspath_ignore_cmd,
       "no bgp bestpath as-path ignore",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ASPATH_IGNORE);
  return CMD_SUCCESS;
}

/* "bgp bestpath as-path confed" configuration.  */
DEFUN (bgp_bestpath_aspath_confed,
       bgp_bestpath_aspath_confed_cmd,
       "bgp bestpath as-path confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_ASPATH_CONFED);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_aspath_confed,
       no_bgp_bestpath_aspath_confed_cmd,
       "no bgp bestpath as-path confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets & sequences in selecting a route\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_ASPATH_CONFED);
  return CMD_SUCCESS;
}

/* "bgp log-neighbor-changes" configuration.  */
DEFUN (bgp_log_neighbor_changes,
       bgp_log_neighbor_changes_cmd,
       "bgp log-neighbor-changes",
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_log_neighbor_changes,
       no_bgp_log_neighbor_changes_cmd,
       "no bgp log-neighbor-changes",
       NO_STR
       "BGP specific commands\n"
       "Log neighbor up/down and reset reason\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
  return CMD_SUCCESS;
}

/* "bgp bestpath med" configuration. */
DEFUN (bgp_bestpath_med,
       bgp_bestpath_med_cmd,
       "bgp bestpath med (confed|missing-as-worst)",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (strncmp (argv[0], "confed", 1) == 0)
    bgp_flag_set (bgp, BGP_FLAG_MED_CONFED);
  else
    {
      bgp_flag_set (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
      bgp->default_med = BGP_MED_MAX ;
    } ;

  return CMD_SUCCESS;
}

DEFUN (bgp_bestpath_med2,
       bgp_bestpath_med2_cmd,
       "bgp bestpath med confed missing-as-worst",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_MED_CONFED);
  bgp_flag_set (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
  bgp->default_med = BGP_MED_MAX ;
  return CMD_SUCCESS;
}

ALIAS (bgp_bestpath_med2,
       bgp_bestpath_med3_cmd,
       "bgp bestpath med missing-as-worst confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

DEFUN (no_bgp_bestpath_med,
       no_bgp_bestpath_med_cmd,
       "no bgp bestpath med (confed|missing-as-worst)",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;

  bgp = vty->index;

  if (strncmp (argv[0], "confed", 1) == 0)
    bgp_flag_unset (bgp, BGP_FLAG_MED_CONFED);
  else
    {
      bgp_flag_unset (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
      bgp->default_med = BGP_MED_MIN ;
    } ;

  return CMD_SUCCESS;
}

DEFUN (no_bgp_bestpath_med2,
       no_bgp_bestpath_med2_cmd,
       "no bgp bestpath med confed missing-as-worst",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_MED_CONFED);
  bgp_flag_unset (bgp, BGP_FLAG_MED_MISSING_AS_WORST);
  bgp->default_med = BGP_MED_MIN ;
  return CMD_SUCCESS;
}

ALIAS (no_bgp_bestpath_med2,
       no_bgp_bestpath_med3_cmd,
       "no bgp bestpath med missing-as-worst confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

/* "no bgp default ipv4-unicast". */
DEFUN (no_bgp_default_ipv4_unicast,
       no_bgp_default_ipv4_unicast_cmd,
       "no bgp default ipv4-unicast",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

DEFUN (bgp_default_ipv4_unicast,
       bgp_default_ipv4_unicast_cmd,
       "bgp default ipv4-unicast",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_NO_DEFAULT_IPV4);
  return CMD_SUCCESS;
}

/* "bgp import-check" configuration.  */
DEFUN (bgp_network_import_check,
       bgp_network_import_check_cmd,
       "bgp network import-check",
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_set (bgp, BGP_FLAG_IMPORT_CHECK);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_network_import_check,
       no_bgp_network_import_check_cmd,
       "no bgp network import-check",
       NO_STR
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_flag_unset (bgp, BGP_FLAG_IMPORT_CHECK);
  return CMD_SUCCESS;
}

DEFUN (bgp_default_local_preference,
       bgp_default_local_preference_cmd,
       "bgp default local-preference <0-4294967295>",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
  struct bgp *bgp;
  u_int32_t local_pref;

  bgp = vty->index;

  VTY_GET_INTEGER ("local preference", local_pref, argv[0]);

  bgp_default_local_preference_set (bgp, local_pref);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_default_local_preference,
       no_bgp_default_local_preference_cmd,
       "no bgp default local-preference",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n")
{
  struct bgp *bgp;

  bgp = vty->index;
  bgp_default_local_preference_unset (bgp);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_default_local_preference,
       no_bgp_default_local_preference_val_cmd,
       "no bgp default local-preference <0-4294967295>",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")

static cmd_ret_t
peer_remote_as_vty (struct vty *vty, const char *peer_str,
                                                const char *as_str, qafx_t qafx)
{
  bgp_ret_t ret;
  as_t as;
  sockunion_t su[1] ;

  /* Get AS number.
   */
  VTY_GET_INTEGER_RANGE ("AS", as, as_str, BGP_ASN_FIRST, BGP_ASN_LAST);

  /* If peer is peer group, call proper function.
   */
  if (str2sockunion (peer_str, su) != 0)
    {
      ret = peer_group_remote_as (vty->index, peer_str, &as);

      if (ret < 0)
        {
          vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      return CMD_SUCCESS;
    }

  if (peer_address_self_check (su))
    {
      vty_out (vty, "%% Can not configure the local system as neighbor%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_remote_as (vty->index, su, &as, qafx);

  /* This peer belongs to peer group.
   */
  switch (ret)
    {
      case BGP_ERR_PEER_GROUP_MEMBER:
        vty_out (vty, "%% Peer-group AS %u.  "
                   "Cannot configure remote-as for member%s", as, VTY_NEWLINE);
        return CMD_WARNING;

      case BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
        vty_out (vty, "%% The AS# can not be changed from %u to %s, "
            "peer-group members must be all internal or all external%s",
                                                      as, as_str, VTY_NEWLINE);
        return CMD_WARNING;

      default:
        break ;
    } ;

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       NEIGHBOR_CMD2 "remote-as " CMD_AS_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR)
{
  return peer_remote_as_vty (vty, argv[0], argv[1], qafx_ipv4_unicast);
}

DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
  struct bgp *bgp;
  struct peer_group *group;

  bgp = vty->index;

  group = peer_group_get (bgp, argv[0]);
  if (! group)
    return CMD_WARNING;

  return CMD_SUCCESS;
}

DEFUN (no_neighbor,
       no_neighbor_cmd,
       NO_NEIGHBOR_CMD2,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2)
{
  int ret;
  union sockunion su;
  struct peer_group *group;
  struct peer *peer;

  ret = str2sockunion (argv[0], &su);
  if (ret == 0)
    {
      peer = peer_lookup (vty->index, &su);
      if (peer != NULL)
        bgp_peer_delete (peer);
    }
  else
    {
      group = peer_group_lookup (vty->index, argv[0]);
      if (group != NULL)
        peer_group_delete (group);
      else
        {
          vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
    } ;

  return CMD_SUCCESS;
}

ALIAS (no_neighbor,
       no_neighbor_remote_as_cmd,
       NO_NEIGHBOR_CMD "remote-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)

DEFUN (no_neighbor_peer_group,
       no_neighbor_peer_group_cmd,
       "no neighbor WORD peer-group",
       NO_STR
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Configure peer-group\n")
{
  struct peer_group *group;

  group = peer_group_lookup (vty->index, argv[0]);
  if (group)
    peer_group_delete (group);
  else
    {
      vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (no_neighbor_peer_group_remote_as,
       no_neighbor_peer_group_remote_as_cmd,
       "no neighbor WORD remote-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       "Neighbor tag\n"
       "Specify a BGP neighbor\n"
       AS_STR)
{
  struct peer_group *group;

  group = peer_group_lookup (vty->index, argv[0]);
  if (group)
    peer_group_remote_as_delete (group);
  else
    {
      vty_out (vty, "%% Create the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

DEFUN (neighbor_local_as,
       neighbor_local_as_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_set (peer, strtoul_s(argv[1]), false /* no-prepend */);
  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_local_as_no_prepend,
       neighbor_local_as_no_prepend_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_set (peer, strtoul_s(argv[1]), true /* no-prepend */);
  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_local_as,
       no_neighbor_local_as_cmd,
       NO_NEIGHBOR_CMD2 "local-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_local_as_unset (peer);
  return bgp_vty_return (vty, ret);
}

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val2_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")

DEFUN (neighbor_password,
       neighbor_password_cmd,
       NEIGHBOR_CMD2 "password LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_password_set (peer, argv[1]);
  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_password,
       no_neighbor_password_cmd,
       NO_NEIGHBOR_CMD2 "password",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_password_unset (peer);
  return bgp_vty_return (vty, ret);
}

/*==============================================================================
 * Activate and de-activate peer or peer-group in the current afi/safi.
 *
 * For activate:
 *
 *
 */

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       NEIGHBOR_CMD2 "activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  peer_set_af (peer, bgp_node_qafx(vty), true /* and enable */);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       NO_NEIGHBOR_CMD2 "activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  int ret;
  struct peer *peer;

  /* Lookup peer. */
  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_deactivate (peer, bgp_node_qafx(vty));

  return bgp_vty_return (vty, ret);
}

/*==============================================================================
 * Add/remove given peer to/from the given peer-group in the current afi/safi.
 *
 * For add:
 *
 *   * if the peer does not exist, will create it iff the group has an AS
 *
 *   * if the peer exists, but is not activated for the afi/safi, this
 *     implicitly activates it -- *after* updating its configuration.
 *
 * For remove:
 *
 *   * has no effect at all if the peer is not activated for the afi/safi.
 */

DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       NEIGHBOR_CMD "peer-group WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "peer-group name\n")
{
  int ret;
  as_t as;
  sockunion_t su[1] ;
  struct bgp *bgp;
  struct peer_group *group;

  bgp = vty->index;

  ret = str2sockunion (argv[0], su);
  if (ret < 0)
    {
      vty_out (vty, "%% Malformed address: %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  group = peer_group_lookup (bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (peer_address_self_check (su))
    {
      vty_out (vty, "%% Can not configure the local system as neighbor%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_bind (bgp, su, group, bgp_node_qafx(vty), &as);

  if (ret == BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT)
    {
      vty_out (vty, "%% Peer with AS %u cannot be in this peer-group, "
             "members must be all internal or all external%s", as, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_vty_return (vty, ret);
}

DEFUN (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_cmd,
       NO_NEIGHBOR_CMD "peer-group WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "peer-group name\n")
{
  int ret;
  struct peer *peer;
  struct peer_group *group;

  peer = peer_lookup_vty_index (vty, argv[0]);
  if (peer == NULL)
    return CMD_WARNING;

  group = peer_group_lookup (peer->bgp, argv[1]);
  if (! group)
    {
      vty_out (vty, "%% Configure the peer-group first%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = peer_group_unbind (peer, group, bgp_node_qafx(vty));

  return bgp_vty_return (vty, ret);
}

static int
peer_flag_modify_vty (struct vty *vty, const char *ip_str,
                      u_int16_t flag, int set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = bgp_peer_flag_modify (peer, flag, set);

  return bgp_vty_return (vty, ret);
}

static int
peer_flag_set_vty (struct vty *vty, const char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (vty, ip_str, flag, 1);
}

static int
peer_flag_unset_vty (struct vty *vty, const char *ip_str, u_int16_t flag)
{
  return peer_flag_modify_vty (vty, ip_str, flag, 0);
}

/* neighbor passive. */
DEFUN (neighbor_passive,
       neighbor_passive_cmd,
       NEIGHBOR_CMD2 "passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_PASSIVE);
}

DEFUN (no_neighbor_passive,
       no_neighbor_passive_cmd,
       NO_NEIGHBOR_CMD2 "passive",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_PASSIVE);
}

/*==============================================================================
 * Peer/Peer-Group shutdown
 *
 * For peer:
 *
 *   * can shutdown a peer which is a member of a group, separately from all
 *     other members of the group.
 *
 *   * shutdown will disable any running session, and leave peer disabled.
 *
 *   * startup (no shutdown) reverses any shutdown.
 *
 *
 * For group:
 *
 */

/* neighbor shutdown. */
DEFUN (neighbor_shutdown,
       neighbor_shutdown_cmd,
       NEIGHBOR_CMD2 "shutdown",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_SHUTDOWN);
}

DEFUN (no_neighbor_shutdown,
       no_neighbor_shutdown_cmd,
       NO_NEIGHBOR_CMD2 "shutdown",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively shut down this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_SHUTDOWN);
}

ALIAS (no_neighbor_shutdown,
       neighbor_startup_cmd,
       NEIGHBOR_CMD2 "startup",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Administratively start this neighbor (reverse shut down)\n") ;



/* Deprecated neighbor capability route-refresh. */
DEFUN_DEPRECATED (neighbor_capability_route_refresh,
                  neighbor_capability_route_refresh_cmd,
                  NEIGHBOR_CMD2 "capability route-refresh",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR2
                  "Advertise capability to the peer\n"
                  "Advertise route-refresh capability to this neighbor\n")
{
  return CMD_SUCCESS;
}

DEFUN_DEPRECATED (no_neighbor_capability_route_refresh,
                  no_neighbor_capability_route_refresh_cmd,
                  NO_NEIGHBOR_CMD2 "capability route-refresh",
                  NO_STR
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR2
                  "Advertise capability to the peer\n"
                  "Advertise route-refresh capability to this neighbor\n")
{
  return CMD_SUCCESS;
}

/* neighbor capability dynamic. */
DEFUN (neighbor_capability_dynamic,
       neighbor_capability_dynamic_cmd,
       NEIGHBOR_CMD2 "capability dynamic",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

DEFUN (no_neighbor_capability_dynamic,
       no_neighbor_capability_dynamic_cmd,
       NO_NEIGHBOR_CMD2 "capability dynamic",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DYNAMIC_CAPABILITY);
}

/* neighbor dont-capability-negotiate */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       NEIGHBOR_CMD2 "dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       NO_NEIGHBOR_CMD2 "dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DONT_CAPABILITY);
}

static int
peer_af_flag_modify_vty (struct vty *vty, const char *peer_str, qafx_t qafx,
                                                        uint32_t flag, bool set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_af_flag_modify(peer, qafx, flag, set);

  return bgp_vty_return (vty, ret);
}

static int
peer_af_flag_set_vty (struct vty *vty, const char *peer_str, qafx_t qafx,
                                                                 uint32_t flag)
{
  return peer_af_flag_modify_vty (vty, peer_str, qafx, flag, true);
}

static int
peer_af_flag_unset_vty (struct vty *vty, const char *peer_str, qafx_t qafx,
                                                                 uint32_t flag)
{
  return peer_af_flag_modify_vty (vty, peer_str, qafx, flag, false);
}

/* neighbor capability orf prefix-list. */
DEFUN (neighbor_capability_orf_prefix,
       neighbor_capability_orf_prefix_cmd,
       NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  bgp_orf_cap_bits_t orfs ;

  if (strncmp (argv[1], "s", 1) == 0)
    orfs = ORF_SM ;
  else if (strncmp (argv[1], "r", 1) == 0)
    orfs = ORF_RM ;
  else if (strncmp (argv[1], "b", 1) == 0)
    orfs = ORF_SM | ORF_RM ;
  else
    return CMD_WARNING;

  return peer_orfs_set_vty (vty, argv[0], bgp_node_qafx(vty), orfs);
}

DEFUN (no_neighbor_capability_orf_prefix,
       no_neighbor_capability_orf_prefix_cmd,
       NO_NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  bgp_orf_cap_bits_t orfs ;

  if (strncmp (argv[1], "s", 1) == 0)
    orfs = ORF_SM;
  else if (strncmp (argv[1], "r", 1) == 0)
    orfs = ORF_RM;
  else if (strncmp (argv[1], "b", 1) == 0)
    orfs = ORF_SM | ORF_RM;
  else
    return CMD_WARNING;

  return peer_orfs_unset_vty (vty, argv[0], bgp_node_qafx(vty), orfs);
}

/* neighbor next-hop-self. */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       NEIGHBOR_CMD2 "next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                       PEER_AFF_NEXTHOP_SELF);
}

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       NO_NEIGHBOR_CMD2 "next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                        PEER_AFF_NEXTHOP_SELF);
}

/* neighbor remove-private-AS. */
DEFUN (neighbor_remove_private_as,
       neighbor_remove_private_as_cmd,
       NEIGHBOR_CMD2 "remove-private-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private AS number from outbound updates\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                   PEER_AFF_REMOVE_PRIVATE_AS);
}

DEFUN (no_neighbor_remove_private_as,
       no_neighbor_remove_private_as_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private AS number from outbound updates\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                   PEER_AFF_REMOVE_PRIVATE_AS);
}

/* neighbor send-community. */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       NEIGHBOR_CMD2 "send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                     PEER_AFF_SEND_COMMUNITY);
}

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       NO_NEIGHBOR_CMD2 "send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                     PEER_AFF_SEND_COMMUNITY);
}

/* neighbor send-community extended. */
DEFUN (neighbor_send_community_type,
       neighbor_send_community_type_cmd,
       NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  if (strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                     PEER_AFF_SEND_COMMUNITY);
  if (strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                 PEER_AFF_SEND_EXT_COMMUNITY);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                    (PEER_AFF_SEND_COMMUNITY | PEER_AFF_SEND_EXT_COMMUNITY));
}

DEFUN (no_neighbor_send_community_type,
       no_neighbor_send_community_type_cmd,
       NO_NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  if (strncmp (argv[1], "s", 1) == 0)
    return peer_af_flag_unset_vty (vty, argv[0],bgp_node_qafx(vty),
                                                      PEER_AFF_SEND_COMMUNITY);
  if (strncmp (argv[1], "e", 1) == 0)
    return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                  PEER_AFF_SEND_EXT_COMMUNITY);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                     (PEER_AFF_SEND_COMMUNITY | PEER_AFF_SEND_EXT_COMMUNITY));
}

/* neighbor soft-reconfig. */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                      PEER_AFF_SOFT_RECONFIG);
}

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       NO_NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                      PEER_AFF_SOFT_RECONFIG);
}

DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       NEIGHBOR_CMD2 "route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  struct peer *peer;


  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                   PEER_AFF_REFLECTOR_CLIENT);
}

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       NO_NEIGHBOR_CMD2 "route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                                   PEER_AFF_REFLECTOR_CLIENT);
}

static int
peer_rsclient_set_vty (struct vty *vty, const char *peer_str, qafx_t qafx)
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;
  struct listnode *node, *nnode;
  struct bgp_filter *pfilter;
  struct bgp_filter *gfilter;

  if ((qafx < qafx_first) || (qafx > qafx_last))
    {
      vty_out (vty, "%% unknown qafx %u -- BUG", qafx) ;
      return CMD_WARNING ;
    } ;

  bgp = vty->index ;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if ( ! peer )
    return CMD_WARNING;

  /* If it is already a RS-Client, don't do anything.
   */
  if ( xxx )
    return CMD_SUCCESS;

  ret = peer_af_flag_set (peer, qafx, PEER_AFF_RSERVER_CLIENT);
  if (ret < 0)
    return bgp_vty_return (vty, ret);

  peer->prib[qafx] = bgp_table_init (qafx);
  peer->prib[qafx]->rib_type = BGP_TABLE_RSCLIENT;

  /* RIB peer reference.  Released when table is free'd in bgp_table_free.
   */
  peer->prib[qafx]->owner = bgp_peer_lock (peer);

  /* Check for existing 'network' and 'redistribute' routes.
   */
  bgp_check_local_routes_rsclient (peer, qafx);

  /* Check for routes for peers configured with 'soft-reconfiguration'.
   */
  bgp_soft_reconfig_rsclient_in (peer, qafx);

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      group   = peer->group;
      gfilter = &group->conf->filter[qafx];

      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          pfilter = &peer->filter[qafx];

          /* Members of a non-RS-Client group should not be RS-Clients, as that
           * is checked when the become part of the peer-group
           */
          ret = peer_af_flag_set (peer, qafx, PEER_AFF_RSERVER_CLIENT);
          if (ret < 0)
            return bgp_vty_return (vty, ret);

          /* Make peer's RIB point to group's RIB.
           */
          peer->prib[qafx] = group->conf->prib[qafx];

          /* Import policy.
           */
          route_map_clear_ref(pprib->filter.rmap[RMAP_IMPORT]) ;
          pprib->filter.rmap[RMAP_IMPORT]
                          = route_map_set_ref(gprib->filter.rmap[RMAP_IMPORT]) ;

          /* Export policy.
           */
          if (pprib->filter.rmap[RMAP_EXPORT] == NULL)
            pprib->filter.rmap[RMAP_EXPORT]
                               = route_map_set_ref(gprib->filter.rmap[RMAP_EXPORT]) ;
        }
    }
  return CMD_SUCCESS;
}

static int
peer_rsclient_unset_vty (struct vty *vty, const char *peer_str,
                         qAFI_t q_afi, qSAFI_t q_safi)
{
  int ret;
  struct bgp *bgp;
  struct peer *peer;
  struct peer_group *group;
  struct listnode *node, *nnode;
  qafx_t qafx ;

  qafx = qafx_from_q(q_afi, q_safi) ;

  bgp = vty->index;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if ( ! peer )
    return CMD_WARNING;

  assert(bgp == peer->bgp) ;

  /* If it is not a RS-Client, don't do anything. */
  if ( ! xxx )
    return CMD_SUCCESS;

  /* If this is a Peer Group, then need to undo the relevant rsclient state
   * for all the group members.
   *
   * That means clearing the state flag and the pointer to the shared RIB.
   *
   * TODO: peer_af_flag_unset PEER_AFF_RSERVER_CLIENT fails for group members ?
   */
  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      group = peer->group;

      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          ret = peer_af_flag_unset (peer, qafx, PEER_AFF_RSERVER_CLIENT);
          if (ret < 0)
            return bgp_vty_return (vty, ret);

          peer->prib[qafx] = NULL;
        }

        peer = group->conf;
    }

  /* Unset the rsclient flag and remove from rsclient list if no longer a
   * distinct rsclient.
   *
   * NB: this takes care of downing the peer, if required.
   */
  ret = peer_af_flag_unset (peer, qafx, PEER_AFF_RSERVER_CLIENT);
  if (ret < 0)
    return bgp_vty_return (vty, ret);

  /* Now tidy up the data structures.                                   */
  peer_rsclient_unset(peer, qafx, false) ;

  return CMD_SUCCESS;
}

/* neighbor route-server-client. */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       NEIGHBOR_CMD2 "route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  return peer_rsclient_set_vty (vty, argv[0], bgp_node_qafx(vty));
}

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       NO_NEIGHBOR_CMD2 "route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  return peer_rsclient_unset_vty (vty, argv[0], bgp_node_afi(vty),
                  bgp_node_safi(vty));
}

DEFUN (neighbor_nexthop_local_unchanged,
       neighbor_nexthop_local_unchanged_cmd,
       NEIGHBOR_CMD2 "nexthop-local unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                           PEER_AFF_NEXTHOP_LOCAL_UNCHANGED );
}

DEFUN (no_neighbor_nexthop_local_unchanged,
       no_neighbor_nexthop_local_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "nexthop-local unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local-nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                           PEER_AFF_NEXTHOP_LOCAL_UNCHANGED );
}

DEFUN (neighbor_attr_unchanged,
       neighbor_attr_unchanged_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                        (PEER_AFF_AS_PATH_UNCHANGED |
                                         PEER_AFF_NEXTHOP_UNCHANGED |
                                         PEER_AFF_MED_UNCHANGED));
}

DEFUN (neighbor_attr_unchanged1,
       neighbor_attr_unchanged1_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = 0;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

DEFUN (neighbor_attr_unchanged2,
       neighbor_attr_unchanged2_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_AFF_AS_PATH_UNCHANGED;

  if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty), flags);

}

DEFUN (neighbor_attr_unchanged3,
       neighbor_attr_unchanged3_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_AFF_NEXTHOP_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

DEFUN (neighbor_attr_unchanged4,
       neighbor_attr_unchanged4_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  u_int16_t flags = PEER_AFF_MED_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);

  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged5_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged6_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged7_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged8_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged9_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged10_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

DEFUN (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty),
                                 (PEER_AFF_AS_PATH_UNCHANGED |
                                  PEER_AFF_NEXTHOP_UNCHANGED |
                                  PEER_AFF_MED_UNCHANGED));
}

DEFUN (no_neighbor_attr_unchanged1,
       no_neighbor_attr_unchanged1_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = 0;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

DEFUN (no_neighbor_attr_unchanged2,
       no_neighbor_attr_unchanged2_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_AFF_AS_PATH_UNCHANGED;

  if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

DEFUN (no_neighbor_attr_unchanged3,
       no_neighbor_attr_unchanged3_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  u_int16_t flags = PEER_AFF_NEXTHOP_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "med", 1) == 0)
    SET_FLAG (flags, PEER_AFF_MED_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

DEFUN (no_neighbor_attr_unchanged4,
       no_neighbor_attr_unchanged4_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  u_int16_t flags = PEER_AFF_MED_UNCHANGED;

  if (strncmp (argv[1], "as-path", 1) == 0)
    SET_FLAG (flags, PEER_AFF_AS_PATH_UNCHANGED);
  else if (strncmp (argv[1], "next-hop", 1) == 0)
    SET_FLAG (flags, PEER_AFF_NEXTHOP_UNCHANGED);

  return peer_af_flag_unset_vty (vty, argv[0], bgp_node_qafx(vty), flags);
}

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged5_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged6_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged7_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged8_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged9_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged10_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

/* For old version Zebra compatibility.  */
DEFUN_DEPRECATED (neighbor_transparent_as,
                  neighbor_transparent_as_cmd,
                  NEIGHBOR_CMD "transparent-as",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Do not append my AS number even peer is EBGP peer\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                  PEER_AFF_AS_PATH_UNCHANGED);
}

DEFUN_DEPRECATED (neighbor_transparent_nexthop,
                  neighbor_transparent_nexthop_cmd,
                  NEIGHBOR_CMD "transparent-nexthop",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Do not change nexthop even peer is EBGP peer\n")
{
  return peer_af_flag_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                  PEER_AFF_NEXTHOP_UNCHANGED);
}

/* EBGP multihop configuration. */
static int
peer_ebgp_multihop_set_vty (struct vty *vty, const char *ip_str,
                            const char *ttl_str)
{
  struct peer *peer;
  unsigned int ttl;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  if (! ttl_str)
    ttl = MAXTTL;
  else
    VTY_GET_INTEGER_RANGE ("TTL", ttl, ttl_str, 1, MAXTTL);

  return bgp_vty_return (vty,  peer_ebgp_multihop_set (peer, ttl));
}

static int
peer_ebgp_multihop_unset_vty (struct vty *vty, const char *ip_str)
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  return bgp_vty_return (vty, peer_ebgp_multihop_unset (peer));
}

/* neighbor ebgp-multihop. */
DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_set_vty (vty, argv[0], NULL);
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return peer_ebgp_multihop_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return peer_ebgp_multihop_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_ttl_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

/* disable-connected-check */
DEFUN (neighbor_disable_connected_check,
       neighbor_disable_connected_check_cmd,
       NEIGHBOR_CMD2 "disable-connected-check",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

DEFUN (no_neighbor_disable_connected_check,
       no_neighbor_disable_connected_check_cmd,
       NO_NEIGHBOR_CMD2 "disable-connected-check",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_DISABLE_CONNECTED_CHECK);
}

/* Enforce multihop.  */
ALIAS (neighbor_disable_connected_check,
       neighbor_enforce_multihop_cmd,
       NEIGHBOR_CMD2 "enforce-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

/* Enforce multihop.  */
ALIAS (no_neighbor_disable_connected_check,
       no_neighbor_enforce_multihop_cmd,
       NO_NEIGHBOR_CMD2 "enforce-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

DEFUN (neighbor_description,
       neighbor_description_cmd,
       NEIGHBOR_CMD2 "description .LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  struct peer *peer;
  char *str;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 1)
    return CMD_SUCCESS;

  str = argv_concat(argv, argc, 1);

  peer_description_set (peer, str);

  XFREE (MTYPE_TMP, str);

  return CMD_SUCCESS;
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       NO_NEIGHBOR_CMD2 "description",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  peer_description_unset (peer);

  return CMD_SUCCESS;
}

ALIAS (no_neighbor_description,
       no_neighbor_description_val_cmd,
       NO_NEIGHBOR_CMD2 "description .LINE",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

/* Neighbor update-source. */
static int
peer_update_source_vty (struct vty *vty, const char *peer_str,
                        const char *source_str)
{
  bgp_peer peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (source_str == NULL)
    peer_update_source_unset (peer);
  else
    {
      sockunion_t su[1] ;

      if (sockunion_str2su (su, source_str))
        peer_update_source_addr_set (peer, su);
      else
        {
          if (strlen(source_str) < sizeof(peer->cops.ifname))
            peer_update_source_if_set (peer, source_str);
          else
            {
              vty_out(vty, "%% '%s' too long for interface name\n",
                                                                  source_str) ;
              return CMD_WARNING ;
            } ;
        } ;
    } ;

  return CMD_SUCCESS;
}

#define BGP_UPDATE_SOURCE_STR "(A.B.C.D|X:X::X:X|WORD)"
#define BGP_UPDATE_SOURCE_HELP_STR \
  "IPv4 address\n" \
  "IPv6 address\n" \
  "Interface name (requires zebra to be running)\n"

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       NEIGHBOR_CMD2 "update-source " BGP_UPDATE_SOURCE_STR,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
  return peer_update_source_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       NO_NEIGHBOR_CMD2 "update-source",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n")
{
  return peer_update_source_vty (vty, argv[0], NULL);
}

static int
peer_default_originate_set_vty (struct vty *vty, const char *peer_str,
                                qafx_t qafx, const char *rmap_name, bool set)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, peer_str);
  if (! peer)
    return CMD_WARNING;

  if (set)
    ret = peer_default_originate_set (peer, qafx, rmap_name);
  else
    ret = peer_default_originate_unset (peer, qafx);

  return bgp_vty_return (vty, ret);
}

/* neighbor default-originate. */
DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       NEIGHBOR_CMD2 "default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                         NULL, true /* set */) ;
}

DEFUN (neighbor_default_originate_rmap,
       neighbor_default_originate_rmap_cmd,
       NEIGHBOR_CMD2 "default-originate route-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                      argv[1], true /* set */);
}

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       NO_NEIGHBOR_CMD2 "default-originate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return peer_default_originate_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                      NULL, false /* clear */);
}

ALIAS (no_neighbor_default_originate,
       no_neighbor_default_originate_rmap_cmd,
       NO_NEIGHBOR_CMD2 "default-originate route-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")

/*------------------------------------------------------------------------------
 * Set/Unset neighbor's BGP port.
 *
 * NB: this cannot be set/unset for a *group*.
 *
 *     BUT... can be set/unset for a *group* *member*
 */
static cmd_ret_t
peer_port_vty (struct vty *vty, const char *ip_str, int afi,
               const char *port_str)
{
  struct peer *peer;
  u_int16_t port;
  struct servent *sp;

  peer = peer_lookup_vty_index (vty, ip_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (port_str == NULL)
    {
      sp = getservbyname ("bgp", "tcp");
      port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);
    }
  else
    {
      VTY_GET_INTEGER("port", port, port_str);
    }

  peer_port_set (peer, port);

  return CMD_SUCCESS;
}

/* Set specified peer's BGP port.  */
DEFUN (neighbor_port,
       neighbor_port_cmd,
       NEIGHBOR_CMD "port <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
  return peer_port_vty (vty, argv[0], AFI_IP, argv[1]);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       NO_NEIGHBOR_CMD "port",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")
{
  return peer_port_vty (vty, argv[0], AFI_IP, NULL);
}

ALIAS (no_neighbor_port,
       no_neighbor_port_val_cmd,
       NO_NEIGHBOR_CMD "port <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")

/* neighbor weight. */
static int
peer_weight_set_vty (struct vty *vty, const char *ip_str,
                     const char *weight_str)
{
  bgp_peer peer;
  uint     weight;
  int      ret ;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE("weight", weight, weight_str, 0, 65535);

  ret = peer_weight_set (peer, weight);

  return bgp_vty_return (vty, ret);
}

static int
peer_weight_unset_vty (struct vty *vty, const char *ip_str)
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  peer_weight_unset (peer);

  return CMD_SUCCESS;
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       NEIGHBOR_CMD2 "weight <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return peer_weight_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       NO_NEIGHBOR_CMD2 "weight",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n")
{
  return peer_weight_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_weight,
       no_neighbor_weight_val_cmd,
       NO_NEIGHBOR_CMD2 "weight <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

/* Override capability negotiation. */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       NEIGHBOR_CMD2 "override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       NO_NEIGHBOR_CMD2 "override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_OVERRIDE_CAPABILITY);
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       NEIGHBOR_CMD "strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_flag_set_vty (vty, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       NO_NEIGHBOR_CMD "strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return peer_flag_unset_vty (vty, argv[0], PEER_FLAG_STRICT_CAP_MATCH);
}

/*------------------------------------------------------------------------------
 * Set neighbor's or group's timers.
 *
 * Sets the given values for KeepAliveTime and HoldTime
 */
static int
peer_timers_set_vty (struct vty *vty, const char *ip_str,
                     const char *keep_str, const char *hold_str)
{
  bgp_ret_t ret;
  bgp_peer  peer;
  uint keepalive, holdtime;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("Keepalive", keepalive, keep_str, 0, 65535);
  VTY_GET_INTEGER_RANGE ("Holdtime", holdtime, hold_str, 0, 65535);

  ret = peer_timers_set (peer, keepalive, holdtime);

  return bgp_vty_return (vty, ret);
}

/*------------------------------------------------------------------------------
 * Unset neighbor's or group's timers.
 *
 * Sets the default values for KeepAliveTime and HoldTime
 */
static int
peer_timers_unset_vty (struct vty *vty, const char *ip_str)
{
  bgp_ret_t ret;
  bgp_peer  peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_timers_unset (peer);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_timers,
       neighbor_timers_cmd,
       NEIGHBOR_CMD2 "timers <0-65535> <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  return peer_timers_set_vty (vty, argv[0], argv[1], argv[2]);
}

DEFUN (no_neighbor_timers,
       no_neighbor_timers_cmd,
       NO_NEIGHBOR_CMD2 "timers",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n")
{
  return peer_timers_unset_vty (vty, argv[0]);
}

/*------------------------------------------------------------------------------
 * Set neighbor's or group's connect timer.
 *
 * Sets the given values for ConnectTime
 */
static int
peer_timers_connect_set_vty (struct vty *vty, const char *ip_str,
                             const char *time_str)
{
  bgp_ret_t ret ;
  bgp_peer  peer;
  uint      connect_retry_secs;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("ConnectRetryTime",
                                       connect_retry_secs, time_str, 0, 65535) ;

  ret = peer_timers_connect_set (peer, connect_retry_secs) ;

  return bgp_vty_return (vty, ret);
}

static int
peer_timers_connect_unset_vty (struct vty *vty, const char *ip_str)
{
  bgp_ret_t ret ;
  bgp_peer  peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_timers_connect_unset (peer);

  return bgp_vty_return (vty, ret);
} ;

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       NEIGHBOR_CMD2 "timers connect <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return peer_timers_connect_set_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       NO_NEIGHBOR_CMD2 "timers connect",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n")
{
  return peer_timers_connect_unset_vty (vty, argv[0]);
}

ALIAS (no_neighbor_timers_connect,
       no_neighbor_timers_connect_val_cmd,
       NO_NEIGHBOR_CMD2 "timers connect <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

/*------------------------------------------------------------------------------
 * Set or clear the advertisement-interval for the given peer or group.
 */
static cmd_ret_t
peer_advertise_interval_vty (struct vty *vty, const char *ip_str,
                             const char *time_str, bool set)
{
  bgp_ret_t ret ;
  bgp_peer  peer ;
  uint      routeadv ;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (time_str != NULL)
    VTY_GET_INTEGER_RANGE ("advertise interval", routeadv, time_str, 0, 600);
  else
    routeadv = 0 ;

  if (set)
    ret = peer_advertise_interval_set (peer, routeadv) ;
  else
    ret = peer_advertise_interval_unset (peer) ;

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_advertise_interval,
       neighbor_advertise_interval_cmd,
       NEIGHBOR_CMD2 "advertisement-interval <0-600>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
  return peer_advertise_interval_vty (vty, argv[0], argv[1], 1);
}

DEFUN (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n")
{
  return peer_advertise_interval_vty (vty, argv[0], NULL, 0);
}

ALIAS (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_val_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval <0-600>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")

/*------------------------------------------------------------------------------
 * Set or clear the interface for the given peer.
 *
 * NB: this cannot be set/cleared for a *group*.
 */
static cmd_ret_t
peer_interface_vty (struct vty *vty, const char *ip_str, const char *str)
{
  int ret  Unused ;
  struct peer *peer;

  peer = peer_lookup_vty_index (vty, ip_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (str != NULL)
    ret = peer_interface_set (peer, str) ;
  else
    ret = peer_interface_unset (peer) ;

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_interface,
       neighbor_interface_cmd,
       NEIGHBOR_CMD "interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return peer_interface_vty (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_interface,
       no_neighbor_interface_cmd,
       NO_NEIGHBOR_CMD "interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return peer_interface_vty (vty, argv[0], NULL);
}

/* Set distribute list to the peer. */
static int
peer_distribute_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                         const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_set (peer, qafx, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_distribute_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                                         const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_distribute_unset (peer, qafx, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_distribute_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                              argv[1], argv[2]);
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       NO_NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_distribute_unset_vty (vty, argv[0], bgp_node_qafx(vty), argv[2]);
}

/* Set prefix list to the peer. */
static int
peer_prefix_list_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                   const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_set (peer, qafx, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_prefix_list_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                                         const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_prefix_list_unset (peer, qafx, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_prefix_list_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                              argv[1], argv[2]);
}

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       NO_NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return peer_prefix_list_unset_vty (vty, argv[0], bgp_node_qafx(vty), argv[2]);
}

static int
peer_aslist_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                     const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_set (peer, qafx, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_aslist_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                                         const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = FILTER_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "i", 1) == 0)
    direct = FILTER_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = FILTER_OUT;

  ret = peer_aslist_unset (peer, qafx, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return peer_aslist_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                             argv[1], argv[2]);
}

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       NO_NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return peer_aslist_unset_vty (vty, argv[0], bgp_node_qafx(vty), argv[2]);
}

/* Set route-map to the peer. */
static int
peer_route_map_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                  const char *name_str, const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = RMAP_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 2) == 0)
    direct = RMAP_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = RMAP_OUT;
  else if (strncmp (direct_str, "im", 2) == 0)
    direct = RMAP_IMPORT;
  else if (strncmp (direct_str, "e", 1) == 0)
    direct = RMAP_EXPORT;
  else if (strncmp (direct_str, "r", 1) == 0)
    direct = RMAP_RS_IN;

  ret = peer_route_map_set (peer, qafx, direct, name_str);

  return bgp_vty_return (vty, ret);
}

static int
peer_route_map_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                                         const char *direct_str)
{
  int ret;
  struct peer *peer;
  int direct = RMAP_IN;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  /* Check filter direction. */
  if (strncmp (direct_str, "in", 2) == 0)
    direct = RMAP_IN;
  else if (strncmp (direct_str, "o", 1) == 0)
    direct = RMAP_OUT;
  else if (strncmp (direct_str, "im", 2) == 0)
    direct = RMAP_IMPORT;
  else if (strncmp (direct_str, "e", 1) == 0)
    direct = RMAP_EXPORT;
  else if (strncmp (direct_str, "r", 1) == 0)
    direct = RMAP_RS_IN;

  ret = peer_route_map_unset (peer, qafx, direct);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       NEIGHBOR_CMD2 "route-map WORD (in|rs-in|out|import|export)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to incoming Route-Server routes\n"
       "Apply map to outbound routes\n"
       "Apply map to routes going into a Route-Server client's table\n"
       "Apply map to routes coming from a Route-Server client")
{
  return peer_route_map_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                              argv[1], argv[2]);
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       NO_NEIGHBOR_CMD2 "route-map WORD (in|rs-in|out|import|export)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to incoming Route-Server routes\n"
       "Apply map to outbound routes\n"
       "Apply map to routes going into a Route-Server client's table\n"
       "Apply map to routes coming from a Route-Server client")
{
  return peer_route_map_unset_vty (vty, argv[0], bgp_node_qafx(vty), argv[2]);
}

/* Set unsuppress-map to the peer. */
static int
peer_unsuppress_map_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                                           const char *name_str)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_unsuppress_map_set (peer, qafx, name_str);

  return bgp_vty_return (vty, ret);
}

/* Unset route-map from the peer. */
static int
peer_unsuppress_map_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_unsuppress_map_unset (peer, qafx);

  return bgp_vty_return (vty, ret);
}

DEFUN (neighbor_unsuppress_map,
       neighbor_unsuppress_map_cmd,
       NEIGHBOR_CMD2 "unsuppress-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return peer_unsuppress_map_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                                      argv[1]) ;
}

DEFUN (no_neighbor_unsuppress_map,
       no_neighbor_unsuppress_map_cmd,
       NO_NEIGHBOR_CMD2 "unsuppress-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return peer_unsuppress_map_unset_vty (vty, argv[0], bgp_node_qafx(vty));
}

static int
peer_maximum_prefix_set_vty (struct vty *vty, const char *ip_str, qafx_t qafx,
                                const char *num_str, const char *threshold_str,
                                          bool warning, const char *restart_str)
{
  int ret;
  bgp_peer peer;
  uint32_t max;
  byte     threshold;
  uint16_t restart;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER ("maximum number", max, num_str);
  if (threshold_str)
    threshold = atoi (threshold_str);
  else
    threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

  if (restart_str)
    restart = atoi (restart_str);
  else
    restart = 0;

  ret = peer_maximum_prefix_set (peer, qafx, max, threshold, warning, restart);

  return bgp_vty_return (vty, ret);
}

static int
peer_maximum_prefix_unset_vty (struct vty *vty, const char *ip_str, qafx_t qafx)
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, ip_str);
  if (! peer)
    return CMD_WARNING;

  ret = peer_maximum_prefix_unset (peer, qafx);

  return bgp_vty_return (vty, ret);
}

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                    argv[1], NULL, false, NULL);
}

DEFUN (neighbor_maximum_prefix_threshold,
       neighbor_maximum_prefix_threshold_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                 argv[1], argv[2], false, NULL);
}

DEFUN (neighbor_maximum_prefix_warning,
       neighbor_maximum_prefix_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                     argv[1], NULL, true, NULL);
}

DEFUN (neighbor_maximum_prefix_threshold_warning,
       neighbor_maximum_prefix_threshold_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                  argv[1], argv[2], true, NULL);
}

DEFUN (neighbor_maximum_prefix_restart,
       neighbor_maximum_prefix_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                                 argv[1], NULL, false, argv[2]);
}

DEFUN (neighbor_maximum_prefix_threshold_restart,
       neighbor_maximum_prefix_threshold_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return peer_maximum_prefix_set_vty (vty, argv[0], bgp_node_qafx(vty),
                                              argv[1], argv[2], false, argv[3]);
}

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n")
{
  return peer_maximum_prefix_unset_vty (vty, argv[0], bgp_node_qafx(vty));
}

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_val_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

/* "neighbor allowas-in" */
DEFUN (neighbor_allowas_in,
       neighbor_allowas_in_cmd,
       NEIGHBOR_CMD2 "allowas-in",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n")
{
  int ret;
  struct peer *peer;
  unsigned int allow_num;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  if (argc == 1)
    allow_num = 3;
  else
    VTY_GET_INTEGER_RANGE ("AS number", allow_num, argv[1], 1, 10);

  ret = peer_allowas_in_set (peer, bgp_node_qafx(vty), allow_num);

  return bgp_vty_return (vty, ret);
}

ALIAS (neighbor_allowas_in,
       neighbor_allowas_in_arg_cmd,
       NEIGHBOR_CMD2 "allowas-in <1-10>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n"
       "Number of occurances of AS number\n")

DEFUN (no_neighbor_allowas_in,
       no_neighbor_allowas_in_cmd,
       NO_NEIGHBOR_CMD2 "allowas-in",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n")
{
  int ret;
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = peer_allowas_in_unset (peer, bgp_node_qafx(vty));

  return bgp_vty_return (vty, ret);
}


DEFUN (neighbor_ttl_security,
       neighbor_ttl_security_cmd,
       NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  struct peer *peer;
  int gtsm_hops;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  VTY_GET_INTEGER_RANGE ("", gtsm_hops, argv[1], 1, 254);

  return bgp_vty_return (vty, peer_ttl_security_hops_set (peer, gtsm_hops));
}

DEFUN (no_neighbor_ttl_security,
       no_neighbor_ttl_security_cmd,
       NO_NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  struct peer *peer;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  return bgp_vty_return (vty, peer_ttl_security_hops_unset (peer));
}

/* Address family configuration.  */
DEFUN_ATTR (address_family_ipv4,
            address_family_ipv4_cmd,
            "address-family ipv4",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_IPV4_NODE)
{
  vty->node = BGP_IPV4_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv4_safi_unicast,
            address_family_ipv4_safi_unicast_cmd,
            "address-family ipv4 unicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV4_NODE)
{
  vty->node = BGP_IPV4_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv4_safi_multicast,
            address_family_ipv4_safi_multicast_cmd,
            "address-family ipv4 multicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV4M_NODE)
{
  vty->node = BGP_IPV4M_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6,
            address_family_ipv6_cmd,
            "address-family ipv6",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_IPV6_NODE)
{
  vty->node = BGP_IPV6_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6_safi_unicast,
            address_family_ipv6_safi_unicast_cmd,
            "address-family ipv6 unicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV6_NODE)
{
  vty->node = BGP_IPV6_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6_safi_multicast,
            address_family_ipv6_safi_multicast_cmd,
            "address-family ipv6 multicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV6M_NODE)
{
  vty->node = BGP_IPV6M_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_vpnv4,
            address_family_vpnv4_cmd,
            "address-family vpnv4",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_VPNV4_NODE)
{
  vty->node = BGP_VPNV4_NODE ;
  return CMD_SUCCESS;
}

ALIAS_ATTR (address_family_vpnv4,
       address_family_vpnv4_unicast_cmd,
       "address-family vpnv4 unicast",
       "Enter Address Family command mode\n"
       "Address family\n"
       "Address Family Modifier\n",
       CMD_ATTR_NODE + BGP_VPNV4_NODE)

DEFUN_ATTR (exit_address_family,
            exit_address_family_cmd,
            "exit-address-family",
            "Exit from Address Family configuration mode\n",
            CMD_ATTR_NODE + BGP_NODE)
{
  node_type_t node = vty->node ;

  if (   node == BGP_IPV4_NODE
      || node == BGP_IPV4M_NODE
      || node == BGP_VPNV4_NODE
      || node == BGP_IPV6_NODE
      || node == BGP_IPV6M_NODE)
    {
      vty->node = BGP_NODE ;
      return CMD_SUCCESS ;
    }
  else
    {
      vty_out(vty, "%% No address family to leave\n") ;
      return CMD_WARNING ;
    } ;
} ;

/* BGP clear sort. */
typedef enum
{
  clear_all,
  clear_peer,
  clear_group,
  clear_external,
  clear_as
} clear_sort_t ;

static cmd_ret_t
bgp_clear_vty_error (vty vty, bgp_peer peer, qafx_t qafx, bgp_ret_t error)
{
  switch (error)
    {
      case BGP_ERR_AF_UNCONFIGURED:
        vty_out (vty,
           "%%BGP: neighbor %s is not enabled for %s\n",
                                               peer->host, get_qafx_name(qafx));
        break;

      case BGP_ERR_SOFT_RECONFIG_UNCONFIGURED:
        vty_out (vty, "%%BGP: Inbound soft reconfig for %s not possible as it\n"
                      "      has neither refresh capability, nor inbound soft"
                                                    " reconfig\n", peer->host);
        break;

      default:
        vty_out (vty, "%%BGP: unknown issue clear for %s\n", peer->host);
        break;
    } ;

  return CMD_WARNING ;
} ;

/*------------------------------------------------------------------------------
 * `clear ip bgp' functions.
 *
 *   * sort   -- clear_all        -- clear all peers
 *            -- clear_peer       -- clear the peer given by 'arg'
 *            -- clear_group      -- clear the group given by 'arg'
 *            -- clear_external   -- clear all external peers
 *            -- clear_as         -- clear all peers with AS given by 'arg'
 *
 *   * type   -- BGP_CLEAR_HARD   -- hard reset of peer(s) -- ignores qafx
 *
 *            -- BGP_CLEAR_SOFT_OUT            ) attempt soft reset of the
 *            -- BGP_CLEAR_SOFT_IN             ) given qafx
 *            -- BGP_CLEAR_SOFT_BOTH           )
 *            -- BGP_CLEAR_SOFT_IN_ORF_PREFIX  )
 *            -- BGP_CLEAR_SOFT_RSCLIENT       )
 */
static int
bgp_clear (struct vty *vty, struct bgp *bgp, qafx_t qafx,
           clear_sort_t sort, bgp_clear_type_t stype, const char *arg)
{
  cmd_ret_t cret ;
  bgp_peer  peer ;
  int ret;
  union sockunion su;
  struct listnode *node, *nnode;
  struct peer_group *group;
  as_t as ;
  bool found ;

  cret = CMD_SUCCESS ;

  switch (sort)
    {
      case clear_all:
        for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
          {
            if (stype == BGP_CLEAR_HARD)
              peer_clear (peer);
            else
              {
                ret = peer_clear_soft (peer, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, peer, qafx, ret);
              } ;
          } ;
        break ;

      case clear_peer:
        ret = str2sockunion (arg, &su);
        if (ret < 0)
          {
            vty_out (vty, "Malformed address: %s\n", arg);
            return CMD_WARNING;
          }

        peer = peer_lookup (bgp, &su);
        if (! peer)
          {
            vty_out (vty, "%%BGP: Unknown neighbor - \"%s\"\n", arg);
            return CMD_WARNING;
          }

        if (stype == BGP_CLEAR_HARD)
          peer_clear (peer);
        else
          {
            ret = peer_clear_soft (peer, qafx, stype);

            if (ret < 0)
              cret =  bgp_clear_vty_error (vty, peer, qafx, ret);
          } ;
        break ;

      case clear_group:
        group = peer_group_lookup (bgp, arg);
        if (! group)
          {
            vty_out (vty, "%%BGP: No such peer-group %s\n", arg);
            return CMD_WARNING;
          }

        for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
          {
            if    (stype == BGP_CLEAR_HARD)
              peer_clear (peer);
            else
              {
                peer_rib  prib ;

                prib = peer_family_prib(peer, qafx) ;

                if ((prib != NULL) && prib->af_group_member)
                  {
                    ret = peer_clear_soft (peer, qafx, stype);

                    if (ret < 0)
                      cret =  bgp_clear_vty_error (vty, peer, qafx, ret);
                  } ;
              } ;
          } ;
        break ;

      case clear_external:
        for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
          {
            if (peer->sort == BGP_PEER_IBGP)
              continue;

            if (stype == BGP_CLEAR_HARD)
              peer_clear (peer);
            else
              {
                ret = peer_clear_soft (peer, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, peer, qafx, ret);
              } ;
          } ;
        break ;

      case clear_as:
        VTY_GET_INTEGER_RANGE ("AS", as, arg, 1, BGP_AS4_MAX);

        found = false ;

        for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
          {
            if (peer->args.remote_as != as)
              continue;

            found = true;

            if (stype == BGP_CLEAR_HARD)
              peer_clear (peer);
            else
              {
                ret = peer_clear_soft (peer, qafx, stype);

                if (ret < 0)
                  cret =  bgp_clear_vty_error (vty, peer, qafx, ret);
              } ;
          } ;

        if (! found)
          {
            vty_out (vty, "%%BGP: No peer is configured with AS %s\n", arg);
            cret = CMD_WARNING ;
          } ;

        break ;

      default:
        vty_out(vty, "%% unknown clear_xx in %s() -- BUG\n", __func__) ;
        return CMD_ERROR ;
    }

  return cret;
} ;

/*------------------------------------------------------------------------------
 * Perform a bgp clear operation
 *
 *   * name  -- NULL => default bgp instance
 *              otherwise, name of BGP instance
 *
 *   * qafx   )
 *   * sort   ) see bgp_clear()
 *   * type   )
 *   * arg    )
 */
static int
bgp_clear_vty (struct vty *vty, const char *name, qafx_t qafx,
                     clear_sort_t sort, bgp_clear_type_t stype, const char *arg)
{
  struct bgp *bgp;

  /* BGP structure lookup. */
  if (name)
    {
      bgp = bgp_lookup_by_name (name);
      if (bgp == NULL)
        {
          vty_out (vty, "Can't find BGP view %s%s", name, VTY_NEWLINE);
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

  return bgp_clear (vty, bgp, qafx, sort, stype, arg);
}

/*------------------------------------------------------------------------------
 * Select unicast or multicast qafx, according to "m" (or "u")
 */
static qafx_t
bgp_clear_qafx_how_cast(const char* opt, qafx_t unicast, qafx_t multicast)
{
  if (*opt == 'm')
    return multicast ;
  else
    return unicast ;
} ;

DEFUN (clear_ip_bgp_all,
       clear_ip_bgp_all_cmd,
       "clear ip bgp *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_undef, clear_all, BGP_CLEAR_HARD,
                                                                         NULL);
}

ALIAS (clear_ip_bgp_all,
       clear_bgp_all_cmd,
       "clear bgp *",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_ipv6_all_cmd,
       "clear bgp ipv6 *",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_ip_bgp_instance_all_cmd,
       "clear ip bgp view WORD *",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n")

ALIAS (clear_ip_bgp_all,
       clear_bgp_instance_all_cmd,
       "clear bgp view WORD *",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n")

DEFUN (clear_ip_bgp_peer,
       clear_ip_bgp_peer_cmd,
       "clear ip bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_peer, BGP_CLEAR_HARD,
                                                                       argv[0]);
}

ALIAS (clear_ip_bgp_peer,
       clear_bgp_peer_cmd,
       "clear bgp (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n")

ALIAS (clear_ip_bgp_peer,
       clear_bgp_ipv6_peer_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X)",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n")

DEFUN (clear_ip_bgp_peer_group,
       clear_ip_bgp_peer_group_cmd,
       "clear ip bgp peer-group WORD",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_group, BGP_CLEAR_HARD,
                                                                       argv[0]);
}

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_peer_group_cmd,
       "clear bgp peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

ALIAS (clear_ip_bgp_peer_group,
       clear_bgp_ipv6_peer_group_cmd,
       "clear bgp ipv6 peer-group WORD",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n")

DEFUN (clear_ip_bgp_external,
       clear_ip_bgp_external_cmd,
       "clear ip bgp external",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_external,
                                                    BGP_CLEAR_HARD, NULL);
}

ALIAS (clear_ip_bgp_external,
       clear_bgp_external_cmd,
       "clear bgp external",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n")

ALIAS (clear_ip_bgp_external,
       clear_bgp_ipv6_external_cmd,
       "clear bgp ipv6 external",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n")

DEFUN (clear_ip_bgp_as,
       clear_ip_bgp_as_cmd,
       "clear ip bgp " CMD_AS_RANGE,
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n")
{
  return bgp_clear_vty (vty, NULL, qafx_undef, clear_as,
                                                  BGP_CLEAR_HARD, argv[0]);
}

ALIAS (clear_ip_bgp_as,
       clear_bgp_as_cmd,
       "clear bgp " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n")

ALIAS (clear_ip_bgp_as,
       clear_bgp_ipv6_as_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE,
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n")

/* Outbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_soft_out_cmd,
       "clear ip bgp * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_all_out_cmd,
       "clear ip bgp * out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_ip_bgp_all_soft_out,
       clear_ip_bgp_instance_all_soft_out_cmd,
       "clear ip bgp view WORD * soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_soft_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all, BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_out,
       clear_ip_bgp_all_ipv4_out_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_out,
       clear_ip_bgp_instance_all_ipv4_soft_out_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                                     BGP_CLEAR_SOFT_OUT, NULL) ;
}

DEFUN (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_soft_out_cmd,
       "clear ip bgp * vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_out,
       clear_ip_bgp_all_vpnv4_out_cmd,
       "clear ip bgp * vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_all_soft_out,
       clear_bgp_all_soft_out_cmd,
       "clear bgp * soft out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_instance_all_soft_out_cmd,
       "clear bgp view WORD * soft out",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_all_out_cmd,
       "clear bgp * out",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_soft_out_cmd,
       "clear bgp ipv6 * soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_all_soft_out,
       clear_bgp_ipv6_all_out_cmd,
       "clear bgp ipv6 * out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_soft_out_cmd,
       "clear ip bgp A.B.C.D soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_out,
       clear_ip_bgp_peer_out_cmd,
       "clear ip bgp A.B.C.D out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_soft_out_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_out,
       clear_ip_bgp_peer_ipv4_out_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_soft_out_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_out,
       clear_ip_bgp_peer_vpnv4_out_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_peer_soft_out,
       clear_bgp_peer_soft_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_soft_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_peer_out_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) out",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_soft_out,
       clear_bgp_ipv6_peer_out_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_soft_out_cmd,
       "clear ip bgp peer-group WORD soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_out,
       clear_ip_bgp_peer_group_out_cmd,
       "clear ip bgp peer-group WORD out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_soft_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_out,
       clear_ip_bgp_peer_group_ipv4_out_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_soft_out_cmd,
       "clear bgp peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_soft_out_cmd,
       "clear bgp ipv6 peer-group WORD soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_peer_group_out_cmd,
       "clear bgp peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_peer_group_soft_out,
       clear_bgp_ipv6_peer_group_out_cmd,
       "clear bgp ipv6 peer-group WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_soft_out_cmd,
       "clear ip bgp external soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_soft_out,
       clear_ip_bgp_external_out_cmd,
       "clear ip bgp external out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_soft_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_out,
       clear_ip_bgp_external_ipv4_out_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_external_soft_out,
       clear_bgp_external_soft_out_cmd,
       "clear bgp external soft out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                      BGP_CLEAR_SOFT_OUT, NULL);
}

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_soft_out_cmd,
       "clear bgp ipv6 external soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_external_out_cmd,
       "clear bgp external out",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_external_soft_out,
       clear_bgp_ipv6_external_out_cmd,
       "clear bgp ipv6 external WORD out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_out,
       clear_ip_bgp_as_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as, BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_out,
       clear_ip_bgp_as_ipv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_soft_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                   BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_out,
       clear_ip_bgp_as_vpnv4_out_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast out",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig outbound update\n")

DEFUN (clear_bgp_as_soft_out,
       clear_bgp_as_soft_out_cmd,
       "clear bgp " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                 BGP_CLEAR_SOFT_OUT, argv[0]);
}

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_soft_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_as_out_cmd,
       "clear bgp " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

ALIAS (clear_bgp_as_soft_out,
       clear_bgp_ipv6_as_out_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " out",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig outbound update\n")

/* Inbound soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_soft_in_cmd,
       "clear ip bgp * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_instance_all_soft_in_cmd,
       "clear ip bgp view WORD * soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_ip_bgp_all_soft_in,
       clear_ip_bgp_all_in_cmd,
       "clear ip bgp * in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_all_in_prefix_filter,
       clear_ip_bgp_all_in_prefix_filter_cmd,
       "clear ip bgp * in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_ip_bgp_all_in_prefix_filter,
       clear_ip_bgp_instance_all_in_prefix_filter_cmd,
       "clear ip bgp view WORD * in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")


DEFUN (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_soft_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_ipv4_soft_in,
       clear_ip_bgp_all_ipv4_in_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_instance_all_ipv4_soft_in,
       clear_ip_bgp_instance_all_ipv4_soft_in_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all, BGP_CLEAR_SOFT_IN, NULL);
}

DEFUN (clear_ip_bgp_all_ipv4_in_prefix_filter,
       clear_ip_bgp_all_ipv4_in_prefix_filter_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_in_prefix_filter,
       clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_soft_in_cmd,
       "clear ip bgp * vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_all_vpnv4_soft_in,
       clear_ip_bgp_all_vpnv4_in_cmd,
       "clear ip bgp * vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_all_soft_in,
       clear_bgp_all_soft_in_cmd,
       "clear bgp * soft in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_instance_all_soft_in_cmd,
       "clear bgp view WORD * soft in",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_soft_in_cmd,
       "clear bgp ipv6 * soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_all_in_cmd,
       "clear bgp * in",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_all_soft_in,
       clear_bgp_ipv6_all_in_cmd,
       "clear bgp ipv6 * in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_all_in_prefix_filter,
       clear_bgp_all_in_prefix_filter_cmd,
       "clear bgp * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_all,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_all_in_prefix_filter,
       clear_bgp_ipv6_all_in_prefix_filter_cmd,
       "clear bgp ipv6 * in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_soft_in_cmd,
       "clear ip bgp A.B.C.D soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_soft_in,
       clear_ip_bgp_peer_in_cmd,
       "clear ip bgp A.B.C.D in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_in_prefix_filter,
       clear_ip_bgp_peer_in_prefix_filter_cmd,
       "clear ip bgp A.B.C.D in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_soft_in_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_ipv4_soft_in,
       clear_ip_bgp_peer_ipv4_in_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_soft_in_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_vpnv4_soft_in,
       clear_ip_bgp_peer_vpnv4_in_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_soft_in,
       clear_bgp_peer_soft_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_soft_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_peer_in_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) in",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_soft_in,
       clear_bgp_ipv6_peer_in_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_in_prefix_filter,
       clear_bgp_peer_in_prefix_filter_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_in_prefix_filter,
       clear_bgp_ipv6_peer_in_prefix_filter_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig inbound update\n"
       "Push out the existing ORF prefix-list\n")

DEFUN (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_soft_in_cmd,
       "clear ip bgp peer-group WORD soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                   BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_soft_in,
       clear_ip_bgp_peer_group_in_cmd,
       "clear ip bgp peer-group WORD in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_group_in_prefix_filter,
       clear_ip_bgp_peer_group_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_soft_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_peer_group_ipv4_soft_in,
       clear_ip_bgp_peer_group_ipv4_in_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_peer_group_ipv4_in_prefix_filter,
       clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                        BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_soft_in_cmd,
       "clear bgp peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_soft_in_cmd,
       "clear bgp ipv6 peer-group WORD soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_peer_group_in_cmd,
       "clear bgp peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_peer_group_soft_in,
       clear_bgp_ipv6_peer_group_in_cmd,
       "clear bgp ipv6 peer-group WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_peer_group_in_prefix_filter_cmd,
       "clear bgp peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_peer_group_in_prefix_filter,
       clear_bgp_ipv6_peer_group_in_prefix_filter_cmd,
       "clear bgp ipv6 peer-group WORD in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_soft_in_cmd,
       "clear ip bgp external soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_soft_in,
       clear_ip_bgp_external_in_cmd,
       "clear ip bgp external in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_external_in_prefix_filter,
       clear_ip_bgp_external_in_prefix_filter_cmd,
       "clear ip bgp external in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_soft_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_ip_bgp_external_ipv4_soft_in,
       clear_ip_bgp_external_ipv4_in_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_external_ipv4_in_prefix_filter,
       clear_ip_bgp_external_ipv4_in_prefix_filter_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

DEFUN (clear_bgp_external_soft_in,
       clear_bgp_external_soft_in_cmd,
       "clear bgp external soft in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                       BGP_CLEAR_SOFT_IN, NULL);
}

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_soft_in_cmd,
       "clear bgp ipv6 external soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_external_in_cmd,
       "clear bgp external in",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_external_soft_in,
       clear_bgp_ipv6_external_in_cmd,
       "clear bgp ipv6 external WORD in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_external_in_prefix_filter,
       clear_bgp_external_in_prefix_filter_cmd,
       "clear bgp external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                            BGP_CLEAR_SOFT_IN_ORF_PREFIX, NULL);
}

ALIAS (clear_bgp_external_in_prefix_filter,
       clear_bgp_ipv6_external_in_prefix_filter_cmd,
       "clear bgp ipv6 external in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

DEFUN (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_soft_in,
       clear_ip_bgp_as_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_as_in_prefix_filter,
       clear_ip_bgp_as_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as, BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_ipv4_soft_in,
       clear_ip_bgp_as_ipv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_ip_bgp_as_ipv4_in_prefix_filter,
       clear_ip_bgp_as_ipv4_in_prefix_filter_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) in prefix-filter",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_soft_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_ip_bgp_as_vpnv4_soft_in,
       clear_ip_bgp_as_vpnv4_in_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast in",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family modifier\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_as_soft_in,
       clear_bgp_as_soft_in_cmd,
       "clear bgp " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                    BGP_CLEAR_SOFT_IN, argv[0]);
}

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_soft_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_as_in_cmd,
       "clear bgp " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

ALIAS (clear_bgp_as_soft_in,
       clear_bgp_ipv6_as_in_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n")

DEFUN (clear_bgp_as_in_prefix_filter,
       clear_bgp_as_in_prefix_filter_cmd,
       "clear bgp " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                         BGP_CLEAR_SOFT_IN_ORF_PREFIX, argv[0]);
}

ALIAS (clear_bgp_as_in_prefix_filter,
       clear_bgp_ipv6_as_in_prefix_filter_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " in prefix-filter",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig inbound update\n"
       "Push out prefix-list ORF and do inbound soft reconfig\n")

/* Both soft-reconfiguration */
DEFUN (clear_ip_bgp_all_soft,
       clear_ip_bgp_all_soft_cmd,
       "clear ip bgp * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_ip_bgp_all_soft,
       clear_ip_bgp_instance_all_soft_cmd,
       "clear ip bgp view WORD * soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n")


DEFUN (clear_ip_bgp_all_ipv4_soft,
       clear_ip_bgp_all_ipv4_soft_cmd,
       "clear ip bgp * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_all,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_instance_all_ipv4_soft,
       clear_ip_bgp_instance_all_ipv4_soft_cmd,
       "clear ip bgp view WORD * ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, argv[0], qafx, clear_all,
                                                    BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_all_vpnv4_soft,
       clear_ip_bgp_all_vpnv4_soft_cmd,
       "clear ip bgp * vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_all,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_all_soft,
       clear_bgp_all_soft_cmd,
       "clear bgp * soft",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_all_soft,
       clear_bgp_instance_all_soft_cmd,
       "clear bgp view WORD * soft",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig\n")

ALIAS (clear_bgp_all_soft,
       clear_bgp_ipv6_all_soft_cmd,
       "clear bgp ipv6 * soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_peer_soft,
       clear_ip_bgp_peer_soft_cmd,
       "clear ip bgp A.B.C.D soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_ipv4_soft,
       clear_ip_bgp_peer_ipv4_soft_cmd,
       "clear ip bgp A.B.C.D ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_vpnv4_soft,
       clear_ip_bgp_peer_vpnv4_soft_cmd,
       "clear ip bgp A.B.C.D vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_peer_soft,
       clear_bgp_peer_soft_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) soft",
       CLEAR_STR
       BGP_STR
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_peer,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_soft,
       clear_bgp_ipv6_peer_soft_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_peer_group_soft,
       clear_ip_bgp_peer_group_soft_cmd,
       "clear ip bgp peer-group WORD soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_peer_group_ipv4_soft,
       clear_ip_bgp_peer_group_ipv4_soft_cmd,
       "clear ip bgp peer-group WORD ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_peer_group_soft,
       clear_bgp_peer_group_soft_cmd,
       "clear bgp peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_group,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_peer_group_soft,
       clear_bgp_ipv6_peer_group_soft_cmd,
       "clear bgp ipv6 peer-group WORD soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all members of peer-group\n"
       "BGP peer-group name\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_external_soft,
       clear_ip_bgp_external_soft_cmd,
       "clear ip bgp external soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_ip_bgp_external_ipv4_soft,
       clear_ip_bgp_external_ipv4_soft_cmd,
       "clear ip bgp external ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all external peers\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[0], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;
  return bgp_clear_vty (vty, NULL, qafx, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

DEFUN (clear_bgp_external_soft,
       clear_bgp_external_soft_cmd,
       "clear bgp external soft",
       CLEAR_STR
       BGP_STR
       "Clear all external peers\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_external,
                                                     BGP_CLEAR_SOFT_BOTH, NULL);
}

ALIAS (clear_bgp_external_soft,
       clear_bgp_ipv6_external_soft_cmd,
       "clear bgp ipv6 external soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all external peers\n"
       "Soft reconfig\n")

DEFUN (clear_ip_bgp_as_soft,
       clear_ip_bgp_as_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_unicast, clear_as,
                                                 BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_as_ipv4_soft,
       clear_ip_bgp_as_ipv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " ipv4 (unicast|multicast) soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  qafx_t qafx = bgp_clear_qafx_how_cast(argv[1], qafx_ipv4_unicast,
                                                 qafx_ipv4_multicast) ;

  return bgp_clear_vty (vty, NULL, qafx, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_ip_bgp_as_vpnv4_soft,
       clear_ip_bgp_as_vpnv4_soft_cmd,
       "clear ip bgp " CMD_AS_RANGE " vpnv4 unicast soft",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Address family\n"
       "Address Family Modifier\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv4_mpls_vpn, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

DEFUN (clear_bgp_as_soft,
       clear_bgp_as_soft_cmd,
       "clear bgp " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Clear peers with the AS number\n"
       "Soft reconfig\n")
{
  return bgp_clear_vty (vty, NULL, qafx_ipv6_unicast, clear_as,
                                                  BGP_CLEAR_SOFT_BOTH, argv[0]);
}

ALIAS (clear_bgp_as_soft,
       clear_bgp_ipv6_as_soft_cmd,
       "clear bgp ipv6 " CMD_AS_RANGE " soft",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear peers with the AS number\n"
       "Soft reconfig\n")

/* RS-client soft reconfiguration. */
#ifdef HAVE_IPV6
DEFUN (clear_bgp_all_rsclient,
       clear_bgp_all_rsclient_cmd,
       "clear bgp * rsclient",
       CLEAR_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_RSCLIENT, NULL);
}

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_ipv6_all_rsclient_cmd,
       "clear bgp ipv6 * rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_instance_all_rsclient_cmd,
       "clear bgp view WORD * rsclient",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_all_rsclient,
       clear_bgp_ipv6_instance_all_rsclient_cmd,
       "clear bgp ipv6 view WORD * rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
#endif /* HAVE_IPV6 */

DEFUN (clear_ip_bgp_all_rsclient,
       clear_ip_bgp_all_rsclient_cmd,
       "clear ip bgp * rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name = (argc == 1) ? argv[0] : NULL ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_all,
                                                 BGP_CLEAR_SOFT_RSCLIENT, NULL);
}

ALIAS (clear_ip_bgp_all_rsclient,
       clear_ip_bgp_instance_all_rsclient_cmd,
       "clear ip bgp view WORD * rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "Clear all peers\n"
       "Soft reconfig for rsclient RIB\n")

#ifdef HAVE_IPV6
DEFUN (clear_bgp_peer_rsclient,
       clear_bgp_peer_rsclient_cmd,
       "clear bgp (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name   = (argc == 2) ? argv[0] : NULL ;
  const char* client = (argc == 2) ? argv[1] : argv[0] ;

  return bgp_clear_vty (vty, name, qafx_ipv6_unicast, clear_peer,
                                               BGP_CLEAR_SOFT_RSCLIENT, client);
}

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_ipv6_peer_rsclient_cmd,
       "clear bgp ipv6 (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_instance_peer_rsclient_cmd,
       "clear bgp view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

ALIAS (clear_bgp_peer_rsclient,
       clear_bgp_ipv6_instance_peer_rsclient_cmd,
       "clear bgp ipv6 view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       BGP_STR
       "Address family\n"
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
#endif /* HAVE_IPV6 */

DEFUN (clear_ip_bgp_peer_rsclient,
       clear_ip_bgp_peer_rsclient_cmd,
       "clear ip bgp (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")
{
  const char* name   = (argc == 2) ? argv[0] : NULL ;
  const char* client = (argc == 2) ? argv[1] : argv[0] ;

  return bgp_clear_vty (vty, name, qafx_ipv4_unicast, clear_peer,
                                              BGP_CLEAR_SOFT_RSCLIENT, client);
}

ALIAS (clear_ip_bgp_peer_rsclient,
       clear_ip_bgp_instance_peer_rsclient_cmd,
       "clear ip bgp view WORD (A.B.C.D|X:X::X:X) rsclient",
       CLEAR_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "view name\n"
       "BGP neighbor IP address to clear\n"
       "BGP IPv6 neighbor to clear\n"
       "Soft reconfig for rsclient RIB\n")

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show bgp views",
       SHOW_STR
       BGP_STR
       "Show the defined BGP views\n")
{
  struct list *inst = bm->bgp;
  struct listnode *node;
  struct bgp *bgp;

  if (!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "Multiple BGP views are not defined%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_out (vty, "Defined BGP views:%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO(inst, node, bgp))
    vty_out (vty, "\t%s (AS%u)\n",
                      ((bgp->name != NULL) ? bgp->name : "(null)"), bgp->my_as);

  return CMD_SUCCESS;
}

DEFUN (show_bgp_memory,
       show_bgp_memory_cmd,
       "show bgp memory",
       SHOW_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
  mem_stats_t mst[1] ;
  char memstrbuf[MTYPE_MEMSTR_LEN];
  ulong count;

  mem_get_stats(mst) ;

  /* RIB related usage stats */
  count = mem_get_alloc(mst, MTYPE_BGP_NODE);
  vty_out (vty, "%ld RIB nodes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_node)),
           VTY_NEWLINE);

  count = mem_get_alloc(mst, MTYPE_BGP_ROUTE);
  vty_out (vty, "%ld BGP routes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_info)),
           VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ROUTE_EXTRA)))
    vty_out (vty, "%ld BGP route ancillaries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_info_extra)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_STATIC)))
    vty_out (vty, "%ld Static routes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_static)),
             VTY_NEWLINE);

  /* Adj-In/Out */
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ADJ_IN)))
    vty_out (vty, "%ld Adj-In entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_in)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ADJ_OUT)))
    vty_out (vty, "%ld Adj-Out entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_out)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_NEXTHOP_CACHE)))
    vty_out (vty, "%ld Nexthop cache entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_nexthop_cache)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_DAMP_INFO)))
    vty_out (vty, "%ld Dampening entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_damp_info)),
             VTY_NEWLINE);

  /* Attributes */
  count = bgp_attr_count();
  vty_out (vty, "%ld BGP attributes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof(attr_set_t)),
           VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_UNKNOWN_ATTR)))
    vty_out (vty, "%ld unknown attributes%s", count, VTY_NEWLINE);

  /* AS_PATH attributes */
  count = as_path_count ();
  vty_out (vty, "%ld BGP AS-PATH entries, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (as_path_t)),
           VTY_NEWLINE);

  count = mem_get_alloc(mst, MTYPE_AS_PATH_BODY);
  vty_out (vty, "%ld BGP AS-PATH bodies, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (as_path_t)),    /* TODO fix !  */
           VTY_NEWLINE);

  /* Other attributes */
  if ((count = mem_get_alloc(mst, MTYPE_COMMUNITY)))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_community_t)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_ECOMMUNITY)))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_ecommunity_t)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_CLUSTER)))
    vty_out (vty, "%ld Cluster lists, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_cluster_t)),
             VTY_NEWLINE);

  /* Peer related usage */
  count = mem_get_alloc(mst, MTYPE_BGP_PEER);
  vty_out (vty, "%ld peers, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct peer)),
           VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_PEER_GROUP)))
    vty_out (vty, "%ld peer groups, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct peer_group)),
             VTY_NEWLINE);

  /* Other */
  if ((count = mem_get_alloc(mst, MTYPE_HASH)))
    vty_out (vty, "%ld hash tables, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_HASH_BACKET)))
    vty_out (vty, "%ld hash buckets, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash_backet)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_BGP_REGEXP)))
    vty_out (vty, "%ld compiled regexes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (regex_t)),
             VTY_NEWLINE);
  return CMD_SUCCESS;
}

/* Show BGP peer's summary information. */
static int
bgp_show_summary (struct vty *vty, struct bgp *bgp, qafx_t qafx)
{
  struct peer *peer;
  struct listnode *node, *nnode;
  unsigned int count = 0;
  char timebuf[BGP_UPTIME_LEN];
  int len;
  bgp_session_stats_t stats;

  /* Header string for each address family. */
  static const char header[] =
   /*123456789012345_1_12345_1234567_1234567_12345678_1234_1234_*/
    "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ "
   /*                         12345678_123456789012 */
                             "Up/Down  State/PfxRcd";

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;
      if (prib == NULL)
        continue ;

      bgp_session_get_stats(&stats, peer->session);

      if (count == 0)
        {
          ulong ents;
          char memstrbuf[MTYPE_MEMSTR_LEN];

          /* Usage summary and header */
          vty_out (vty,
                   "BGP router identifier %s, local AS number %u\n",
                siptoa(AF_INET, &bgp->router_id).str, bgp->my_as) ;

          ents = bgp_rib_count (bgp->rib[qafx][rib_main]);
          vty_out (vty, "RIB entries %ld, using %s of memory%s", ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (bgp_rib_node_t)),
                   VTY_NEWLINE);

          ents = bgp_rib_count (bgp->rib[qafx][rib_rs]);
          if (ents != 0)
            vty_out (vty, "RIB entries %ld, using %s of memory%s", ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (bgp_rib_node_t)),
                   VTY_NEWLINE);

          /* Peer related usage */
          ents = listcount (bgp->peer);
          vty_out (vty, "Peers %ld, using %s of memory%s",
                   ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (struct peer)),
                   VTY_NEWLINE);

#if 0
          if ((ents = listcount (bgp->rsclient)))
            vty_out (vty, "RS-Client peers %ld, using %s of memory%s",
                     ents,
                     mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                   ents * sizeof (struct peer)),
                     VTY_NEWLINE);
#endif

          if ((ents = listcount (bgp->group)))
            vty_out (vty, "Peer groups %ld, using %s of memory\n", ents,
                     mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                   ents * sizeof (struct peer_group)));

          if (CHECK_FLAG (bgp->af_flags[qafx], BGP_CONFIG_DAMPING))
            vty_out (vty, "Dampening enabled.\n");

          vty_out (vty, "\n"
                        "%s\n", header);
        }

      count++;

      vty_out (vty, "%s", peer->host);
      len = 15 - strlen(peer->host);
      if      (len < 0)
        vty_out (vty, "\n%*s", 15, " ");
      else if (len > 0)
        vty_out (vty, "%*s",  len, " ");

      vty_out (vty, " 4 ");

      vty_out (vty, "%5u %7d %7d %8d %4d %4lu ",
               peer->args.remote_as,
               stats.open_in + stats.update_in + stats.keepalive_in
               + stats.notify_in + stats.refresh_in + stats.dynamic_cap_in,
               stats.open_out + stats.update_out + stats.keepalive_out
               + stats.notify_out + stats.refresh_out
               + stats.dynamic_cap_out,
               0, 0, (ulong)0 /* TODO "output queue depth" */);

      vty_out (vty, "%-8s",
               peer_uptime (peer->uptime, timebuf, BGP_UPTIME_LEN));

      if (peer->state == bgp_pEstablished)
        {
          vty_out (vty, " %8u", prib->pcount);
        }
      else
        {
          if (peer->cops.conn_state & bc_is_down)
            vty_out (vty, " Idle (Admin)");
          else if (peer->sflags & PEER_STATUS_PREFIX_OVERFLOW)
            vty_out (vty, " Idle (PfxCt)");
          else
            vty_out (vty, " %-11s",
                         map_direct(bgp_peer_status_map, peer->state).str) ;
        }

      vty_out (vty, "\n");
    } ;

  if (count)
    vty_out (vty, "%sTotal number of neighbors %d%s", VTY_NEWLINE,
             count, VTY_NEWLINE);
  else
    vty_out (vty, "No %s neighbor is configured%s",
             qafx_is_ipv4(qafx) ? "IPv4" : "IPv6", VTY_NEWLINE);
  return CMD_SUCCESS;
}

static int
bgp_show_summary_vty (struct vty *vty, const char *name, qafx_t qafx)
{
  struct bgp *bgp;

  if (name)
    {
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
        {
          vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      bgp_show_summary (vty, bgp, qafx);
      return CMD_SUCCESS;
    }

  bgp = bgp_get_default ();

  if (bgp)
    bgp_show_summary (vty, bgp, qafx);

  return CMD_SUCCESS;
}

/* `show ip bgp summary' commands. */
DEFUN (show_ip_bgp_summary,
       show_ip_bgp_summary_cmd,
       "show ip bgp summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_instance_summary,
       show_ip_bgp_instance_summary_cmd,
       "show ip bgp view WORD summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, argv[0], qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_summary,
       show_ip_bgp_ipv4_summary_cmd,
       "show ip bgp ipv4 (unicast|multicast) summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_summary_vty (vty, NULL, qafx);
}

ALIAS (show_ip_bgp_ipv4_summary,
       show_bgp_ipv4_safi_summary_cmd,
       "show bgp ipv4 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_instance_ipv4_summary,
       show_ip_bgp_instance_ipv4_summary_cmd,
       "show ip bgp view WORD ipv4 (unicast|multicast) summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_summary_vty (vty, argv[0], qafx);
}

ALIAS (show_ip_bgp_instance_ipv4_summary,
       show_bgp_instance_ipv4_safi_summary_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_vpnv4_all_summary,
       show_ip_bgp_vpnv4_all_summary_cmd,
       "show ip bgp vpnv4 all summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_mpls_vpn);
}

DEFUN (show_ip_bgp_vpnv4_rd_summary,
       show_ip_bgp_vpnv4_rd_summary_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Summary of BGP neighbor status\n")
{
  struct prefix_rd prd;

  if (! str2prefix_rd_vty (vty, &prd, argv[0]))
    return CMD_WARNING;

  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_mpls_vpn);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_summary,
       show_bgp_summary_cmd,
       "show bgp summary",
       SHOW_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

DEFUN (show_bgp_instance_summary,
       show_bgp_instance_summary_cmd,
       "show bgp view WORD summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (show_bgp_summary,
       show_bgp_ipv6_summary_cmd,
       "show bgp ipv6 summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Summary of BGP neighbor status\n")

ALIAS (show_bgp_instance_summary,
       show_bgp_instance_ipv6_summary_cmd,
       "show bgp view WORD ipv6 summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_bgp_ipv6_safi_summary,
       show_bgp_ipv6_safi_summary_cmd,
       "show bgp ipv6 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_summary_vty (vty, NULL, qafx);
}

DEFUN (show_bgp_instance_ipv6_safi_summary,
       show_bgp_instance_ipv6_safi_summary_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[1][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_summary_vty (vty, argv[0], qafx);
}

/* old command */
DEFUN (show_ipv6_bgp_summary,
       show_ipv6_bgp_summary_cmd,
       "show ipv6 bgp summary",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_summary,
       show_ipv6_mbgp_summary_cmd,
       "show ipv6 mbgp summary",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_multicast);
}
#endif /* HAVE_IPV6 */

static const char *
qafx_string(qafx_t qafx)
{
  switch (qafx)
    {
      case qafx_ipv4_unicast:
        return "IPv4 Unicast";

      case qafx_ipv4_multicast:
        return "IPv4 Multicast";

      case qafx_ipv4_mpls_vpn:
        return "VPNv4 Unicast";

      case qafx_ipv6_unicast:
        return "IPv6 Unicast";

      case qafx_ipv6_multicast:
        return "IPv6 Multicast";

      default:
        return "Unknown";
    } ;
} ;

const char *
afi_safi_print (qAFI_t q_afi, qSAFI_t q_safi)
{
  return qafx_string(qafx_from_q(q_afi, q_safi)) ;
}

/* Show BGP peer's information. */
enum show_type
{
  show_all,
  show_peer
};

static void
bgp_show_peer_afi_orf_cap (vty vty, bgp_orf_cap_bits_t orf_pfx_sent,
                                                       peer_af_cap_bits_t sm,
                                    bgp_orf_cap_bits_t orf_pfx_recv,
                                                       peer_af_cap_bits_t rm)
{
  bool sent, recv ;

  /* Send-Mode
   */
  sent = (orf_pfx_sent & sm) ;
  recv = (orf_pfx_recv & rm) ;

  if (sent || recv)
    {
      vty_out (vty, "      Send-mode: ");
      if (sent)
        vty_out (vty, "requested");
      if (sent && recv)
        vty_out (vty, " and ") ;
      if (recv)
        vty_out (vty, "allowed") ;
      vty_out (vty, "\n");
    } ;

  /* Receive-Mode
   */
  sent = (orf_pfx_sent & rm) ;
  recv = (orf_pfx_recv & sm) ;

  if (sent || recv)
    {
      vty_out (vty, "      Receive-mode: ");
      if (sent)
        vty_out (vty, "requested");
      if (sent && recv)
        vty_out (vty, " and ") ;
      if (recv)
        vty_out (vty, "allowed") ;
      vty_out (vty, "\n");
    } ;
} ;

static void
bgp_show_peer_afi (vty vty, bgp_peer peer, qafx_t qafx)
{
  peer_rib     prib ;
  access_list  dlist ;
  prefix_list  plist ;
  as_list      flist ;
  route_map    rmap ;
  bgp_orf_name orf_pfx_name;
  int orf_pfx_count;
  peer_af_flag_bits_t aff ;

  prib = peer_family_prib(peer, qafx) ;
  qassert(prib != NULL) ;
  if (prib == NULL)
    return ;

  vty_out (vty, " For address family: %s\n", qafx_string(qafx));

  if (prib->af_group_member)
    vty_out (vty, "  %s peer-group member\n", peer->group->name);

  if (peer->state == bgp_pEstablished)
    {
      bgp_orf_cap_bits_t orf_pfx_sent, orf_pfx_recv ;

      orf_pfx_sent = peer->session->open_recv->args->can_orf_pfx[qafx] ;
      orf_pfx_recv = peer->session->open_recv->args->can_orf_pfx[qafx] ;

      if ((orf_pfx_sent | orf_pfx_recv) != 0)
        vty_out (vty, "  AF-dependant capabilities:\n");

      if ((orf_pfx_sent | orf_pfx_recv) & (ORF_SM | ORF_RM) )
        {
          vty_out (vty,
                   "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
                                                                BGP_ORF_T_PFX);
          bgp_show_peer_afi_orf_cap (vty, orf_pfx_sent, orf_pfx_recv,
                                                               ORF_SM, ORF_RM) ;
        } ;

      if ((orf_pfx_sent | orf_pfx_recv) & (ORF_SM_pre | ORF_RM_pre) )
        {
          vty_out (vty,
                   "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
                                                             BGP_ORF_T_PFX_pre);
          bgp_show_peer_afi_orf_cap (vty, orf_pfx_sent, orf_pfx_recv,
                                                       ORF_SM_pre, ORF_RM_pre) ;
        } ;
    } ;

  prefix_bgp_orf_name_set(orf_pfx_name, peer->su_name, qafx) ;

  orf_pfx_count = prefix_bgp_show_prefix_list (NULL, orf_pfx_name);

  if ((prib->af_status & PEER_AFS_ORF_PFX_SENT) || (orf_pfx_count != 0))
    {
      vty_out (vty, "  Outbound Route Filter (ORF):");
      if (prib->af_status & PEER_AFS_ORF_PFX_SENT)
        vty_out (vty, " sent;");
      if (orf_pfx_count)
        vty_out (vty, " received (%d entries)", orf_pfx_count);
      vty_out (vty, "\n");
    } ;

  if (prib->af_status & PEER_AFS_ORF_PFX_WAIT)
      vty_out (vty, "  First update is deferred until ORF or ROUTE-REFRESH "
                                                  "is received\n");

  aff = peer->config.af_flags ;

  if (aff & PEER_AFF_REFLECTOR_CLIENT)
    vty_out (vty, "  Route-Reflector Client\n");
  if (aff & PEER_AFF_RSERVER_CLIENT)
    vty_out (vty, "  Route-Server Client\n");
  if (aff & PEER_AFF_SOFT_RECONFIG)
    vty_out (vty, "  Inbound soft reconfiguration allowed\n");
  if (aff & PEER_AFF_REMOVE_PRIVATE_AS)
    vty_out (vty, "  Private AS number removed from updates to this neighbor\n");
  if (aff & PEER_AFF_NEXTHOP_SELF)
    vty_out (vty, "  NEXT_HOP is always this router\n");
  if (aff & PEER_AFF_AS_PATH_UNCHANGED)
    vty_out (vty, "  AS_PATH is propagated unchanged to this neighbor\n");
  if (aff & PEER_AFF_NEXTHOP_UNCHANGED)
    vty_out (vty, "  NEXT_HOP is propagated unchanged to this neighbor\n");
  if (aff & PEER_AFF_MED_UNCHANGED)
    vty_out (vty, "  MED is propagated unchanged to this neighbor\n");
  if (aff & (PEER_AFF_SEND_COMMUNITY | PEER_AFF_SEND_EXT_COMMUNITY))
    {
      vty_out (vty, "  Community attribute sent to this neighbor");
      if ( (aff & PEER_AFF_SEND_COMMUNITY) &&
           (aff & PEER_AFF_SEND_EXT_COMMUNITY) )
        vty_out (vty, "(both)\n");
      else if (aff & PEER_AFF_SEND_EXT_COMMUNITY)
        vty_out (vty, "(extended)\n");
      else
        vty_out (vty, "(standard)\n");
    }
  if (aff & PEER_AFF_DEFAULT_ORIGINATE)
    {
      vty_out (vty, "  Default information originate,");

      if (prib->default_rmap != NULL)
        vty_out (vty, " default route-map %s%s,",
                 route_map_is_set(prib->default_rmap) ? "*" : "",
                 route_map_get_name(prib->default_rmap)) ;
      if (prib->af_status & PEER_AFS_DEFAULT_SENT)
        vty_out (vty, " default sent\n");
      else
        vty_out (vty, " default not sent\n");
    }

  if ( (prib->plist[FILTER_IN]  != NULL)  ||
       (prib->dlist[FILTER_IN]  != NULL)  ||
       (prib->flist[FILTER_IN] != NULL) ||
       (prib->rmap[RMAP_IN]     != NULL) )
    vty_out (vty, "  Inbound path policy configured\n");

  if (prib->rmap[RMAP_RS_IN] != NULL)
    vty_out (vty, "  RS-Inbound policy configured\n");

  if ( (prib->plist[FILTER_OUT]  != NULL)  ||
       (prib->dlist[FILTER_OUT]  != NULL)  ||
       (prib->flist[FILTER_OUT] != NULL) ||
       (prib->rmap[RMAP_OUT]     != NULL) ||
       (prib->us_rmap            != NULL) )
    vty_out (vty, "  Outbound path policy configured\n");

  if (prib->rmap[RMAP_IMPORT] != NULL)
    vty_out (vty, "  Import policy for this RS-client configured\n");

  if (prib->rmap[RMAP_EXPORT] != NULL)
    vty_out (vty, "  Export policy for this RS-client configured\n");

  /* prefix-list */
  plist = prib->plist[FILTER_IN] ;
  if (plist != NULL)
    vty_out (vty, "  Incoming update prefix filter list is %s%s\n",
             prefix_list_is_set(plist) ? "*" : "", prefix_list_get_name(plist));

  plist = prib->plist[FILTER_OUT] ;
  if (plist != NULL)
    vty_out (vty, "  Outgoing update prefix filter list is %s%s\n",
             prefix_list_is_set(plist) ? "*" : "", prefix_list_get_name(plist));

  /* distribute-list */
  dlist = prib->dlist[FILTER_IN] ;
  if (dlist != NULL)
    vty_out (vty, "  Incoming update network filter list is %s%s\n",
             access_list_is_set(dlist) ? "*" : "", access_list_get_name(dlist));
  dlist = prib->dlist[FILTER_OUT] ;
  if (dlist != NULL)
    vty_out (vty, "  Outgoing update network filter list is %s%s\n",
             access_list_is_set(dlist) ? "*" : "", access_list_get_name(dlist));

  /* filter-list. */
  flist = prib->flist[FILTER_IN] ;
  if (flist != NULL)
    vty_out (vty, "  Incoming update AS path filter list is %s%s\n",
             as_list_is_set(flist) ? "*" : "", as_list_get_name(flist));
  flist = prib->flist[FILTER_OUT] ;
  if (flist != NULL)
    vty_out (vty, "  Outgoing update AS path filter list is %s%s\n",
             as_list_is_set(flist) ? "*" : "", as_list_get_name(flist));

  /* route-map. */
  rmap = prib->rmap[RMAP_IN] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for incoming advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_RS_IN] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for RS incoming advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_OUT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for outgoing advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_IMPORT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for advertisements going into this"
                                                 " RS-client's table is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_EXPORT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for advertisements coming from this "
                                                          "RS-client is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));

  /* unsuppress-map
   */
  rmap = prib->us_rmap ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for selective unsuppress is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));

  /* Receive prefix count
   */
  vty_out (vty, "  %u accepted prefixes\n", prib->pcount);

  /* Maximum prefix
   */
  if (prib->pmax.set)
    {
      vty_out (vty, "  Maximum prefixes allowed %u%s\n", prib->pmax.limit,
                                (prib->pmax.warning) ? " (warning-only)" : "") ;
      vty_out (vty, "  Threshold for warning message %d%%",
                                                      prib->pmax.thresh_pc);
      if (prib->pmax.restart != 0)
        vty_out (vty, ", restart interval %d min", prib->pmax.restart);

      vty_out (vty, "\n");
    }

  vty_out (vty, "\n");
}


/*------------------------------------------------------------------------------
 * Show state of a *real* peer
 */
static void bgp_capability_vty_out (struct vty *vty, struct peer *peer)

static void
bgp_show_peer (struct vty *vty, bgp_peer peer)
{
  bgp_inst bgp;
  char timebuf[BGP_UPTIME_LEN];
  qafx_t qafx ;
  bgp_session_stats_t stats;
  bool established_gr ;

  qassert(peer->type == PEER_TYPE_REAL) ;

  bgp_session_get_stats(&stats, peer->session);

  bgp = peer->bgp;

  /* Configured IP address.
   */
  vty_out (vty, "BGP neighbor is %s, ", peer->host);
  vty_out (vty, "remote AS %u, ", peer->args.remote_as);
  vty_out (vty, "local AS %u", peer->args.local_as) ;
  if ((peer->sort == BGP_PEER_EBGP)
        && (peer->change_local_as != BGP_ASN_NULL)
        && (peer->change_local_as != bgp->ebgp_as))
    vty_out (vty, " (changed%s)", (peer->change_local_as_prepend
                                                       ? "" : " no-prepend")) ;
  vty_out (vty, ", %s link\n",
                     (peer->sort == BGP_PEER_IBGP) ? "internal" : "external") ;

  /* Description.
   */
  if (peer->desc)
    vty_out (vty, " Description: %s%s", peer->desc, VTY_NEWLINE);

  /* Peer-group
   */
  if (peer->group)
    vty_out (vty, " Member of peer-group %s for session parameters%s",
             peer->group->name, VTY_NEWLINE);

  /* Administrative shutdown.
   */
  if (peer->cops.conn_state == bc_is_shutdown)
    vty_out (vty, " Administratively shut down\n");

  /* BGP Version.
   */
  vty_out (vty, "  BGP version 4");
  vty_out (vty, ", remote router ID %s%s\n",
                    siptoa(AF_INET, &peer->args.remote_id).str,
                     (peer->state == bgp_pEstablished) ? ""
                                                       : " (in last session)") ;
  /* Confederation
   */
  if (bgp_confederation_peers_check (bgp, peer->args.remote_as))
    vty_out (vty, "  Neighbor under common administration\n");

  /* Status.
   */
  vty_out (vty, "  BGP state = %s",
                             map_direct(bgp_peer_status_map, peer->state).str) ;
  if (peer->state == bgp_pEstablished)
    vty_out (vty, ", up for %-8s",
                          peer_uptime (peer->uptime, timebuf, BGP_UPTIME_LEN)) ;

  /* TODO: what is state "Active" now?  pUp? */
#if 0
  else if (peer->status == Active)
    {
      if (CHECK_FLAG (peer->flags, PEER_FLAG_PASSIVE))
        vty_out (vty, " (passive)");
      else if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT))
        vty_out (vty, " (NSF passive)");
    }
#endif

  vty_out (vty, "\n");

  /* read timer and holdtime/keepalive
   */
  vty_out (vty, "  Last read %s", peer_uptime (peer->readtime, timebuf,
                                                               BGP_UPTIME_LEN));
  if (peer->state == bgp_pEstablished)
    vty_out (vty, " -- current "
                      "hold time is %u, keepalive interval is %u seconds\n",
                                          peer->session->args->holdtime_secs,
                                          peer->session->args->keepalive_secs) ;
  else
    vty_out (vty, " -- configured "
                      "hold time is %u, keepalive interval is %u seconds\n",
                          peer->args.holdtime_secs, peer->args.keepalive_secs) ;

  /* Capabilities.
   */
  established_gr = false ;

  if (peer->state == bgp_pEstablished)
    {
      bgp_session_args args_sent, args_recv, args ;

      args_sent = peer->session->open_sent->args ;
      args_recv = peer->session->open_recv->args ;
      args      = peer->session->args ;

      vty_out (vty, "  Neighbor capabilities:\n");

      if (args_sent->can_capability)
        {
          if (!args_recv->can_capability)
            vty_out(vty, "    capabilities sent, but none received") ;
        }
      else
        {
          if (args_sent->cap_suppressed)
            vty_out(vty, "    peer refused capabilities") ;
          else
            vty_out(vty, "    'dont-capability-negotiate'") ;

          if (args_recv->can_capability)
            vty_out(vty, " BUT some received\n") ;
          else
            vty_out(vty, " and none received\n") ;
        } ;

      /* AS4
       */
      if ((args_sent->can_as4) || (args_sent->can_as4))
        {
          vty_out (vty, "    4 Byte AS:");
          if (args_sent->can_as4)
            vty_out (vty, " advertised%s", (args_recv->can_as4) ? " and"
                                                                : "") ;
          if (args_recv->can_as4)
            vty_out (vty, " received");
          vty_out (vty, "\n");
        }

      /* Multiprotocol Extensions
       */
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          qafx_bit_t qb ;

          qb = qafx_bit(qafx) ;

          if ((args_sent->can_af |args_recv->can_af | args->can_af) & qb)
            {
              const char* and ;

              vty_out (vty, "    Address family %s:", qafx_string(qafx));

              /* args_sent->can_af registers which afi/safi have been
               * advertised, explicitly by MP-Ext or implicitly.
               */
              and = "" ;
              if (args_sent->can_af & qb)
                {
                  if      (args_sent->can_mp_ext)
                    vty_out(vty, " advertised") ;
                  else
                    vty_out(vty, " implied") ;

                  and = " and" ;
                } ;

              /* args_recv->can_af registers which afi/safi were announced, or
               * implicitly announced.
               *
               * So, if is not args_recv->can_af, but is args->can_af, then it
               * must have been forced !
               */
              if      (args_recv->can_af & qb)
                {
                  if (args_recv->can_mp_ext)
                    vty_out(vty, "%s received", and) ;
                  else
                    vty_out(vty, "%s implied", and) ;
                }
              else if (args->can_af & qb)
                vty_out(vty, "%s forced", and) ;

              /* args->can_af is the final result.
               */
              if (args->can_af & qb)
                vty_out (vty, " -- in use") ;

              vty_out (vty, "\n");
            } ;
        } ;

      /* Route Refresh
       */
      if ( (args_sent->can_rr != bgp_form_none) ||
           (args_recv->can_rr != bgp_form_none) )
        {
          const char* adv_tag ;
          const char* rcv_tag ;

          adv_tag = "" ;
          if (args_sent->can_rr == bgp_form_pre)
            adv_tag = "(old)" ;

          rcv_tag = "" ;
          if (args_recv->can_rr == bgp_form_pre)
            rcv_tag = "(old)" ;

          vty_out (vty, "    Route refresh:");
          if (args_sent->can_rr != bgp_form_none)
            vty_out (vty, " advertised%s%s", adv_tag,
                        ((args_recv->can_rr != bgp_form_none) ? " and" : "")) ;
          if (args_recv->can_rr != bgp_form_none)
            vty_out (vty, " received%s", rcv_tag) ;
          vty_out (vty, "\n");
        }

      /* Graceful Restart
       */
      established_gr = args->gr.can ;

      if (args_sent->gr.can || args_recv->gr.can)
        {
          vty_out (vty, "    Graceful Restart Capability:");
          if (args_sent->gr.can)
            vty_out (vty, " advertised%s", (args_recv->gr.can ? " and" : ""));
          if (args_recv->gr.can)
            vty_out (vty, " received");
          vty_out (vty, "\n");

          if (args_recv->gr.can)
            {
              int restart_af_count = 0;

              vty_out (vty, "      Remote Restart timer is %d seconds\n",
                                                           peer->v_gr_restart) ;
              vty_out (vty, "      Address families by peer:\n"
                            "        ") ;

              for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
                {
                  qafx_bit_t qb ;

                  qb = qafx_bit(qafx) ;

                  if (args_recv->gr.can_preserve & qb)
                    {
                      vty_out (vty, "%s%s(%s)", (restart_af_count ? ", " : ""),
                                                qafx_string(qafx),
                          (args_recv->gr.can_preserve & qb ? "preserved"
                                                           : "not preserved")) ;
                      restart_af_count++;
                    } ;
                } ;

              if (restart_af_count == 0)
                vty_out (vty, "none");
              vty_out (vty, "\n") ;
            } ;
        } ;

      /* Dynamic
       */
      if (args_sent->can_dynamic || args_recv->can_dynamic)
        {
          vty_out (vty, "    Dynamic:");
          if (args_sent->can_dynamic)
            vty_out (vty, " advertised%s",
                                         args_recv->can_dynamic ? " and" : "") ;
          if (args_recv->can_dynamic)
            vty_out (vty, " received") ;
          vty_out (vty, "\n");
        } ;

      /* Dynamic Deprecated
       */
      if (args_sent->can_dynamic_dep || args_recv->can_dynamic_dep)
        {
          vty_out (vty, "    Dynamic (deprecated):");
          if (args_sent->can_dynamic_dep)
            vty_out (vty, " advertised%s",
                                     args_recv->can_dynamic_dep ? " and" : "") ;
          if (args_recv->can_dynamic_dep)
            vty_out (vty, " received") ;
          vty_out (vty, "\n");
        } ;
    } ;

  /* graceful restart information
   */
  if ( established_gr || (peer->t_gr_restart != NULL)
                      || (peer->t_gr_stale   != NULL) )
    {
      int eor_send_af_count = 0;
      int eor_receive_af_count = 0;

      vty_out (vty, "  Graceful Restart information:\n");

      if (peer->state == bgp_pEstablished)
        {
          vty_out (vty, "    End-of-RIB sent: ");
          for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
            {
              peer_rib prib ;
              prib = peer_family_prib(peer, qafx) ;

              if ((prib != NULL) && (prib->af_status & PEER_AFS_EOR_SENT))
                {
                  vty_out (vty, "%s%s", eor_send_af_count ? ", " : "",
                                                            qafx_string(qafx));
                  eor_send_af_count++;
                } ;
              } ;
          vty_out (vty, "\n");

          vty_out (vty, "    End-of-RIB received: ");
          for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
            {
              peer_rib prib ;
              prib = peer_family_prib(peer, qafx) ;

              if ((prib != NULL) &&
                                (prib->af_status & PEER_AFS_EOR_RECEIVED))
                {
                  vty_out (vty, "%s%s", eor_receive_af_count ? ", " : "",
                                                            qafx_string(qafx));
                  eor_receive_af_count++;
                } ;
            } ;
          vty_out (vty, "\n");
        }

      if (peer->t_gr_restart)
        vty_out (vty, "    The remaining time of restart timer is %ld\n",
                              thread_timer_remain_second (peer->t_gr_restart)) ;

      if (peer->t_gr_stale)
        vty_out (vty, "    The remaining time of stalepath timer is %ld\n",
                                thread_timer_remain_second (peer->t_gr_stale)) ;
    }

  /* Packet counts.
   */
  vty_out (vty, "  Message statistics:\n");
  vty_out (vty, "    Inq depth is 0\n");
  vty_out (vty, "    Outq depth is %lu\n", (ulong)0 /* TODO */);
  vty_out (vty, "                         Sent       Rcvd\n");
  vty_out (vty, "    Opens:         %10u %10u\n", stats.open_out,
                                                  stats.open_in);
  vty_out (vty, "    Notifications: %10u %10u\n", stats.notify_out,
                                                  stats.notify_in);
  vty_out (vty, "    Updates:       %10u %10u\n", stats.update_out,
                                                  stats.update_in);
  vty_out (vty, "    Keepalives:    %10u %10u\n", stats.keepalive_out,
                                                  stats.keepalive_in);
  vty_out (vty, "    Route Refresh: %10u %10u\n", stats.refresh_out,
                                                  stats.refresh_in);
  vty_out (vty, "    Capability:    %10u %10u\n", stats.dynamic_cap_out,
                                                  stats.dynamic_cap_in);
  vty_out (vty, "    Total:         %10u %10u\n",
              (stats.open_out + stats.notify_out + stats.update_out +
               stats.keepalive_out + stats.refresh_out + stats.dynamic_cap_out),
              (stats.open_in + stats.notify_in + stats.update_in +
               stats.keepalive_in + stats.refresh_in + stats.dynamic_cap_in));

  /* advertisement-interval
   */
  vty_out (vty, "  Minimum time between advertisement runs is %d seconds\n",
                                                           peer_get_mrai(peer));

  /* Update-source.
   */
  if ((peer->cops.ifname[0] != '\0') ||
      (sockunion_family(&peer->cops.su_local) != AF_UNSPEC))
    {
      if (peer->config.set & PEER_CONFIG_INTERFACE)
        {
          vty_out (vty, "  Interface is %s\n", peer->cops.ifname);
        }
      else
        {
          vty_out (vty, "  Update source is ");
          if (peer->cops.ifname[0] != '\0')
            vty_out (vty, "%s", peer->cops.ifname);
          else
            vty_out (vty, "%s", sutoa(&peer->cops.su_local).str);
          vty_out (vty, "\n");
        } ;
    } ;

  /* Default weight
   */
  if (peer->config.set & PEER_CONFIG_WEIGHT)
    vty_out (vty, "  Default weight %d\n", peer->weight);

  vty_out (vty, "\n");

  /* Address Family Information
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    if (peer_family_is_active(peer, qafx))
      bgp_show_peer_afi (vty, peer, qafx);

  vty_out (vty, "  Connections established %d; dropped %d\n",
                                             peer->established, peer->dropped) ;

  if (! peer->dropped)
    vty_out (vty, "  Last reset never\n");
  else
    vty_out (vty, "  Last reset %s, due to %s\n",
                      peer_uptime (peer->resettime, timebuf, BGP_UPTIME_LEN),
                                        peer_down_str[(int) peer->last_reset]) ;

  if (peer->idle & (bgp_pisMaxPrefixWait | bgp_pisMaxPrefixStop))
    {
      vty_out (vty,
          "  Peer had exceeded the max. no. of prefixes configured.\n") ;

      if (peer->idle & bgp_pisMaxPrefixStop)
        vty_out (vty, "  Needs 'clear ip bgp %s' to restore peering\n",
                                                                   peer->host) ;
      else
        vty_out (vty, "  Will restart %s in %ld seconds\n", peer->host,
                         (long)(qtimer_has_left(peer->qt_restart) / QTIME(1))) ;
    } ;

  /* EBGP Multihop and GTSM -- for these purposes eBGP includes Confed eBGP.
   */
  if (peer->sort != BGP_PEER_IBGP)
    {
      if (peer->cops.gtsm)
        vty_out (vty, "  External BGP neighbor may be up to %d hops away"
                                                            " -- using GTSM.\n",
                                                               peer->cops.ttl) ;
      else if (peer->cops.ttl > 1)
        vty_out (vty, "  External BGP neighbor may be up to %d hops away.\n",
                                                               peer->cops.ttl) ;
    }

  /* Local address and remote address, if established.
   *
   * Also next-hop(s)
   */
  if (peer->state == bgp_pEstablished)
    {
      vty_out (vty, "Local host: %s, Local port: %u\n",
                         sutoa(&peer->session->cops->su_local).str,
                          ntohs(peer->session->cops->su_local.sin.sin_port)) ;

      vty_out (vty, "Foreign host: %s, Foreign port: %u\n",
                        sutoa(&peer->session->cops->su_remote).str,
                          ntohs(peer->session->cops->su_remote.sin.sin_port)) ;

      vty_out (vty, "Nexthop: %s\n", siptoa(AF_INET, &peer->nexthop.v4).str) ;
#ifdef HAVE_IPV6
      vty_out (vty, "Nexthop global: %s\n",
                                 siptoa(AF_INET6, &peer->nexthop.v6_global).str) ;
      vty_out (vty, "Nexthop local: %s\n",
                                  siptoa(AF_INET6, &peer->nexthop.v6_local).str) ;
      vty_out (vty, "BGP connection: %s\n",
               peer->shared_network ? "shared network" : "non shared network");
#endif /* HAVE_IPV6 */
    }

  /* TODO: Timer information. */
#if 0
  if (peer->t_start)
    vty_out (vty, "Next start timer due in %ld seconds%s",
             thread_timer_remain_second (peer->t_start), VTY_NEWLINE);
  if (peer->t_connect)
    vty_out (vty, "Next connect timer due in %ld seconds%s",
             thread_timer_remain_second (peer->t_connect), VTY_NEWLINE);
#endif

#if 0
  vty_out (vty, "Read thread: %s  Write thread: %s%s",
           peer->t_read ? "on" : "off",
           peer->t_write ? "on" : "off",
           VTY_NEWLINE);
#endif

  if (peer->session != NULL && peer->session->note != NULL
      && peer->session->note->code    == BGP_NOMC_OPEN
      && peer->session->note->subcode == BGP_NOMS_O_CAPABILITY)
    bgp_capability_vty_out (vty, peer);

  vty_out (vty, "%s", VTY_NEWLINE);
}

static void
bgp_capability_vty_out (struct vty *vty, struct peer *peer)
{
  /* Standard header for capability TLV */
  struct capability_header
  {
    u_char code;
    u_char length;
  };

  /* Generic MP capability data */
  typedef struct capability_mp_data  capability_mp_data_t ;
  typedef struct capability_mp_data* capability_mp_data ;

  struct capability_mp_data
  {
    afi_t afi;
    u_char reserved;
    safi_t safi;
  };
  CONFIRM(offsetof(capability_mp_data_t, reserved) == 2) ;
  CONFIRM(offsetof(capability_mp_data_t, safi) == 3) ;

  #pragma pack(1)
  struct capability_orf_entry
  {
    struct capability_mp_data mpc;
    u_char num;
    struct {
      u_char type;
      u_char mode;
    } orfs[];
  } __attribute__ ((packed));
  #pragma pack()

  struct capability_as4
  {
    uint32_t as4;
  };

  struct graceful_restart_af
  {
    afi_t afi;
    safi_t safi;
    u_char flag;
  };

  struct capability_gr
  {
    u_int16_t restart_flag_time;
    struct graceful_restart_af gr[];
  };

  /* Cooperative Route Filtering Capability.  */

  /* ORF Type */
  #define ORF_TYPE_PREFIX                64
  #define ORF_TYPE_PREFIX_OLD           128

  /* ORF Mode */
  #define ORF_MODE_RECEIVE                1
  #define ORF_MODE_SEND                   2
  #define ORF_MODE_BOTH                   3

  /* Capability Message Action.  */
  #define CAPABILITY_ACTION_SET           0
  #define CAPABILITY_ACTION_UNSET         1

  /* Graceful Restart */
  #define RESTART_R_BIT              0x8000
  #define RESTART_F_BIT              0x80

  static const struct message orf_type_str[] =
  {
    { ORF_TYPE_PREFIX,            "Prefixlist"            },
    { ORF_TYPE_PREFIX_OLD,        "Prefixlist (old)"      },
  };
  static const int orf_type_str_max
          = sizeof(orf_type_str)/sizeof(orf_type_str[0]);

  static const struct message orf_mode_str[] =
  {
    { ORF_MODE_RECEIVE,   "Receive"       },
    { ORF_MODE_SEND,      "Send"          },
    { ORF_MODE_BOTH,      "Both"          },
  };
  static const int orf_mode_str_max
           = sizeof(orf_mode_str)/sizeof(orf_mode_str[0]);

  static const struct message capcode_str[] =
  {
    { BGP_CAN_MP_EXT    ,                 "MultiProtocol Extensions"      },
    { BGP_CAN_R_REFRESH,                  "Route Refresh"                 },
    { BGP_CAN_ORF,                        "Cooperative Route Filtering"   },
    { BGP_CAN_G_RESTART,                  "Graceful Restart"              },
    { BGP_CAN_AS4,                        "4-octet AS number"             },
    { BGP_CAN_DYNAMIC_CAP_dep,            "Dynamic"                       },
    { BGP_CAN_R_REFRESH_pre,              "Route Refresh (Old)"           },
    { BGP_CAN_ORF_pre,                    "ORF (Old)"                     },
  };
  static const int capcode_str_max = sizeof(capcode_str)/sizeof(capcode_str[0]);

  /* Minimum sizes for length field of each cap (so not inc. the header)
   */
  static const size_t cap_minsizes[] =
  {
    [BGP_CAN_MP_EXT]              = sizeof (struct capability_mp_data),
    [BGP_CAN_R_REFRESH]           = BGP_CAP_RRF_L,
    [BGP_CAN_ORF]                 = sizeof (struct capability_orf_entry),
    [BGP_CAN_G_RESTART]           = sizeof (struct capability_gr),
    [BGP_CAN_AS4]                 = BGP_CAP_AS4_L,
    [BGP_CAN_DYNAMIC_CAP_dep]     = BGP_CAP_DYN_L,
    [BGP_CAN_R_REFRESH_pre]       = BGP_CAP_RRF_L,
    [BGP_CAN_ORF_pre]             = sizeof (struct capability_orf_entry),
  };

  char *pnt;
  char *end;
  struct capability_mp_data mpc;
  struct capability_header *hdr;

  if ((peer == NULL) || (peer->session == NULL)
                     || (peer->session->note == NULL))
    return;

  pnt = (char*)peer->session->note->data;
  end = pnt + peer->session->note->length;

  while (pnt < end)
    {
      if (pnt + sizeof (struct capability_mp_data) + 2 > end)
        return;

      hdr = (struct capability_header *)pnt;
      if (pnt + hdr->length + 2 > end)
        return;

      memcpy (&mpc, pnt + 2, sizeof(struct capability_mp_data));

      if (hdr->code == BGP_CAN_MP_EXT)
        {
          vty_out (vty, "  Capability error for: Multi protocol ");

          switch (ntohs (mpc.afi))
            {
            case iAFI_IP:
              vty_out (vty, "AFI IPv4, ");
              break;
            case iAFI_IP6:
              vty_out (vty, "AFI IPv6, ");
              break;
            default:
              vty_out (vty, "AFI Unknown %d, ", ntohs (mpc.afi));
              break;
            }
          switch (mpc.safi)
            {
            case iSAFI_Unicast:
              vty_out (vty, "SAFI Unicast");
              break;
            case iSAFI_Multicast:
              vty_out (vty, "SAFI Multicast");
              break;
            case iSAFI_MPLS_VPN:
              vty_out (vty, "SAFI MPLS-labeled VPN");
              break;
            default:
              vty_out (vty, "SAFI Unknown %d ", mpc.safi);
              break;
            }
          vty_out (vty, "%s", VTY_NEWLINE);
        }
      else if (hdr->code >= 128)
        vty_out (vty, "  Capability error: vendor specific capability code %d",
                                                                   hdr->code);
      else
        vty_out (vty, "  Capability error: unknown capability code %d",
                                                                   hdr->code);
      pnt += hdr->length + 2;
    }
}

static int
bgp_show_neighbor (struct vty *vty, struct bgp *bgp,
                   enum show_type type, union sockunion *su)
{
  struct listnode *node, *nnode;
  struct peer *peer;
  int find = 0;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      switch (type)
        {
          case show_all:
            bgp_show_peer (vty, peer);
            break;

          case show_peer:
            if (sockunion_same (peer->su_name, su))
              {
                find = 1;
                bgp_show_peer (vty, peer);
              }
            break;

          default:
            break ;
        }
    }

  if (type == show_peer && ! find)
    vty_out (vty, "%% No such neighbor%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

static int
bgp_show_neighbor_vty (struct vty *vty, const char *name,
                       enum show_type type, const char *ip_str)
{
  int ret;
  struct bgp *bgp;
  union sockunion su;

  if (ip_str)
    {
      ret = str2sockunion (ip_str, &su);
      if (ret < 0)
        {
          vty_out (vty, "%% Malformed address: %s%s", ip_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  if (name)
    {
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
        {
          vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
          return CMD_WARNING;
        }

      bgp_show_neighbor (vty, bgp, type, &su);

      return CMD_SUCCESS;
    }

  bgp = bgp_get_default ();

  if (bgp)
    bgp_show_neighbor (vty, bgp, type, &su);

  return CMD_SUCCESS;
}

/* "show ip bgp neighbors" commands.  */
DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")
{
  return bgp_show_neighbor_vty (vty, NULL, show_all, NULL);
}

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_ipv4_neighbors_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_all_neighbors_cmd,
       "show ip bgp vpnv4 all neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_rd_neighbors_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_neighbors_cmd,
       "show bgp neighbors",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_ipv6_neighbors_cmd,
       "show bgp ipv6 neighbors",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFUN (show_ip_bgp_neighbors_peer,
       show_ip_bgp_neighbors_peer_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  return bgp_show_neighbor_vty (vty, NULL, show_peer, argv[argc - 1]);
}

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_ipv4_neighbors_peer_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_all_neighbors_peer_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_rd_neighbors_peer_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_neighbors_peer_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_ipv6_neighbors_peer_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFUN (show_ip_bgp_instance_neighbors,
       show_ip_bgp_instance_neighbors_cmd,
       "show ip bgp view WORD neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n")
{
  return bgp_show_neighbor_vty (vty, argv[0], show_all, NULL);
}

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_neighbors_cmd,
       "show bgp view WORD neighbors",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_ipv6_neighbors_cmd,
       "show bgp view WORD ipv6 neighbors",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFUN (show_ip_bgp_instance_neighbors_peer,
       show_ip_bgp_instance_neighbors_peer_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  return bgp_show_neighbor_vty (vty, argv[0], show_peer, argv[1]);
}

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_neighbors_peer_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_ipv6_neighbors_peer_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

/* Show BGP's AS paths internal data.  There are both `show ip bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths,
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Path information\n")
{
  as_path_print_all_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_paths,
       show_ip_bgp_ipv4_paths_cmd,
       "show ip bgp ipv4 (unicast|multicast) paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Path information\n")
{
  as_path_print_all_vty (vty);
  return CMD_SUCCESS;
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info,
       show_ip_bgp_community_info_cmd,
       "show ip bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
  attr_community_print_all_vty (vty) ;

  return CMD_SUCCESS;
}

/* Show BGP's ecommunity internal data. */
DEFUN (show_ip_bgp_ecommunity_info,
       show_ip_bgp_ecommunity_info_cmd,
       "show ip bgp extcommunity-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp extcommunity information\n")
{
  attr_ecommunity_print_all_vty (vty) ;

  return CMD_SUCCESS;
}


DEFUN (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show ip bgp attribute-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")
{
  bgp_attr_show_all (vty);
  return CMD_SUCCESS;
}

static int
bgp_write_rsclient_summary (vty vty, bgp_peer rsclient, qafx_t qafx)
{
  char timebuf[BGP_UPTIME_LEN];
  char rmbuf[14];
  const char *rmname;
  struct listnode *node, *nnode;
  int len;
  int count = 0;
  peer_rib prib ;

  count = 0 ;

  if (rsclient->type == PEER_TYPE_GROUP_CONF)
    {
      for (ALL_LIST_ELEMENTS (rsclient->group->peer, node, nnode, rsclient))
        {
          count++;
          bgp_write_rsclient_summary (vty, rsclient, qafx);
        }
      return count;
    }

  prib = peer_family_prib(rsclient, qafx) ;
  if (prib == NULL)
    return 0 ;

  vty_out (vty, "%s", rsclient->host);
  len = 16 - strlen(rsclient->host) ;

  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 16, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "4 ");

  vty_out (vty, "%11d ", rsclient->args.remote_as);

  rmname = route_map_get_name(prib->rmap[RMAP_EXPORT]);
  if ( rmname && strlen (rmname) > 13 )
    {
      sprintf (rmbuf, "%13s", "...");
      rmname = strncpy (rmbuf, rmname, 10);
    }
  else if (! rmname)
    rmname = "<none>";
  vty_out (vty, " %13s ", rmname);

  rmname = route_map_get_name(prib->rmap[RMAP_IMPORT]);
  if ( rmname && strlen (rmname) > 13 )
    {
      sprintf (rmbuf, "%13s", "...");
      rmname = strncpy (rmbuf, rmname, 10);
    }
  else if (! rmname)
    rmname = "<none>";
  vty_out (vty, " %13s ", rmname);

  vty_out (vty, "%8s", peer_uptime (rsclient->uptime, timebuf, BGP_UPTIME_LEN));

  if (rsclient.cops->conn_state == bc_is_shutdown)
    vty_out (vty, " Idle (Admin)");
  else if (rsclient->sflags & PEER_STATUS_PREFIX_OVERFLOW)
    vty_out (vty, " Idle (PfxCt)");
  else
    vty_out (vty, " %-11s",
                         map_direct(bgp_peer_status_map, rsclient->state).str) ;

  vty_out (vty, "\n");

  return 1;
}

static int
bgp_show_rsclient_summary (struct vty *vty, struct bgp *bgp, qafx_t qafx)
{
  bgp_peer   peer ;
  struct listnode *node, *nnode;
  uint count = 0;

  /* Header string for each address family. */
  static char header[] =
       "Neighbor        V    AS  Export-Policy  Import-Policy  Up/Down  State";

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer_rib   prib ;

      prib = peer_family_prib(peer, qafx) ;
      if (prib == NULL)
        continue ;

      if (!prib->route_server_client)
        continue ;

      if (count == 0)
        {
          vty_out (vty, "Route Server's BGP router identifier %s\n",
                                         siptoa(AF_INET, &bgp->router_id).str) ;
          vty_out (vty, "Route Server's local AS number %u\n", bgp->my_as);

          vty_out (vty, "\n"
                        "%s\n", header) ;
        }

      count += bgp_write_rsclient_summary (vty, peer, qafx);
    }

  if (count)
    vty_out (vty, "\n"
                  "Total number of Route Server Clients %u\n", count) ;
  else
    vty_out (vty, "No %s Route Server Client is configured\n",
                                   get_qAFI(qafx) == qAFI_IP ? "IPv4" : "IPv6");
  return CMD_SUCCESS;
}

static int
bgp_show_rsclient_summary_vty (struct vty *vty, const char *name, qafx_t qafx)
{
  struct bgp *bgp;

  if (name)
    {
      bgp = bgp_lookup_by_name (name);

      if (! bgp)
       {
         vty_out (vty, "%% No such BGP instance exist%s", VTY_NEWLINE);
         return CMD_WARNING;
       }

      bgp_show_rsclient_summary (vty, bgp, qafx);
      return CMD_SUCCESS;
    }

  bgp = bgp_get_default ();

  if (bgp)
    bgp_show_rsclient_summary (vty, bgp, qafx);

  return CMD_SUCCESS;
}

/* 'show bgp rsclient' commands. */
DEFUN (show_ip_bgp_rsclient_summary,
       show_ip_bgp_rsclient_summary_cmd,
       "show ip bgp rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, NULL, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_instance_rsclient_summary,
       show_ip_bgp_instance_rsclient_summary_cmd,
       "show ip bgp view WORD rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  const char* name ;

  name = argv[0] ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_rsclient_summary,
      show_ip_bgp_ipv4_rsclient_summary_cmd,
      "show ip bgp ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  name = NULL ;
  cast = argv[0] ;

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

DEFUN (show_ip_bgp_instance_ipv4_rsclient_summary,
      show_ip_bgp_instance_ipv4_rsclient_summary_cmd,
      "show ip bgp view WORD ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  name = argv[0] ;
  cast = argv[1] ;

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

DEFUN (show_bgp_instance_ipv4_safi_rsclient_summary,
       show_bgp_instance_ipv4_safi_rsclient_summary_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  if (argc == 1)
    {
      name = NULL ;
      cast = argv[0] ;
    }
  else
    {
      name = argv[0] ;
      cast = argv[1] ;
    }

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

ALIAS (show_bgp_instance_ipv4_safi_rsclient_summary,
       show_bgp_ipv4_safi_rsclient_summary_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_rsclient_summary,
       show_bgp_rsclient_summary_cmd,
       "show bgp rsclient summary",
       SHOW_STR
       BGP_STR
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

DEFUN (show_bgp_instance_rsclient_summary,
       show_bgp_instance_rsclient_summary_cmd,
       "show bgp view WORD rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (show_bgp_rsclient_summary,
      show_bgp_ipv6_rsclient_summary_cmd,
      "show bgp ipv6 rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

ALIAS (show_bgp_instance_rsclient_summary,
      show_bgp_instance_ipv6_rsclient_summary_cmd,
       "show bgp view WORD ipv6 rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

DEFUN (show_bgp_instance_ipv6_safi_rsclient_summary,
       show_bgp_instance_ipv6_safi_rsclient_summary_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  if (argc == 1)
    {
      name = NULL ;
      cast = argv[0] ;
    }
  else
    {
      name = argv[0] ;
      cast = argv[1] ;
    }

  qafx = (*cast == 'm') ? qafx_ipv6_multicast : qafx_ipv6_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

ALIAS (show_bgp_instance_ipv6_safi_rsclient_summary,
       show_bgp_ipv6_safi_rsclient_summary_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

#endif /* HAVE IPV6 */

/* Redistribute VTY commands.  */

DEFUN (bgp_redistribute_ipv4,
       bgp_redistribute_ipv4_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  return bgp_redistribute_set (vty->index, AFI_IP, type);
}

DEFUN (bgp_redistribute_ipv4_rmap,
       bgp_redistribute_ipv4_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_rmap_set (vty->index, AFI_IP, type, argv[1]);
  return bgp_redistribute_set (vty->index, AFI_IP, type);
}

DEFUN (bgp_redistribute_ipv4_metric,
       bgp_redistribute_ipv4_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  bgp_redistribute_metric_set (vty->index, AFI_IP, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, type);
}

DEFUN (bgp_redistribute_ipv4_rmap_metric,
       bgp_redistribute_ipv4_rmap_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  bgp_redistribute_rmap_set (vty->index, AFI_IP, type, argv[1]);
  bgp_redistribute_metric_set (vty->index, AFI_IP, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP, type);
}

DEFUN (bgp_redistribute_ipv4_metric_rmap,
       bgp_redistribute_ipv4_metric_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  bgp_redistribute_metric_set (vty->index, AFI_IP, type, metric);
  bgp_redistribute_rmap_set (vty->index, AFI_IP, type, argv[2]);
  return bgp_redistribute_set (vty->index, AFI_IP, type);
}

DEFUN (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_redistribute_unset (vty->index, qAFI_IP, type);
}

DEFUN (no_bgp_redistribute_ipv4_rmap,
       no_bgp_redistribute_ipv4_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_routemap_unset (vty->index, AFI_IP, type);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_ipv4_metric,
       no_bgp_redistribute_ipv4_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_metric_unset (vty->index, AFI_IP, type);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_ipv4_rmap_metric,
       no_bgp_redistribute_ipv4_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;

  type = proto_redistnum (AFI_IP, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_metric_unset (vty->index, AFI_IP, type);
  bgp_redistribute_routemap_unset (vty->index, AFI_IP, type);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_redistribute_ipv4_rmap_metric,
       no_bgp_redistribute_ipv4_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

#ifdef HAVE_IPV6
DEFUN (bgp_redistribute_ipv6,
       bgp_redistribute_ipv6_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_redistribute_set (vty->index, AFI_IP6, type);
}

DEFUN (bgp_redistribute_ipv6_rmap,
       bgp_redistribute_ipv6_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_rmap_set (vty->index, AFI_IP6, type, argv[1]);
  return bgp_redistribute_set (vty->index, AFI_IP6, type);
}

DEFUN (bgp_redistribute_ipv6_metric,
       bgp_redistribute_ipv6_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  bgp_redistribute_metric_set (vty->index, AFI_IP6, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP6, type);
}

DEFUN (bgp_redistribute_ipv6_rmap_metric,
       bgp_redistribute_ipv6_rmap_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[2]);

  bgp_redistribute_rmap_set (vty->index, AFI_IP6, type, argv[1]);
  bgp_redistribute_metric_set (vty->index, AFI_IP6, type, metric);
  return bgp_redistribute_set (vty->index, AFI_IP6, type);
}

DEFUN (bgp_redistribute_ipv6_metric_rmap,
       bgp_redistribute_ipv6_metric_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  u_int32_t metric;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  VTY_GET_INTEGER ("metric", metric, argv[1]);

  bgp_redistribute_metric_set (vty->index, AFI_IP6, type, metric);
  bgp_redistribute_rmap_set (vty->index, AFI_IP6, type, argv[2]);
  return bgp_redistribute_set (vty->index, AFI_IP6, type);
}

DEFUN (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_redistribute_unset (vty->index, qAFI_IP6, type);
}

DEFUN (no_bgp_redistribute_ipv6_rmap,
       no_bgp_redistribute_ipv6_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_routemap_unset (vty->index, AFI_IP6, type);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_ipv6_metric,
       no_bgp_redistribute_ipv6_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_metric_unset (vty->index, AFI_IP6, type);
  return CMD_SUCCESS;
}

DEFUN (no_bgp_redistribute_ipv6_rmap_metric,
       no_bgp_redistribute_ipv6_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  int type;

  type = proto_redistnum (AFI_IP6, argv[0]);
  if (type < 0 || type == ZEBRA_ROUTE_BGP)
    {
      vty_out (vty, "%% Invalid route type%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  bgp_redistribute_metric_unset (vty->index, AFI_IP6, type);
  bgp_redistribute_routemap_unset (vty->index, AFI_IP6, type);
  return CMD_SUCCESS;
}

ALIAS (no_bgp_redistribute_ipv6_rmap_metric,
       no_bgp_redistribute_ipv6_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
#endif /* HAVE_IPV6 */

extern int
bgp_config_write_redistribute (struct vty *vty, struct bgp *bgp, qafx_t qafx,
                                                                   int* p_write)
{
  uint type ;
  qAFI_t q_afi ;

  /* Unicast redistribution only.  */
  if (!qafx_is_unicast(qafx))
    return 0;

  q_afi = get_qAFI(qafx) ;

  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
    {
      if (type == ZEBRA_ROUTE_BGP)
        continue ;                      /* not to self  */

      if (bgp->redist[q_afi][type])
        {
          /* Display "address-family" when it is not yet diplayed.
           */
          bgp_config_write_family_header (vty, qafx, p_write);

          /* "redistribute" configuration.
           */
          vty_out (vty, " redistribute %s", zebra_route_string(type));

          if (bgp->redist_metric_set[q_afi][type])
            vty_out (vty, " metric %d", bgp->redist_metric[q_afi][type]);

          if (bgp->rmap[q_afi][type].name != NULL)
            vty_out (vty, " route-map %s", bgp->rmap[q_afi][type].name);

          vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
  return *p_write;
}

/*------------------------------------------------------------------------------
 * Table of commands to be installed for bgp_vty
 */
CMD_INSTALL_TABLE(static, bgp_vty_cmd_table, BGPD) =
{
  /* "bgp multiple-instance" commands. */
  { CONFIG_NODE,     &bgp_multiple_instance_cmd                         },
  { CONFIG_NODE,     &no_bgp_multiple_instance_cmd                      },

  /* "bgp config-type" commands. */
  { CONFIG_NODE,     &bgp_config_type_cmd                               },
  { CONFIG_NODE,     &no_bgp_config_type_cmd                            },

  /* Dummy commands (Currently not supported) */
  { BGP_NODE,        &no_synchronization_cmd                            },
  { BGP_NODE,        &no_auto_summary_cmd                               },

  /* "router bgp" commands. */
  { CONFIG_NODE,     &router_bgp_cmd                                    },
  { CONFIG_NODE,     &router_bgp_view_cmd                               },

  /* "no router bgp" commands. */
  { CONFIG_NODE,     &no_router_bgp_cmd                                 },
  { CONFIG_NODE,     &no_router_bgp_view_cmd                            },

  /* "bgp router-id" commands. */
  { BGP_NODE,        &bgp_router_id_cmd                                 },
  { BGP_NODE,        &no_bgp_router_id_cmd                              },
  { BGP_NODE,        &no_bgp_router_id_val_cmd                          },

  /* "bgp cluster-id" commands. */
  { BGP_NODE,        &bgp_cluster_id_cmd                                },
  { BGP_NODE,        &bgp_cluster_id32_cmd                              },
  { BGP_NODE,        &no_bgp_cluster_id_cmd                             },
  { BGP_NODE,        &no_bgp_cluster_id_arg_cmd                         },

  /* "bgp confederation" commands. */
  { BGP_NODE,        &bgp_confederation_identifier_cmd                  },
  { BGP_NODE,        &no_bgp_confederation_identifier_cmd               },
  { BGP_NODE,        &no_bgp_confederation_identifier_arg_cmd           },

  /* "bgp confederation peers" commands. */
  { BGP_NODE,        &bgp_confederation_peers_cmd                       },
  { BGP_NODE,        &no_bgp_confederation_peers_cmd                    },

  /* "timers bgp" commands. */
  { BGP_NODE,        &bgp_timers_cmd                                    },
  { BGP_NODE,        &no_bgp_timers_cmd                                 },
  { BGP_NODE,        &no_bgp_timers_arg_cmd                             },

  /* "bgp client-to-client reflection" commands */
  { BGP_NODE,        &no_bgp_client_to_client_reflection_cmd            },
  { BGP_NODE,        &bgp_client_to_client_reflection_cmd               },

  /* "bgp always-compare-med" commands */
  { BGP_NODE,        &bgp_always_compare_med_cmd                        },
  { BGP_NODE,        &no_bgp_always_compare_med_cmd                     },

  /* "bgp deterministic-med" commands */
  { BGP_NODE,        &bgp_deterministic_med_cmd                         },
  { BGP_NODE,        &no_bgp_deterministic_med_cmd                      },

  /* "bgp graceful-restart" commands */
  { BGP_NODE,        &bgp_graceful_restart_cmd                          },
  { BGP_NODE,        &no_bgp_graceful_restart_cmd                       },
  { BGP_NODE,        &bgp_graceful_restart_stalepath_time_cmd           },
  { BGP_NODE,        &no_bgp_graceful_restart_stalepath_time_cmd        },
  { BGP_NODE,        &no_bgp_graceful_restart_stalepath_time_val_cmd    },

  /* "bgp fast-external-failover" commands */
  { BGP_NODE,        &bgp_fast_external_failover_cmd                    },
  { BGP_NODE,        &no_bgp_fast_external_failover_cmd                 },

  /* "bgp enforce-first-as" commands */
  { BGP_NODE,        &bgp_enforce_first_as_cmd                          },
  { BGP_NODE,        &no_bgp_enforce_first_as_cmd                       },

  /* "bgp bestpath compare-routerid" commands */
  { BGP_NODE,        &bgp_bestpath_compare_router_id_cmd                },
  { BGP_NODE,        &no_bgp_bestpath_compare_router_id_cmd             },

  /* "bgp bestpath as-path ignore" commands */
  { BGP_NODE,        &bgp_bestpath_aspath_ignore_cmd                    },
  { BGP_NODE,        &no_bgp_bestpath_aspath_ignore_cmd                 },

  /* "bgp bestpath as-path confed" commands */
  { BGP_NODE,        &bgp_bestpath_aspath_confed_cmd                    },
  { BGP_NODE,        &no_bgp_bestpath_aspath_confed_cmd                 },

  /* "bgp log-neighbor-changes" commands */
  { BGP_NODE,        &bgp_log_neighbor_changes_cmd                      },
  { BGP_NODE,        &no_bgp_log_neighbor_changes_cmd                   },

  /* "bgp bestpath med" commands */
  { BGP_NODE,        &bgp_bestpath_med_cmd                              },
  { BGP_NODE,        &bgp_bestpath_med2_cmd                             },
  { BGP_NODE,        &bgp_bestpath_med3_cmd                             },
  { BGP_NODE,        &no_bgp_bestpath_med_cmd                           },
  { BGP_NODE,        &no_bgp_bestpath_med2_cmd                          },
  { BGP_NODE,        &no_bgp_bestpath_med3_cmd                          },

  /* "no bgp default ipv4-unicast" commands. */
  { BGP_NODE,        &no_bgp_default_ipv4_unicast_cmd                   },
  { BGP_NODE,        &bgp_default_ipv4_unicast_cmd                      },

  /* "bgp network import-check" commands. */
  { BGP_NODE,        &bgp_network_import_check_cmd                      },
  { BGP_NODE,        &no_bgp_network_import_check_cmd                   },

  /* "bgp default local-preference" commands. */
  { BGP_NODE,        &bgp_default_local_preference_cmd                  },
  { BGP_NODE,        &no_bgp_default_local_preference_cmd               },
  { BGP_NODE,        &no_bgp_default_local_preference_val_cmd           },

  /* "neighbor remote-as" commands. */
  { BGP_NODE,        &neighbor_remote_as_cmd                            },
  { BGP_NODE,        &no_neighbor_cmd                                   },
  { BGP_NODE,        &no_neighbor_remote_as_cmd                         },

  /* "neighbor peer-group" commands. */
  { BGP_NODE,        &neighbor_peer_group_cmd                           },
  { BGP_NODE,        &no_neighbor_peer_group_cmd                        },
  { BGP_NODE,        &no_neighbor_peer_group_remote_as_cmd              },

  /* "neighbor local-as" commands. */
  { BGP_NODE,        &neighbor_local_as_cmd                             },
  { BGP_NODE,        &neighbor_local_as_no_prepend_cmd                  },
  { BGP_NODE,        &no_neighbor_local_as_cmd                          },
  { BGP_NODE,        &no_neighbor_local_as_val_cmd                      },
  { BGP_NODE,        &no_neighbor_local_as_val2_cmd                     },

  /* "neighbor password" commands. */
  { BGP_NODE,        &neighbor_password_cmd                             },
  { BGP_NODE,        &no_neighbor_password_cmd                          },

  /* "neighbor activate" commands. */
  { BGP_NODE,        &neighbor_activate_cmd                             },
  { BGP_IPV4_NODE,   &neighbor_activate_cmd                             },
  { BGP_IPV4M_NODE,  &neighbor_activate_cmd                             },
  { BGP_IPV6_NODE,   &neighbor_activate_cmd                             },
  { BGP_IPV6M_NODE,  &neighbor_activate_cmd                             },
  { BGP_VPNV4_NODE,  &neighbor_activate_cmd                             },

  /* "no neighbor activate" commands. */
  { BGP_NODE,        &no_neighbor_activate_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_activate_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_activate_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_activate_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_activate_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_activate_cmd                          },

  /* "neighbor peer-group set" commands. */
  { BGP_NODE,        &neighbor_set_peer_group_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_set_peer_group_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_set_peer_group_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_set_peer_group_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_set_peer_group_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_set_peer_group_cmd                       },

  /* "no neighbor peer-group unset" commands. */
  { BGP_NODE,        &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_set_peer_group_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_set_peer_group_cmd                    },

  /* "neighbor softreconfiguration inbound" commands.*/
  { BGP_NODE,        &neighbor_soft_reconfiguration_cmd                 },
  { BGP_NODE,        &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV4_NODE,   &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV4_NODE,   &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV4M_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV4M_NODE,  &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV6_NODE,   &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV6_NODE,   &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV6M_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV6M_NODE,  &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_VPNV4_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_VPNV4_NODE,  &no_neighbor_soft_reconfiguration_cmd              },

  /* "neighbor attribute-unchanged" commands.  */
  { BGP_NODE,        &neighbor_attr_unchanged_cmd                       },
  { BGP_NODE,        &neighbor_attr_unchanged1_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged2_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged3_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged4_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged5_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged6_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged7_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged8_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged9_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged10_cmd                     },
  { BGP_NODE,        &no_neighbor_attr_unchanged_cmd                    },
  { BGP_NODE,        &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged10_cmd                  },

  /* "nexthop-local unchanged" commands */
  { BGP_IPV6_NODE,   &neighbor_nexthop_local_unchanged_cmd              },
  { BGP_IPV6_NODE,   &no_neighbor_nexthop_local_unchanged_cmd           },

  /* "transparent-as" and "transparent-nexthop" for old version
     compatibility.  */
  { BGP_NODE,        &neighbor_transparent_as_cmd                       },
  { BGP_NODE,        &neighbor_transparent_nexthop_cmd                  },

  /* "neighbor next-hop-self" commands. */
  { BGP_NODE,        &neighbor_nexthop_self_cmd                         },
  { BGP_NODE,        &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_nexthop_self_cmd                         },
  { BGP_IPV4_NODE,   &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_IPV4M_NODE,  &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_nexthop_self_cmd                         },
  { BGP_IPV6_NODE,   &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_IPV6M_NODE,  &no_neighbor_nexthop_self_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_VPNV4_NODE,  &no_neighbor_nexthop_self_cmd                      },

  /* "neighbor remove-private-AS" commands. */
  { BGP_NODE,        &neighbor_remove_private_as_cmd                    },
  { BGP_NODE,        &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV4_NODE,   &neighbor_remove_private_as_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV4M_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV6_NODE,   &neighbor_remove_private_as_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV6M_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_remove_private_as_cmd                 },
  { BGP_VPNV4_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_remove_private_as_cmd                 },

  /* "neighbor send-community" commands.*/
  { BGP_NODE,        &neighbor_send_community_cmd                       },
  { BGP_NODE,        &neighbor_send_community_type_cmd                  },
  { BGP_NODE,        &no_neighbor_send_community_cmd                    },
  { BGP_NODE,        &no_neighbor_send_community_type_cmd               },
  { BGP_IPV4_NODE,   &neighbor_send_community_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_send_community_type_cmd                  },
  { BGP_IPV4_NODE,   &no_neighbor_send_community_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_send_community_type_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_send_community_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_IPV4M_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_send_community_type_cmd               },
  { BGP_IPV6_NODE,   &neighbor_send_community_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_send_community_type_cmd                  },
  { BGP_IPV6_NODE,   &no_neighbor_send_community_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_send_community_type_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_send_community_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_IPV6M_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_send_community_type_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_send_community_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_VPNV4_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_send_community_type_cmd               },

  /* "neighbor route-reflector" commands.*/
  { BGP_NODE,        &neighbor_route_reflector_client_cmd               },
  { BGP_NODE,        &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV4_NODE,   &neighbor_route_reflector_client_cmd               },
  { BGP_IPV4_NODE,   &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV4M_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_IPV4M_NODE,  &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV6_NODE,   &neighbor_route_reflector_client_cmd               },
  { BGP_IPV6_NODE,   &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV6M_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_IPV6M_NODE,  &no_neighbor_route_reflector_client_cmd            },
  { BGP_VPNV4_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_VPNV4_NODE,  &no_neighbor_route_reflector_client_cmd            },

  /* "neighbor route-server" commands.*/
  { BGP_NODE,        &neighbor_route_server_client_cmd                  },
  { BGP_NODE,        &no_neighbor_route_server_client_cmd               },
  { BGP_IPV4_NODE,   &neighbor_route_server_client_cmd                  },
  { BGP_IPV4_NODE,   &no_neighbor_route_server_client_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_IPV4M_NODE,  &no_neighbor_route_server_client_cmd               },
  { BGP_IPV6_NODE,   &neighbor_route_server_client_cmd                  },
  { BGP_IPV6_NODE,   &no_neighbor_route_server_client_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_IPV6M_NODE,  &no_neighbor_route_server_client_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_VPNV4_NODE,  &no_neighbor_route_server_client_cmd               },

  /* "neighbor passive" commands. */
  { BGP_NODE,        &neighbor_passive_cmd                              },
  { BGP_NODE,        &no_neighbor_passive_cmd                           },

  /* "neighbor shutdown" commands. */
  { BGP_NODE,        &neighbor_shutdown_cmd                             },
  { BGP_NODE,        &no_neighbor_shutdown_cmd                          },
  { BGP_NODE,        &neighbor_startup_cmd                              },

  /* Deprecated "neighbor capability route-refresh" commands.*/
  { BGP_NODE,        &neighbor_capability_route_refresh_cmd             },
  { BGP_NODE,        &no_neighbor_capability_route_refresh_cmd          },

  /* "neighbor capability orf prefix-list" commands.*/
  { BGP_NODE,        &neighbor_capability_orf_prefix_cmd                },
  { BGP_NODE,        &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV4_NODE,   &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV4_NODE,   &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV4M_NODE,  &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV4M_NODE,  &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV6_NODE,   &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV6_NODE,   &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV6M_NODE,  &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV6M_NODE,  &no_neighbor_capability_orf_prefix_cmd             },

  /* "neighbor capability dynamic" commands.*/
  { BGP_NODE,        &neighbor_capability_dynamic_cmd                   },
  { BGP_NODE,        &no_neighbor_capability_dynamic_cmd                },

  /* "neighbor dont-capability-negotiate" commands. */
  { BGP_NODE,        &neighbor_dont_capability_negotiate_cmd            },
  { BGP_NODE,        &no_neighbor_dont_capability_negotiate_cmd         },

  /* "neighbor ebgp-multihop" commands. */
  { BGP_NODE,        &neighbor_ebgp_multihop_cmd                        },
  { BGP_NODE,        &neighbor_ebgp_multihop_ttl_cmd                    },
  { BGP_NODE,        &no_neighbor_ebgp_multihop_cmd                     },
  { BGP_NODE,        &no_neighbor_ebgp_multihop_ttl_cmd                 },

  /* "neighbor disable-connected-check" commands.  */
  { BGP_NODE,        &neighbor_disable_connected_check_cmd              },
  { BGP_NODE,        &no_neighbor_disable_connected_check_cmd           },
  { BGP_NODE,        &neighbor_enforce_multihop_cmd                     },
  { BGP_NODE,        &no_neighbor_enforce_multihop_cmd                  },

  /* "neighbor description" commands. */
  { BGP_NODE,        &neighbor_description_cmd                          },
  { BGP_NODE,        &no_neighbor_description_cmd                       },
  { BGP_NODE,        &no_neighbor_description_val_cmd                   },

  /* "neighbor update-source" commands. "*/
  { BGP_NODE,        &neighbor_update_source_cmd                        },
  { BGP_NODE,        &no_neighbor_update_source_cmd                     },

  /* "neighbor default-originate" commands. */
  { BGP_NODE,        &neighbor_default_originate_cmd                    },
  { BGP_NODE,        &neighbor_default_originate_rmap_cmd               },
  { BGP_NODE,        &no_neighbor_default_originate_cmd                 },
  { BGP_NODE,        &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV4_NODE,   &neighbor_default_originate_cmd                    },
  { BGP_IPV4_NODE,   &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV4_NODE,   &no_neighbor_default_originate_cmd                 },
  { BGP_IPV4_NODE,   &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV4M_NODE,  &neighbor_default_originate_cmd                    },
  { BGP_IPV4M_NODE,  &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV4M_NODE,  &no_neighbor_default_originate_cmd                 },
  { BGP_IPV4M_NODE,  &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV6_NODE,   &neighbor_default_originate_cmd                    },
  { BGP_IPV6_NODE,   &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV6_NODE,   &no_neighbor_default_originate_cmd                 },
  { BGP_IPV6_NODE,   &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV6M_NODE,  &neighbor_default_originate_cmd                    },
  { BGP_IPV6M_NODE,  &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV6M_NODE,  &no_neighbor_default_originate_cmd                 },
  { BGP_IPV6M_NODE,  &no_neighbor_default_originate_rmap_cmd            },

  /* "neighbor port" commands. */
  { BGP_NODE,        &neighbor_port_cmd                                 },
  { BGP_NODE,        &no_neighbor_port_cmd                              },
  { BGP_NODE,        &no_neighbor_port_val_cmd                          },

  /* "neighbor weight" commands. */
  { BGP_NODE,        &neighbor_weight_cmd                               },
  { BGP_NODE,        &no_neighbor_weight_cmd                            },
  { BGP_NODE,        &no_neighbor_weight_val_cmd                        },

  /* "neighbor override-capability" commands. */
  { BGP_NODE,        &neighbor_override_capability_cmd                  },
  { BGP_NODE,        &no_neighbor_override_capability_cmd               },

  /* "neighbor strict-capability-match" commands. */
  { BGP_NODE,        &neighbor_strict_capability_cmd                    },
  { BGP_NODE,        &no_neighbor_strict_capability_cmd                 },

  /* "neighbor timers" commands. */
  { BGP_NODE,        &neighbor_timers_cmd                               },
  { BGP_NODE,        &no_neighbor_timers_cmd                            },

  /* "neighbor timers connect" commands. */
  { BGP_NODE,        &neighbor_timers_connect_cmd                       },
  { BGP_NODE,        &no_neighbor_timers_connect_cmd                    },
  { BGP_NODE,        &no_neighbor_timers_connect_val_cmd                },

  /* "neighbor advertisement-interval" commands. */
  { BGP_NODE,        &neighbor_advertise_interval_cmd                   },
  { BGP_NODE,        &no_neighbor_advertise_interval_cmd                },
  { BGP_NODE,        &no_neighbor_advertise_interval_val_cmd            },

  /* "neighbor version" commands. */
  { BGP_NODE,        &neighbor_version_cmd                              },

  /* "neighbor interface" commands. */
  { BGP_NODE,        &neighbor_interface_cmd                            },
  { BGP_NODE,        &no_neighbor_interface_cmd                         },

  /* "neighbor distribute" commands. */
  { BGP_NODE,        &neighbor_distribute_list_cmd                      },
  { BGP_NODE,        &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV4_NODE,   &neighbor_distribute_list_cmd                      },
  { BGP_IPV4_NODE,   &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV4M_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_IPV4M_NODE,  &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV6_NODE,   &neighbor_distribute_list_cmd                      },
  { BGP_IPV6_NODE,   &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV6M_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_IPV6M_NODE,  &no_neighbor_distribute_list_cmd                   },
  { BGP_VPNV4_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_VPNV4_NODE,  &no_neighbor_distribute_list_cmd                   },

  /* "neighbor prefix-list" commands. */
  { BGP_NODE,        &neighbor_prefix_list_cmd                          },
  { BGP_NODE,        &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_prefix_list_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_prefix_list_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_prefix_list_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_prefix_list_cmd                       },

  /* "neighbor filter-list" commands. */
  { BGP_NODE,        &neighbor_filter_list_cmd                          },
  { BGP_NODE,        &no_neighbor_filter_list_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_filter_list_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_filter_list_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_filter_list_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_filter_list_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_filter_list_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_filter_list_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_filter_list_cmd                       },

  /* "neighbor route-map" commands. */
  { BGP_NODE,        &neighbor_route_map_cmd                            },
  { BGP_NODE,        &no_neighbor_route_map_cmd                         },
  { BGP_IPV4_NODE,   &neighbor_route_map_cmd                            },
  { BGP_IPV4_NODE,   &no_neighbor_route_map_cmd                         },
  { BGP_IPV4M_NODE,  &neighbor_route_map_cmd                            },
  { BGP_IPV4M_NODE,  &no_neighbor_route_map_cmd                         },
  { BGP_IPV6_NODE,   &neighbor_route_map_cmd                            },
  { BGP_IPV6_NODE,   &no_neighbor_route_map_cmd                         },
  { BGP_IPV6M_NODE,  &neighbor_route_map_cmd                            },
  { BGP_IPV6M_NODE,  &no_neighbor_route_map_cmd                         },
  { BGP_VPNV4_NODE,  &neighbor_route_map_cmd                            },
  { BGP_VPNV4_NODE,  &no_neighbor_route_map_cmd                         },

  /* "neighbor unsuppress-map" commands. */
  { BGP_NODE,        &neighbor_unsuppress_map_cmd                       },
  { BGP_NODE,        &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV4_NODE,   &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV4_NODE,   &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV4M_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV4M_NODE,  &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV6_NODE,   &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV6_NODE,   &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV6M_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV6M_NODE,  &no_neighbor_unsuppress_map_cmd                    },
  { BGP_VPNV4_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_VPNV4_NODE,  &no_neighbor_unsuppress_map_cmd                    },

  /* "neighbor maximum-prefix" commands. */
  { BGP_NODE,        &neighbor_maximum_prefix_cmd                       },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_NODE,        &neighbor_maximum_prefix_warning_cmd               },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_NODE,        &neighbor_maximum_prefix_restart_cmd               },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_NODE,        &no_neighbor_maximum_prefix_cmd                    },
  { BGP_NODE,        &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_NODE,        &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_NODE,        &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },

  /* "neighbor allowas-in" */
  { BGP_NODE,        &neighbor_allowas_in_cmd                           },
  { BGP_NODE,        &neighbor_allowas_in_arg_cmd                       },
  { BGP_NODE,        &no_neighbor_allowas_in_cmd                        },
  { BGP_IPV4_NODE,   &neighbor_allowas_in_cmd                           },
  { BGP_IPV4_NODE,   &neighbor_allowas_in_arg_cmd                       },
  { BGP_IPV4_NODE,   &no_neighbor_allowas_in_cmd                        },
  { BGP_IPV4M_NODE,  &neighbor_allowas_in_cmd                           },
  { BGP_IPV4M_NODE,  &neighbor_allowas_in_arg_cmd                       },
  { BGP_IPV4M_NODE,  &no_neighbor_allowas_in_cmd                        },
  { BGP_IPV6_NODE,   &neighbor_allowas_in_cmd                           },
  { BGP_IPV6_NODE,   &neighbor_allowas_in_arg_cmd                       },
  { BGP_IPV6_NODE,   &no_neighbor_allowas_in_cmd                        },
  { BGP_IPV6M_NODE,  &neighbor_allowas_in_cmd                           },
  { BGP_IPV6M_NODE,  &neighbor_allowas_in_arg_cmd                       },
  { BGP_IPV6M_NODE,  &no_neighbor_allowas_in_cmd                        },
  { BGP_VPNV4_NODE,  &neighbor_allowas_in_cmd                           },
  { BGP_VPNV4_NODE,  &neighbor_allowas_in_arg_cmd                       },
  { BGP_VPNV4_NODE,  &no_neighbor_allowas_in_cmd                        },

  /* address-family commands. */
  { BGP_NODE,        &address_family_ipv4_cmd                           },
  { BGP_NODE,        &address_family_ipv4_safi_unicast_cmd              },
  { BGP_NODE,        &address_family_ipv4_safi_multicast_cmd            },
#ifdef HAVE_IPV6
  { BGP_NODE,        &address_family_ipv6_cmd                           },
  { BGP_NODE,        &address_family_ipv6_safi_unicast_cmd              },
  { BGP_NODE,        &address_family_ipv6_safi_multicast_cmd            },
#endif /* HAVE_IPV6 */
  { BGP_NODE,        &address_family_vpnv4_cmd                          },
  { BGP_NODE,        &address_family_vpnv4_unicast_cmd                  },

  /* "exit-address-family" command. */
  { BGP_IPV4_NODE,   &exit_address_family_cmd                           },
  { BGP_IPV4M_NODE,  &exit_address_family_cmd                           },
  { BGP_IPV6_NODE,   &exit_address_family_cmd                           },
  { BGP_IPV6M_NODE,  &exit_address_family_cmd                           },
  { BGP_VPNV4_NODE,  &exit_address_family_cmd                           },

  /* "clear ip bgp commands" */
  { ENABLE_NODE,     &clear_ip_bgp_all_cmd                              },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_as_cmd                               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_cmd                             },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_external_cmd                         },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_cmd                                 },
  { ENABLE_NODE,     &clear_bgp_instance_all_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_cmd                            },
  { ENABLE_NODE,     &clear_bgp_peer_cmd                                },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_cmd                           },
  { ENABLE_NODE,     &clear_bgp_peer_group_cmd                          },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_cmd                     },
  { ENABLE_NODE,     &clear_bgp_external_cmd                            },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_cmd                       },
  { ENABLE_NODE,     &clear_bgp_as_cmd                                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_cmd                             },
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft in" */
  { ENABLE_NODE,     &clear_ip_bgp_all_soft_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_in_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_all_in_cmd                           },
  { ENABLE_NODE,     &clear_ip_bgp_all_in_prefix_filter_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_in_prefix_filter_cmd    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_in_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_in_prefix_filter_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_in_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_in_prefix_filter_cmd      },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_external_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_external_in_prefix_filter_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_in_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_as_in_cmd                            },
  { ENABLE_NODE,     &clear_ip_bgp_as_in_prefix_filter_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_in_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_in_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_in_prefix_filter_cmd        },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_in_prefix_filter_cmd },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_in_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_in_prefix_filter_cmd       },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_in_cmd          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_in_prefix_filter_cmd },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_in_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_in_prefix_filter_cmd   },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_in_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_in_cmd                       },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_in_prefix_filter_cmd         },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_in_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_in_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_in_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_in_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_in_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_in_cmd                      },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_in_cmd                },
  { ENABLE_NODE,     &clear_bgp_all_in_cmd                              },
  { ENABLE_NODE,     &clear_bgp_all_in_prefix_filter_cmd                },
  { ENABLE_NODE,     &clear_bgp_peer_soft_in_cmd                        },
  { ENABLE_NODE,     &clear_bgp_peer_in_cmd                             },
  { ENABLE_NODE,     &clear_bgp_peer_in_prefix_filter_cmd               },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_in_cmd                  },
  { ENABLE_NODE,     &clear_bgp_peer_group_in_cmd                       },
  { ENABLE_NODE,     &clear_bgp_peer_group_in_prefix_filter_cmd         },
  { ENABLE_NODE,     &clear_bgp_external_soft_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_external_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_external_in_prefix_filter_cmd           },
  { ENABLE_NODE,     &clear_bgp_as_soft_in_cmd                          },
  { ENABLE_NODE,     &clear_bgp_as_in_cmd                               },
  { ENABLE_NODE,     &clear_bgp_as_in_prefix_filter_cmd                 },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_in_cmd                         },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_in_prefix_filter_cmd           },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_in_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_in_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_in_prefix_filter_cmd          },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_in_cmd             },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_in_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_in_prefix_filter_cmd    },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_in_cmd               },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_in_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_in_prefix_filter_cmd      },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_in_cmd                     },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_in_cmd                          },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_in_prefix_filter_cmd            },
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft out" */
  { ENABLE_NODE,     &clear_ip_bgp_all_soft_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_out_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_all_out_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_out_cmd                         },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_out_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_external_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_out_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_as_out_cmd                           },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_out_cmd       },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_out_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_out_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_out_cmd         },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_out_cmd           },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_out_cmd                 },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_out_cmd                      },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_out_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_out_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_out_cmd              },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_out_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_out_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_out_cmd                     },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_out_cmd               },
  { ENABLE_NODE,     &clear_bgp_all_out_cmd                             },
  { ENABLE_NODE,     &clear_bgp_peer_soft_out_cmd                       },
  { ENABLE_NODE,     &clear_bgp_peer_out_cmd                            },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_out_cmd                 },
  { ENABLE_NODE,     &clear_bgp_peer_group_out_cmd                      },
  { ENABLE_NODE,     &clear_bgp_external_soft_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_external_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_as_soft_out_cmd                         },
  { ENABLE_NODE,     &clear_bgp_as_out_cmd                              },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_out_cmd                        },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_out_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_out_cmd                       },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_out_cmd            },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_out_cmd                 },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_out_cmd              },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_out_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_out_cmd                    },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_out_cmd                         },
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor soft" */
  { ENABLE_NODE,     &clear_ip_bgp_all_soft_cmd                         },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_soft_cmd                },
  { ENABLE_NODE,     &clear_ip_bgp_peer_soft_cmd                        },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_soft_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_external_soft_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_as_soft_cmd                          },
  { ENABLE_NODE,     &clear_ip_bgp_all_ipv4_soft_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_ipv4_soft_cmd           },
  { ENABLE_NODE,     &clear_ip_bgp_peer_ipv4_soft_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_peer_group_ipv4_soft_cmd             },
  { ENABLE_NODE,     &clear_ip_bgp_external_ipv4_soft_cmd               },
  { ENABLE_NODE,     &clear_ip_bgp_as_ipv4_soft_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_all_vpnv4_soft_cmd                   },
  { ENABLE_NODE,     &clear_ip_bgp_peer_vpnv4_soft_cmd                  },
  { ENABLE_NODE,     &clear_ip_bgp_as_vpnv4_soft_cmd                    },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_soft_cmd                            },
  { ENABLE_NODE,     &clear_bgp_instance_all_soft_cmd                   },
  { ENABLE_NODE,     &clear_bgp_peer_soft_cmd                           },
  { ENABLE_NODE,     &clear_bgp_peer_group_soft_cmd                     },
  { ENABLE_NODE,     &clear_bgp_external_soft_cmd                       },
  { ENABLE_NODE,     &clear_bgp_as_soft_cmd                             },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_soft_cmd                       },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_soft_cmd                      },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_group_soft_cmd                },
  { ENABLE_NODE,     &clear_bgp_ipv6_external_soft_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_as_soft_cmd                        },
#endif /* HAVE_IPV6 */

  /* "clear ip bgp neighbor rsclient" */
  { ENABLE_NODE,     &clear_ip_bgp_all_rsclient_cmd                     },
  { ENABLE_NODE,     &clear_ip_bgp_instance_all_rsclient_cmd            },
  { ENABLE_NODE,     &clear_ip_bgp_peer_rsclient_cmd                    },
  { ENABLE_NODE,     &clear_ip_bgp_instance_peer_rsclient_cmd           },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &clear_bgp_all_rsclient_cmd                        },
  { ENABLE_NODE,     &clear_bgp_instance_all_rsclient_cmd               },
  { ENABLE_NODE,     &clear_bgp_ipv6_all_rsclient_cmd                   },
  { ENABLE_NODE,     &clear_bgp_ipv6_instance_all_rsclient_cmd          },
  { ENABLE_NODE,     &clear_bgp_peer_rsclient_cmd                       },
  { ENABLE_NODE,     &clear_bgp_instance_peer_rsclient_cmd              },
  { ENABLE_NODE,     &clear_bgp_ipv6_peer_rsclient_cmd                  },
  { ENABLE_NODE,     &clear_bgp_ipv6_instance_peer_rsclient_cmd         },
#endif /* HAVE_IPV6 */

  /* "show ip bgp summary" commands. */
  { VIEW_NODE,       &show_ip_bgp_summary_cmd                           },
  { VIEW_NODE,       &show_ip_bgp_instance_summary_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_ipv4_summary_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv4_safi_summary_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_instance_ipv4_summary_cmd             },
  { VIEW_NODE,       &show_bgp_instance_ipv4_safi_summary_cmd           },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_summary_cmd                              },
  { VIEW_NODE,       &show_bgp_instance_summary_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_summary_cmd                         },
  { VIEW_NODE,       &show_bgp_ipv6_safi_summary_cmd                    },
  { VIEW_NODE,       &show_bgp_instance_ipv6_summary_cmd                },
  { VIEW_NODE,       &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */
  { RESTRICTED_NODE, &show_ip_bgp_summary_cmd                           },
  { RESTRICTED_NODE, &show_ip_bgp_instance_summary_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_summary_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_summary_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_instance_ipv4_summary_cmd             },
  { RESTRICTED_NODE, &show_bgp_instance_ipv4_safi_summary_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { RESTRICTED_NODE, &show_bgp_summary_cmd                              },
  { RESTRICTED_NODE, &show_bgp_instance_summary_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_summary_cmd                         },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_summary_cmd                    },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_summary_cmd                },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */
  { ENABLE_NODE,     &show_ip_bgp_summary_cmd                           },
  { ENABLE_NODE,     &show_ip_bgp_instance_summary_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_summary_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_summary_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_instance_ipv4_summary_cmd             },
  { ENABLE_NODE,     &show_bgp_instance_ipv4_safi_summary_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &show_bgp_summary_cmd                              },
  { ENABLE_NODE,     &show_bgp_instance_summary_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_summary_cmd                         },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_summary_cmd                    },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_summary_cmd                },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */

  /* "show ip bgp neighbors" commands. */
  { VIEW_NODE,       &show_ip_bgp_neighbors_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbors_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_neighbors_peer_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbors_cmd               },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbors_cmd                },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { VIEW_NODE,       &show_ip_bgp_instance_neighbors_cmd                },
  { VIEW_NODE,       &show_ip_bgp_instance_neighbors_peer_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_neighbors_peer_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_instance_neighbors_peer_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_neighbors_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbors_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_neighbors_peer_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbors_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbors_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_instance_neighbors_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_instance_neighbors_peer_cmd           },

#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_neighbors_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_neighbors_cmd                       },
  { VIEW_NODE,       &show_bgp_neighbors_peer_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_neighbors_peer_cmd                  },
  { VIEW_NODE,       &show_bgp_instance_neighbors_cmd                   },
  { VIEW_NODE,       &show_bgp_instance_ipv6_neighbors_cmd              },
  { VIEW_NODE,       &show_bgp_instance_neighbors_peer_cmd              },
  { VIEW_NODE,       &show_bgp_instance_ipv6_neighbors_peer_cmd         },
  { RESTRICTED_NODE, &show_bgp_neighbors_peer_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv6_neighbors_peer_cmd                  },
  { RESTRICTED_NODE, &show_bgp_instance_neighbors_peer_cmd              },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_neighbors_peer_cmd         },
  { ENABLE_NODE,     &show_bgp_neighbors_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbors_cmd                       },
  { ENABLE_NODE,     &show_bgp_neighbors_peer_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbors_peer_cmd                  },
  { ENABLE_NODE,     &show_bgp_instance_neighbors_cmd                   },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_neighbors_cmd              },
  { ENABLE_NODE,     &show_bgp_instance_neighbors_peer_cmd              },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_neighbors_peer_cmd         },

  /* Old commands.  */
  { VIEW_NODE,       &show_ipv6_bgp_summary_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_summary_cmd                        },
  { ENABLE_NODE,     &show_ipv6_bgp_summary_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_summary_cmd                        },
#endif /* HAVE_IPV6 */

  /* "show ip bgp rsclient" commands. */
  { VIEW_NODE,       &show_ip_bgp_rsclient_summary_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_instance_rsclient_summary_cmd         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { VIEW_NODE,       &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { VIEW_NODE,       &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_summary_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_summary_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_instance_rsclient_summary_cmd         },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { RESTRICTED_NODE, &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_summary_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_summary_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_instance_rsclient_summary_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { ENABLE_NODE,     &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_summary_cmd           },

#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_rsclient_summary_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_rsclient_summary_cmd                },
  { VIEW_NODE,       &show_bgp_instance_rsclient_summary_cmd            },
  { VIEW_NODE,       &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { VIEW_NODE,       &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_summary_cmd           },
  { RESTRICTED_NODE, &show_bgp_rsclient_summary_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_rsclient_summary_cmd                },
  { RESTRICTED_NODE, &show_bgp_instance_rsclient_summary_cmd            },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_summary_cmd           },
  { ENABLE_NODE,     &show_bgp_rsclient_summary_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_rsclient_summary_cmd                },
  { ENABLE_NODE,     &show_bgp_instance_rsclient_summary_cmd            },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_summary_cmd           },
#endif /* HAVE_IPV6 */

  /* "show ip bgp paths" commands. */
  { VIEW_NODE,       &show_ip_bgp_paths_cmd                             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_paths_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_paths_cmd                             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_paths_cmd                        },

  /* "show ip bgp community" commands. */
  { VIEW_NODE,       &show_ip_bgp_community_info_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_community_info_cmd                    },

  /* "show ip bgp extcommunity" commands. */
  { VIEW_NODE,       &show_ip_bgp_ecommunity_info_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ecommunity_info_cmd                   },

  /* "show ip bgp attribute-info" commands. */
  { VIEW_NODE,       &show_ip_bgp_attr_info_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_attr_info_cmd                         },

  /* "redistribute" commands.  */
  { BGP_NODE,        &bgp_redistribute_ipv4_cmd                         },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_cmd                      },
  { BGP_NODE,        &bgp_redistribute_ipv4_rmap_cmd                    },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_rmap_cmd                 },
  { BGP_NODE,        &bgp_redistribute_ipv4_metric_cmd                  },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_metric_cmd               },
  { BGP_NODE,        &bgp_redistribute_ipv4_rmap_metric_cmd             },
  { BGP_NODE,        &bgp_redistribute_ipv4_metric_rmap_cmd             },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_rmap_metric_cmd          },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_metric_rmap_cmd          },
#ifdef HAVE_IPV6
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_cmd                         },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_cmd                      },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_rmap_cmd                    },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_rmap_cmd                 },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_metric_cmd                  },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_metric_cmd               },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_rmap_metric_cmd             },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_metric_rmap_cmd             },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_rmap_metric_cmd          },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_metric_rmap_cmd          },
#endif /* HAVE_IPV6 */

  /* ttl_security commands */
  { BGP_NODE,        &neighbor_ttl_security_cmd                         },
  { BGP_NODE,        &no_neighbor_ttl_security_cmd                      },

  /* "show bgp memory" commands. */
  { VIEW_NODE,       &show_bgp_memory_cmd                               },
  { RESTRICTED_NODE, &show_bgp_memory_cmd                               },
  { ENABLE_NODE,     &show_bgp_memory_cmd                               },

  /* "show bgp views" commands. */
  { VIEW_NODE,       &show_bgp_views_cmd                                },
  { RESTRICTED_NODE, &show_bgp_views_cmd                                },
  { ENABLE_NODE,     &show_bgp_views_cmd                                },

  CMD_INSTALL_END
} ;

extern void
bgp_vty_cmd_init (void)
{
  /* Install bgp top node. */
  cmd_install_node_config_write(BGP_NODE, bgp_config_write);

  cmd_install_table(bgp_vty_cmd_table) ;
}

void
bgp_vty_init (void)
{
}

#include "memory.h"
#include "bgp_regex.h"
#include "bgp_clist.h"
#include "bgp_ecommunity.h"

/* VTY functions.  */

/* Direction value to string conversion.  */
static const char *
community_action_str (clist_action_type_t action)
{
  switch (action)
    {
    case COMMUNITY_DENY:
      return "deny";
    case COMMUNITY_PERMIT:
      return "permit";
    default:
      return "unknown";
    }
}

/* Display error string.  */
static void
community_list_perror (struct vty *vty, int ret)
{
  switch (ret)
    {
    case COMMUNITY_LIST_ERR_CANT_FIND_LIST:
      vty_out (vty, "%% Can't find community-list\n");
      break;
    case COMMUNITY_LIST_ERR_MALFORMED_VAL:
      vty_out (vty, "%% Malformed community-list value\n");
      break;
    case COMMUNITY_LIST_ERR_STANDARD_CONFLICT:
      vty_out (vty, "%% Community name conflict, "
                                  "previously defined as standard community\n");
      break;
    case COMMUNITY_LIST_ERR_EXPANDED_CONFLICT:
      vty_out (vty, "%% Community name conflict, "
                                  "previously defined as expanded community\n");
      break;
    case COMMUNITY_LIST_ERR_ENTRY_EXISTS:
      vty_out (vty, "%% Community-list entry already exists\n");
      break;
    default:
      break ;
    }
}

/*------------------------------------------------------------------------------
 * VTY interface for community_set() function.
 */
static int
community_list_set_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;
  clist_action_type_t action ;
  char *str;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    }

  /* Check the list type.
   */
  switch (argv[1][0])
    {
      case 'p':
        action = COMMUNITY_PERMIT ;
        break ;

      case 'd':
        action = COMMUNITY_DENY;
        break ;

      default:
        vty_out (vty, "%% Matching condition must be permit or deny\n") ;
        return CMD_WARNING;
    } ;

  /* When community_list_set() return negative value, it means malformed
   * community string or a clash of style.
   */
  str = argv_concat (argv, argc, 2);

  ret = community_list_set (bgp_clist, argv[0], str, action, style);

  XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      /* Display error string.  */
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Community-list entry delete.
 */
static int
community_list_unset_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    } ;

  if (argc < 2)
    {
      ret = community_list_unset_all (bgp_clist, argv[0]);
    }
  else
    {
      clist_action_type_t action ;
      char* str ;

      switch (argv[1][0])
        {
          case 'p':
            action = COMMUNITY_PERMIT ;
            break ;

          case 'd':
            action = COMMUNITY_DENY;
            break ;

          default:
            vty_out (vty, "%% Matching condition must be permit or deny\n") ;
            return CMD_WARNING;
        } ;

      /* Concat community string argument and unset the relevant entry.
       */
      str = argv_concat (argv, argc, 2) ;

      ret = community_list_unset (bgp_clist, argv[0], str, action, style);

      XFREE (MTYPE_TMP, str);
    } ;

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "community-list" keyword help string.  */
#define COMMUNITY_LIST_STR "Add a community list entry\n"
#define COMMUNITY_VAL_STR  "Community number in aa:nn format or internet|local-AS|no-advertise|no-export\n"

DEFUN (ip_community_list_standard,
       ip_community_list_standard_cmd,
       "ip community-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

ALIAS (ip_community_list_standard,
       ip_community_list_standard2_cmd,
       "ip community-list <1-99> (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_expanded,
       ip_community_list_expanded_cmd,
       "ip community-list <100-500> (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (ip_community_list_name_standard,
       ip_community_list_name_standard_cmd,
       "ip community-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

ALIAS (ip_community_list_name_standard,
       ip_community_list_name_standard2_cmd,
       "ip community-list standard WORD (deny|permit)",
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_community_list_name_expanded,
       ip_community_list_name_expanded_cmd,
       "ip community-list expanded WORD (deny|permit) .LINE",
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_set_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_standard_all,
       no_ip_community_list_standard_all_cmd,
       "no ip community-list <1-99>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_expanded_all,
       no_ip_community_list_expanded_all_cmd,
       "no ip community-list <100-500>",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_name_standard_all,
       no_ip_community_list_name_standard_all_cmd,
       "no ip community-list standard WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add a standard community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_name_expanded_all,
       no_ip_community_list_name_expanded_all_cmd,
       "no ip community-list expanded WORD",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Add an expanded community-list entry\n"
       "Community list name\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_standard,
       no_ip_community_list_standard_cmd,
       "no ip community-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_expanded,
       no_ip_community_list_expanded_cmd,
       "no ip community-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                        false /* not a named community-list */);
}

DEFUN (no_ip_community_list_name_standard,
       no_ip_community_list_name_standard_cmd,
       "no ip community-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify a standard community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       COMMUNITY_VAL_STR)
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_STANDARD,
                                             true /* a named community-list */);
}

DEFUN (no_ip_community_list_name_expanded,
       no_ip_community_list_name_expanded_cmd,
       "no ip community-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       COMMUNITY_LIST_STR
       "Specify an expanded community-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return community_list_unset_vty (vty, argc, argv, COMMUNITY_LIST_EXPANDED,
                                             true /* a named community-list */);
}

static qstring
community_list_entry_value(qstring qs, community_entry entry)
{
  qstring     qsx ;
  const char* what ;

  qsx = NULL ;

  if (entry->u.any == NULL)
    {
      switch (entry->act)
        {
          case act_internet:
            what = "internet" ;
            break ;

          case act_any:
            what = "any" ;
            break ;

          default:
            what = "" ;
            break ;
        } ;
    }
  else
    {
      switch (entry->style)
        {
          case COMMUNITY_LIST_STANDARD:
            what = attr_community_str(entry->u.comm) ;
            break ;

          case ECOMMUNITY_LIST_STANDARD:
            qsx = attr_ecommunity_str_form(qsx, entry->u.ecomm,
                                        ECOMMUNITY_FORMAT_COMMUNITY_LIST) ;
            what = qs_string(qsx) ;
            break ;

          case COMMUNITY_LIST_EXPANDED:
          case ECOMMUNITY_LIST_EXPANDED:
            what = entry->raw ;
            break ;

          default:
            what = "???" ;
            break ;
        } ;
    } ;

  qs = qs_set_str(qs, community_action_str (entry->action)) ;

  if (*what != '\0')
    {
      qs_append_ch(qs, ' ') ;
      qs_append_str(qs, what) ;
    } ;

  qs_free(qsx) ;

  return qs ;
} ;

static void
community_list_show (struct vty *vty, community_list list, const char* tag)
{
  community_entry entry;
  qstring     qs ;

  qs = NULL ;

  for (entry = ddl_head(list->entries); entry; entry = ddl_next(entry, list))
    {
      if (entry == ddl_head(list->entries))
        {
          if (all_digit (list->name))
            vty_out (vty, "Community %s list %s%s",
                     entry->style == COMMUNITY_LIST_STANDARD ? "(standard)"
                                                             : "(expanded)",
                     list->name, VTY_NEWLINE);
          else
            vty_out (vty, "Named Community %s list %s%s",
                     entry->style == COMMUNITY_LIST_STANDARD ?
                     "standard" : "expanded",
                     list->name, VTY_NEWLINE);
        }

      qs = community_list_entry_value(qs, entry) ;
      vty_out (vty, "    %s\n", qs_string(qs));
    } ;

  qs_free(qs) ;
} ;

DEFUN (show_ip_community_list,
       show_ip_community_list_cmd,
       "show ip community-list",
       SHOW_STR
       IP_STR
       "List community-list\n")
{
  vector extract ;
  vector_index_t i ;
  struct community_list *list;

  extract = community_list_extract(bgp_clist, COMMUNITY_LIST,
                                                           NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    community_list_show (vty, list, "Community");

  vector_free(extract) ;        /* discard temporary vector */

  return CMD_SUCCESS;
}

DEFUN (show_ip_community_list_arg,
       show_ip_community_list_arg_cmd,
       "show ip community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List community-list\n"
       "Community-list number\n"
       "Community-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, COMMUNITY_LIST, argv[0]);
  if (! list)
    {
      vty_out (vty, "%% Can't find community-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  community_list_show (vty, list, "Community");

  return CMD_SUCCESS;
}

static int
extcommunity_list_set_vty (struct vty *vty, int argc, argv_t argv,
                           int style, int reject_all_digit_name)
{
  int ret;
  int direct;
  char *str;

  /* Check the list type.
   */
  if (strncmp (argv[1], "p", 1) == 0)
    direct = COMMUNITY_PERMIT;
  else if (strncmp (argv[1], "d", 1) == 0)
    direct = COMMUNITY_DENY;
  else
    {
      vty_out (vty, "%% Matching condition must be permit or deny%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* All digit name check.
   */
  if (reject_all_digit_name && all_digit (argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  str = argv_concat (argv, argc, 2);

  ret = extcommunity_list_set (bgp_clist, argv[0], str, direct, style);

  XFREE (MTYPE_TMP, str);

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * extcommunity-list entry delete.
 */
static int
extcommunity_list_unset_vty (struct vty *vty, int argc, argv_t argv,
                                     clist_entry_style_t style, bool named_list)
{
  int ret;

  /* All digit name check.
   */
  if (named_list && all_digit(argv[0]))
    {
      vty_out (vty, "%% Community name cannot have all digits\n");
      return CMD_WARNING;
    } ;

  /* Now unset everything or just the given entry.
   */
  if (argc < 2)
    {
      ret = extcommunity_list_unset_all (bgp_clist, argv[0]);
    }
  else
    {
      clist_action_type_t action ;
      char* str ;

      switch (argv[1][0])
        {
          case 'p':
            action = COMMUNITY_PERMIT ;
            break ;

          case 'd':
            action = COMMUNITY_DENY;
            break ;

          default:
            vty_out (vty, "%% Matching condition must be permit or deny\n") ;
            return CMD_WARNING;
        } ;

      str = argv_concat (argv, argc, 2) ;

      ret = extcommunity_list_unset (bgp_clist, argv[0], str, action, style);

      XFREE (MTYPE_TMP, str) ;
    } ;

  if (ret < 0)
    {
      community_list_perror (vty, ret);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}

/* "extcommunity-list" keyword help string.  */
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR  "Extended community attribute in "\
                 "'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

DEFUN (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard_cmd,
       "ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

ALIAS (ip_extcommunity_list_standard,
       ip_extcommunity_list_standard2_cmd,
       "ip extcommunity-list <1-99> (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_expanded,
       ip_extcommunity_list_expanded_cmd,
       "ip extcommunity-list <100-500> (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard_cmd,
       "ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

ALIAS (ip_extcommunity_list_name_standard,
       ip_extcommunity_list_name_standard2_cmd,
       "ip extcommunity-list standard WORD (deny|permit)",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n")

DEFUN (ip_extcommunity_list_name_expanded,
       ip_extcommunity_list_name_expanded_cmd,
       "ip extcommunity-list expanded WORD (deny|permit) .LINE",
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_set_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (no_ip_extcommunity_list_standard_all,
       no_ip_extcommunity_list_standard_all_cmd,
       "no ip extcommunity-list <1-99>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

DEFUN (no_ip_extcommunity_list_expanded_all,
       no_ip_extcommunity_list_expanded_all_cmd,
       "no ip extcommunity-list <100-500>",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (no_ip_extcommunity_list_name_standard_all,
       no_ip_extcommunity_list_name_standard_all_cmd,
       "no ip extcommunity-list standard WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

DEFUN (no_ip_extcommunity_list_name_expanded_all,
       no_ip_extcommunity_list_name_expanded_all_cmd,
       "no ip extcommunity-list expanded WORD",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Extended Community list name\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (no_ip_extcommunity_list_standard,
       no_ip_extcommunity_list_standard_cmd,
       "no ip extcommunity-list <1-99> (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (standard)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_STANDARD, false);
}

DEFUN (no_ip_extcommunity_list_expanded,
       no_ip_extcommunity_list_expanded_cmd,
       "no ip extcommunity-list <100-500> (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Extended Community list number (expanded)\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                               ECOMMUNITY_LIST_EXPANDED, false);
}

DEFUN (no_ip_extcommunity_list_name_standard,
       no_ip_extcommunity_list_name_standard_cmd,
       "no ip extcommunity-list standard WORD (deny|permit) .AA:NN",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify standard extcommunity-list\n"
       "Extended Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       EXTCOMMUNITY_VAL_STR)
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_STANDARD, true);
}

DEFUN (no_ip_extcommunity_list_name_expanded,
       no_ip_extcommunity_list_name_expanded_cmd,
       "no ip extcommunity-list expanded WORD (deny|permit) .LINE",
       NO_STR
       IP_STR
       EXTCOMMUNITY_LIST_STR
       "Specify expanded extcommunity-list\n"
       "Community list name\n"
       "Specify community to reject\n"
       "Specify community to accept\n"
       "An ordered list as a regular-expression\n")
{
  return extcommunity_list_unset_vty (vty, argc, argv,
                                                ECOMMUNITY_LIST_EXPANDED, true);
}

DEFUN (show_ip_extcommunity_list,
       show_ip_extcommunity_list_cmd,
       "show ip extcommunity-list",
       SHOW_STR
       IP_STR
       "List extended-community list\n")
{
  vector extract ;
  vector_index_t i ;
  struct community_list *list;

  extract = community_list_extract(bgp_clist, ECOMMUNITY_LIST,
                                                            NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    community_list_show (vty, list, "Extended-Community");

  vector_free(extract) ;        /* discard temporary vector */

  return CMD_SUCCESS;
}

DEFUN (show_ip_extcommunity_list_arg,
       show_ip_extcommunity_list_arg_cmd,
       "show ip extcommunity-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       "List extended-community list\n"
       "Extcommunity-list number\n"
       "Extcommunity-list name\n")
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, ECOMMUNITY_LIST, argv[0]);
  if (! list)
    {
      vty_out (vty, "%% Can't find extcommunity-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  community_list_show (vty, list, "Extended-Community");

  return CMD_SUCCESS;
}

/* Put entire community-list or extcommunity-list.      */
static int
community_list_config_write_list(struct vty* vty, clist_type_t what)
{
  vector extract ;
  vector_index_t i ;
  community_list list;
  qstring  qs ;

  int write = 0;
  qs = NULL ;

  extract = community_list_extract(bgp_clist, what, NULL, NULL, false) ;
  for (VECTOR_ITEMS(extract, list, i))
    {
      community_entry entry;

      for (entry = ddl_head(list->entries); entry;
                                            entry = ddl_next(entry, list))
        {
          const char* list_type  = "" ;
          const char* list_style = "" ;

          switch (entry->style)
            {
              case COMMUNITY_LIST_STANDARD:
                list_type  = "community-list" ;
                list_style = "standard " ;
                break ;
              case COMMUNITY_LIST_EXPANDED:
                list_type  = "community-list" ;
                list_style = "expanded " ;
                break ;
              case ECOMMUNITY_LIST_STANDARD:
                list_type  = "extcommunity-list" ;
                list_style = "standard " ;
                break ;
              case ECOMMUNITY_LIST_EXPANDED:
                list_type  = "extcommunity-list" ;
                list_style = "expanded " ;
                break ;
              default:
                break ;
            } ;

          if (all_digit(list->name))
            list_style = "" ;   /* squash style for all digit names     */

          qs = community_list_entry_value(qs, entry) ;

          vty_out (vty, "ip %s %s%s %s\n",
                             list_type, list_style, list->name, qs_string(qs));
          write++;
        }
   }

  vector_free(extract) ;        /* discard temporary vector */
  qs_free(qs) ;

  return write;
}

/* Display community-list and extcommunity-list configuration.  */
static int
community_list_config_write (struct vty *vty)
{
  int write = 0;

  write += community_list_config_write_list(vty, COMMUNITY_LIST) ;
  write += community_list_config_write_list(vty, ECOMMUNITY_LIST);

  return write;
}

CMD_INSTALL_TABLE(static, bgp_community_cmd_table, BGPD) =
{
  /* Community-list.  */
  { CONFIG_NODE,     &ip_community_list_standard_cmd                    },
  { CONFIG_NODE,     &ip_community_list_standard2_cmd                   },
  { CONFIG_NODE,     &ip_community_list_expanded_cmd                    },
  { CONFIG_NODE,     &ip_community_list_name_standard_cmd               },
  { CONFIG_NODE,     &ip_community_list_name_standard2_cmd              },
  { CONFIG_NODE,     &ip_community_list_name_expanded_cmd               },
  { CONFIG_NODE,     &no_ip_community_list_standard_all_cmd             },
  { CONFIG_NODE,     &no_ip_community_list_expanded_all_cmd             },
  { CONFIG_NODE,     &no_ip_community_list_name_standard_all_cmd        },
  { CONFIG_NODE,     &no_ip_community_list_name_expanded_all_cmd        },
  { CONFIG_NODE,     &no_ip_community_list_standard_cmd                 },
  { CONFIG_NODE,     &no_ip_community_list_expanded_cmd                 },
  { CONFIG_NODE,     &no_ip_community_list_name_standard_cmd            },
  { CONFIG_NODE,     &no_ip_community_list_name_expanded_cmd            },
  { VIEW_NODE,       &show_ip_community_list_cmd                        },
  { VIEW_NODE,       &show_ip_community_list_arg_cmd                    },
  { ENABLE_NODE,     &show_ip_community_list_cmd                        },
  { ENABLE_NODE,     &show_ip_community_list_arg_cmd                    },

  /* Extcommunity-list.  */
  { CONFIG_NODE,     &ip_extcommunity_list_standard_cmd                 },
  { CONFIG_NODE,     &ip_extcommunity_list_standard2_cmd                },
  { CONFIG_NODE,     &ip_extcommunity_list_expanded_cmd                 },
  { CONFIG_NODE,     &ip_extcommunity_list_name_standard_cmd            },
  { CONFIG_NODE,     &ip_extcommunity_list_name_standard2_cmd           },
  { CONFIG_NODE,     &ip_extcommunity_list_name_expanded_cmd            },
  { CONFIG_NODE,     &no_ip_extcommunity_list_standard_all_cmd          },
  { CONFIG_NODE,     &no_ip_extcommunity_list_expanded_all_cmd          },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_standard_all_cmd     },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_expanded_all_cmd     },
  { CONFIG_NODE,     &no_ip_extcommunity_list_standard_cmd              },
  { CONFIG_NODE,     &no_ip_extcommunity_list_expanded_cmd              },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_standard_cmd         },
  { CONFIG_NODE,     &no_ip_extcommunity_list_name_expanded_cmd         },
  { VIEW_NODE,       &show_ip_extcommunity_list_cmd                     },
  { VIEW_NODE,       &show_ip_extcommunity_list_arg_cmd                 },
  { ENABLE_NODE,     &show_ip_extcommunity_list_cmd                     },
  { ENABLE_NODE,     &show_ip_extcommunity_list_arg_cmd                 },

  CMD_INSTALL_END
} ;

extern void
community_list_cmd_init(void)
{
  cmd_install_node_config_write(COMMUNITY_LIST_NODE,
                                                   community_list_config_write);
  cmd_install_table(bgp_community_cmd_table) ;
} ;
