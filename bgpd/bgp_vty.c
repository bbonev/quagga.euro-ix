/* BGP VTY interface.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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
#include "misc.h"

#include "command.h"
#include "vty.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer_config.h"
#include "bgpd/bgp_inst_config.h"

#include "bgpd/bgp_run.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_prun.h"


/*==============================================================================
 * Here we have vty stuff which is common to the configuration and run-time.
 */

/*------------------------------------------------------------------------------
 * Utility function to get qafx from current node.
 *
 * Returns IPv4/Unicast if not in an explicit address family.
 */
extern qafx_t
bgp_node_qafx (struct vty *vty)
{
  switch (vty->node)
    {
      default:
        qassert(false) ;
        return qafx_none ;

      case BGP_NODE:
      case BGP_IPV4_NODE:
        return qafx_ipv4_unicast ;

      case BGP_IPV4M_NODE:
        return qafx_ipv4_multicast ;

      case BGP_VPNV4_NODE:
        return qafx_ipv4_mpls_vpn ;

      case BGP_IPV6_NODE:
        return qafx_ipv4_unicast ;

      case BGP_IPV6M_NODE:
        return qafx_ipv4_multicast ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Utility function to get qafx from current node.
 *
 * Returns "none" if not in an explicit address family.
 */
extern qafx_t
bgp_node_qafx_explicit(vty vty)
{
  switch (vty->node)
    {
      default:
        qassert(false) ;
        fall_through ;

      case BGP_NODE:
        return qafx_none ;

      case BGP_IPV4_NODE:
        return qafx_ipv4_unicast ;

      case BGP_IPV4M_NODE:
        return qafx_ipv4_multicast ;

      case BGP_VPNV4_NODE:
        return qafx_ipv4_mpls_vpn ;

      case BGP_IPV6_NODE:
        return qafx_ipv4_unicast ;

      case BGP_IPV6M_NODE:
        return qafx_ipv4_multicast ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Utility function to get address family from current node.
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

/*------------------------------------------------------------------------------
 * Utility function to get subsequent address family from current node.
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

/*==============================================================================
 * BGP Instance and BGP Run lookups.
 */

/*------------------------------------------------------------------------------
 * Get the current vty bgp-instance.
 *
 * Paranoia of the first kind !
 */
extern bgp_inst
bgp_node_inst(vty vty)
{
  bgp_inst bgp ;

  for (bgp = ddl_head(bm->bgps) ; bgp != NULL ; bgp = ddl_next(bgp, bgp_list))
    {
      if (bgp == vty->index)
        return bgp ;
    } ;

  vty_out(vty, "%% BUG: no valid bgp instance currently selected") ;
  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Lookup bgp instance for vty.
 *
 * Lookup by name and (if given) ASN.
 */
extern bgp_inst
bgp_inst_lookup_vty(vty vty, chs_c name, as_t as)
{
  bgp_inst bgp ;

  bgp = bgp_inst_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured\n");
    }
  else
    {
      bgp = bgp_inst_lookup(name, as);
      if (bgp == NULL)
        {
          if ((name == NULL) || (name[0] == '\0'))
            {
              if (as == BGP_ASN_NULL)
                vty_out(vty, "There is no 'unnamed' view\n") ;
              else
                vty_out(vty, "There is no 'unnamed' view with ASN %u\n", as) ;
            }
          else
            {
              if (as == BGP_ASN_NULL)
                vty_out(vty, "There is no view named '%s'\n", name) ;
              else
                vty_out(vty, "There is no view named '%s' with ASN %u\n",
                                                                     name, as) ;
            } ;
        } ;
    } ;

  return bgp ;
} ;

/*------------------------------------------------------------------------------
 * Lookup run-time bgp instance for vty.
 *
 * If the given name is NULL, return "default" bgp instance (if any).  Note
 * that if there is an 'unnamed' view, then it will be the first view.
 *
 * This kludge is to support "
 *
 * Otherwise lookup by name.
 */
extern bgp_inst
bgp_brun_lookup_vty(vty vty, chs_c name, as_t as)
{
  bgp_inst bgp ;

  bgp = bgp_inst_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured\n");
      return NULL ;
    }
  else
    {
      bgp = bgp_inst_lookup(name, as);
      if (bgp == NULL)
        {
          if ((name == NULL) || (name[0] == '\0'))
            {


            }
          vty_out (vty, "Can't find BGP view %s\n", name);
        } ;
    } ;

  return bgp ;
} ;

/*==============================================================================
 * Peer lookups
 *
 * These are used for Configuration Commands, where we must know what view
 * we are in -- the view as given by the vty->index.
 */
static bgp_peer bgp_peer_and_or_group_lookup_vty(vty vty, chs_c p_str,
                                                     bgp_peer_or_group_t bpog) ;

/*------------------------------------------------------------------------------
 * Look-up peer or peer/group by its address in the current vty view.
 *
 * See bgp_peer_and_or_group_lookup_vty(), below.
 */
extern bgp_peer
bgp_peer_or_group_lookup_vty(vty vty, chs_c p_str)
{
  return bgp_peer_and_or_group_lookup_vty(vty, p_str, bpog_peer_or_group) ;
} ;

/*------------------------------------------------------------------------------
 * Look-up peer in the current vty view.
 *
 * See bgp_peer_and_or_group_lookup_vty(), below.
 */
extern bgp_peer
bgp_peer_lookup_vty(vty vty, chs_c p_str)
{
  return bgp_peer_and_or_group_lookup_vty(vty, p_str, bpog_peer_ip) ;
} ;

/*------------------------------------------------------------------------------
 * Look-up group in the current vty view.
 *
 * See bgp_peer_and_or_group_lookup_vty(), below.
 */
extern bgp_peer
bgp_group_lookup_vty(vty vty, chs_c g_str)
{
  return bgp_peer_and_or_group_lookup_vty(vty, g_str, bpog_group_name) ;
} ;

/*------------------------------------------------------------------------------
 * Look-up peer or peer/group by its address in the current vty view.
 *
 * Looks for peer or group, or peer only.
 *
 * Issues error messages to vty if:
 *
 *   * cannot find a bgp instance !!
 *
 *   * peer_only and the string is not an IP address
 *
 *   * peer is not found in the bgp instance
 *
 *   * group is not found in the bgp instance
 *
 * Returns:  peer address of peer or peer-group if found
 *           NULL if not found
 */
static bgp_peer
bgp_peer_and_or_group_lookup_vty(vty vty, chs_c p_str, bgp_peer_or_group_t bpog)
{
  bgp_inst    bgp ;
  sockunion_t su[1] ;
  bgp_peer    peer ;
  const char* what ;
  bgp_ret_t   ret ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return NULL ;

  ret = bgp_peer_sex(p_str, su, bpog) ;

  switch (ret)
    {
      case BGP_OK_PEER_IP:
        peer = bgp_peer_lookup_su(bgp, su);
        if (peer != NULL)
          return peer ;

        what = "neighbor" ;
        break ;

      case BGP_OK_GROUP_NAME:
        peer = bgp_peer_lookup_group(bgp, p_str);
        if (peer != NULL)
          return peer ;

        what = "peer-group" ;
        break ;

      default:
        bgp_vty_return(vty, ret) ;
        return NULL ;
    } ;

  vty_out (vty, "%% %s '%s' not configured", what, p_str) ;
  if (bm->bgp_count > 1)
    {
      chs_c view_name ;

      view_name = bgp_nref_name(bgp->name) ;

      if ((view_name == NULL) || (view_name[0] == '\0'))
        vty_out(vty, " in the 'unnamed' view") ;
      else
        vty_out(vty, " in view '%s'", view_name) ;
    } ;
  vty_out(vty, "\n") ;

  return NULL;
} ;

/*==============================================================================
 * Prun Lookups.
 */

/*------------------------------------------------------------------------------
 * Look-up running peer by its address in the given bgp instance or all such.
 *
 * If the given 'view_name' is NULL, try all bgp instances.
 *
 * Returns:  the prun for the peer
 *           NULL if not found
 */
extern bgp_prun
prun_lookup_view_vty(vty vty, chs_c view_name, chs_c peer_name)
{
#if 0
  bgp_run    brun ;
  bgp_prun   prun ;

  if (view_name == NULL)
    bgp = NULL ;
  else
    {
      bgp = bgp_lookup_vty(vty, view_name) ;
      if (bgp == NULL)
        return NULL ;
    } ;

  peer = prun_lookup_view_vty(vty, bgp, peer_name, true /* real_peer */) ;

  if (peer == NULL)
    return NULL ;

  return peer->prun ;
#else
  return NULL ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Look-up running peer by its address in the given bgp instance or all such.
 *
 * If the given 'view_name' is NULL, try all bgp instances.
 *
 * Returns:  the prun for the peer
 *           NULL if not found or not configured for given afi/safi
 */
extern bgp_prun
prun_lookup_view_qafx_vty(vty vty, chs_c view_name, chs_c peer_name,
                                                                    qafx_t qafx)
{
  bgp_prun    prun ;

  prun = prun_lookup_view_vty(vty, view_name, peer_name) ;
  if (prun == NULL)
    return NULL ;

  if ((qafx != qafx_undef) && (prun->prib[qafx] == NULL))
    {
      vty_out (vty, "%% Neighbor not activated in address family\n");
      return NULL ;
    } ;

  return prun ;
} ;

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Table of return code -> error/warning message
 */
static const chs_c bgp_vty_return_strings[BGP_RET_COUNT] =
  {
    [BGP_ERR_BUG]
        = "Invalid/Unknown something... report as *BUG*",
    [BGP_ERR_INVALID_VALUE]
        = "Invalid value",
    [BGP_ERR_INVALID_FLAG]
         = "Invalid flag",
    [BGP_ERR_INVALID_IF_NAME]
        = "Invalid interface name",
    [BGP_ERR_INVALID_IP_ADDRESS]
        = "Invalid IP address",
    [BGP_ERR_INVALID_CLUSTER_ID]
        = "Invalid Cluster-ID",
    [BGP_ERR_INVALID_ROUTE_TYPE]
        = "Invalid route type",
    [BGP_ERR_INVALID_FAMILY]
        = "Invalid address family",
    [BGP_ERR_INVALID_METRIC]
        = "Invalid metric value",
    [BGP_ERR_INVALID_PEER_IP]
        = "Invalid peer IP address",
    [BGP_ERR_IPV4_MAPPED]
        = "IPv4-Mapped address is invalid",
    [BGP_ERR_INVALID_GROUP_NAME]
        = "Invalid peer-group name",
    [BGP_ERR_PEER_NOT_GROUP]
        = "Expecting peer IP address, not peer-group name",
    [BGP_ERR_GROUP_NOT_PEER]
        = "Expecting peer-group name, not peer IP address",

    [BGP_ERR_MULTIPLE_INSTANCE_USED]
        = "Cannot clear 'multiple-instance'",
    [BGP_ERR_MULTIPLE_INSTANCE_NOT_SET]
        = "Need 'multiple-instance' in order to create more than one 'view'",
    [BGP_ERR_INSTANCE_MISMATCH]
        = "BGP view name and AS number mismatch",
    [BGP_ERR_AS_MISMATCH]
        = "BGP is already running with a different AS number",

    [BGP_ERR_AF_NOT_CONFIGURED]
        = "Peer/Peer-Group not configured for this afi/safi",
    [BGP_ERR_PEER_GROUP_AF_NOT_CONFIGURED]
        = "Peer-Group not configured for this afi/safi",

    [BGP_ERR_PEER_EXISTS]
        = "Neighbor already exists (in another view)",
    [BGP_ERR_PEER_EXISTS_IN_VIEW]
        = "Neighbor already exists",
    [BGP_ERR_CANNOT_SET_AS_AND_GROUP]
        = "Cannot create neighbor with AS different to peer-group's AS",
    [BGP_ERR_PEER_NEEDS_REMOTE_AS]
        = "Need an AS to create a new neighbor",
    [BGP_ERR_GROUP_NEEDS_REMOTE_AS]
        = "Peer-Group must have an AS to create a new neighbor using it",
    [BGP_ERR_AS_IS_CONFED_ID]
        = "Cannot set AS for eBGP peer to the current Confed-ID",

    [BGP_ERR_PEER_GROUP_EXISTS]
        = "Peer-Group already exists",

    [BGP_ERR_PEER_CANNOT_SET_AS]
        = "Cannot set neighbor ASN which is set by peer-group",
    [BGP_ERR_PEER_CANNOT_UNSET_AS]
        = "Cannot unset neighbor ASN",
    [BGP_ERR_GROUP_CANNOT_SET_AS]
        = "Cannot set ASN for peer-group while any member has a different ASN",
    [BGP_ERR_CANNOT_CHANGE_AS]
        = "Cannot change ASN with the current peer-group/peer settings",
    [BGP_ERR_CANNOT_BIND_GROUP]
        = "Cannot bind to group with current settings",
    [BGP_ERR_PEER_GROUP_CANNOT_CHANGE]
        = "Cannot change the peer-group. Deconfigure first",

    [BGP_ERR_PEER_GROUP_SHUTDOWN]
        = "Peer-group has been shutdown. Activate the peer-group first",
    [BGP_ERR_PEER_FLAG_CONFLICT_1]
        = "Cannot set strict-capability-match with dont-capability-negotiate",
    [BGP_ERR_PEER_FLAG_CONFLICT_2]
        = "Cannot set override-capability with strict-capability-match",
    [BGP_ERR_PEER_FLAG_CONFLICT_3]
        = "Cannot set dont-capability-negotiate with strict-capability-match",


    [BGP_ERR_PEER_FILTER_CONFLICT]
        = "Prefix/distribute list cannot co-exist",
    [BGP_ERR_NOT_INTERNAL_PEER]
        = "Only allowed for iBGP peers",
    [BGP_ERR_REMOVE_PRIVATE_AS]
        = "Private AS cannot be removed for iBGP peers",
    [BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP]
        = "Local-AS allowed only for eBGP peers",
    [BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS]
        = "Cannot have local-as same as BGP AS",
    [BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_CONFED_ID]
        = "Cannot have local-as same as Confed-ID",

    [BGP_ERR_CONFED_ID_USED_AS_EBGP_PEER]
        = "Given Confed-ID is already used by an eBGP neighbor",
    [BGP_ERR_NO_CBGP_WITH_LOCAL_AS]
        = "Cannot create Confed-Peer with local-as",
    [BGP_ERR_CONFED_ID_USED_AS_LOCAL_AS]
        = "Given Confed-ID already set as local-as",
    [BGP_ERR_CONFED_PEER_AS_LOCAL_AS]
        = "Cannot have local-as same as Confed-Peer",

    [BGP_ERR_LOCAL_AS_ALREADY_SET]
        = "New Confed-Peer has local-as set already",

    [BGP_ERR_TCPSIG_FAILED]
        = "Error while applying TCP-Sig to session(s)",
    [BGP_ERR_NO_MULTIHOP_WITH_GTSM]
        = "multihop and ttl-security cannot be configured together",
    [BGP_ERR_NOT_SUPPORTED]
        = "Not supported",
  } ;

/*------------------------------------------------------------------------------
 * Process given bgp_ret_t: generate any message required.
 *
 * Returns:  suitable cmd_ret_t value
 */
extern cmd_ret_t
bgp_vty_return (vty vty, bgp_ret_t ret)
{
  cmd_ret_t cret ;
  chs_c     str ;

  /* Deal with returns which do not map to warning message + CMD_WARNING.
   */
  switch (ret)
    {
      case BGP_SUCCESS:
        return CMD_SUCCESS ;

      case BGP_WARNING:
        return CMD_WARNING ;

      case BGP_ERROR:
        return CMD_ERROR ;

      case BGP_ERR_BUG:
        cret = CMD_ERROR ;
        break ;

      default:
        cret = CMD_WARNING ;
        break ;
    } ;

  /* Look up the error/warning message
   */
  if (ret < BGP_RET_COUNT)
    str = bgp_vty_return_strings[ret] ;
  else
    str = NULL ;

  if (str != NULL)
    vty_out (vty, "%% %s\n", str, VTY_NEWLINE);
  else
    {
      vty_out (vty, "%% unknown bgp_ret_t %d\n", ret);
      cret = CMD_ERROR ;
    } ;

  return cret ;
} ;


