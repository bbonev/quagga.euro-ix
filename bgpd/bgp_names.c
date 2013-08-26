/* bgpd mapping protocol values to names
   Copyright (C) 1996, 97, 99 Kunihiro Ishiguro

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

#include "bgpd/bgp_names.h"
#include "bgpd/bgp_common.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_peer.h"

/*------------------------------------------------------------------------------
 * Names of FSM state values
 */
static const char* const bgp_fsm_state_map_body[] =
{
  [bgp_fsNULL]         = "Initial",
  [bgp_fsIdle]         = "Idle",
  [bgp_fsConnect]      = "Connect",
  [bgp_fsActive]       = "Active",
  [bgp_fsOpenSent]     = "OpenSent",
  [bgp_fsOpenConfirm]  = "OpenConfirm",
  [bgp_fsEstablished]  = "Established",
  [bgp_fsStop]         = "Stop",
} ;

const map_direct_t bgp_fsm_state_map =
      map_direct_s(bgp_fsm_state_map_body, "unknown(%d)") ;

/*------------------------------------------------------------------------------
 * Names of FSM event values
 */
static const char* const bgp_fsm_event_map_body[] =
{
  [bgp_feNULL]                        = "NULL",
  [bgp_feManualStart]                 = "ManualStart",
  [bgp_feManualStop]                  = "ManualStop",
  [bgp_feAutomaticStart]              = "AutomaticStart",
  [bgp_feManualStart_with_Passive]    = "ManualStart_with_Passive",
  [bgp_feAutomaticStart_with_Passive] = "AutomaticStart_with_Passive",
  [bgp_feAutomaticStart_with_Damp]    = "AutomaticStart_with_Damp",
  [bgp_feAutomaticStart_with_Damp_and_Passive]
                                      = "AutomaticStart_with_Damp_and_Passive",
  [bgp_feAutomaticStop]               = "AutomaticStop",
  [bgp_feConnectRetryTimer_Expires]   = "ConnectRetryTimer_Expires",
  [bgp_feHoldTimer_Expires]           = "HoldTimer_Expires",
  [bgp_feKeepaliveTimer_Expires]      = "KeepaliveTimer_Expires",
  [bgp_feDelayOpenTimer_Expires]      = "DelayOpenTimer_Expires",
  [bgp_feIdleHoldTimer_Expires]       = "IdleHoldTimer_Expires",
  [bgp_feTcpConnection_Valid]         = "TcpConnection_Valid",
  [bgp_feTcp_CR_Invalid]              = "Tcp_CR_Invalid",
#if 0
  /* We have a local alias for these -- see below
   */
  [bgp_feTcp_CR_Acked]                = "Tcp_CR_Acked",
  [bgp_feTcpConnectionConfirmed]      = "TcpConnectionConfirmed",
  [bgp_feTcpConnectionFails]          = "TcpConnectionFails",
#endif

  [bgp_feBGPOpen]                     = "BGPOpen",
  [bgp_feBGPOpen_with_DelayOpenTimer] = "BGPOpen_with_DelayOpenTimer",
  [bgp_feBGPHeaderErr]                = "BGPHeaderErr",
  [bgp_feBGPOpenMsgErr]               = "BGPOpenMsgErr",
  [bgp_feOpenCollisionDump]           = "OpenCollisionDump",
  [bgp_feNotifyMsgVerErr]             = "NotifyMsgVerErr",
  [bgp_feNotifyMsg]                   = "NotifyMsg",
  [bgp_feKeepAliveMsg]                = "KeepAliveMsg",
  [bgp_feUpdateMsg]                   = "UpdateMsg",
  [bgp_feUpdateMsgErr]                = "UpdateMsgErr",

  [bgp_feError]                       = "Error",
  [bgp_feConnectFailed]               = "ConnectFailed",
  [bgp_feConnected]                   = "Connected (Tcp_CR_Acked)",
  [bgp_feAccepted]                    = "Accepted (TcpConnectionConfirmed)",
  [bgp_feDown]                        = "Down (TcpConnectionFails)",
  [bgp_feRRMsg]                       = "RRMsg",
  [bgp_feRRMsgErr]                    = "RRMsgErr",
  [bgp_feAcceptOPEN]                  = "AcceptedOPEN",
  [bgp_feRestart]                     = "Restart",
  [bgp_feShut_RD]                     = "Shut_RD (internal)",
  [bgp_feShut_WR]                     = "Shut_WR (internal)",

  [bgp_feIO]                          = "I/O (internal)",
} ;

const map_direct_t bgp_fsm_event_map =
      map_direct_s(bgp_fsm_event_map_body, "unknown(%d)") ;

/*------------------------------------------------------------------------------
 * Names of Peer status values
 */
const char* const bgp_peer_status_map_body[] =
{
  [bgp_pDown]         = "Idle (Down)",
  [bgp_pStarted]      = "Idle (Up)",
  [bgp_pEstablished]  = "Established",
  [bgp_pClearing]     = "Clearing",
  [bgp_pDeleting]     = "Deleting",
};

const map_direct_t bgp_peer_status_map =
     map_direct_s(bgp_peer_status_map_body, "unknown(%d)") ;

/*------------------------------------------------------------------------------
 * BGP message type names.
 */
static const char* const bgp_message_type_map_body[] =
{
  [BGP_MT_OPEN]               = "OPEN",
  [BGP_MT_UPDATE]             = "UPDATE",
  [BGP_MT_NOTIFICATION]       = "NOTIFICATION",
  [BGP_MT_KEEPALIVE]          = "KEEPALIVE",
  [BGP_MT_ROUTE_REFRESH]      = "ROUTE-REFRESH",

  [BGP_MT_CAPABILITY]         = "CAPABILITY",

  [BGP_MT_ROUTE_REFRESH_pre]  = "ROUTE-REFRESH(pre-RFC2918)",
} ;

const map_direct_t bgp_message_type_map =
      map_direct_s(bgp_message_type_map_body, "unknown(%d)") ;

/*------------------------------------------------------------------------------
 * Names for notification types and sub-types
 */
static const char* const bgp_notify_msg_map_body[] =
{
  [BGP_NOMC_HEADER]        = "Message Header Error",
  [BGP_NOMC_OPEN]          = "OPEN Message Error",
  [BGP_NOMC_UPDATE]        = "UPDATE Message Error",
  [BGP_NOMC_HOLD_EXP]      = "Hold Timer Expired",
  [BGP_NOMC_FSM]           = "Finite State Machine Error",
  [BGP_NOMC_CEASE]         = "Cease",
  [BGP_NOMC_DYN_CAP]       = "CAPABILITY Message Error",
} ;

const map_direct_t bgp_notify_msg_map =
      map_direct_s(bgp_notify_msg_map_body, "Unknown(%d)") ;

/* BGP_NOMC_HEADER subtypes
 */
static const char* const bgp_notify_head_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]    = "/Unspecific",
  [BGP_NOMS_H_NOT_SYNC]    = "/Connection Not Synchronized",
  [BGP_NOMS_H_BAD_LEN]     = "/Bad Message Length",
  [BGP_NOMS_H_BAD_TYPE]    = "/Bad Message Type",
};

const map_direct_t bgp_notify_head_msg_map =
      map_direct_s(bgp_notify_head_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_OPEN subtypes
 */
static const char* const bgp_notify_open_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]    = "/Unspecific",
  [BGP_NOMS_O_VERSION]     = "/Unsupported Version Number",
  [BGP_NOMS_O_BAD_AS]      = "/Bad Peer AS",
  [BGP_NOMS_O_BAD_ID]      = "/Bad BGP Identifier",
  [BGP_NOMS_O_OPTION]      = "/Unsupported Optional Parameter",
  [BGP_NOMS_O_AUTH]        = "/Authentication Failure",
  [BGP_NOMS_O_H_TIME]      = "/Unacceptable Hold Time",
  [BGP_NOMS_O_CAPABILITY]  = "/Unsupported Capability",
} ;

const map_direct_t bgp_notify_open_msg_map =
      map_direct_s(bgp_notify_open_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_UPDATE subtypes
 */
static const char* const bgp_notify_update_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]    = "/Unspecific",
  [BGP_NOMS_U_MAL_ATTR]    = "/Malformed Attribute List",
  [BGP_NOMS_U_UNKNOWN]     = "/Unknown Well-known Attribute",
  [BGP_NOMS_U_MISSING]     = "/Missing Well-known Attribute",
  [BGP_NOMS_U_A_FLAGS]     = "/Attribute Flags Error",
  [BGP_NOMS_U_A_LENGTH]    = "/Attribute Length Error",
  [BGP_NOMS_U_ORIGIN]      = "/Invalid ORIGIN Attribute",
  [BGP_NOMS_U_AS_LOOP]     = "/AS Routing Loop",
  [BGP_NOMS_U_NEXT_HOP]    = "/Invalid NEXT_HOP Attribute",
  [BGP_NOMS_U_OPTIONAL]    = "/Optional Attribute Error",
  [BGP_NOMS_U_NETWORK]     = "/Invalid Network Field",
  [BGP_NOMS_U_MAL_AS_PATH] = "/Malformed AS_PATH",
};

const map_direct_t bgp_notify_update_msg_map =
      map_direct_s(bgp_notify_update_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_FSM subtypes
 */
static const char* const bgp_notify_fsm_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]        = "/Unspecific",
  [BGP_NOMS_F_IN_OPEN_SENT]    = "/Unexpected message in OpenSent state",
  [BGP_NOMS_F_IN_OPEN_CONFIRM] = "/Unexpected message in OpenConfirm",
  [BGP_NOMS_F_IN_ESTABLISHED]  = "/Unexpected message in Established",
} ;

const map_direct_t bgp_notify_fsm_msg_map =
      map_direct_s(bgp_notify_fsm_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_CEASE subtypes
 */
static const char* const bgp_notify_cease_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]    = "/Unspecific",
  [BGP_NOMS_C_MAX_PREF]    = "/Maximum Number of Prefixes Reached",
  [BGP_NOMS_C_SHUTDOWN]    = "/Administratively Shutdown",
  [BGP_NOMS_C_DECONFIG]    = "/Peer Unconfigured",
  [BGP_NOMS_C_RESET]       = "/Administratively Reset",
  [BGP_NOMS_C_REJECTED]    = "/Connection Rejected",
  [BGP_NOMS_C_CONFIG]      = "/Other Configuration Change",
  [BGP_NOMS_C_COLLISION]   = "/Connection collision resolution",
  [BGP_NOMS_C_RESOURCES]   = "/Out of Resource",
};

const map_direct_t bgp_notify_cease_msg_map =
      map_direct_s(bgp_notify_cease_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_DYN_CAP subtypes
 */
static const char* const bgp_notify_capability_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC]    = "/Unspecific",
  [BGP_NOMS_D_UNKN_SEQ]    = "/Umknown Sequence Number",
  [BGP_NOMS_D_INV_LEN]     = "/Invalid Capability Length",
  [BGP_NOMS_D_MALFORM]     = "/Malformed Capability Value",
  [BGP_NOMS_D_UNSUP]       = "/Unsupported Capability Code",
};

const map_direct_t bgp_notify_capability_msg_map =
      map_direct_s(bgp_notify_capability_msg_map_body, "/Unknown(%d)") ;

/* BGP_NOMC_HOLD_EXP subtypes
 *
 * This is a common table for any notification code for which there are no
 * subtypes.
 */
static const char* const bgp_notify_unspecific_msg_map_body[] =
{
  [BGP_NOMS_UNSPECIFIC] = "",
};

const map_direct_t bgp_notify_unspecific_msg_map =
      map_direct_s(bgp_notify_unspecific_msg_map_body, "/Unknown(%d)") ;

/* Notification subtypes for unknown type !
 */
static const char* const bgp_notify_unknown_msg_map_body[] = {} ;

const map_direct_t bgp_notify_unknown_msg_map =
      map_direct_s(bgp_notify_unknown_msg_map_body, "/Unknown(%d)") ;

/*------------------------------------------------------------------------------
 * Select message map for notification subcode, based on code.
 */
extern map_direct_p
bgp_notify_subcode_msg_map(uint code)
{
  switch (code)
    {
    case BGP_NOMC_HEADER:
      return bgp_notify_head_msg_map ;

    case BGP_NOMC_OPEN:
      return bgp_notify_open_msg_map ;

    case BGP_NOMC_UPDATE:
      return bgp_notify_update_msg_map ;

    case BGP_NOMC_HOLD_EXP:
      return bgp_notify_unspecific_msg_map ;

    case BGP_NOMC_FSM:
      return bgp_notify_fsm_msg_map ;

    case BGP_NOMC_CEASE:
      return bgp_notify_cease_msg_map ;

    case BGP_NOMC_DYN_CAP:
      return bgp_notify_capability_msg_map ;

    default:
      return bgp_notify_unknown_msg_map ;
    }
} ;

/*------------------------------------------------------------------------------
 * Origin names -- short and long
 */
const char* const bgp_origin_short_map_body[] =
{
  [BGP_ATT_ORG_IGP]    = "i",
  [BGP_ATT_ORG_EGP]    = "e",
  [BGP_ATT_ORG_INCOMP] = "?",
};

const map_direct_t bgp_origin_short_map =
      map_direct_s(bgp_origin_short_map_body, "X") ;

const char* const bgp_origin_long_map_body[] =
{
  [BGP_ATT_ORG_IGP]    = "IGP",
  [BGP_ATT_ORG_EGP]    = "EGP",
  [BGP_ATT_ORG_INCOMP] = "incomplete",
};

const map_direct_t bgp_origin_long_map =
      map_direct_s(bgp_origin_long_map_body, "unknown(%d)") ;

/*------------------------------------------------------------------------------
 * Attribute type names
 */
const char* const bgp_attr_name_map_body[] =
{
  [BGP_ATT_ORIGIN]           = "ORIGIN",
  [BGP_ATT_AS_PATH]          = "AS_PATH",
  [BGP_ATT_NEXT_HOP]         = "NEXT_HOP",
  [BGP_ATT_MED]              = "MULTI_EXIT_DISC",
  [BGP_ATT_LOCAL_PREF]       = "LOCAL_PREF",
  [BGP_ATT_A_AGGREGATE]      = "ATOMIC_AGGREGATE",
  [BGP_ATT_AGGREGATOR]       = "AGGREGATOR",
  [BGP_ATT_COMMUNITIES]      = "COMMUNITY",
  [BGP_ATT_ORIGINATOR_ID]    = "ORIGINATOR_ID",
  [BGP_ATT_CLUSTER_LIST]     = "CLUSTER_LIST",
  [BGP_ATT_DPA]              = "DPA",
  [BGP_ATT_ADVERTISER]       = "ADVERTISER" ,
  [BGP_ATT_RCID_PATH]        = "RCID_PATH",
  [BGP_ATT_MP_REACH_NLRI]    = "MP_REACH_NLRI",
  [BGP_ATT_MP_UNREACH_NLRI]  = "MP_UNREACH_NLRI",
  [BGP_ATT_ECOMMUNITIES]     = "EXT_COMMUNITIES",
  [BGP_ATT_AS4_PATH]         = "AS4_PATH",
  [BGP_ATT_AS4_AGGREGATOR]   = "AS4_AGGREGATOR",
  [BGP_ATT_AS_PATHLIMIT]     = "AS_PATHLIMIT",
};

const map_direct_t bgp_attr_name_map =
      map_direct_s(bgp_attr_name_map_body, "unknown(%u)") ;

/*------------------------------------------------------------------------------
 * AFI names -- Internet AFI  TODO *********************************************
 */
const char* const bgp_afi_name_map_body[] =
{
  [iAFI_IP]                   = "AFI_IP",
  [iAFI_IP6]                  = "AFI_IP6",
};

const map_direct_t bgp_afi_name_map =
      map_direct_s(bgp_afi_name_map_body, "unknown AFI(%u)") ;

/*------------------------------------------------------------------------------
 * SAFI names -- Internet SAFI TODO ********************************************
 */
const char* const bgp_safi_name_map_body[] =
{
  [iSAFI_Unicast]             = "SAFI_UNICAST",
  [iSAFI_Multicast]           = "SAFI_MULTICAST",
  [qSAFI_MPLS_VPN]            = "SAFI_MPLS_VPN",        // XXX .................
  [iSAFI_MPLS_VPN]            = "SAFI_MPLS_VPN",
};

const map_direct_t bgp_safi_name_map =
      map_direct_s(bgp_safi_name_map_body, "unknown SAFI(%u)") ;

/*------------------------------------------------------------------------------
 * Capability codes
 */
const char* const bgp_capcode_name_map_body[] =
{
  [BGP_CAN_MP_EXT]          = "MultiProtocol Extensions",
  [BGP_CAN_R_REFRESH]       = "Route Refresh",
  [BGP_CAN_ORF]             = "Cooperative Route Filtering",
  [BGP_CAN_M_ROUTES]        = "Multiple Routes",
  [BGP_CAN_E_NEXT_HOP]      = "Extended Next Hop Encoding",
  [BGP_CAN_G_RESTART]       = "Graceful Restart",
  [BGP_CAN_AS4]             = "4-octet AS number",
  [BGP_CAN_DYNAMIC_CAP_dep] = "Dynamic Capabilities (Deprecated)",
  [BGP_CAN_DYNAMIC_CAP]     = "Dynamic Capabilities",
  [BGP_CAN_MULTI_SESS]      = "Multi-Session",
  [BGP_CAN_ADD_PATH]        = "Add-Paths",
  [BGP_CAN_R_REFRESH_pre]   = "Route Refresh (pre-RFC)",
  [BGP_CAN_ORF_pre]         = "ORF (pre-RFC)",
};

const map_direct_t bgp_capcode_name_map =
      map_direct_s(bgp_capcode_name_map_body, "unknown Capability(%u)") ;

/*------------------------------------------------------------------------------
 * BGP Peer Down Causes mapped to strings
 */
const char* const bgp_peer_down_map_body[] =
{
  [PEER_DOWN_NULL]                 = "",

  [PEER_DOWN_UNSPECIFIED]          = "Unspecified reason",

  [PEER_DOWN_CONFIG_CHANGE]        = "Unspecified config change",

  [PEER_DOWN_RID_CHANGE]           = "Router ID changed",
  [PEER_DOWN_REMOTE_AS_CHANGE]     = "Remote AS changed",
  [PEER_DOWN_LOCAL_AS_CHANGE]      = "Local AS change",
  [PEER_DOWN_CLID_CHANGE]          = "Cluster ID changed",
  [PEER_DOWN_CONFED_ID_CHANGE]     = "Confederation identifier changed",
  [PEER_DOWN_CONFED_PEER_CHANGE]   = "Confederation peer changed",
  [PEER_DOWN_RR_CLIENT_CHANGE]     = "RR client config change",
  [PEER_DOWN_RS_CLIENT_CHANGE]     = "RS client config change",
  [PEER_DOWN_UPDATE_SOURCE_CHANGE] = "Update source change",
  [PEER_DOWN_AF_ACTIVATE]          = "Address family activated",
  [PEER_DOWN_GROUP_BIND]            = "Peer-group add member",
  [PEER_DOWN_GROUP_UNBIND]          = "Peer-group delete member",
  [PEER_DOWN_DONT_CAPABILITY]      = "dont-capability-negotiate changed",
  [PEER_DOWN_OVERRIDE_CAPABILITY]  = "override-capability changed",
  [PEER_DOWN_STRICT_CAP_MATCH]     = "strict-capability-match changed",
  [PEER_DOWN_CAPABILITY_CHANGE]    = "Capability changed",
  [PEER_DOWN_PASSIVE_CHANGE]       = "Passive config change",
  [PEER_DOWN_MULTIHOP_CHANGE]      = "Multihop config change",
  [PEER_DOWN_AF_DEACTIVATE]        = "Address family deactivated",
  [PEER_DOWN_PASSWORD_CHANGE]      = "MD5 Password changed",
  [PEER_DOWN_ALLOWAS_IN_CHANGE]    = "Allow AS in changed",

  [PEER_DOWN_USER_SHUTDOWN]        = "Admin. shutdown",
  [PEER_DOWN_USER_RESET]           = "User reset",
  [PEER_DOWN_NEIGHBOR_DELETE]      = "Neighbor deleted",

  [PEER_DOWN_INTERFACE_DOWN]       = "Interface down",

  [PEER_DOWN_MAX_PREFIX]           = "Max Prefix Limit exceeded",

  [PEER_DOWN_HEADER_ERROR]         = "Error in message header",
  [PEER_DOWN_OPEN_ERROR]           = "Error in BGP OPEN message",
  [PEER_DOWN_UPDATE_ERROR]         = "Error in BGP UPDATE message",
  [PEER_DOWN_HOLD_TIMER]           = "HoldTimer expired",
  [PEER_DOWN_FSM_ERROR]            = "Error in FSM sequence",
  [PEER_DOWN_DYN_CAP_ERROR]        = "Error in Dynamic Capability",

  [PEER_DOWN_NOTIFY_RECEIVED]      = "Notification received",
  [PEER_DOWN_NSF_CLOSE_SESSION]    = "NSF peer closed the session",
  [PEER_DOWN_CLOSE_SESSION]        = "Peer closed the session",
} ;

const map_direct_t bgp_peer_down_map =
      map_direct_s(bgp_peer_down_map_body, "unknown(%u)") ;

