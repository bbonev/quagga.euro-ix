/* BGP Peer -- header
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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

#ifndef _QUAGGA_BGP_PEER_H
#define _QUAGGA_BGP_PEER_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_filter.h"

#include "lib/routemap.h"
#include "lib/plist.h"
#include "lib/filter.h"
#include "lib/vhash.h"
#include "lib/vty.h"

/*==============================================================================
 * struct peer and struct peer_rib  -- the BGP neighbor structures.
 */
typedef struct bgp_nexthop bgp_nexthop_t ;

struct bgp_nexthop
{
  struct interface* ifp;
  struct in_addr    v4;
#ifdef HAVE_IPV6
  struct in6_addr  v6_global;
  struct in6_addr  v6_local;
#endif /* HAVE_IPV6 */
};

enum PEER_DOWN
{
  PEER_DOWN_first            =  0,

  PEER_DOWN_NULL             =  0, /* Not a PEER_DOWN                      */

  /* Session taken down at this end for some unspecified reason
   */
  PEER_DOWN_UNSPECIFIED,

  /* Configuration changes that cause a session to be reset.
   */
  PEER_DOWN_CONFIG_CHANGE,         /* Unspecified config change            */

  PEER_DOWN_RID_CHANGE,            /* 'bgp router-id'                      */
  PEER_DOWN_REMOTE_AS_CHANGE,      /* 'neighbor remote-as'                 */
  PEER_DOWN_LOCAL_AS_CHANGE,       /* 'neighbor local-as'                  */
  PEER_DOWN_CLID_CHANGE,           /* 'bgp cluster-id'                     */
  PEER_DOWN_CONFED_ID_CHANGE,      /* 'bgp confederation identifier'       */
  PEER_DOWN_CONFED_PEER_CHANGE,    /* 'bgp confederation peer'             */
  PEER_DOWN_RR_CLIENT_CHANGE,      /* 'neighbor route-reflector-client'    */
  PEER_DOWN_RS_CLIENT_CHANGE,      /* 'neighbor route-server-client'       */
  PEER_DOWN_UPDATE_SOURCE_CHANGE,  /* 'neighbor update-source'             */
  PEER_DOWN_AF_ACTIVATE,           /* 'neighbor activate'                  */
  PEER_DOWN_GROUP_BIND,            /* 'neighbor peer-group'                */
  PEER_DOWN_GROUP_UNBIND,          /* 'no neighbor peer-group'             */
  PEER_DOWN_DONT_CAPABILITY,       /* 'neighbor dont-capability-negotiate' */
  PEER_DOWN_OVERRIDE_CAPABILITY,   /* 'neighbor override-capability'       */
  PEER_DOWN_STRICT_CAP_MATCH,      /* 'neighbor strict-capability-match'   */
  PEER_DOWN_CAPABILITY_CHANGE,     /* 'neighbor capability'                */
  PEER_DOWN_PASSIVE_CHANGE,        /* 'neighbor passive'                   */
  PEER_DOWN_MULTIHOP_CHANGE,       /* 'neighbor multihop'                  */
  PEER_DOWN_AF_DEACTIVATE,         /* 'no neighbor activate'               */
  PEER_DOWN_PASSWORD_CHANGE,       /* password changed                     */
  PEER_DOWN_ALLOWAS_IN_CHANGE,     /* allowas-in change                    */

  /* Other actions that cause a session to be reset
   */
  PEER_DOWN_USER_SHUTDOWN,         /* 'neighbor shutdown'               */
  PEER_DOWN_USER_RESET,            /* 'clear ip bgp'                    */
  PEER_DOWN_NEIGHBOR_DELETE,       /* neighbor delete                   */

  PEER_DOWN_INTERFACE_DOWN,        /* interface reported to be down     */

  /* Errors and problems that cause a session to be reset
   */
  PEER_DOWN_MAX_PREFIX,            /* max prefix limit exceeded         */

  PEER_DOWN_HEADER_ERROR,          /* error in BGP Message header       */
  PEER_DOWN_OPEN_ERROR,            /* error in BGP OPEN message         */
  PEER_DOWN_UPDATE_ERROR,          /* error in BGP UPDATE message       */
  PEER_DOWN_HOLD_TIMER,            /* HoldTimer expired                 */
  PEER_DOWN_FSM_ERROR,             /* error in FSM sequence             */
  PEER_DOWN_DYN_CAP_ERROR,         /* error in Dynamic Capability       */

  /* Things the far end can do to cause a session to be reset
   */
  PEER_DOWN_NOTIFY_RECEIVED,       /* notification received             */
  PEER_DOWN_CLOSE_SESSION,         /* tcp session close                 */
  PEER_DOWN_NSF_CLOSE_SESSION,     /* NSF tcp session close             */

  /* Number of down causes
   */
  PEER_DOWN_count
} ;

typedef enum PEER_DOWN peer_down_t ;

enum peer_cap_bits
{
  /* These are general peer capabilities
   */
  PEER_CAP_MP_EXT             = BIT( 0),
  PEER_CAP_AS4                = BIT( 1),
  PEER_CAP_RR                 = BIT( 2), /* Route Refresh               */
  PEER_CAP_GR                 = BIT( 3), /* Graceful Restart            */
  PEER_CAP_ORF                = BIT( 4), /* ORF of any sort             */
  PEER_CAP_DYNAMIC            = BIT( 5), /* "Current" Dynamic Caps.     */

  PEER_CAP_RR_old             = BIT(10), /* "old" Route Refresh         */
  PEER_CAP_ORF_pre            = BIT(12), /* pre-RFC ORF of any sort     */
  PEER_CAP_DYNAMIC_dep        = BIT(13), /* Deprecated Dynamic Caps.    */

  PEER_CAP_NONE               = BIT(15), /* No capabilities at all      */
};
typedef uint16_t peer_cap_bits_t ;      /* NB: <= 16 flags      */

#if 0
enum peer_cap_bits
{
  PEER_CAP_REFRESH_ADV        = BIT( 0), /* refresh advertised          */
  PEER_CAP_REFRESH_OLD_RCV    = BIT( 1), /* refresh old received        */
  PEER_CAP_REFRESH_NEW_RCV    = BIT( 2), /* refresh rfc received        */
  PEER_CAP_DYNAMIC_DEP_ADV    = BIT( 3), /* deprecated dynamic advertised */
  PEER_CAP_DYNAMIC_DEP_RCV    = BIT( 4), /* deprecated dynamic received */
  PEER_CAP_DYNAMIC_ADV        = BIT( 5), /* dynamic advertised          */
  PEER_CAP_DYNAMIC_RCV        = BIT( 6), /* dynamic received            */
  PEER_CAP_RESTART_ADV        = BIT( 7), /* restart advertised          */
  PEER_CAP_RESTART_RCV        = BIT( 8), /* restart received            */
  PEER_CAP_AS4_ADV            = BIT( 9), /* as4 advertised              */
  PEER_CAP_AS4_RCV            = BIT(10), /* as4 received                */

  PEER_CAP_NO_MP_ADV          = BIT(12), /* no MP CAP advertised        */
  PEER_CAP_NO_MP_RCV          = BIT(13), /* no MP CAP received          */

  PEER_CAP_NONE_ADV           = BIT(14), /* none received               */
  PEER_CAP_NONE_RCV           = BIT(15), /* none received               */

  PEER_CAP_AS4_BOTH  = PEER_CAP_AS4_ADV | PEER_CAP_AS4_RCV,
};
typedef uint16_t peer_cap_bits_t ;      /* NB: <= 16 flags      */

#define PEER_CAP_AS4_USE(peer) \
  (((peer)->cap & PEER_CAP_AS4_BOTH) == PEER_CAP_AS4_BOTH)
#endif

enum peer_af_cap_bits
{
  /* These are afi/safi specific peer capabilities
   */
  PEER_AF_CAP_GR_CAN_PRESERVE      = BIT( 0), /* GR afi/safi received       */
  PEER_AF_CAP_GR_HAS_PRESERVED     = BIT( 1), /* GR afi/safi F-bit received */
#if 0

  PEER_AF_CAP_ORF_PFX_SM_pre       = BIT( 8), /* pre-RFC Send Mode          */
  PEER_AF_CAP_ORF_PFX_RM_pre       = BIT( 9), /* pre-RFC Receive Mode       */

  /* For af_caps_use: these bits are set if RFC or pre-RFC has been
   * negotiated -- uses pre-RFC ORF Type if PEER_AF_CAP_ORF_PFX_SM_pre is set.
   */
  PEER_AF_CAP_ORF_PFX_SM           = BIT( 0), /* RFC Send Mode              */
  PEER_AF_CAP_ORF_PFX_RM           = BIT( 1), /* RFC Receive Mode           */

  PEER_AF_CAP_ORF_PFX_SEND         = PEER_AF_CAP_ORF_PFX_SM,
  PEER_AF_CAP_ORF_PFX_RECV         = PEER_AF_CAP_ORF_PFX_RM
#endif
};
typedef uint8_t peer_af_cap_bits_t ;    /* NB: <= 8 flags       */

#if 0
enum peer_af_cap_bits
{
  PEER_AF_CAP_ORF_PFX_OUT_NEG      = BIT( 0), /* sending negotiated         */
  PEER_AF_CAP_ORF_PFX_IN_NEG       = BIT( 1), /* receiving negotiated       */

  PEER_AF_CAP_RESTART_RCV          = BIT( 2), /* GR afi/safi received       */
  PEER_AF_CAP_RESTART_PRESERVE_RCV = BIT( 3), /* GR afi/safi F-bit received */

  PEER_AF_CAP_ORF_PFX_SM_RFC_ADV   = BIT( 4), /* RFC advertised             */
  PEER_AF_CAP_ORF_PFX_RM_RFC_ADV   = BIT( 5), /* RFC advertised             */
  PEER_AF_CAP_ORF_PFX_SM_RFC_RCV   = BIT( 6), /* RFC received               */
  PEER_AF_CAP_ORF_PFX_RM_RFC_RCV   = BIT( 7), /* RFC received               */
  PEER_AF_CAP_ORF_PFX_SM_PRE_ADV   = BIT( 8), /* pre-RFC advertised         */
  PEER_AF_CAP_ORF_PFX_RM_PRE_ADV   = BIT( 9), /* pre-RFC advertised         */
  PEER_AF_CAP_ORF_PFX_SM_PRE_RCV   = BIT(10), /* pre-RFC received           */
  PEER_AF_CAP_ORF_PFX_RM_PRE_RCV   = BIT(11), /* pre-RFC received           */
};
typedef uint16_t peer_af_cap_bits_t ;   /* NB: <= 16 flags      */
#endif

enum peer_flag_bits
{
  /* These are configuration flags, for general configuration stuff.
   *
   *   * PEER_FLAG_DONT_CAPABILITY
   *
   *     Turns off the sending of any capabilities.  This is historic, and
   *     provided because in the dim and distant past, some BGP implementations
   *     would fall over when presented with (some) capabilities.
   *
   *     In the absence of PEER_FLAG_OVERRIDE_CAPABILITY this implies that
   *     only IPv4 Unicast can be used.
   *
   *   * PEER_FLAG_OVERRIDE_CAPABILITY
   *
   *     If the peer does not send any MP-Ext capabilities, then this causes
   *     Quagga to assume that the peer supports all the afi/safi that the
   *     session is enabled for.
   *
   *     This is also historic, and provided to cope with pre-RFC2858
   *     Multiprotocol stuff -- before MP-Ext capabilities existed !
   *
   *  * PEER_STRICT_CAP_MATCH
   *
   *    Mutually exclusive with PEER_FLAG_OVERRIDE_CAPABILITY
   *                   and with PEER_FLAG_DONT_CAPABILITY.
   *
   *    Requires the far end to support all the capabilities this end does.
   */
  PEER_FLAG_SHUTDOWN                 = BIT( 0),
  PEER_FLAG_PASSIVE                  = BIT( 1),
  PEER_FLAG_DONT_CAPABILITY          = BIT( 2),
  PEER_FLAG_OVERRIDE_CAPABILITY      = BIT( 3),
  PEER_FLAG_STRICT_CAP_MATCH         = BIT( 4),
  PEER_FLAG_DYNAMIC_CAPABILITY       = BIT( 5),
  PEER_FLAG_DISABLE_CONNECTED_CHECK  = BIT( 6),
  PEER_FLAG_LOCAL_AS_NO_PREPEND      = BIT( 7),
};
typedef uint16_t peer_flag_bits_t ;     /* NB: <= 16 flags      */

enum peer_af_flag_bits
{
  /* These are configuration flags, for per afi/safi configuration stuff.
   */
  PEER_AFF_SEND_COMMUNITY           = BIT( 0),
  PEER_AFF_SEND_EXT_COMMUNITY       = BIT( 1),
  PEER_AFF_NEXTHOP_SELF             = BIT( 2),
  PEER_AFF_REFLECTOR_CLIENT         = BIT( 3), /* Route Reflector           */
  PEER_AFF_RSERVER_CLIENT           = BIT( 4), /* Route Server              */
  PEER_AFF_SOFT_RECONFIG            = BIT( 5),
  PEER_AFF_AS_PATH_UNCHANGED        = BIT( 6), /* transparent-as            */
  PEER_AFF_NEXTHOP_UNCHANGED        = BIT( 7), /* transparent-next-hop      */
  PEER_AFF_MED_UNCHANGED            = BIT( 8), /* transparent-med           */
  PEER_AFF_DEFAULT_ORIGINATE        = BIT( 9),
  PEER_AFF_REMOVE_PRIVATE_AS        = BIT(10),
  PEER_AFF_ALLOWAS_IN               = BIT(11),
  PEER_AFF_ORF_PFX_SM               = BIT(12), /* Prefix ORF Send Mode      */
  PEER_AFF_ORF_PFX_RM               = BIT(13), /* Prefix ORF Receive Mode   */
  PEER_AFF_NEXTHOP_LOCAL_UNCHANGED  = BIT(14),
} ;
typedef uint32_t peer_af_flag_bits_t ;  /* NB: <= 32 flags      */

enum peer_status_bits
{
  /* These are states of a peer.
   */
  PEER_STATUS_PREFIX_OVERFLOW   = BIT(0), /* prefix-overflow             */

  PEER_STATUS_NSF_MODE          = BIT(1), /* NSF aware peer              */
  PEER_STATUS_NSF_WAIT          = BIT(2), /* wait comeback peer          */
} ;
typedef uint16_t peer_status_bits_t ;   /* NB: <= 16 flags      */

enum peer_af_status_bits
{
  /* These are states of a given afi/safi, mostly while pEstablished.
   */
  PEER_STATUS_RUNNING           = BIT(0), /* session is up              */
  PEER_STATUS_DEFAULT_ORIGINATE = BIT(1), /* default-originate peer     */
  PEER_STATUS_EOR_SEND          = BIT(2), /* end-of-rib send to peer    */
  PEER_STATUS_EOR_RECEIVED      = BIT(3), /* end-of-rib received from peer */
  PEER_STATUS_ORF_PREFIX_SENT   = BIT(4), /* prefix-list send peer      */
  PEER_STATUS_ORF_WAIT_REFRESH  = BIT(5), /* wait refresh received peer */
  PEER_STATUS_PREFIX_THRESHOLD  = BIT(6), /* exceed prefix-threshold    */
  PEER_STATUS_PREFIX_LIMIT      = BIT(7), /* exceed prefix-limit        */
} ;
typedef uint16_t peer_af_status_bits_t ;        /* NB: <= 16 flags      */

enum peer_config_bits
{
  /* These record that certain configuration settings have been made.
   */
  PEER_CONFIG_WEIGHT            = BIT(0), /* Default weight.            */
  PEER_CONFIG_TIMER             = BIT(1), /* HoldTime and KeepaliveTime */
  PEER_CONFIG_CONNECT           = BIT(2), /* ConnectRetryTime           */
  PEER_CONFIG_MRAI              = BIT(3), /* MRAI                       */
} ;
typedef uint16_t peer_config_bits_t ;   /* NB: <= 16 flags      */


/*------------------------------------------------------------------------------
 * Each peer has a peer rib for each AFI/SAFI it is configured for.
 *
 * This refers to the bgp instance's RIB, and contains the adj_in and adj_out
 * for the peer.
 *
 * The peer_rib is pointed to by the bgp_peer structure.  When the peer is
 * active for the AFI/SAFI, the peer_rib is on the bgp_rib's peers list.
 */
typedef struct peer_rib peer_rib_t ;

typedef enum bgp_route_map_types bgp_route_map_types_t ;
enum bgp_route_map_types
{
  RMAP_IN       = 0,
  RMAP_OUT      = 1,
  RMAP_IMPORT   = 2,
  RMAP_EXPORT   = 3,
  RMAP_RS_IN    = 4,

  RMAP_COUNT    = 5,
} ;

typedef struct prefix_max  prefix_max_t ;
typedef struct prefix_max* prefix_max ;

struct prefix_max
{
  bool        set ;
  bool        warning ;

  uint        limit ;
  uint        threshold ;
  uint16_t    thresh_pc ;
  uint16_t    restart ;
} ;

struct peer_rib
{
  bgp_peer    peer ;                    /* parent peer                  */

  /* Each peer_rib is associated with the respective bgp->rib, for the
   * AFI/SAFI and rib_main or rib_rs
   */
  bgp_rib     rib ;

  /* When a peer_rib is enabled (ie the exchange of routes is enabled) the
   * peer_rib is associated with a bgp_rib_walker.
   *
   * The walker has two queues, one for peer_ribs which are in "update" state
   * and one for peer_ribs in "initial" state -- where "initial" state means
   * that the peer has just established, or is being route_refreshed, so is
   * being sent the initial state of the rib.
   *
   * When the peer_rib is in "update" state, it is attached to the bgp_rib's
   * walker, on its "update" list.
   *
   * When the peer_rib is in "initial" state, it may be attached to the
   * bgp_rib's walker, on its "initial" list, or it may be attached to some
   * other walker, on its "initial" list.
   *
   * The update_state signals which state the peer_rib is in.
   */
  bgp_rib_walker  walker ;

  struct dl_list_pair(peer_rib) walk_list ;

  /* General stuff for the peer re this qafx.
   */
  qafx_t      qafx ;
  rib_type_t  rib_type ;                /* Main or RS                   */

  prib_state_t update_state ;           /* initial or update            */

  bool        is_mpls ;

  bool        refresh ;

  bool        eor_required ;

  uint        lock;

  /* Per AF configuration and status flags.
   */
  peer_af_flag_bits_t   af_flags ;
  peer_af_status_bits_t af_status ;

  peer_af_cap_bits_t    af_caps_adv ;
  peer_af_cap_bits_t    af_caps_rcv ;
  peer_af_cap_bits_t    af_caps_use ;

  bgp_orf_cap_bits_t    af_orf_pfx_adv ;
  bgp_orf_cap_bits_t    af_orf_pfx_rcv ;
  bgp_orf_cap_bits_t    af_orf_pfx_use ;

  /* Where a peer is a member of a peer-group in a given AFI/SAFI, the
   * relevant bit is set in the peer->group_membership.  The af_group_member
   * is a copy of that bit.
   *
   * Where a peer is pEstablished (which means the session is sEstablished)
   * the af_session_up flag is set if the AFI/SAFI is now up.  The
   * af_session_up flag is false at all other times.
   *
   * NB: for a peer-group configuration af_group_member and af_session_up are
   *     *always* false.
   */
  bool        af_group_member ;
  bool        af_session_up ;

  /* allowas-in.
   */
  uint8_t     allowas_in ;

  /* NSF mode (graceful restart)
   */
  bool        nsf ;

  /* Prefix count and sent prefix count.
   */
  uint        pcount ;
  uint        scount ;

  /* Filters and route-maps.
    */
  access_list dlist[FILTER_MAX] ;       /* distribute-list.     */

  prefix_list plist[FILTER_MAX] ;       /* prefix-list.         */

  as_list     flist[FILTER_MAX] ;       /* filter-list          */

  route_map   rmap[RMAP_COUNT] ;        /* route-map            */

  route_map   us_rmap ;                 /* Unsuppress-map.      */

  route_map   default_rmap ;

  /* ORF Prefix-list
   */
  prefix_list orf_plist ;

  /* Max prefix count.
   */
  prefix_max_t pmax ;

  /* The peer's adj_in stuff for this qafx
   *
   * The adj_in are ihash by prefix_id_t, giving a route_info object for each
   * route received from the peer.  Those route_info objects are "owned" by
   * the peer, but are also referred to by the bgp_rib_node for the prefix
   * (where the route is not filtered out).
   *
   * Note that Main Peers and RS Clients contribute routes in both the Main
   * and the RS RIBs.  But only routes from the Main RIB are announced to Main
   * Peers, and only routes from the RS RIB are announced to RS Clients.
   *
   * If there are no RS clients, there is no RS RIB and the RS adj_in is empty.
   *
   * The adj_in entries are "route_info" objects.  Note that there are small
   * differences in what is stored in the route_info for the Main RIB and
   * what is stored in the route_info for the RS RIB.  In particular:
   *
   *
   */
  ihash_table     adj_in[rib_type_count] ;   /* route_info                   */

  struct dl_base_pair(route_info) stale_routes ;

  /* The peer's adj_out stuff for this qafx
   *
   * A Main Peer receives routes from the Main RIB.
   * An RS Client receives routes from the RS RIB.
   */
  pfifo_period_t  batch_delay ;
  pfifo_period_t  batch_delay_extra ;   /* maximum extra delay          */
  pfifo_period_t  announce_delay ;
  pfifo_period_t  mrai_delay ;          /* actual MRAI                  */
  pfifo_period_t  mrai_delay_left ;     /* actual MRAI - batch_delay    */

  qtime_mono_t    period_origin ;
  pfifo_period_t  now ;

  pfifo_period_t  t0 ;
  pfifo_period_t  tx ;

  ihash_table     adj_out ;             /* adj_out_ptr_t                */

  pfifo           fifo_batch ;          /* rf_act_batch         */
  pfifo           fifo_mrai ;           /* rf_act_mrai          */
  pfifo           announce_queue ;      /* rf_act_announce      */
  struct dl_base_pair(route_flux)
                  withdraw_queue ;      /* rf_act_withdraw      */

  vhash_table     attr_flux_hash ;

  attr_flux       eor ;                 /* End-of-RIB signal    */

  /* Scheduling the running of the dispatch "process", which is timer driven.
   *
   * Dispatches from the fifo_batch and fifo_mrai
   *
   */
  pfifo_period_t  dispatch_delay ;
  pfifo_period_t  dispatch_time ;

  qtimer          dispatch_qtr ;
} ;

/*------------------------------------------------------------------------------
 * The structure for each peer.
 *
 * Most bgp_peer structures are "real" peers, but each peer group uses one to
 * hold the group configuration, and each bgp instance uses one for static
 * routes etc.
 */
enum peer_type
{
  PEER_TYPE_REAL         = 0,           /* not group conf or peer_self */
  PEER_TYPE_GROUP_CONF   = 1,           /* peer-group conf             */
  PEER_TYPE_SELF         = 2,           /* holder of statics etc       */
} ;
typedef uint8_t peer_type_t ;           /* NB: <= 256 types (!) */

typedef struct peer bgp_peer_t ;

struct peer
{
  /* BGP structure.
   *
   * Peer structures are:
   *
   *   * PEER_TYPE_REAL    -- ordinary "real" peers
   *
   *                          Live on the bgp instance's a list of peers, and
   *                          in the peer index.
   *
   *                          A PEER_TYPE_REAL may be a member of a group, in
   *                          one or more afi/safi.
   *
   *   * PEER_TYPE_GROUP_CONF -- where the configuration of a group is stored.
   *
   *                          The parent peer_group structure points here.
   *
   *                          The pointer to the bgp instance is a duplicate
   *                          of the pointer in the peer_group.
   *
   *   * PEER_TYPE_SELF    -- one per bgp instance, for static routes etc.
   */
  bgp_inst      bgp;

  peer_type_t   type ;
  qafx_set_t    group_membership ;

  /* State of the peer
   */
  bgp_peer_state_t state ;
  bool             clearing ;

  bool          down_pending ;

  /* reference count, primarily to allow bgp_process'ing of route_node's
   * to be done after a struct peer is deleted.
   *
   * named 'lock' for hysterical reasons within Quagga.
   */
  uint          lock;

  /* BGP peer group.
   *
   *   * PEER_TYPE_REAL    -- ordinary "real" peers
   *
   *     A peer may be a member of at most one group.  A peer is bound to to a
   *     group on a per AFI/SAFI basis.  The first time it is bound to a group,
   *     the group pointer and the group_membership bit are set.  The last time
   *     the peer is unbound from a group, the pointer is unset.
   *
   *     Some group properties apply to the peer in general, others apply only
   *     to the AFI/SAFI for which the peer is bound to the group.
   *
   *   * PEER_TYPE_GROUP_CONF
   *
   *     The group pointer points to the parent group.
   *
   *   * PEER_TYPE_SELF
   *
   *     Never a group member, so this is always NULL.
   */
  peer_group group ;

  /* Peer's AS numbers.
   *
   *   peer->as         -- neighbor remote-as
   *
   *                       The OPEN received from the neighbor must have this
   *                       as the 'My AS'.
   *
   *                       The peer-sort will be:
   *
   *                         iBGP:   if peer->as == bgp->as
   *
   *                         CONFED: if peer->as is any of the
   *                                           bgp confederation peers (if any)
   *
   *                         eBGP:   otherwise
   *
   *   peer->local_as   -- our (true) ASN for this peering.
   *
   *                       With no CONFED this is a copy of bgp->as
   *
   *                       With CONFED this depends on the peer->sort:
   *
   *                         - for eBGP:  copy of bgp->confed_id
   *
   *                         - otherwise: copy of bgp->as
   *
   *                       ... ie: bgp->as is the ASN for talking to peers
   *                               within the CONFED, and is the Member AS
   *
   *                               bgp->confed_id is the ASN for talking to
   *                               anyone outside the CONFED.
   *
   *   peer->change_local_as  -- set when we are pretending that a previous
   *                             ASN still exists.
   *
   *                       for *true* eBGP (ie not different CONFED Member AS)
   *                       we can pretend that the 'change_local_as' AS sits
   *                       between us (peer->local_as) and the peer.
   *
   *                       This allows the peer to believe that they are
   *                       peering with 'change_local_as'.
   *
   * The OPEN sent to the the peer will contain peer->local_as, unless
   * peer->change_local_as is set, in which case it contains that.
   */
  as_t as ;
  as_t local_as ;
  as_t change_local_as ;

  /* The sort of peer depends on the ASN of the peer, our ASN, CONFED
   * stuff etc.
   */
  bgp_peer_sort_t  sort ;

  /* Router ID's
   *
   *   peer->remote_id    -- BGP Id from the OPEN received.
   *
   *   peer->local_id     -- BGP Id in the OPEN sent == bgp router-id A.B.C.D
   */
  in_addr_t remote_id;
  in_addr_t local_id;

  /* Peer RIBS -- contain adj_in and adj_out.
   */
  peer_rib  prib[qafx_count];

  /* Packet receive and send buffers -- for PEER_TYPE_REAL.
   */
  stream      ibuf;

  stream_fifo obuf_fifo;
  stream      work;

  /* Peer index, used for dumping TABLE_DUMP_V2 format -- for PEER_TYPE_REAL
   */
  uint16_t table_dump_index;

  /* Peer information
   *
   * NB: the su_name is IPv4 if the original name was IPv4-Mapped !!  TODO !!!
   */
  sockunion  su_name ;          /* Name of the peer is address of same  */
  char *host;                   /* Printable address of the peer.       */

  bgp_peer_index_entry  peer_ie ;
  bgp_session  session ;        /* Current session                      */

  bgp_peer_session_state_t session_state ;




  ttl_t ttl ;                   /* TTL of TCP connection to the peer.   */
  bool  gtsm ;                  /* ttl set by neighbor xxx ttl_security */

  char *desc;                   /* Description of the peer.             */
  uint16_t port;                /* Destination port for peer            */
  time_t uptime;                /* Last Up/Down time                    */
  time_t readtime;              /* Last read time                       */
  time_t resettime;             /* Last reset time                      */

  uint  ifindex;                /* ifindex of the BGP connection.       */
  char* ifname;                 /* bind interface name.                 */
  char* update_if;
  sockunion update_source;

  struct zlog *log;

  sockunion  su_local;          /* Sockunion of local address.          */
  sockunion  su_remote;         /* Sockunion of remote address.         */
  bool       shared_network;    /* Is this peer shared same network.    */
  bgp_nexthop_t nexthop;        /* Nexthop                              */

  /* Peer address family state and negotiation.
   *
   *   * af_configured -- the set of afi/safi for which the peer or peer-group
   *                      is configured.
   *
   *     There will be a prib[qafx] for each one.
   *
   *     For a real peer:
   *
   *       When the peer is configured for a given qafx:
   *
   *         * there is always a rib_main bgp_rib -- for main and RS client
   *           peers.
   *
   *         * if there is at least one RS client, there is a rib_rs bgp_rib.
   *
   *       Unless BGP_FLAG_NO_DEFAULT_IPV4, configuring a peer by:
   *
   *         neighbor nnn remote-as aaa
   *         neighbor nnn peer-group ggg
   *
   *       implicitly configures IPv4 Unicast.
   *
   *       An afi/safi is configured for the peer by:
   *
   *         neighbor nnn activate
   *         neighbor nnn peer-group ggg
   *
   *       in the required afi/safi -- or IPv4 Unicast if in no explicit
   *       afi/safi (address-family).
   *
   *       NB: in the case of "neighbor nnn peer-group ggg":
   *
   *         * the peer-group must exist and must be configured for the
   *           afi/safi in question.
   *
   *         * if the peer does not exist, then this can bring the peer
   *           into existence, provided the group has a remote-as specified.
   *
   *       "no neighbor nnn activate" has the effect of discarding all the
   *       peer's configuration for the afi/safi.
   *
   *       See notes on af_enabled for further magic and the effect on any
   *       session for the peer.
   *
   *     For a peer-group:
   *
   *       Configuring a peer-group for a new afi/safi simply has the effect
   *       of creating the required prib[qafx], in default state.
   *
   *       Configuring a peer-group for a new afi/safi has no effect on any
   *       peers associated with the peer-group.  The association is from the
   *       peer to the peer-group on a per afi/safi basis: configuring a new
   *       afi/safi for the peer-group does not create any new associations.
   *
   *       Unless BGP_FLAG_NO_DEFAULT_IPV4, configuring a peer-group by:
   *
   *         neighbor ggg peer-group
   *
   *       implicitly configures IPv4 Unicast.
   *
   *       An afi/safi is configured for the peer-group by:
   *
   *         neighbor ggg activate
   *
   *       in the required afi/safi -- or IPv4 Unicast if in no explicit
   *       afi/safi (address-family).
   *
   *       "no neighbor nnn activate" has the effect of discarding all the
   *       peer-group's configuration for the afi/safi, BUT is invalid if any
   *       peer is associated with the peer-group in that afi/safi.
   *
   * For (real) peers there are:
   *
   *   * af_enabled    -- the set of afi/safi which should be enabled.
   *
   *     This specifies which afi/safi a session should be enabled and started
   *     (or restarted).  This will always be a subset of af_configured.
   *
   *     A peer may be disabled by:
   *
   *       * global "is reading configuration" flag
   *
   *       * PEER_FLAG_SHUTDOWN  -- which disables all afi/safi
   *
   *         see "neighbor nnn/ggg shutdown" and "no neighbor nnn/ggg shutdown"
   *
   *       * PEER_STATUS_PREFIX_OVERFLOW -- which disables all afi/safi
   *
   *         which is cleared when the timer expires or is cleared.
   *
   *     When a reason for being disabled is changed, af_enabled is
   *     recalculated, if it changes, then the session (if any) needs to be
   *     started, restarted or stopped.
   *
   * The following are valid for a real peer while it is pEnabled or
   * pEstablished:
   *
   *   * af_adv        -- the set of afi/safi which were actually advertised
   *                      when the current session was enabled, or were
   *                      implied or have been forced.
   *
   *                      Generally this is a copy of af_enabled made at the
   *                      time the session was enabled (or re-enabled).
   *
   *                      PEER_CAP_MP_EXT is set in cap_adv if afi/safi were
   *                      actually advertised.  Otherwise, the sending of
   *                      capabilities was disabled either by configuration
   *                      (PEER_FLAG_DONT_CAPABILITY) or because peer rejected
   *                      the sending of capabilities.
   *
   *   * af_rcv        -- the set of afi/safi received in incoming OPEN or
   *                      implied by it.
   *
   *                      This is cleared when pEnabled and set when
   *                      pEstablished.
   *
   *                      If any MP-Ext were received, this will be the
   *                      afi/safi received and known to us -- configured or
   *                      otherwise.
   *
   *                      Otherwise, this will be IPv4 Unicast.
   *
   *                      Note that PEER_FLAG_OVERRIDE_CAPABILITY does NOT
   *                      affect what is recorded here.
   *
   *   * af_use        -- the set of afi/safi which is negotiated.
   *
   *                      This is cleared when pEnabled and set when
   *                      pEstablished.
   *
   *                      This is the intersection of the af_adv af_rcv.
   *
   *                      Except when PEER_FLAG_OVERRIDE_CAPABILITY and
   *                      no MP-Ext were received, in which case it is the
   *                      same as af_adv !
   *
   * Finally:
   *
   *   * af_running    -- the set of afi/safi for which a session is currently
   *                      running.
   *
   *                      This is empty unless is pEstablished.
   *
   *                      This is set to af_use when becomes pEstablished.
   *
   *                      When a session for an afi/safi is terminated, it
   *                      is knocked out of the af_running.  (Generally this
   *                      is shortly before goes pDown -- but individual
   *                      afi/safi may be terminated and the session remain.)
   */
  qafx_set_t af_configured ;

  qafx_set_t af_enabled ;       /* what we want session to carry        */

  qafx_set_t af_adv ;           /* what we advertised                   */
  qafx_set_t af_rcv ;           /* what we received                     */
  qafx_set_t af_use ;           /* what we may use                      */

  qafx_set_t af_running ;       /* what current session carries         */

  /* Capability flags (reset in bgp_stop) -- peer in general.
   *
   *   * caps_adv   -- the set of capabilities actually advertised.
   *
   *                   This is set when pEnabled but may be changed when goes
   *                   pEstablished -- if sending capabilities had to be
   *                   suppressed because the far end refused them.
   *
   *                   PEER_CAP_NONE is set iff PEER_FLAG_DONT_CAPABILITY.
   *                   (It is NOT set if capabilities were suppressed.)
   *
   *   * caps_rcv   -- the set of capabilities actually received.
   *
   *                   PEER_CAP_NONE is set if no capability option is received.
   *
   *   * caps_use   -- the set of capabilities that have been negotiated.
   *
   *                   PEER_CAP_NONE is set if capabilities had to be
   *                   suppressed (because the far end refused them.)
   */
  peer_cap_bits_t caps_adv ;
  peer_cap_bits_t caps_rcv ;
  peer_cap_bits_t caps_use ;

  /* Global configuration flags.
   */
  peer_flag_bits_t flags;

  /* MD5 password
   */
  char* password;

  /* Peer status flags.
   */
  peer_status_bits_t sflags;

  /* Values for which we need to know whether an explicit value is set,
   * or the (current) default applies.
   *
   *   * weight is special, and is valid at all times.
   *
   *     - if PEER_CONFIG_WEIGHT is set, the weight has been explicity set
   *       for this peer or group.
   *
   *       If a group does not have an explicit weight, then it inherits from
   *       the bgp instance.
   *
   *       Note that where a peer does not have an explicit weight, then if
   *       it is a member of a group, it inherits the group's weight (which
   *       may be inherited from the bgp instance).
   *
   *   *
   */
  peer_config_bits_t config;

  uint16_t weight ;             /* valid at all times                   */

  uint32_t config_holdtime;     /* valid iff PEER_CONFIG_TIMER          */
  uint32_t config_keepalive;    /* valid iff PEER_CONFIG_TIMER          */
  uint32_t config_connect;      /* valid iff PEER_CONFIG_CONNECT        */
  uint32_t config_mrai ;        /* valid iff PEER_CONFIG_MRAI           */

  /* Current holdtime and keepalive
   *
   *   * for (real) peer which is pEnabled
   *
   *     this is the value which is currently being advertised.
   *
   *   * for (real) peer which is pEstablished
   *
   *     this is the value which has been negotiated and is in effect.
   *
   *   * otherwise -- see peer_get_holdtime() and peer_get_keepalive().
   */
  uint32_t current_holdtime ;
  uint32_t current_keepalive ;

  /* Timer values.
   */
  uint32_t v_start;

  uint32_t v_asorig;
  uint32_t v_pmax_restart;
  uint32_t v_gr_restart;

  /* Threads
   */
  struct thread *t_pmax_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;

  /* BGP state count
   */
  uint32_t established;
  uint32_t dropped;

#if 0
  /* Update/Withdraw lists, Attribute Hash and synctime
   */
  bgp_adv_base_t  adv_fifo[bgp_adv_count][qafx_count] ;

  vhash_table     adv_attr_hash[qafx_count] ;
#endif
  time_t synctime;

  bool   do_updates ;

#define MAXIMUM_PREFIX_THRESHOLD_DEFAULT 75

  /* peer reset cause
   */
  peer_down_t last_reset;

  bgp_notify notification ;

#if 0
  /* The kind of route-map Flags.                       */
  u_int16_t rmap_type;
#define PEER_RMAP_TYPE_IN             (1 << 0) /* neighbor route-map in       */
#define PEER_RMAP_TYPE_OUT            (1 << 1) /* neighbor route-map out      */
#define PEER_RMAP_TYPE_NETWORK        (1 << 2) /* network route-map           */
#define PEER_RMAP_TYPE_REDISTRIBUTE   (1 << 3) /* redistribute route-map      */
#define PEER_RMAP_TYPE_DEFAULT        (1 << 4) /* default-originate route-map */
#define PEER_RMAP_TYPE_NOSET          (1 << 5) /* not allow to set commands   */
#define PEER_RMAP_TYPE_IMPORT         (1 << 6) /* neighbor route-map import   */
#define PEER_RMAP_TYPE_EXPORT         (1 << 7) /* neighbor route-map export   */
#define PEER_RMAP_TYPE_RS_IN          (1 << 8) /* neighbor route-map rs-in    */
#endif
} ;


#define BGP_TIMER_ON(T,F,V)                     \
  do {                                          \
    if (!(T) && (peer->state != bgp_pDeleting)) \
      THREAD_TIMER_ON(master,(T),(F),peer,(V)); \
  } while (0)

#define BGP_TIMER_OFF(T)                        \
  do {                                          \
    if (T)                                      \
      THREAD_TIMER_OFF(T);                      \
  } while (0)

#if 0
#define BGP_EVENT_ADD(P,E)                      \
  do {                                          \
    if ((P)->state != bgp_pDeleting)            \
      thread_add_event (master, bgp_event, (P), (E)); \
  } while (0)

#define BGP_EVENT_FLUSH(P)                      \
  do {                                          \
    assert (peer);                              \
    thread_cancel_event (master, (P));          \
  } while (0)

/* Prototypes. */
extern int bgp_event (struct thread *);
extern int bgp_stop (struct peer *peer);
#if 0
extern void bgp_timer_set (struct peer *);
#endif
extern void bgp_fsm_change_status (struct peer *peer, int status);

#endif

extern const char *peer_down_str[];

/*==============================================================================
 *
 */
extern bgp_peer bgp_peer_new (bgp_inst bgp, peer_type_t type);
extern bgp_peer bgp_peer_create (sockunion su, bgp_inst bgp,
                                                   as_t remote_as, qafx_t qafx);
extern bgp_peer bgp_peer_lock (bgp_peer peer) ;
extern bgp_peer bgp_peer_unlock (bgp_peer peer) ;
extern bgp_peer bgp_peer_delete (bgp_peer peer);
extern sockunion bgp_peer_get_ifaddress(bgp_peer peer, const char* ifname,
                                                               sa_family_t af) ;

extern void peer_rsclient_unset(bgp_peer peer, qafx_t qafx, bool keep_export) ;
extern void peer_clear (bgp_peer);
extern bgp_ret_t peer_clear_soft (bgp_peer peer, qafx_t qafx,
                                                       bgp_clear_type_t stype) ;

extern bgp_peer peer_lookup (bgp_inst bgp, sockunion su) ;
extern bgp_peer peer_lookup_vty (vty vty, bgp_inst bgp, const char* peer_str,
                                                                  qafx_t qafx) ;
extern int peer_cmp (bgp_peer p1, bgp_peer p2) ;
extern char* peer_uptime (time_t, char*, size_t);

extern peer_group peer_group_lookup (bgp_inst bgp, const char* name);
extern peer_group peer_group_get (bgp_inst bgp, const char* name);
extern bgp_ret_t peer_group_delete (peer_group group) ;
extern int peer_group_cmp (peer_group g1, peer_group g2) ;

extern int peer_activate(bgp_peer peer, qafx_t qafx);
extern int peer_deactivate(bgp_peer peer, qafx_t qafx) ;

extern bgp_peer_sort_t peer_sort (bgp_peer peer);
extern bool peer_sort_set(bgp_peer peer, bgp_peer_sort_t sort) ;

extern bgp_ret_t peer_remote_as (bgp_inst bgp, sockunion su, as_t* p_as,
                                                                  qafx_t qafx) ;
extern bgp_ret_t peer_group_remote_as (bgp_inst bgp, const char* name,
                                                                   as_t* p_as) ;
extern bgp_ret_t peer_group_remote_as_delete (peer_group);

extern bgp_ret_t peer_flag_set (bgp_peer peer, peer_flag_bits_t flag) ;
extern bgp_ret_t peer_flag_unset (bgp_peer peer, peer_flag_bits_t flag) ;

extern bgp_ret_t peer_af_flag_set(bgp_peer peer, qafx_t qafx,
                                                     peer_af_flag_bits_t flag) ;
extern bgp_ret_t peer_af_flag_unset(bgp_peer peer, qafx_t qafx,
                                                     peer_af_flag_bits_t flag) ;
extern bgp_ret_t peer_af_flag_modify(bgp_peer peer, qafx_t qafx,
                                           peer_af_flag_bits_t flag, bool set) ;

extern bgp_ret_t peer_group_bind (bgp_inst, sockunion, peer_group,
                                                                qafx_t, as_t*) ;
extern bgp_ret_t peer_group_unbind (bgp_peer, peer_group, qafx_t) ;

extern void bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag);
extern void bgp_peer_enable(bgp_peer peer);
extern void bgp_peer_down(bgp_peer peer, peer_down_t why_down) ;
extern void bgp_peer_down_error(bgp_peer peer,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;
extern void bgp_peer_down_error_with_data (bgp_peer peer,
                              bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                             const byte* data, size_t datalen) ;

extern uint peer_get_keepalive(bgp_peer peer, bool current) ;
extern uint peer_get_holdtime(bgp_peer peer, bool current) ;
extern uint peer_get_connect_retry_time(bgp_peer peer) ;
extern uint peer_get_accept_retry_time(bgp_peer peer) ;
extern uint peer_get_open_hold_time(bgp_peer peer) ;
extern uint peer_get_mrai(bgp_peer peer) ;

#if 0
extern void bgp_withdraw_schedule(bgp_peer peer) ;
#endif

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Return true iff given peer is activated for the given qafx.
 */
Inline bool
peer_family_is_active(bgp_peer peer, qafx_t qafx)
{
  return (peer->prib[qafx] != NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Return address of peer_rib for the given peer for the given qafx.
 *
 * Returns:  address of peer_rib
 *       or: NULL if peer not activated for the given qafx
 */
Inline peer_rib
peer_family_prib(bgp_peer peer, qafx_t qafx)
{
  return peer->prib[qafx] ;
} ;

#endif /* _QUAGGA_BGP_PEER_H */

