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

typedef enum PEER_DOWN peer_down_t ;
enum PEER_DOWN
{
  PEER_DOWN_NULL        =  0,      /* Not a PEER_DOWN                      */

  /* Session taken down at this end for some unspecified reason
   */
  PEER_DOWN_UNSPECIFIED,

  PEER_DOWN_first       =  1,      /* first not-NULL                       */

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
  PEER_DOWN_count,
  PEER_DOWN_last        = PEER_DOWN_count - 1,
} ;

typedef enum peer_flag peer_flag_t ;
enum peer_flag
{
//  PEER_FLAG_SHUTDOWN                 = BIT( 0),
  PEER_FLAG_PASSIVE,
  PEER_FLAG_DONT_CAPABILITY,
  PEER_FLAG_OVERRIDE_CAPABILITY,
  PEER_FLAG_STRICT_CAP_MATCH,
  PEER_FLAG_DYNAMIC_CAPABILITY,
  PEER_FLAG_DISABLE_CONNECTED_CHECK,
  PEER_FLAG_LOCAL_AS_NO_PREPEND,
};

enum peer_status_bits
{
  /* These are states of a peer.
   */
  PEER_STATUS_PREFIX_OVERFLOW   = BIT(0), /* prefix-overflow             */

  PEER_STATUS_NSF_MODE          = BIT(1), /* NSF aware peer              */
  PEER_STATUS_NSF_WAIT          = BIT(2), /* wait comeback peer          */
} ;
typedef uint16_t peer_status_bits_t ;   /* NB: <= 16 flags      */

enum peer_config_bits
{
  /* These record that certain configuration settings have been made.
   */
  PEER_CONFIG_WEIGHT            = BIT(0), /* Default weight.            */
  PEER_CONFIG_TIMER             = BIT(1), /* HoldTime and KeepaliveTime */
  PEER_CONFIG_MRAI              = BIT(2), /* MRAI                       */
  PEER_CONFIG_CONNECT_RETRY     = BIT(3), /* cops->connect_retry_secs   */

  PEER_CONFIG_INTERFACE         = BIT(8), /* neighbor xx interface      */

  /* These are all overridden by group configuration.
   */
  PEER_CONFIG_GROUP_OVERRIDE    = PEER_CONFIG_WEIGHT
                                | PEER_CONFIG_TIMER
                                | PEER_CONFIG_MRAI
                                | PEER_CONFIG_CONNECT_RETRY,
} ;
typedef uint16_t peer_config_bits_t ;   /* NB: <= 16 flags      */

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
  PEER_AFF_NEXTHOP_LOCAL_UNCHANGED  = BIT(12),
} ;
typedef uint32_t peer_af_flag_bits_t ;  /* NB: <= 32 flags      */

enum peer_af_status_bits
{
  /* These are states of a given afi/safi, mostly while pEstablished.
   */
  PEER_AFS_DISABLED             = BIT( 0), /* configured, but disabled  */
  PEER_AFS_RUNNING              = BIT( 1), /* session is up             */
  PEER_AFS_DEFAULT_ORIGINATE    = BIT( 2), /* default-originate peer    */
  PEER_AFS_EOR_SENT             = BIT( 3), /* end-of-rib send to peer   */
  PEER_AFS_EOR_RECEIVED         = BIT( 4), /* end-of-rib received from peer */
  PEER_AFS_PREFIX_THRESHOLD     = BIT( 5), /* exceed prefix-threshold   */
  PEER_AFS_PREFIX_LIMIT         = BIT( 6), /* exceed prefix-limit       */

  /* These are afi/safi specific peer capabilities
   */
  PEER_AFS_GR_CAN_PRESERVE      = BIT( 7), /* GR afi/safi received       */
  PEER_AFS_GR_HAS_PRESERVED     = BIT( 8), /* GR afi/safi F-bit received */

  /* For Prefix ORF:
   *
   *   _CAN_SEND => we expressed the wish, and we have received the go-ahead
   *   _SENT     => we have sent the Prefix ORF.
   *
   *   _EXPECT   => we expressed willing-ness, and received the wish to send
   *   _WAIT     => waiting to receive the Prefix ORF (just established)
   */
  PEER_AFS_ORF_PFX_CAN_SEND     = BIT( 9), /* Prefix ORF Send Mode      */
  PEER_AFS_ORF_PFX_SENT         = BIT(10), /* prefix-list send peer     */

  PEER_AFS_ORF_PFX_MAY_RECV     = BIT(11), /* Prefix ORF Receive Mode   */
  PEER_AFS_ORF_PFX_WAIT         = BIT(12), /* wait refresh received peer */
} ;
typedef uint16_t peer_af_status_bits_t ;   /* NB: <= 16 flags           */

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

  /* Per AF configuration flags and status bits.
   */
  peer_af_flag_bits_t   af_flags ;
  peer_af_status_bits_t af_status ;

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
  /* Parent bgp instance -- all types of peer have a parent.
   */
  bgp_inst      bgp;

  /* Peer structures are:
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
  peer_type_t   type ;
  qafx_set_t    group_membership ;

  /* State of the peer
   */
  bgp_peer_state_t  state ;

  bool          clearing ;

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

  /* The sort of peer depends on the ASN of the peer, our ASN, CONFED
   * stuff etc.
   *
   *   iBGP: if peer->args.remote_as == bgp->my_as -- whether or not that
   *         is a confederation member AS.
   *
   *   cBGP: if peer->args.remote_as is one of a bgp confederation peer
   *
   *   eBGP:   otherwise
   */
  bgp_peer_sort_t  sort ;

  /* Peer information
   *
   * NB: the su_name is IPv4 if the original name was IPv4-Mapped !!  TODO !!!
   */
  sockunion su_name ;           /* Name of the peer is address of same  */
  char*     host ;              /* Printable address of the peer.       */
  char*     desc ;              /* Description of the peer.             */

  bgp_peer_index_entry  peer_ie ;
  bgp_session  session ;        /* Current session                      */

  bgp_peer_session_state_t session_state ;

  time_t uptime;                /* Last Up/Down time                    */
  time_t readtime;              /* Last read time                       */
  time_t resettime;             /* Last reset time                      */

  struct zlog *log;

  bool       shared_network;    /* Is this peer shared same network.    */
  bgp_nexthop_t nexthop;        /* Nexthop                              */

  /* peer reset cause
   */
  peer_down_t last_reset;

  bgp_notify notification ;

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
   *   * args.can_af    -- the set of afi/safi which are enabled.
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
   *         [Keeps track of exceeding the threshold and the limit on a per
   *          afi/safi basis... but as soon as exceeds limit on one family,
   *          brings the entire session down, setting peer level flag.]
   *
   *     An address family may be disabled by:
   *
   *       * PEER_AFS_DISABLED   -- so can set up an address family initially
   *                                disabled, and then enable.  Can also
   *                                disable an address family, reconfigure and
   *                                then re-enable.
   *
   *     When a reason for being disabled is changed, af_enabled is
   *     recalculated, if it changes, then the session (if any) needs to be
   *     started, restarted or stopped.
   *
   * The following are valid for a real peer while it is pEnabled or
   * pEstablished:
   *
   *   * af_running    -- the set of afi/safi for which a session is currently
   *                      running.
   *
   *                      This is empty unless is pEstablished.
   *
   *                      This is set when becomes pEstablished.
   *
   *                      When a session for an afi/safi is terminated, it
   *                      is knocked out of the af_running.  (Generally this
   *                      is shortly before goes pDown -- but individual
   *                      afi/safi may be terminated and the session remain.)
   */
  qafx_set_t af_configured ;
  qafx_set_t af_running ;       /* what current session carries         */

  /* Peer RIBS -- contain adj_in and adj_out.
   */
  peer_rib  prib[qafx_count];

  /* Peer's configured session arguments
   *
   *   * local_as               -- our ASN for this peering -- see below
   *   * local_id               -- as set by configuration or otherwise
   *
   *     The local_as is what we say in any OPEN we send, and for:
   *
   *       - iBGP == bgp->my_as
   *       - cBGP == bgp->my_as
   *       - eBGP == bgp->ebgp_as -- *except* when is change_local_as
   *
   *   * remote_as              -- as set by configuration
   *   * remote_id              -- as received in most recent session
   *
   *     The OPEN received must carry the expected remote_as.
   *
   *   * can_capability         -- ! PEER_FLAG_DONT_CAPABILITY
   *
   *     Nearly always true !!  Purpose is *deeply* historic... provided to
   *     cope with pre-RFC2842 peers who crash if given Capability Options !
   *
   *     In the absence of cap_af_override this implies that only IPv4 Unicast
   *     can be used, and all other capabilities are ignored.
   *
   *     This is not set if is cap_strict.
   *
   *   * can_mp_ext             -- true
   *
   *     When a set of session arguments are created, this will be overridden
   *     by !can_capability.
   *
   *     When open_sent arguments are constructed, this may be suppressed by
   *     cap_suppressed.
   *
   *   * can_as4                -- !bm->as2_speaker
   *
   *     When a set of session arguments are created, this will be overridden
   *     by !can_capability.
   *
   *     When open_sent arguments are constructed, this may be suppressed by
   *     cap_suppressed.
   *
   *   * cap_suppressed         -- N/A
   *
   *   * cap_af_override        -- see PEER_FLAG_OVERRIDE_CAPABILITY
   *
   *     If the peer does not send any MP-Ext capabilities, then this causes
   *     Quagga to assume that the peer supports all the afi/safi that the
   *     session is enabled for.
   *
   *     This is historic, and provided to cope with pre-RFC2858 Multiprotocol
   *     stuff -- before MP-Ext capabilities existed !
   *
   *     This is not set if is cap_strict.
   *
   *   * cap_strict             -- PEER_FLAG_STRICT_CAP_MATCH
   *
   *     Requires the far end to support all the capabilities this end does.
   *
   *     This is not set if is cap_af_override or !can_capability.
   *
   *   * can_af                 -- for peer->args: the enabled address families
   *
   *     See notes above.
   *
   *     When creating a set of session arguments, the can_af will be masked
   *     down if !can_mp_ext, unless have cap_af_override.
   *
   * When creating a set of session arguments, the following will be suppressed
   * if !can_capability.  And when creating a set of arguments for open_sent,
   * these will be suppressed if cap_suppressed.
   *
   *   * can_rr                 -- bgp_form_both
   *
   *     We default to supporting both the RFC and the pre-RFC Route Refresh.
   *
   *     Could create an option to turn off one or both.
   *
   *   * gr.can                 -- BGP_FLAG_GRACEFUL_RESTART
   *   * gr.restarting          -- false
   *   * gr.restart_time        -- 0
   *   * gr.can_preserve        -- empty
   *   * gr.has_preserved       -- empty
   *
   *     These are set on the fly when a set of session arguments is created.
   *
   *   * can_orf                -- bgp_form_both
   *
   *     We default to supporting both the RFC and the pre-RFC ORF capability,
   *     and Prefix ORF types.
   *
   *   * can_orf_pfx[]          -- per "neighbor capability orf prefix-list"
   *
   *     For the peer->args we register only the RFC types.  As we construct
   *     arguments for session and for open_sent, will expand this to include
   *     the pre-RFC types -- where the pre-RFC capability is advertised.
   *
   *   * can_dynamic            -- false
   *   * can_dynamic_dep        -- false
   *
   * These are always relevant
   *
   *   * holdtime_secs          -- peer->config_holdtime
   *   * keepalive_secs         -- peer->config_keepalive
   */
  bgp_session_args_t  args ;            /* NB: embedded         */

  /* change_local_as is set when we are pretending that a previous ASN still
   * exists.
   *
   * For eBGP (not cBGP !) we pretend that the 'change_local_as' AS sits
   * between us (local_as) and the peer.  This allows the peer to believe that
   * they are peering with 'change_local_as' (as it was before).
   *
   * The args.local_as is set to change_local_as (not bgp->ebgp_as), because
   * that is the AS used for the session (and in the OPEN sent).
   */
  as_t          change_local_as ;
  bool          change_local_as_prepend ;

  /* Other flags
   */
  bool          disable_connected_check ;

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
   */
  peer_config_bits_t config;

  uint16_t      weight ;        /* valid at all times                   */

  uint          config_mrai ;   /* default unless PEER_CONFIG_MRAI      */

  /* The connection options include:
   *
   *   * su_remote              -- used by connect() and listen()
   *
   *                               copy of su_name (but could be something
   *                               else, eg a link-local address for the peer !
   *
   *   * su_local               -- "neighbor xx update-source <addr>" et al.
   *
   *   * port                   -- for connect() and listen()
   *
   *   * conn_let               -- generally true, once enabled XXX XXX XXX
   *
   *   * connect_retry_secs     -- per default, or otherwise
   *   * accept_retry_secs      -- per default, or otherwise
   *   * open_hold_secs         -- per default, or otherwise
   *
   *   * ttl                    -- "neighbor xx ebgp-multihop" etc.
   *   * gtsm                   -- "neighbor xx ttl-security hops" etc.
   *
   *   * password               -- "neighbor xx password"
   *
   *   * ifname                 -- "neighbor xx update-source <name>"
   *                               "neighbor xx interface <name>"
   *
   * The cops_set are the configuration options last passed to the session.
   */
  bgp_cops_t    cops ;

  /* Timer values.
   */
  uint32_t      v_start;

  uint32_t      v_asorig;
  uint32_t      v_pmax_restart;
  uint32_t      v_gr_restart;

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




  /* Packet receive and send buffers -- for PEER_TYPE_REAL.
   */
  stream      ibuf;

  stream_fifo obuf_fifo;
  stream      work;

  /* Peer index, used for dumping TABLE_DUMP_V2 format -- for PEER_TYPE_REAL
   */
  uint16_t table_dump_index;
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

extern bgp_ret_t peer_set_af(bgp_peer peer, qafx_t qafx, bool enable);
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

