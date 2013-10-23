/* BGP Peer Run -- header
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

#ifndef _QUAGGA_BGP_PRUN_H
#define _QUAGGA_BGP_PRUN_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_filter.h"

#include "lib/routemap.h"
#include "lib/plist.h"
#include "lib/filter.h"
#include "lib/vhash.h"
#include "lib/vty.h"
#include "lib/qfstring.h"


/*==============================================================================
 * States of Peer and Session
 */


/* The state of the peer -- strongly related to the state of the session !
 *
 *   1. pDown
 *
 *      All real peers start in this state.
 *
 *      This is the case while no address families are enabled, eg:
 *
 *        a. when a bgp_peer structure is first created.
 *
 *           Note that PEER_TYPE_GROUP_CONF and PEER_TYPE_SELF are permanently
 *           pDown.
 *
 *        b. not one address family is configured *and* enabled
 *
 *        c. peer is administratively down/disabled/deactivated
 *
 *        d. peer is waiting for route flap or other such timer before
 *           reawakening.
 *
 *      The peer-session states relate to the above as follows:
 *
 *        pssInitial -- case (a)
 *
 *        pssStopped -- all of the above
 *
 *                      NB: in pDown and pssStopped, the acceptor will be
 *                          running if the current cops allow.
 *
 *        all other states are IMPOSSIBLE
 *
 *      When at least one address family is enabled the peer can go pStarted,
 *      and a session will be started.
 *
 *   2. pStarted
 *
 *      This is the case when a message has been sent to the BGP engine to
 *      enable a new session, and is now waiting for the session to be
 *      established.
 *
 *      The session must be sUp.
 *
 *      If the Routeing Engine disables the session -> pLimping and sLimping
 *
 *      The BGP Engine may send event messages, which signal:
 *
 *        * feXxxxx, but not "stopped"    -> remains pStarted
 *
 *          the BGP Engine signals various events which do not stop it from
 *          trying to establish a session, but may be of interest.
 *
 *        * session is (now) sEstablished -> pEstablished
 *
 *        * feXxxxx, and "stopped"        -> pResetting (however briefly)
 *
 *      All other messages are discarded -- there should not be any.
 *
 *   3. pEstablished
 *
 *      Reaches this state from pStarted when a session becomes established.
 *
 *      The session must be sUp.
 *
 *      If the Routeing Engine disables the session -> pResetting/pssLimping.
 *
 *          The Routeing Engine sets the "down reason" etc. according to why
 *          the session is being disabled.  While pssLimping, this is
 *          provisional.  When a "stopped" event arrives, it may be found that
 *          the session stopped in the BGP Engine before the disable message
 *          arrived, in which case the "down reason" will change to whatever
 *          happened in the BGP Engine.
 *
 *      The BGP Engine may signal:
 *
 *        * feXxxxx, but not "stopped"    -> remains pEstablished
 *
 *          the BGP Engine may signal events which do not stop the established
 *          session, but may be of interest.
 *
 *        * feXxxxx, and "stopped"        -> pResetting (however briefly)
 *                                           and psStopped
 *
 *          The "down reason" is set according to what the BGP Engine reports.
 *
 *      Accepts and sends UPDATE etc messages while is pEstablished.
 *
 *   4. pResetting
 *
 *      Reaches this state from pStarted or pEstablished, as above.
 *
 *      When a disable message is sent to the BGP Engine it is set pssLimping,
 *      and will go pssStopped when is seen to stop.  While is pssLimping, all
 *      messages from the BGP Engine are discarded, until it is seen to stop,
 *      and is set pssStopped.
 *
 *      (When pssStopped is set, will flush all message queues for the session,
 *      since the BGP Engine is now done with it.)
 *
 *      Tidies up the peer, including clearing routes etc.  Once the peer is
 *      completely tidy, and the session is pssStopped:
 *
 *         peer    -> pDown/pssStopped
 *
 *      NB: while pResetting the peer's routes and RIBs may be being processed
 *         (and may or may not be being discarded).
 *
 *          All other parts of the peer may be modified... but mindful of the
 *          "background" tasks which are yet to complete.
 *
 *   5. bgp_pDeleting
 *
 *      This is an exotic state, reached only when a peer is being completely
 *      deleted.
 *
 *      This state may be reached from any of the above.
 *
 *      If there is an active session, it will be sLimping.  When advances to
 *      sDown it will be deleted.
 *
 *      The remaining tasks are to clear out routes, dismantle the peer
 *      structure and delete it.  While that is happening, the peer is in this
 *      state.
 */
typedef enum bgp_peer_states bgp_peer_state_t ;
enum bgp_peer_states
{
  bgp_peer_state_min     = 0,

  bgp_pInitial      = 0,        /* in the process of being created      */

  bgp_pDown         = 1,        /* not yet started/restarted            */
  bgp_pStarted      = 2,        /* started, but not yet established     */
  bgp_pEstablished  = 3,        /* session established                  */

  bgp_pResetting    = 4,        /* session stopping/stopped, clearing   */

  bgp_pDeleting     = 5,        /* lingers until lock count == 0        */

  bgp_peer_state_max     = 6
} ;

/* The state of the session, as far as the peer is concerned.
 *
 * The peer->session_state belongs to the Routing Engine (RE), and is updated
 * as messages are sent to and arrive from the BGP Engine (BE).
 *
 *   * pssInitial   -- means that the peer and session are being created (or
 *                     are about to be).
 *
 *   * pssStopped   -- means that the session is not running -- nothing at all
 *                     is happening for the session in the BE, EXCEPT that the
 *                     acceptor may (well) be running.
 *
 *                     NB: while is pssStopped, any changes to the peer->cops
 *                         cause the BE to be prodded if this may affect the
 *                         acceptor, or if becomes pisRunnable.
 *
 *                         The pisReset may hold the session pssStopped until
 *                         the restart timer goes off.
 *
 *                         while is pssStopped, any changes to the peer->args
 *                         do not cause the BE to be prodded.
 *
 *   * pssRunning   -- means that the session is running (something is, as far
 *                     as the RE is concerned, happening for the session in the
 *                     BE).
 *
 *                     NB: changes to peer->cops and/or peer->args will cause
 *                         the BE to be prodded.
 *
 *                         Changing to anything other than pisRunnable will
 *                         send to pssLimping.
 *
 *                         If the session stops spontaneously (from the
 *                         perspective of the RE) then it drops to pssStopped.
 *
 *   * pssLimping   -- means that was pssRunning and the RE is now waiting to
 *                     see a Stopped message from the BE.
 *
 *                     NB: while is pssLimping, changes to peer->cops and
 *                         peer->args are treated in the same way as in
 *                         pssStopped.
 *
 *                         At a minimum will be pisReset.
 *
 *   * pssDeleted   -- means that the peer is being deleted, and session has
 *                     been -- at least, the peer has cut the session away,
 *                     and sent a message to the BE to delete the session..
 */
typedef enum bgp_peer_session_state bgp_peer_session_state_t ;
enum bgp_peer_session_state
{
  bgp_peer_session_state_min = 0,

  bgp_pssInitial    = 0,        /* in the process of being created      */

  bgp_pssStopped    = 1,
  bgp_pssRunning    = 2,
  bgp_pssLimping    = 3,        /* neither up nor down                  */

  bgp_pssDeleted    = 4,        /* gone                                 */

  bgp_peer_session_state_max = 2
} ;

/*------------------------------------------------------------------------------
 * Whether and why the peer is "Idle".
 */
typedef enum bgp_peer_idle_state bgp_peer_idle_state_t ;
enum bgp_peer_idle_state
{
  bgp_pisRunnable       = 0,

  /* This is set while a peer is in the process of being configured.
   */
  bgp_pisConfiguring    = BIT(0),

  /* This is the all purpose is reset and pending some sort of restart, flag.
   *
   * When the Peering Engine is ready, it will release this and proceed to
   * restart the session.
   */
  bgp_pisReset          = BIT(1),

  /* These are temporary states -- when they are cleared, the connection may
   * well be up again, and that should trigger session state change.
   */
  bgp_pisClearing       = BIT(2),   /* clearing from last session drop  */
  bgp_pisMaxPrefixWait  = BIT(3),   /* waiting for restart timer        */

  /* These are serious, configuration set issues, and will cause the acceptor
   * to reject incoming connections.
   *
   * NB: for status display, the highest numbered bit is used.
   */
  bgp_pisMaxPrefixStop  = BIT(4),   /* max prefix -- no restart         */
  bgp_pisNoAF           = BIT(5),   /* no address families are enabled  */
  bgp_pisShutdown       = BIT(6),   /* "administratively SHUTDOWN"      */
  bgp_pisDeconfigured   = BIT(7),   /* administratively dead            */

  bgp_pisDown           = bgp_pisDeconfigured  |
                          bgp_pisShutdown      |
                          bgp_pisNoAF          |
                          bgp_pisMaxPrefixStop,
} ;

/*==============================================================================
 * struct prun and struct peer_rib  -- the BGP neighbor structures.
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
  PEER_DOWN_GTSM_CHANGE,           /* 'neighbor ttl-security hops'         */
  PEER_DOWN_AF_DEACTIVATE,         /* 'no neighbor activate'               */
  PEER_DOWN_PASSWORD_CHANGE,       /* 'neighbor password'                  */
  PEER_DOWN_ALLOWAS_IN_CHANGE,     /* 'neighbor allowas-in'                */

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

/*------------------------------------------------------------------------------
 * The restart state for a peer.
 *
 *
 *
 */
typedef enum bgp_conf_change  bgp_conf_change_t ;
enum bgp_conf_change
{
  bgp_ccNone            = 0,

  bgp_ccRecharge        = BIT(0),
  bgp_ccSoft_in         = BIT(1),
  bgp_ccSoft_out        = BIT(2),
  bgp_ccRestart         = BIT(3),
  bgp_ccStart           = BIT(4),
} ;

/*------------------------------------------------------------------------------
 * The running configuration for a peer
 *
 * This encapsulates all the things that are established by configuration, so
 * that a change in configuration can be
 *
 */






/*------------------------------------------------------------------------------
 * The structure for each running peer.
 */
typedef struct bgp_prun bgp_prun_t ;
typedef const bgp_prun_t* bgp_prun_c ;

struct bgp_prun
{
  /* The running peer belongs to the parent bgp_run structure.
   */
  bgp_run       brun ;

  /* For convenience we have a pointer to the printable name of the peer.
   * The actual name is in a bgp_nref in the running params.
   */
  chs_c         name ;          /* Printable name of the peer.          */

  /* The running parameters and delta
   */
  bgp_prun_param_t  rp ;

  bgp_run_delta_t   delta ;

  /* State of the peer
   */
  bgp_peer_state_t      state ;
  bgp_peer_idle_state_t idle ;

  /* nsf_enabled means....    XXX
   *
   * nsf_restarting means...  XXX
   */
  bool          nsf_enabled ;
  bool          nsf_restarting ;

  /* The session and state thereof
   */
  bgp_session   session ;

  bgp_peer_session_state_t session_state ;

  /* Peer information
   */
  time_t uptime;                /* Last Up/Down time                    */
  time_t readtime;              /* Last read time                       */
  time_t resettime;             /* Last reset time                      */

  struct zlog *log;

  bool       shared_network;    /* Is this peer shared same network.    */
  bgp_nexthop_t nexthop;        /* Nexthop                              */

  /* peer reset cause
   */
  peer_down_t   last_reset;

  bgp_note      note ;

  /* Peer address family state and negotiation.
   *
   *   * af_set_up      -- the set of afi/safi for which the peer has been
   *                       set up.
   *
   *     There will be a prib[qafx] for each one.
   *
   *     The afi/safi which have been set up are the ones which will be/have
   *     been advertised to the peer.  So this is the same as args.can_af.
   *
   *   * af_running    -- the set of afi/safi for which a session is currently
   *                      running.
   *
   *     This is empty unless is pEstablished and is set when becomes
   *     pEstablished.
   *
   *     When a session for an afi/safi is terminated, it is knocked out of the
   *     af_running.  (Generally this is shortly before goes pDown -- but
   *     individual afi/safi may be terminated and the session remain.)
   */
  qafx_set_t    af_set_up ;
  qafx_set_t    af_running ;    /* what current session carries */

  /* Peer RIBS -- contain adj_in and adj_out etc.
   */
  bgp_prib      prib[qafx_count] ;

  uint          prib_running_count ;
  bgp_prib      prib_running[qafx_count] ;

  /* List of pending outgoing Route_Refresh requests.
   */
  struct dl_base_pair(bgp_route_refresh) rr_pending ;

  /* Timers.
   *
   *   * qt_restart     -- used for general restart (or initial start) and for
   *                       max-prefix delayed restart.
   */
  qtimer        qt_restart ;

  /* Timer values.
   */
  qtime_t       idle_hold_time ;        /* lots of resolution   */

  uint          v_asorig;
  uint          v_gr_restart;

  /* Threads
   */
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;

  /* BGP state count
   */
  uint32_t      established;
  uint32_t      dropped;

  /* Peer index, used for dumping TABLE_DUMP_V2 format
   */
  uint16_t      table_dump_index;
} ;

#define BGP_TIMER_ON(T,F,V)                     \
  do {                                          \
    if (!(T) && (prun->state != bgp_pDeleting)) \
      THREAD_TIMER_ON(master,(T),(F),prun,(V)); \
  } while (0)

#define BGP_TIMER_OFF(T)                        \
  do {                                          \
    if (T)                                      \
      THREAD_TIMER_OFF(T);                      \
  } while (0)

/*------------------------------------------------------------------------------
 * Each peer has a peer rib for each AFI/SAFI it is configured for.
 *
 * This refers to the bgp instance's RIB, and contains the adj_in and adj_out
 * for the peer.
 *
 * The peer_rib is pointed to by the bgp_peer structure.  When the peer is
 * active for the AFI/SAFI, the peer_rib is on the bgp_rib's peers list.
 */
typedef struct bgp_prib bgp_prib_t ;
typedef const bgp_prib_t* bgp_prib_c ;

typedef enum adj_in_state adj_in_state_t ;
enum adj_in_state
{
  ai_next     = 0,              /* process next 'pending' if any        */

  ai_next_hop_valid,
  ai_next_hop_reachable,
} ;

struct bgp_prib
{
  bgp_prun      prun ;                  /* parent peer running          */

  /* Running parameters and delta
   */
  bgp_prib_param_t  rp ;

  bgp_run_delta_t   delta ;

  /* Each peer-rib is associated with the respective bgp-rib -- for the
   * same AFI/SAFI and for that bgp instance.
   *
   * And the bgp-rib has a list of peers known to it.
   */
  bgp_rib       rib ;                   /* parent rib                   */
  struct dl_list_pair(bgp_prib) prib_list ;

  /* Each peer-rib is also associated with a "local-context" -- the context
   * "local" to the bgp-rib.  The local-context is a dense set of contexts,
   * which are the contexts known to the rib-nodes and the route-infos in
   * the rib.
   */
  bgp_lc_id_t   lc_id ;                 /* parent local-context in rib  */
  struct dl_list_pair(bgp_prib) lc_list ;

  /* When a peer_rib is enabled (ie the exchange of routes is enabled) the
   * peer_rib is associated with a bgp_rib_walker.
   *
   * The peer_rib walker may be:
   *
   *   * the rib's own walker -- in "update" (or not "refresh") state.
   *
   *     This is the steady state for a prib.
   *
   *     The prib is on one of the rib's update_view_peers or update_peers
   *     lists, and updates will be sent to the peer when required.
   *
   *   * a "refresh" walker or the rib's own walker -- in "refresh" state.
   *
   *     In this state updates are being sent to bring the peer up to date.
   *     This may be after a session has started, or after a route refresh,
   *     or after some change to 'out' filtering etc.
   *
   *     The prib is on the walker's refresh_peers list.
   *
   *     A "refresh" walker is always behind the rib's own walker.  If it meets
   *     the rib's own walker, the list of refresh_peers is transferred, and
   *     the now redundant "refresh" walker is discarded.
   *
   * If there is no walker, then the prib is in some intermediate state (and,
   * in particular, is not on any of the rib's update_view_peers or update_peers
   * lists.
   */
  bgp_rib_walker  walker ;
  struct dl_list_pair(bgp_prib) walk_list ;

  bool          refresh ;               /* is on walker's refresh list  */
  bool          eor_required ;

  /* General stuff for the peer re this qafx.
   */
  qafx_t        qafx ;
  iAFI_t        i_afi ;
  iSAFI_t       i_safi ;
  bool          is_mpls ;

  bool          real_rib ;      /* With or without zroute       */
  bool          session_up ;

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

  /* NSF mode (graceful restart) means...  XXX
   */
  bool          nsf_mode ;

  /* Status flags set/cleared as we go along.
   */
  bool          default_sent ;
  bool          eor_sent ;
  bool          eor_received ;

  bool          max_prefix_threshold ;
  bool          max_prefix_limit ;

  bool          gr_can_preserve ;
  bool          gr_has_preserved ;

  /* For Prefix ORF:
   *
   *   _CAN_SEND => we expressed the wish, and we have received the go-ahead
   *   _SENT     => we have sent the Prefix ORF.
   *
   *   _EXPECT   => we expressed willing-ness, and received the wish to send
   *   _WAIT     => waiting to receive the Prefix ORF (just established)
   */
  bool          orf_pfx_can_send ;
  bool          orf_pfx_sent ;

  bool          orf_pfx_may_recv ;
  bool          orf_pfx_wait ;

  /* Prefix recv/in counts and sent prefix count.
   *
   *   * pcount_recv  -- number of routes received, this excludes routes
   *                     which are:
   *
   *                       * RINFO_WITHDRAWN -- withdrawn by peer
   *
   *                       * RINFO_STALE     -- effectively withdrawn by peer
   *
   *                     and includes:
   *
   *                       * RINFO_REFUSED   -- too invalid to accept
   *
   *                       * RINFO_DENIED    -- denied by 'in' filtering
   *
   *                     Note that this is the number used for max-prefix.
   *
   *                     Note that this count takes into account routes
   *                     received which are pending processing.
   *
   *   * pcount_in    -- number of routes which have passed the 'in' filtering.
   *
   *                     Note that this count is for the current, processed
   *                     route state.  So, while there are stale routes, or
   *                     pending routes, this count may be greater than or
   *                     less than the pcount_recv !
   */
  uint        pcount_recv ;
  uint        pcount_in ;

  uint        pcount_sent ;

  /* The peer's adj_in stuff for this qafx
   *
   * The adj_in are ihash by prefix_id_t, giving a route_info object for each
   * route received from the peer.  Those route_info objects are "owned" by
   * the peer, but are also referred to by the bgp_rib_node for the prefix
   * (where the route is not filtered out).
   *
   *
   */
  ihash_table     adj_in ;              /* route_info           */

  struct dl_base_pair(route_info) stale_routes ;
  struct dl_base_pair(route_info) pending_routes ;

  adj_in_state_t  in_state ;
  attr_set        in_attrs ;

  /* The peer's adj_out stuff for this qafx
   *
   * A Main Peer receives routes from the Main RIB.
   * An RS Client receives routes from the RS RIB.
   */
  ihash_table     adj_out ;             /* adj_out_ptr_t                */

  pfifo_period_t  batch_delay ;
  pfifo_period_t  batch_delay_extra ;   /* maximum extra delay          */
  pfifo_period_t  announce_delay ;
  pfifo_period_t  mrai_delay ;          /* actual MRAI                  */
  pfifo_period_t  mrai_delay_left ;     /* actual MRAI - batch_delay    */

  qtime_mono_t    period_origin ;
  pfifo_period_t  now ;

  pfifo_period_t  t0 ;
  pfifo_period_t  tx ;

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
 * For clearing operations.
 */
typedef enum bgp_clear_type bgp_clear_type_t ;
enum bgp_clear_type
{
  BGP_CLEAR_HARD,
  BGP_CLEAR_SOFT_OUT,
  BGP_CLEAR_SOFT_IN,
  BGP_CLEAR_SOFT_BOTH,
  BGP_CLEAR_SOFT_IN_ORF_PREFIX,
  BGP_CLEAR_SOFT_RSCLIENT
} ;

/*==============================================================================
 *
 */
extern bgp_prun bgp_prun_new(bgp_run brun, bgp_prun_param prp) ;
extern bgp_prib bgp_prib_new(bgp_prun prun, qafx_t qafx) ;

extern void bgp_prun_shutdown(bgp_prun prun, peer_down_t why_down) ;
extern void bgp_prun_execute(bgp_prun prun, peer_down_t why_down) ;










extern bgp_prib bgp_prib_new(bgp_prun prun, qafx_t qafx) ;
extern bgp_prib bgp_prib_free(bgp_prib prib) ;

extern bgp_prib peer_rib_set_rs(bgp_prun prun, qafx_t qafx) ;
extern bgp_prib peer_rib_unset_rs(bgp_prun prun, qafx_t qafx) ;





extern void bgp_peer_start(bgp_prun prun) ;
extern void bgp_peer_restart(bgp_prun prun, peer_down_t why_down) ;
extern void bgp_peer_cops_recharge(bgp_prun prun, peer_down_t why_down) ;

extern void bgp_session_has_established(bgp_session session);
extern void bgp_session_has_stopped(bgp_session session, bgp_note note) ;

//extern sockunion bgp_peer_get_ifaddress(bgp_prun prun, const char* ifname,
//                                                              sa_family_t af) ;

extern void peer_clear (bgp_prun prun);
extern bgp_ret_t peer_clear_soft (bgp_prun prun, qafx_t qafx,
                                                       bgp_clear_type_t stype) ;

extern void bgp_peer_enable(bgp_prun prun);

extern void bgp_peer_down(bgp_prun prun, peer_down_t why_down) ;
extern void bgp_peer_down_error(bgp_prun prun,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode) ;

extern void bgp_peer_down_error_with_data (bgp_prun prun,
                              bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                             const byte* data, size_t datalen) ;

extern prefix_max bgp_prib_pmax_reset(bgp_prib prib) ;
extern bool bgp_peer_pmax_check(bgp_prib prib) ;
extern void bgp_peer_pmax_clear(bgp_prib prib) ;


extern bgp_prun prun_lookup_view_vty(vty vty, chs_c view_name,
                                                              chs_c peer_name) ;
extern bgp_prun prun_lookup_view_qafx_vty(vty vty, chs_c view_name,
                                                 chs_c peer_name, qafx_t qafx) ;

extern int peer_cmp (bgp_peer p1, bgp_peer p2) ;
extern qfb_time_t peer_uptime (time_t time);

/* This is actually defined in bgp_names.c... but if the extern is there, we
 * have to drag a *huge* amount of stuff into bgp_names.h.
 */
extern name_str_t bgp_peer_idle_state_str(bgp_peer_state_t state,
                                                   bgp_peer_idle_state_t idle) ;

#endif /* _QUAGGA_BGP_PRUN_H */

