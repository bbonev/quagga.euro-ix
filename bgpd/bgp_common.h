/* BGP Common -- functions
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_COMMON_H
#define _QUAGGA_BGP_COMMON_H

#include "misc.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/if.h>

#include "bgpd/bgp.h"
#include "list_util.h"
#include "qafi_safi.h"
#include "vhash.h"
#include "log.h"

/*==============================================================================
 * Here are a number of "incomplete" declarations, which allow a number of
 * bgpd structures to refer to each other.
 */
typedef struct bgp*             bgp_inst ;
typedef struct peer*            bgp_peer ;
typedef struct peer_group*      peer_group ;
typedef struct bgp_session*     bgp_session ;
typedef struct bgp_connection*  bgp_connection ;
typedef struct bgp_cops*        bgp_cops ;
typedef const struct bgp_cops*  bgp_cops_c ;
typedef struct bgp_session_args* bgp_session_args ;
typedef struct bgp_acceptor*    bgp_acceptor ;
typedef struct bgp_open_state*  bgp_open_state ;
typedef struct bgp_nexthop*     bgp_nexthop ;
typedef struct bgp_peer_index_entry* bgp_peer_index_entry ;
typedef struct bgp_msg_reader*  bgp_msg_reader ;
typedef struct bgp_notify*      bgp_notify ;
typedef struct bgp_fsm_eqb*     bgp_fsm_eqb ;

//typedef struct bgp_event*      bgp_event ;

typedef struct attr_set*        attr_set ;
typedef struct asn_set*         asn_set ;

typedef struct bgp_rib*         bgp_rib ;
typedef struct peer_rib*        peer_rib ;
typedef struct bgp_rib_node*    bgp_rib_node ;
typedef struct bgp_rib_walker*  bgp_rib_walker ;
typedef struct bgp_rib_item*    bgp_rib_item ;

typedef struct route_info*      route_info ;
typedef struct route_extra*     route_extra ;
typedef struct route_zebra*     route_zebra ;

typedef struct adj_out*         adj_out ;
typedef struct route_in_parcel*  route_in_parcel ;
typedef struct route_out_parcel* route_out_parcel ;

typedef struct route_mpls*      route_mpls ;
typedef struct attr_flux*       attr_flux ;
typedef struct route_flux*      route_flux ;








typedef struct bgp_table*       bgp_table ;
typedef struct bgp_node*        bgp_node ;
typedef struct bgp_info*        bgp_info ;
typedef struct bgp_info_extra*  bgp_info_extra ;
typedef struct bgp_adj_out*     bgp_adj_out ;
typedef struct bgp_adj_in*      bgp_adj_in ;
typedef struct bgp_sync*        bgp_sync ;
typedef struct bgp_adv_attr*    bgp_adv_attr ;

typedef struct bgp_adv*         bgp_adv ;

/*==============================================================================
 * AFI/SAFI encodings for bgpd
 *
 * This captures the AFI/SAFI combinations that bgpd supports.
 *
 * Note that this defines "qafx" for IPv6 even if do not HAVE_IPV6.
 */
enum
{
  /* Generally, if we don't HAVE_IPV6, we don't have any of the definitions,
   * functions etc. that do IPv6 things.  Occasionally, it is useful to do
   * something different of do or do not have IPv6.
   */
  have_ipv6 =
#ifdef HAVE_IPV6
                  1
#else
                  0
#endif
} ;

/*------------------------------------------------------------------------------
 * A qafx_t identifies a supported AFI/SAFI combination
 *
 * NB: when changing anything here make sure that the various sexing functions
 *     below will still work !
 */
typedef enum qafx_num  qafx_t ;

enum qafx_num
{
  qafx_undef            = -1,   /* No defined AFI/SAFI                  */
  qafx_min              = 0,    /* minimum valid qafx                   */

  qafx_first            = 0,    /* all first..last are "real" qafx      */

  qafx_ipv4_unicast     = 0,    /* iAFI = 1, iSAFI = 1                  */
  qafx_ipv4_multicast   = 1,    /* iAFI = 1, iSAFI = 2                  */
  qafx_ipv4_mpls_vpn    = 2,    /* iAFI = 1, iSAFI = 128                */

  qafx_ipv6_unicast     = 3,    /* iAFI = 2, iSAFI = 1                  */
  qafx_ipv6_multicast   = 4,    /* iAFI = 2, iSAFI = 2                  */
  qafx_ipv6_mpls_vpn    = 5,    /* iAFI = 2, iSAFI = 128                */

  qafx_last             = 5,    /* last "real" qafx                     */

  qafx_other            = 6,    /* place-holder: for unknown AFI/SAFI   */

  qafx_max              = 6,    /* maximum qafx                         */
  qafx_count                    /* number of qafx                       */
} ;

CONFIRM(qafx_other >  qafx_last) ;
CONFIRM(qafx_other == qafx_max) ;

/*------------------------------------------------------------------------------
 * A qafx_set_t is a set of qafx_bit_t -- a bit-vector
 */
typedef enum qafx_bit   qafx_bit_t ;
typedef      qafx_bit_t qafx_set_t ;

enum qafx_bit
{
  qafx_bits_min           = 0,

  qafx_set_empty          = 0,

  qafx_first_bit          = (1 << qafx_first),
                                /* first..last are all "real" qafx      */

  qafx_ipv4_unicast_bit   = (1 << qafx_ipv4_unicast),
  qafx_ipv4_multicast_bit = (1 << qafx_ipv4_multicast),
  qafx_ipv4_mpls_vpn_bit  = (1 << qafx_ipv4_mpls_vpn),

  qafx_ipv6_unicast_bit   = (1 << qafx_ipv6_unicast),
  qafx_ipv6_multicast_bit = (1 << qafx_ipv6_multicast),
  qafx_ipv6_mpls_vpn_bit  = (1 << qafx_ipv6_mpls_vpn),

  qafx_last_bit           = (1 << qafx_last),

  qafx_other_bit          = (1 << qafx_other),

  qafx_bits_max           = (1 << qafx_count) - 1,

  qafx_known_bits         = (1 << (qafx_last + 1)) - 1
} ;

CONFIRM(qafx_known_bits == ( qafx_ipv4_unicast_bit
                           | qafx_ipv4_multicast_bit
                           | qafx_ipv4_mpls_vpn_bit
                           | qafx_ipv6_unicast_bit
                           | qafx_ipv6_multicast_bit
                           | qafx_ipv6_mpls_vpn_bit )) ;

/*------------------------------------------------------------------------------
 * Conversions qafx_num <-> qafx_bit
 *
 * The conversion from qafx_bit -> qafx_num is not built for speed.
 */

/* Get qafx_bit_t for given qafx_t
 *
 * NB: it is a mistake to try to map qafx_undef (FATAL unless NDEBUG).
 */
Inline qafx_bit_t
qafx_bit(qafx_t num)
{
  dassert((num >= qafx_min) && (num <= qafx_max)) ;
  return (1 << num) ;
} ;

/* Get qafx_t for the given qafx_bit_t.
 */
extern qafx_t qafx_num(qafx_bit_t bit) ;

/*==============================================================================
 * A dense set of the BGP Messages known to Quagga
 */
typedef enum qBGP_MSG qBGP_MSG_t ;
enum qBGP_MSG
{
  qBGP_MSG_unknown    = 0,

  qBGP_MSG_OPEN,
  qBGP_MSG_UPDATE,
  qBGP_MSG_NOTIFICATION,
  qBGP_MSG_KEEPALIVE,
  qBGP_MSG_ROUTE_REFRESH,
  qBGP_MSG_CAPABILITY,
  qBGP_MSG_ROUTE_REFRESH_pre,

  qBGP_MSG_count,
} ;

/*==============================================================================
 * Some BGP capabilities and messages have RFC and pre-RFC forms.
 *
 * Sometimes see both, or send RFC and/or pre-RFC forms, or track what form(s)
 * are being used.
 */
typedef enum bgp_form bgp_form_t ;

enum bgp_form
{
  bgp_form_none     = 0,
  bgp_form_pre      = 1,
  bgp_form_rfc      = 2,
  bgp_form_both     = 3     /* _rfc and _pre are bits !     */
} ;

/*==============================================================================
 * Common data types
 */
enum bgp_password_length
{
  BGP_PASSWORD_MIN_LEN    =   1,
  BGP_PASSWORD_MAX_LEN    = 103,        /* 104 divides exactly by 8     */
  BGP_PASSWORD_SIZE       = 104,        /* including the '\0'           */
} ;

typedef char bgp_password_t[BGP_PASSWORD_SIZE] ;
typedef char bgp_ifname_t[IF_NAMESIZE] ;        /* IF_NAMESIZE includes '\0' */

typedef struct bgp_connection_logging  bgp_connection_logging_t ;
typedef struct bgp_connection_logging* bgp_connection_logging ;

struct bgp_connection_logging
{
  char*             host ;              /* peer "name" (+ tag)          */
  struct zlog*      log ;               /* where to log to              */
} ;

#if 0
typedef enum bgp_update_source_type bgp_update_source_type_t ;
enum bgp_update_source_type
{
  bgp_upst_none    = 0,

  bgp_upst_source_address,      /* neighbor xx update-source <address>  */
  bgp_upst_source_interface,    /* neighbor xx update-source <if-name>  */

  bgp_upst_interface,           /* neighbor xx interface <if-name>      */
} ;

typedef struct bgp_update_source  bgp_update_source_t ;
typedef struct bgp_update_source* bgp_update_source ;

struct bgp_update_source
{
  bgp_update_source_type_t  type ;

  union
    {
      sockunion_t   su ;        /* embedded             */
      bgp_ifname_t  if_name ;   /* embedded             */
    } u ;
} ;
#endif

/*==============================================================================
 * BGP FSM States and events.
 */
typedef enum bgp_fsm_states bgp_fsm_state_t ;
enum bgp_fsm_states
{
  bgp_fs_first         = 0,

  /* Extra state while has none, eg while FSM/Connection is being initialised.
   */
  bgp_fsNULL           = 0,  /* no state                                */

  /* These are the RFC4271 states
   */
  bgp_fsIdle           = 1,  /* waiting for Idle Hold time               */
  bgp_fsConnect        = 2,  /* waiting for connect (may be listening)   */
  bgp_fsActive         = 3,  /* listening only                           */
  bgp_fsOpenSent       = 4,  /* sent Open -- awaits Open                 */
  bgp_fsOpenConfirm    = 5,  /* sent & received Open -- awaits keepalive */
  bgp_fsEstablished    = 6,  /* running connection                       */

  /* Extra state while bringing FSM/Connection to a halt.
   */
  bgp_fsStop           = 7,  /* connection coming to a stop              */

  bgp_fs_count,
  bgp_fs_last          = bgp_fs_count - 1,
} ;

typedef enum bgp_fsm_events bgp_fsm_event_t ;
enum bgp_fsm_events
{
  bgp_feNULL                          =  0,

  /* 8.1.2 Administrative Events
   */
  bgp_feManualStart                   =  1,
  bgp_feManualStop                    =  2,
  bgp_feAutomaticStart                =  3,
  bgp_feManualStart_with_Passive      =  4,
  bgp_feAutomaticStart_with_Passive   =  5,
  bgp_feAutomaticStart_with_Damp      =  6,
  bgp_feAutomaticStart_with_Damp_and_Passive   =  7,
  bgp_feAutomaticStop                 =  8,

  /* 8.1.3 Timer Events
   */
  bgp_feConnectRetryTimer_Expires     =  9,
  bgp_feHoldTimer_Expires             = 10,
  bgp_feKeepaliveTimer_Expires        = 11,
  bgp_feDelayOpenTimer_Expires        = 12,
  bgp_feIdleHoldTimer_Expires         = 13,

  /* 8.1.4 TCP Connection-Based Events
   *
   * These are less than obvious...
   *
   *   14. TcpConnection_Valid    -- in-bound connection    -- N/A
   *
   *       A SYN has been received, and the source address and port and the
   *       destination address and port are all valid.
   *
   *       This is not something we can see in a POSIX environment (except with
   *       raw sockets perhaps).
   *
   *       We don't use this.
   *
   *   15. Tcp_CR_Invalid         -- in-bound connection    -- N/A
   *
   *       A SYN has been received, but something is invalid about it.
   *
   *       This is not something we can see in a POSIX environment (except with
   *       raw sockets perhaps).
   *
   *       We don't use this.
   *
   *   16. Tcp_CR_Acked           -- out-bound connection   -- feConnected
   *
   *       Connection is up -- three-way handshake completed.
   *
   *   17. TcpConnectionConfirmed -- in-bound connection    -- feAccepted
   *
   *       Connection is up -- three-way handshake completed.
   *
   *   18. TcpConnectionFails     -- after 16 or 17...      -- feDown
   *                                 ...or at any time ?
   *       Connection is down.
   */
  bgp_feTcpConnection_Valid           = 14,     /* N/A                  */
  bgp_feTcp_CR_Invalid                = 15,     /* N/A                  */
  bgp_feTcp_CR_Acked                  = 16,     /* feConnected          */
  bgp_feTcpConnectionConfirmed        = 17,     /* feAccepted           */
  bgp_feTcpConnectionFails            = 18,     /* feDown               */

  /* 8.1.5 BGP Message-Based Events
   */
  bgp_feBGPOpen                       = 19,
  bgp_feBGPOpen_with_DelayOpenTimer   = 20,
  bgp_feBGPHeaderErr                  = 21,
  bgp_feBGPOpenMsgErr                 = 22,
  bgp_feOpenCollisionDump             = 23,
  bgp_feNotifyMsgVerErr               = 24,
  bgp_feNotifyMsg                     = 25,
  bgp_feKeepAliveMsg                  = 26,
  bgp_feUpdateMsg                     = 27,
  bgp_feUpdateMsgErr                  = 28,

  /* End of the standard event numbers
   */
  bgp_fe_rfc_count,
  bgp_fe_rfc_last       = bgp_fe_rfc_count - 1,

  bgp_fe_extra_first    = bgp_fe_rfc_count,

  /*--------------------------------------------------------------------
   * Alias TCP events and some extra ones.
   *
   *   * feConnected        -- out-bound        == feTcp_CR_Acked
   *
   *     An outbound connection is now up.
   *
   *   * feAccepted         -- in-bound         == feTcpConnectionConfirmed
   *
   *     An inbound connection is now up in the Acceptor.
   *
   *   * feDown             -- in-/out-bound    == feTcpConnectionFails
   *
   *     But this is *strictly* where an existing connection stops after it
   *     came up either feConnected or feAccepted.
   *
   *   * feError            -- in-/out-bound    -- extra
   *
   *     This is a sort of catch-all for socket and such-like errors which
   *     we don't really expect to get.  These errors suggest something is
   *     missing or not working properly, and should be fixed.
   *
   *   * feConnectFailed    -- out-bound        -- extra
   *
   *     Cannot get a connection up for a variety of reasons to do with the
   *     underlying network, or the other end not playing nicely.  These are
   *     the sorts of things that indicate (a possibly transient) network or
   *     configuration problem at either end.
   *
   *   * feAcceptOPEN       -- in-bound         -- extra
   *
   *     The acceptor has seen an complete OPEN message.
   */
  bgp_feConnected      = bgp_feTcp_CR_Acked,
  bgp_feAccepted       = bgp_feTcpConnectionConfirmed,
  bgp_feDown           = bgp_feTcpConnectionFails,

  bgp_feError          = bgp_fe_extra_first,
  bgp_feConnectFailed,
  bgp_feAcceptOPEN,

  /* Other extra events
   *
   *   * feRRMsg           -- a Route Refresh message has been received
   *   * feRRMsgErr        -- a Route Refresh message has been recieved but all
   *                          is not well with it.
   *
   *   * feRestart         -- the connection should fall fsIdle, or stop
   *                          if is fsEstablished.
   *
   *   * feShut_RD         -- the read side has shutdown.
   *   * feShut_WR         -- the write side has shutdown.
   */
  bgp_feRRMsg,
  bgp_feRRMsgErr,

  bgp_feRestart,
  bgp_feShut_RD,
  bgp_feShut_WR,

  /* Extra error events
   *
   *   * feUnexpected      -- an unexpected message has arrived.
   *
   *                          This will generally map to a BGP_NOMC_FSM
   *                          NOTIFICATION message.
   *
   *   * feInvalid         -- something has gone wrong (at our end).
   *
   *                          This will generally map to a BGP_NOMC_CEASE/
   *                          BGP_NOMS_UNSPECIFIC NOTIFICATION message.
   */
  bgp_feUnexpected,
  bgp_feInvalid,

  /* The feIO "pseudo" event -- not handled by the event-handler itself.
   */
  bgp_feIO,

  /* Number of events -- including the feNULL
   */
  bgp_fe_count,
  bgp_fe_last           = bgp_fe_count - 1,
} ;

#if 0
/*==============================================================================
 * Session level events -- which arise in the BGP Engine and are (generally)
 * reported back to the Peering Engine.
 *
 * Many of these are (strongly) related to FSM level events (bgp_fsm_eXxxx),
 * but some are not.
 */
typedef enum bgp_session_events bgp_session_event_t ;
enum bgp_session_events
{
  bgp_seNULL         =  0,

  bgp_seStart,                  /* enter fsConnect/fsActive from fsIdle */
  bgp_seRetry,                  /* fsConnect/fsActive                   */

  bgp_seFSM,                    /* had to reject an OPEN message        */
  bgp_seInvalid_msg,            /* BGP message invalid                  */
  bgp_seFSM_error,              /* unexpected BGP message received      */
  bgp_seNOM_recv,               /* NOTIFICATION message received        */

  bgp_seExpired,                /* HoldTime expired                     */
  bgp_seTCP_dropped,            /* TCP connection dropped               */

  bgp_seTCP_open_failed,        /* TCP connection failed to come up     */
  bgp_seTCP_error,              /* some socket level error              */

  bgp_seEstablished,            /* session state -> sEstablished        */
  bgp_seStop,                   /* disabled by Routeing Engine          */

  bgp_seInvalid,                /* invalid internal event               */

  bgp_se_count,
  bgp_se_last        = bgp_se_count - 1,
} ;
#endif

/*==============================================================================
 * States of Peer and Session and Connections
 */

/* The state of the peer -- strongly related to the state of the session !
 *
 *   0. pDisabled
 *
 *      All peers start in this state.
 *
 *      This is the case while no address families are enabled, eg:
 *
 *        a. when a bgp_peer structure is first created.
 *
 *           Note that PEER_TYPE_GROUP_CONF and PEER_TYPE_SELF are permanently
 *           pDisabled.
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
 *        psInitial -- case (a)
 *
 *        psDown    -- all of the above
 *
 *                     NB: in pDisabled and psDown, the acceptor will be
 *                         running if the current cops->accept is true.
 *
 *        all other states are IMPOSSIBLE
 *
 *      When at least one address family is enabled the peer can go pEnabled,
 *      and then a session will be enabled.
 *
 *   1. pEnabled
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
 *        * feXxxxx, but not "stopped"    -> remains pEnabled
 *
 *          the BGP Engine signals various events which do not stop it from
 *          trying to establish a session, but may be of interest.
 *
 *        * session is (now) sEstablished -> pEstablished
 *
 *        * feXxxxx, and "stopped"        -> pClearing (however briefly)
 *
 *      All other messages are discarded -- there should not be any.
 *
 *   2. pEstablished
 *
 *      Reaches this state from pEnabled when a session becomes established.
 *
 *      The session must be sUp.
 *
 *      If the Routeing Engine disables the session -> pClearing and psLimping.
 *
 *          The Routeing Engine sets the "down reason" etc. according to why
 *          the session is being disabled.  While psLimping, this is
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
 *        * feXxxxx, and "stopped"        -> pClearing (however briefly)
 *                                           and psDown
 *
 *          The "down reason" is set according to what the BGP Engine reports.
 *
 *      Accepts and sends UPDATE etc messages while is pEstablished.
 *
 *   4. pClearing
 *
 *      Reaches this state from pEnabled or pEstablished, as above.
 *
 *      When a disable message is sent to the BGP Engine it is set psLimping,
 *      and will go psDown when is seen to stop.  While is psLimping, all
 *      messages from the BGP Engine are discarded, until it is seen to stop,
 *      and is set psDown.
 *
 *      (When psDown is set, will flush all message queues for the session,
 *      since the BGP Engine is now done with it.)
 *
 *      Tidies up the peer, including clearing routes etc.  Once the peer is
 *      completely tidy, and the session is psDown:
 *
 *         peer    -> pDisabled/psDown or pEnabled/psUp
 *
 *      NB: while pClearing the peer's routes and RIBs may be being processed
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

  bgp_pDisabled     = 1,        /* may not be started                   */
  bgp_pEnabled      = 2,        /* started, but not yet established     */
  bgp_pEstablished  = 3,        /* session established                  */
  bgp_pClearing     = 4,        /* session stopping/stopped, clearing   */

  bgp_pDown,
  bgp_pDeleting     = 5,        /* lingers until lock count == 0        */

  bgp_peer_state_max     = 6
} ;

/* The state of the session, as far as the peer is concerned.
 *
 * The session->peer_state belongs to the Routing Engine (RE), and is updated
 * as messages are sent to and arrive from the BGP Engine (BE).
 *
 *   * psInitial    -- means that the peer and session are being created (or
 *                     are about to be).
 *
 *   * psDown       -- means that the session is not running (nothing at all
 *                     is happening for the session in the BE, EXCEPT that the
 *                     acceptor may be running and the cops remain in force).
 *
 *   * psUp         -- means that the session is running (something is, as far
 *                     as the RE is concerned, happening for the session in the
 *                     BE).
 *
 *   * psDeleted    -- means that the peer is being deleted, and session has
 *                     been -- at least, the peer has cut the session away,
 *                     and sent a message to the BE to delete the session..
 */
typedef enum bgp_peer_session_state bgp_peer_session_state_t ;
enum bgp_peer_session_state
{
  bgp_peer_session_state_min = 0,

  bgp_psInitial      = 0,       /* in the process of being created      */

  bgp_psDown         = 1,
  bgp_psUp           = 2,
  bgp_psLimping      = 3,       /* neither up nor down                  */

  bgp_psDeleted      = 4,       /* gone                                 */

  bgp_peer_session_state_max = 2
} ;

/* The state of the session, as far as the session is concerned.
 *
 * The session->state belongs to the BGP Engine (BE), and is updated as
 * messages are sent to and arrive from the Routeing Engine (RE).
 *
 *   * sInitial     -- means that the session has been initialised, but not
 *                     yet kicked into action.  The BE has yet to do anything
 *                     with the session, which may be in a message on its
 *                     way to the BE.
 *
 *                     The acceptor is not yet running.
 *
 *   * sStopped     -- means that the session is stopped, so the fsm(s) are
 *                     not running.
 *
 *                     The acceptor will be running.
 *
 *   * sAcquiring   -- means that the session has been started, so the fsm(s)
 *                     are running and trying to acquire and establish a
 *                     session.
 *
 *                     The acceptor will be running.
 *
 *   * sEstablished -- means an fsm is running and the session has established.
 *
 *                     The acceptor will be running.
 *
 *   * sStopping    -- means that the session will shortly be stopped.
 *
 *                     This can happen in one (obscure) case... in which the
 *                     established session has been stopped (and detached
 *                     from the session) but its sibling has not yet
 *                     stopped.
 *
 *                     The acceptor will be running.
 *
 *   * sDeleting    -- means the session is in the process of being deleted,
 *                     by the BE.
 *
 *                     The session is no longer attached to the parent peer,
 *                     or referred to by the peer_index.
 *
 *                     The acceptor is not running or will be stopped.
 */
typedef enum bgp_session_state bgp_session_state_t ;
enum bgp_session_state
{
  bgp_session_state_min     = 0,

  bgp_sInitial      = 0,

  bgp_sStopped      = 1,
  bgp_sAcquiring    = 2,
  bgp_sEstablished  = 3,
  bgp_sStopping     = 4,

  bgp_sDeleting     = 5,

  bgp_session_state_max     = 5
} ;

typedef enum bgp_conn_ord bgp_conn_ord_t ;
enum bgp_conn_ord
{
  bc_estd       = 0,
  bc_connect    = 1,
  bc_accept     = 2,

  bc_first      = bc_connect,   /* for stepping through same !  */
  bc_last       = bc_accept,

  bc_count,
} ;

/* Whether the connection is prepared to accept and/or connect.
 *
 * If is not prepared to accept:  will not run a bc_accept connection
 *                          and:  will reject (RST) at accept() time
 *
 * If is not prepared to connect: will not run a bc_connect connection
 */
typedef enum bgp_conn_let bgp_conn_let_t ;
enum bgp_conn_let
{
  bc_can_nothing    = 0,

  bc_can_accept     = BIT(0),           /* ie "passive" */
  bc_can_connect    = BIT(1),

  bc_can_both       = bc_can_accept | bc_can_connect,
} ;

/* Whether the connection(s) are enabled or not.
 */
typedef enum bgp_conn_state bgp_conn_state_t ;
enum bgp_conn_state
{
  bc_is_shutdown    = 0,        /* "administratively SHUTDOWN"  */

  bc_is_disabled,               /* for some (other) reason      */
  bc_is_enabled
} ;

/*==============================================================================
 * A bgp_route_type is a packed value:
 *
 *   * bits 1..0:  the bgp_route_subtype, as below
 *
 *   * bits 7..2:  the zebra route type (ZEBRA_ROUTE_XXX)
 */
typedef byte bgp_route_type_t ;

typedef byte bgp_route_subtype_t ;
typedef byte bgp_zebra_route_t ;

enum bgp_route_subtype
{
  BGP_ROUTE_NORMAL,
  BGP_ROUTE_AGGREGATE,
  BGP_ROUTE_REDISTRIBUTE,
  BGP_ROUTE_STATIC,

  BGP_ROUTE_SUBTYPE_COUNT
};

enum bgp_route_type
{
  BGP_ZEBRA_ROUTE_SHIFT   = 2,

  BGP_ROUTE_SUBTYPE_MASK  = BIT(BGP_ZEBRA_ROUTE_SHIFT)     - 1,
  BGP_ZEBRA_ROUTE_MASK    = BIT(8 - BGP_ZEBRA_ROUTE_SHIFT) - 1,
} ;

CONFIRM((BGP_ROUTE_SUBTYPE_COUNT - 1) <= BGP_ROUTE_SUBTYPE_MASK) ;
CONFIRM((ZEBRA_ROUTE_MAX         - 1) <= BGP_ZEBRA_ROUTE_MASK) ;

Inline bgp_route_subtype_t bgp_route_subtype(bgp_route_type_t type)
                                                                 Always_Inline ;
Inline bgp_zebra_route_t bgp_zebra_route(bgp_route_type_t type)  Always_Inline ;
Inline bgp_route_type_t bgp_route_type(bgp_zebra_route_t ztype,
                                    bgp_route_subtype_t stype)   Always_Inline ;

/*------------------------------------------------------------------------------
 * Extract bgp_route_subtype_t from given bgp_route_type_t
 */
Inline bgp_route_subtype_t
bgp_route_subtype(bgp_route_type_t type)
{
  return type & BGP_ROUTE_SUBTYPE_MASK ;
} ;

/*------------------------------------------------------------------------------
 * Extract bgp_zebra_route_t from given bgp_route_type_t
 */
Inline bgp_zebra_route_t
bgp_zebra_route(bgp_route_type_t type)
{
  return type >> BGP_ZEBRA_ROUTE_SHIFT ;
}

/*------------------------------------------------------------------------------
 * Construct bgp_route_type_t from given bgp_zebra_route_t + bgp_route_subtype_t
 */
Inline bgp_route_type_t
bgp_route_type(bgp_zebra_route_t ztype, bgp_route_subtype_t stype)
{
  return (ztype << BGP_ZEBRA_ROUTE_SHIFT) | stype ;
} ;

/*==============================================================================
 * The peer adj-out points either to attr_set or to a bgp_adv, so those must
 * be distinguishable by a common element in the structure.
 *
 * The attr_set is the "primary" in this, so the "bgp_adv" is organised to fit
 * in with that.  The attr_set is constrained to have a vhash_node at the
 * front, so the distinguisher -- the attr_state_t -- must follow that.
 */
typedef union peer_adj_out* peer_adj_out ;
typedef union peer_adj_out  peer_adj_out_t ;

typedef struct attr_set_h* attr_set_h ;
typedef struct attr_set_h  attr_set_ht ;

union peer_adj_out
{
  attr_set   attr ;
  bgp_adv    adv ;

  attr_set_h head ;
} ;

typedef byte attr_state_t ;

struct attr_set_h
{
  vhash_node_t  place_holder ;

  /* For the attr_set and bgp_adv structures we must CONFIRM that this
   * field is common to both.
   *
   * When handling a peer_adj_out pointer, we can check which of the two
   * types of value it is by checking the ptr->head.common value.
   */
  attr_state_t  common ;
} ;

enum attr_state
{
  /* These values are the only valid ones for attr_set.
   *
   * The bgp_attr_store code treats this as a boolean.  That code will never
   * see a bgp_adv value, and where a peer_adj_out is an attr_set, it will
   * always be 'ats_stored'.
   */
  ats_temp       = 0,   /* => attr_set, not stored      */
  ats_stored     = 1,   /* => attr_set, stored          */

  /* All other values are not attr_set.
   */
  ats_parcel_in  = 2,   /* => incoming "route_parcel"   */
  ats_parcel_out = 3,   /* => outgoing "route_parcel"   */

  ats_route_mpls = 4,   /* => state of mpls adj_out     */

  /* It's a byte, guys
   */
  ats_limit,
  ats_last       = ats_limit - 1,
} ;

CONFIRM(((uint)ats_last <= BYTE_MAX)
                                    && (sizeof(attr_state_t) >= sizeof(byte))) ;

/*==============================================================================
 * Other common types
 */

/* AS Numbers
 */
typedef uint32_t as_t ;         /* general ASN                  */

/* TTL value
 */
typedef byte ttl_t ;
CONFIRM(MAXTTL <= 255) ;

/* Port number
 *
 * NB: we use port_t where we have a *host* order port number, and in_port_t
 *     where we have the network order port number.
 */
typedef in_port_t port_t ;

/* A single MPLS Label, as a simple 20-bit integer -- 0x00000..0xFFFFF
 */
typedef uint32_t mpls_label_t ;

enum
{
  mpls_label_bad      = UINT32_MAX - 1, /* value >= to this is bad      */

  mpls_label_invalid  = UINT32_MAX - 1,
  mpls_label_overflow = UINT32_MAX,
} ;

CONFIRM(mpls_label_invalid  > (uint)MPLS_LABEL_LAST) ;
CONFIRM(mpls_label_overflow > (uint)MPLS_LABEL_LAST) ;

/* Opaque value representing an MPLS Tag Stack.
 *
 * Convenient to have an mpls_tags_t for simple comparison of tag values, for
 * equality at least.
 *
 * At present, Quagga allows only one level of tag stack -- so the "opaque"
 * value is the 24 bit RFC3017 label, in Host Order, complete with BoS bit.
 *
 * Since the BoS bit is not zero, we can use zero as a null, "no tag" value.
 */
typedef uint32_t mpls_tags_t ;

enum
{
  mpls_tags_null     = 0,               /* no tag                       */

  mpls_tags_bad      = UINT32_MAX - 1,  /* value >= to this is bad      */

  mpls_tags_invalid  = UINT32_MAX - 1,
  mpls_tags_overflow = UINT32_MAX,
} ;


/*==============================================================================
 * Sexing functions for qafx_t
 *
 * NB: these depend critically on the order of values in the qafx_t enum.
 */

/*------------------------------------------------------------------------------
 * Is AFI IPv4 ?
 */
Inline bool
qafx_is_ipv4(qafx_t num)
{
#define QAFX_IS_IPV4(num) \
          ((uint)num <= (uint)qafx_ipv4_mpls_vpn)

  return QAFX_IS_IPV4(num) ;

  confirm(!QAFX_IS_IPV4(qafx_undef)) ;

  confirm(QAFX_IS_IPV4(qafx_ipv4_unicast)) ;
  confirm(QAFX_IS_IPV4(qafx_ipv4_multicast)) ;
  confirm(QAFX_IS_IPV4(qafx_ipv4_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV4(qafx_ipv6_unicast)) ;
  confirm(!QAFX_IS_IPV4(qafx_ipv6_multicast)) ;
  confirm(!QAFX_IS_IPV4(qafx_ipv6_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV4(qafx_other)) ;

#undef QAFX_IS_IPV4
} ;

/*------------------------------------------------------------------------------
 * Is AFI IPv6 ?
 */
Inline bool
qafx_is_ipv6(qafx_t num)
{
#define QAFX_IS_IPV6(num) \
                ((num >= qafx_ipv6_unicast) && (num <= qafx_ipv6_mpls_vpn))

  return QAFX_IS_IPV6(num) ;

  confirm(!QAFX_IS_IPV6(qafx_undef)) ;

  confirm(!QAFX_IS_IPV6(qafx_ipv4_unicast)) ;
  confirm(!QAFX_IS_IPV6(qafx_ipv4_multicast)) ;
  confirm(!QAFX_IS_IPV6(qafx_ipv4_mpls_vpn)) ;

  confirm(QAFX_IS_IPV6(qafx_ipv6_unicast)) ;
  confirm(QAFX_IS_IPV6(qafx_ipv6_multicast)) ;
  confirm(QAFX_IS_IPV6(qafx_ipv6_mpls_vpn)) ;

  confirm(!QAFX_IS_IPV6(qafx_other)) ;

#undef QAFX_IS_IPV6
} ;

/*------------------------------------------------------------------------------
 * Is SAFI Unicast ?
 */
Inline bool
qafx_is_unicast(qafx_t num)
{
  return (num == qafx_ipv4_unicast) || (num == qafx_ipv6_unicast) ;
} ;

/*------------------------------------------------------------------------------
 * Is SAFI Multicast ?
 */
Inline bool
qafx_is_multicast(qafx_t num)
{
  return (num == qafx_ipv4_multicast) || (num == qafx_ipv6_multicast) ;
} ;

/*------------------------------------------------------------------------------
 * Is SAFI MPLS VPN (iSAFI == 128) ?
 */
Inline bool
qafx_is_mpls_vpn(qafx_t num)
{
  return (num == qafx_ipv4_mpls_vpn) || (num == qafx_ipv6_mpls_vpn) ;
} ;


/*==============================================================================
 * Conversions for qafx_t => qAFI, qSAFI, iAFI, iSAFI and pAF
 */

/*------------------------------------------------------------------------------
 * Convert qafx_t to qAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown values to qAFI_undef
 */
extern const qAFI_t qAFI_map[qafx_count] ;

Inline qAFI_t
get_qAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return qAFI_map[num] ;
  else
    return qAFI_undef ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to qSAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown values to qSAFI_undef
 */
extern const qSAFI_t qSAFI_map[qafx_count] ;

Inline qSAFI_t
get_qSAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return qSAFI_map[num] ;
  else
    return qSAFI_undef ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to iAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to iAFI_Reserved
 */
extern const iAFI_t iAFI_map[qafx_count] ;

Inline iAFI_t
get_iAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return iAFI_map[num] ;
  else
    return iAFI_Reserved ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to iSAFI_xxx
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to iSAFI_Reserved
 */
extern const iSAFI_t iSAFI_map[qafx_count] ;

Inline iSAFI_t
get_iSAFI(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return iSAFI_map[num] ;
  else
    return iSAFI_Reserved ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to AF_xxx (pAF_t)
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to AF_UNSPEC
 */
extern const sa_family_t sa_family_map[qafx_count] ;

Inline sa_family_t
get_qafx_sa_family(qafx_t num)
{
  if ((uint)num < (uint)qafx_count)
    return sa_family_map[num] ;
  else
    return AF_UNSPEC ;
} ;

/*------------------------------------------------------------------------------
 * Convert qafx_t to string
 *
 * Maps qafx_other, qafx_undef and any unknown qafx_num to AF_UNSPEC
 */
extern const char* qafx_name_map[qafx_max + 1] ;

Inline const char*
get_qafx_name(qafx_t num)
{
  if ((uint)num <= (uint)qafx_max)
    return qafx_name_map[num] ;
  else
    return "??invalid qafx??" ;
} ;

/*==============================================================================
 * Conversions for iAFI/iSAFI => qafx_t
 *             and qAFI/qSAFI => qafx_t
 *
 *             and iAFI/iSAFI => qafx_bit_t
 *             and qAFI/qSAFI => qafx_bit_t
 */
extern qafx_t qafx_from_i(iAFI_t afi, iSAFI_t safi) ;
extern qafx_t qafx_from_q(qAFI_t afi, qSAFI_t safi) ;
extern qafx_bit_t qafx_bit_from_i(iAFI_t afi, iSAFI_t safi) ;
extern qafx_bit_t qafx_bit_from_q(qAFI_t afi, qSAFI_t safi) ;


#endif /* _QUAGGA_BGP_COMMON_H */

