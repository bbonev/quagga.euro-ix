/* BGP-4 Finite State Machine
 * From RFC1771 [A Border Gateway Protocol 4 (BGP-4)]
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Recast for pthreaded bgpd: Copyright (C) Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_FSM_H
#define _QUAGGA_BGP_FSM_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_notification.h"

#include "qpselect.h"
#include "qtimers.h"

/*==============================================================================
 * The BGP Finite State Machine
 *
 * Each connection has its FSM.
 */

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

/*------------------------------------------------------------------------------
 * Connection "meta-events".
 */
typedef enum bgp_fsm_meta bgp_fsm_meta_t ;

enum bgp_fsm_meta
{
  bgp_fmStop             = 0,
  bgp_fmRun              = BIT( 0),

  bgp_fmKeepaliveTimer   = BIT( 1),
  bgp_fmHoldTimer        = BIT( 2),
  bgp_fmIO               = BIT( 3),
  bgp_fmSocket           = BIT( 4),
  bgp_fmAdmin            = BIT( 5),

  bgp_fmNULL             = 0,           /* for no event set     */
} ;

/*------------------------------------------------------------------------------
 * The idle state is used to manage timer(s) in fsIdle/fsStop.
 *
 * If some I/O is running, IO-Hold-Timer is running.
 *
 * In fsIdle, there will be a follow on IdleHoldTime, and possibly an
 * extension to that.
 *
 * In fsStop, there can only be the IO-Hold-Time.
 *
 * The IO-Hold-Time is a local invention.  It is
 *
 *   1) the time we are prepared to wait for an outgoing NOTIFICATION
 *      (and/or any other pending stuff) to be written away to the system.
 *
 *   2) the time we are prepared to wait for the reader to hit eof, or fail
 *      or for a NOTIFICATION to arrive.  We do this so that we tidy up any
 *      remaining input, which may include a NOTIFICATION.
 *
 *      If the write side detects an error it may do so before the read side
 *      sees it, because the read side defers errors while there is buffered
 *      input.  So we allow some time to keep reading to tidy that up.  When
 *      the write side does detect an error it will SHUT_WR, so the far end
 *      should see that, and act accordingly.
 *
 *   3) the minimum IdleHoldTime if there was any of (1) or (2) when
 *      enters fsIdle.
 *
 *      If goes from fsIdle to fsStop, as soon as the io_state goes fDown, the
 *      connection will be stopped.
 *
 * The idle state is:
 *
 *     1. fisExtended   -- fsIdle only -- qfDown
 *
 *        When the extension timer goes off, will leave fsIdle.
 *
 *        If goes to stopping, can exit immediately.
 *
 *     2. fisHold       -- fsIdle only -- qfDown
 *
 *        When the timer goes off the fsIdle is done, unless we extend it.
 *
 *        When fsIdle is done, if there is a sibling in fsOpenSent or
 *        fsOpenConfirm, then the IdleHoldTime is extended by a little, once.
 *
 *     3. fisIO         -- fsIdle or fsStop
 *
 *        in fsIdle:
 *
 *          * if the connection goes fDown, for whatever reason, the
 *            connection can be closed -- but the timer is left running.
 *
 *          * when the timer goes off, the connection can be closed.
 *
 *            Proceeds to fisHold, to run the balance of the full IdleHoldTime
 *            (the balance is arranged to not be zero).
 *
 *        in fsStop:
 *
 *          * if the connection goes fDown, for whatever reason, the
 *            connection is stopped.
 *
 *          * when the timer goes off, the connection is stopped.
 */
typedef enum bgp_fsm_idle_state bgp_fsm_idle_state_t ;
enum bgp_fsm_idle_state
{
  bgp_fisNULL   = 0,
  bgp_fisExtended,
  bgp_fisHold,
  bgp_fisIO,
} ;

/*------------------------------------------------------------------------------
 * A parcel for an event in the FSM, which may be copied to the session and
 * back to the peer.
 */
typedef struct bgp_fsm_eqb* bgp_fsm_eqb ;
typedef struct bgp_fsm_eqb  bgp_fsm_eqb_t ;

struct bgp_fsm_eqb
{
  bgp_fsm_event_t  fsm_event ;
  bgp_note         note ;
  int              err ;
} ;

/*------------------------------------------------------------------------------
 * FSM Timer.
 */
enum bgp_fsm_timer_state
{
  bfts_stopped      = 0,
  bfts_running,
  bfts_suspended,
  bfts_expired,
} ;
typedef enum bgp_fsm_timer_state bgp_fsm_timer_state_t ;

typedef struct bgp_fsm_timer  bgp_fsm_timer_t ;
typedef struct bgp_fsm_timer* bgp_fsm_timer ;

struct bgp_fsm_timer
{
  bgp_connection  connection ;
  bgp_fsm_meta_t  fsm_meta ;
  bgp_fsm_event_t fsm_event ;

  qtimer        qtr ;
  qtime_t       interval ;

  uint          jitter ;
  qtime_t       jitter_unit ;

  bgp_fsm_timer_state_t state ;
} ;

/*==============================================================================
 * Prototypes.
 */
extern void bgp_fsm_start_session(bgp_session session) ;
extern bgp_note bgp_fsm_stop_session(bgp_session session, bgp_note note) ;
extern void bgp_fsm_start_connection(bgp_connection connection) ;
extern void bgp_fsm_restart_connection(bgp_connection connection,
                                                                bgp_note note) ;
extern void bgp_fsm_stop_connection(bgp_connection connection,
                                                                bgp_note note) ;

extern void bgp_fsms_init(void) ;
extern void bgp_fsms_stop(void) ;
extern void bgp_fsm_events_flush(bgp_connection connection) ;
extern int bgp_fsm_events_run(void) ;

extern void bgp_fsm_io_event(bgp_connection connection) ;

extern void bgp_fsm_accept_event(bgp_session session,
                                                    bgp_fsm_event_t fsm_event) ;
extern void bgp_fsm_connect_event(bgp_connection connection,
                                                         int sock_fd, int err) ;

extern bgp_fsm_event_t bgp_fsm_io_failed(bgp_connection_logging plox,
                                      int sock_fd, int err, const char* where) ;

extern void bgp_fsm_timer_init(bgp_fsm_timer ft, bgp_connection connection) ;
extern void bgp_fsm_timer_stop(bgp_fsm_timer ft) ;
extern void bgp_fsm_timer_free(bgp_fsm_timer ft) ;
extern void bgp_keepalive_timer_recharge(bgp_connection connection) ;
extern void bgp_keepalive_timer_suspend(bgp_connection connection) ;

#endif /* _QUAGGA_BGP_FSM_H */
