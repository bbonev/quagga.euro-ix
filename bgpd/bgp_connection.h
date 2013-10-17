/* BGP Connection Handling -- header
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

#ifndef _QUAGGA_BGP_CONNECTION_H
#define _QUAGGA_BGP_CONNECTION_H

#include "lib/misc.h"

#include "lib/mqueue.h"
#include "lib/qpthreads.h"
#include "lib/qtimers.h"
#include "lib/qpselect.h"

#include "lib/sockunion.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_msg_read.h"
#include "bgpd/bgp_msg_write.h"
#include "bgpd/bgp_route_refresh.h"

/*==============================================================================
 * BGP Connection Options Structure
 *
 * This is a discrete structure so that the accept() handling can handle these
 * things without requiring the complete bgp_connection or bgp_session !
 */

/* Whether the connection is prepared to accept and/or connect and/or track.
 *
 * This is the primary control over the connection handling in the BGP Engine,
 * and lives in the connection options as transmitted to the BGP Engine.
 *
 *   * csMayAccept      -- is allowed to accept() a connection
 *
 *   * csMayConnect     -- is allowed to make a connect() connection
 *
 *   * csTrack          -- run the acceptor and track incoming connections
 *
 *                         Ignored if not csMay_Accept !
 *
 *                         This is cleared if the peer is pisDown
 *
 *   * csRun            -- run the session or session acquisition.
 *
 *                         Ignored if not csMay_Accept or csMay_Connect,
 *                         unless a session is established already.
 *
 *                         This is cleared if the peer is not pisRunnable
 *
 * Note that may be csRun without either csMayAccept/Connect.  In particular,
 * once a session is Established, changes to csMayAccept/Connect do not affect
 * the session, but clearing csRun brings it down.
 *
 * When a peer is stopped, will clear csRun, and when it is down, will clear
 * both csRun and csTrack.
 */
typedef enum bgp_conn_state bgp_conn_state_t ;
enum bgp_conn_state
{
  bgp_csDown        = 0,

  bgp_csMayAccept   = BIT(0),
  bgp_csMayConnect  = BIT(1),

  bgp_csMayMask     = bgp_csMayAccept | bgp_csMayConnect,
  bgp_csMayBoth     = bgp_csMayAccept | bgp_csMayConnect,

  bgp_csTrack       = BIT(4),
  bgp_csRun         = BIT(5),

  bgp_csCanTrack    = bgp_csTrack | bgp_csMayAccept,
} ;

typedef struct bgp_cops bgp_cops_t ;

struct bgp_cops
{
  /* For configuration options:
   *
   *   su_remote    = peer->su_name      -- used by connect() and listen()
   *   su_local     = for bind()         -- used by connect()
   *
   *   The su_local is, for example, set by "neighbor xx update-source <addr>".
   *
   *   NB: ifname takes precedence over su_local.
   *
   * For connections once connect() or accept() have succeeded
   *
   *   su_remote    = getpeername()
   *   su_local     = getsockname()
   *
   * NB: these are embedded, so can be copied around etc. without fuss.
   */
  sockunion_t su_remote ;
  sockunion_t su_local ;

  /* The port to be used or currently in use.
   */
  in_port_t port ;

  /* Whether to connections are shutdown/disabled/enabled.
   */
  bgp_conn_state_t  conn_state ;

  /* Flag so can suppress sending NOTIFICATION messages without first
   * sending an OPEN -- just in case, but default is to not send !
   */
  bool      can_notify_before_open ;

  /* Timer intervals for pre-OPEN timers.
   */
  uint       idle_hold_max_secs ;
  uint       connect_retry_secs ;
  uint       accept_retry_secs ;
  uint       open_hold_secs ;

  /* Both connect() and accept() will attempt to set the required ttl/gtsm
   *
   * The ttl and gtsm are configuration options, which are unchanged by
   * attempts to set them.
   *
   * ttl_out and ttl_min are set when a connection is actually made, and
   * reflect what was possible at the time.  They default to TTL_MAX and
   * 0 respectively.
   *
   * If gtsm is true, then ttl_min == 0 => either GTSM not yet set, or
   * failed to set it when we tried.  When gtsm is true, ttl_out is set to
   * TTL_MAX, whether succeeds in setting GTSM or not.
   *
   * NB: if gtsm is requested, the ttl is the maximum number of hops to/from
   *     the remote end.  The ttl set on outgoing packets will be 0xFF.  The
   *     maximum allowed incoming ttl will be 0xFF less the nominal ttl.
   */
  ttl_t     ttl ;               /* 1..TTL_MAX                           */
  bool      gtsm ;              /* set GTSM if possible                 */

  ttl_t     ttl_out ;           /* actual value set                     */
  ttl_t     ttl_min ;           /* actual min_ttl -- 0 <=> not GTSM     */

  /* Both connect() and listen() will apply MD5 password to connections.
   *
   * NB: this is embedded, so can be copied around etc. without fuss.
   */
  bgp_password_t password ;     /* copy of MD5 password                 */

  /* For configuration options:
   *
   *   ifname       = if to bid to, if any -- used by connect()
   *   ifindex      = N/A
   *
   *   The ifname is set, for example, by "neighbor xx update-source <name>"
   *
   *   Note that if the ifname is set, su_local is ignored.
   *
   * For connections once connect() or accept() have succeeded
   *
   *   ifname       = set to the interface name   ) from the getsockname()
   *   ifindex      = set to the interface index  ) address, via certain magic
   *
   * NB: these are embedded, so can be copied around etc. without fuss.
   */
  bgp_ifname_t ifname ;         /* interface to bind to, if any         */

  uint         ifindex ;        /* and its index, if any                */
} ;

/*==============================================================================
 * BGP Connection Structure
 *
 * The BGP Connection is the main data structure for the FSM.
 *
 * When a session terminates, or a connection is shut it may have a short
 * independent life, if a NOTIFICATION message is pending.
 *
 * A session may have two connections -- connect() and accept(), one of which
 * will (we sincerely hope) become the established connection.
 */
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

enum
{
  IO_Hold_Time          = 5,            /* seconds      */
  Extension_Hold_Time   = 5,            /* seconds      */

  Open_Hold_Time        = 4 * 60,       /* seconds      */

  /* Sizes for: read ring-buffer -- which currently carries raw UPDATEs
   */
  bgp_read_rb_size  =  32 * BGP_MSG_MAX_L,      /* 128K         */
  bgp_write_rb_size =  32 * BGP_MSG_MAX_L,      /* 128K         */
} ;

CONFIRM(BGP_MSG_MAX_L == 4096) ;        /* if not, reconsider the above */

/*------------------------------------------------------------------------------
 * How to log stuff for given connection
 */
typedef struct bgp_connection_logging  bgp_connection_logging_t ;

struct bgp_connection_logging
{
  char*             name ;              /* peer "name" (+ tag)          */
  struct zlog*      log ;               /* where to log to              */
} ;

/*------------------------------------------------------------------------------
 * The Connection Structure
 */
struct bgp_connection
{
  struct dl_list_pair(bgp_connection) exist ;
                                        /* existing connections         */

  bgp_session       session ;           /* parent session
                                         * NULL if connection stopping  */

  bgp_conn_ord_t    ord ;               /* accept/connect connection    */
  bgp_connection_logging_t lox ;        /* how to log                   */

  /* The event state
   */
  struct dl_list_pair(bgp_connection) event_ring ;
                                        /* connections with events      */
  bgp_fsm_meta_t    meta_events ;

  bgp_fsm_event_t   admin_event ;
  bgp_note          admin_note ;

  bgp_fsm_event_t   socket_event ;
  int               socket_err ;

  /* The finite state machine state of the connection, and its sub-state
   * flags.
   */
  bgp_fsm_state_t   fsm_state ;         /* FSM state of connection      */
  qfile_state_t     io_state ;          /* I/O state of connection      */

  bgp_fsm_idle_state_t idling_state ;   /* in fsIdle and fsStop         */
  qtime_t           idle_time_pending ; /* after Notification-Hold-Time */

  bool              holdtimer_suppressed ;      /* fsOpenConfirm and
                                                 * fsEstablished        */

  bool              delaying_open ;     /* fsConnect or fsActive and
                                         * DelayOpenTimer running       */

  /* The qfile and the connection options for this connection.
   *
   * For connect() the qf is set when the connect() starts, successfully.
   * The cops are copied from the session at the point the connect() is
   * started.  They are updated when the connect() succeeds.
   *
   * For accept() the qf is co-opted from the acceptor, and the cops are
   * copied from the acceptor at the same time.
   *
   * So connection only holds the effective cops.  The session holds the
   * cops_config.
   */
  qfile             qf ;                /* qpselect file structure      */
  bgp_cops cops ;         /* connection options in force  */

  /* The opens as sent and received and stuff.
   *
   *   * open_sent/open_recv are not set until actually sends/receives OPEN.
   *
   *   * local_id and remote_as are set when the connection is created, so
   *     that are on hand if OPEN is received (even if connection no longer
   *     attached to session !!)
   */
  bgp_open_state    open_sent ;         /* the open as sent             */
  bgp_open_state    open_recv ;         /* the open received.           */

  /* Properties of a connection while we are trying to make one.
   *
   *   * cap_suppress starts false, but if at any time the far end rejects
   *     Capability Option, we set this true and try again.  If we succeed
   *     in getting to OpenConfirm, but then reject the OPEN, we clear the
   *     flag before going back to sIdle.
   *
   *     So... if suppressing capabilities doesn't do the job, will keep
   *     trying, with and without capabilities, until get something.
   *
   *   * idle_hold_time is set when the session is enabled.
   *
   *     Each time passes through sIdle after a failure, increases this.
   */
  bool              cap_suppress ;
  qtime_t           idle_hold_time ;

  /* Timer objects.
   */
  bgp_fsm_timer_t   hold_timer[1] ;
  bgp_fsm_timer_t   keepalive_timer[1] ;

  /* Reader I/O for the connection.
   *
   * The ring-buffer belongs to the session, and this pointer to it is
   * set while the session is fsEstablished.  When a session falls out of
   * fsEstablished the connection loses interest, removes anything it needs
   * from the ring-buffer and forgets about it.  The Routeing Engine will
   * discard the ring-buffer when it sees the session stop.
   */
  bgp_msg_reader    reader ;            /* reading of messages          */
  ring_buffer       read_rb ;           /* ring buffer to read into     */

  /* Writer I/O for the connection.
   *
   * The ring-buffer belongs to the session, and this pointer to it is
   * set while the session is established.  When a session falls out of
   * fsEstablished the connection loses interest, removes anything it needs
   * from the ring-buffer and forgets about it.  The Routeing Engine will
   * discard the ring-buffer when it sees the session stop.
   */
  bgp_msg_writer    writer ;            /* writing of messages          */
  ring_buffer       write_rb ;          /* ring buffer to write from    */
} ;

/*==============================================================================
 * Accepting connections object
 */
typedef enum bgp_accept_state bgp_accept_state_t ;

enum bgp_accept_state
{
  bacs_unset   = 0,     /* not yet set or has been unset                */

  bacs_idle,            /* waiting after session established            */
  bacs_listening,       /* waiting for connection                       */
  bacs_paused,          /* waiting before starting to read              */
  bacs_open_awaited,    /* told FSM (if any), waiting for an OPEN       */
  bacs_open_received,   /* OPEN has arrived                             */
  bacs_busted,          /* something, incomplete, before/after OPEN     */
} ;

typedef enum bgp_accept_pending bgp_accept_pending_t ;

enum bgp_accept_pending
{
  bacp_none   = 0,      /* nothing pending                              */

  bacp_close,           /* waiting to close a connection                */
  bacp_open,            /* waiting for complete opening one             */
} ;

typedef struct bgp_acceptor bgp_acceptor_t ;

struct bgp_acceptor
{
  bgp_session        session ;          /* to which the acceptor belongs  */
  bgp_connection_logging_t lox ;        /* how to log                   */

  /* The state:
   *
   *   * bacs_unset        => not configured
   *
   *     This is the state before an acceptor is fully initialised, or while
   *     it is being closed down.
   *
   *   * bacs_idle         => an outgoing connection reached fsEstablished,
   *                          the acceptor at the time will have been closed,
   *                          but placed in this state so that incoming
   *                          connections are "blanked" for a while.
   *
   *     There may be a pending close if we have seen an incoming connection
   *     while idle.
   *
   *     There is no current connection and no pending open.
   *
   *     On an incoming connection (don't care if it's acceptable or not):
   *
   *       if there is a previous close pending, close it now.
   *       set close_pending (Collision Resolution), LEAVING the timer.
   *
   *     Timer running, when it expires: if there is a close pending, deal with
   *     it, then change to bacs_listening.
   *
   *   * bacs_listening    => ready for accept() -- no current connection.
   *
   *     NB: if configured to not actually accept, will reject connections
   *         at this point.
   *
   *         The peer, session and acceptor all exist while the peer is
   *         configured.  When the peer/session is shut-down will be set to not
   *         accept connections.  When the peer/session is disabled, will
   *         accept connections and hold on to them.  A peer/session may be
   *         enabled, but configured not to accept, in which case, will reject
   *         here.
   *
   *     There is no current connection and no pending close or open, and
   *     no timer is running.
   *
   *     On an incoming connection, if it is acceptable, change up to
   *     bacs_open_awaited, and:
   *
   *         set the current connection
   *         set read-ready
   *         set timer to AcceptRetryTime
   *         tell FSM (if any) that an accept() connection has been accepted.
   *
   *     If not acceptable, reject the connection (immediately) and then go to
   *     bacs_paused with a time-out -- so the first not acceptable is
   *     responded to instantly, but any further connections will be subject
   *     to a short delay.
   *
   *   * bacs_paused       => delaying things...
   *                          ... may have a pending close or a pending open
   *                              (but not both) and may be neither.
   *
   *     Timer running -- balance of pause.
   *
   *     On an incoming connection:
   *
   *       If there is a pending close, complete it now.
   *
   *       If there is a pending open, reject it now.
   *
   *       If connection is acceptable, set pending open.
   *       Otherwise, set pending close.
   *
   *     On time-out:
   *
   *       If there is a pending close, complete it, and go bacs_listening.
   *
   *       If there is a pending open, go to bacs_open_awaited, as above.
   *
   *       Otherwise, go bacs_listening.
   *
   *   * bacs_open_awaited    => have a connection up, in various states of
   *   * bacs_open_received      completion of the process
   *   * bacs_busted
   *
   *     Timer running -- the AcceptRetryTime, or a short time if bacs_busted.
   *
   *     Cannot have a close pending or an open pending.
   *
   *     If fails, if failed on an incomplete message, reset the timer to
   *     a short wait for the message to complete and change to bacs_busted.
   *     On all other failures, set a pending close (with timer) and fall back
   *     to bacs_paused.
   *
   *     On an incoming connection, close immediately, and:
   *
   *       If acceptable, set pending open and go bacs_paused with a time-out.
   *
   *       If not acceptable, set pending close with a time-out.
   *
   *     On time-out, close immediately and fall back to bacs_listening.
   */
  bgp_accept_state_t state ;

  int           sock_fd_pending ;
  bgp_accept_pending_t  pending ;
  bgp_note      note ;

  bgp_cops      cops ;
  sockunion     su_password ;

  qfile          qf ;
  bgp_msg_reader reader ;

  qtimer        timer ;
} ;

/*==============================================================================
 * The functions
 */
extern void bgp_connections_init(void) ;
extern void bgp_connections_stop(void) ;

extern bgp_connection bgp_connection_init_new(bgp_connection connection,
                                  bgp_session session, bgp_conn_ord_t ordinal) ;
extern void bgp_connection_start(bgp_session session, bgp_conn_ord_t ord) ;

extern void bgp_connection_free(bgp_connection connection) ;
extern bgp_cops bgp_connection_prepare(bgp_connection connection) ;
extern qfile bgp_connection_connecting(bgp_connection connection, int sock_fd) ;

extern bool bgp_connection_io_start(bgp_connection connection) ;

extern bgp_note bgp_connection_establish(bgp_connection connection) ;
extern bgp_connection bgp_connection_get_sibling(bgp_connection connection) ;
extern void bgp_connection_down(bgp_connection connection) ;
extern void bgp_connection_shut_rd(bgp_connection connection) ;
extern void bgp_connection_shut_wr(bgp_connection connection) ;


extern int bgp_connection_queue_process(void) ;


extern void bgp_acceptor_set_cops(bgp_session session, bgp_cops_c new_config) ;
extern bgp_acceptor bgp_acceptor_free(bgp_acceptor acceptor) ;
extern void bgp_acceptor_cops_reset(bgp_acceptor acceptor) ;
extern void bgp_acceptor_accept(bgp_acceptor acceptor, int sock_fd, bool ok,
                                                          sockunion_c sock_su) ;

extern bgp_fsm_event_t bgp_acceptor_state(bgp_acceptor acceptor) ;
extern void bgp_acceptor_squelch(bgp_acceptor acceptor) ;

extern bgp_cops bgp_cops_init_new(bgp_cops cops) ;
extern bgp_cops bgp_cops_copy(bgp_cops dst, bgp_cops_c src) ;
extern bgp_cops bgp_cops_dup(bgp_cops_c src) ;
extern bgp_cops bgp_cops_reset(bgp_cops cops) ;
extern bgp_cops bgp_cops_free(bgp_cops cops) ;

#endif /* QUAGGA_BGP_CONNECTION_H */
