/* BGP Session -- header
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

#ifndef _QUAGGA_BGP_SESSION_H
#define _QUAGGA_BGP_SESSION_H

#include <zebra.h>
#include "lib/misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_route_refresh.h"

#include "lib/qtimers.h"
#include "lib/qpthreads.h"
#include "lib/sockunion.h"
#include "lib/mqueue.h"
#include "lib/stream.h"
#include "lib/ring_buffer.h"

/*==============================================================================
 * BGP Session and Related data structures.
 *
 * The bgp_session structure encapsulates a BGP session from the perspective
 * of the BGP Engine, and that is shared with the Routeing Engine.
 *
 * The session may have up to two BGP connections associated with it, managed
 * by the BGP Engine.
 *
 * The session includes the "negotiating position" for the BGP Open exchange,
 * which is managed by the BGP Engine.  Changes to that negotiating position
 * may require any existing session to be terminated.
 */

/* Statistics
 */
typedef struct bgp_session_stats  bgp_session_stats_t ;
typedef struct bgp_session_stats* bgp_session_stats ;

struct bgp_session_stats
{
  uint   open_in;               /* Open message input count             */
  uint   open_out;              /* Open message output count            */
  uint   update_in;             /* Update message input count           */
  uint   update_out;            /* Update message ouput count           */
  time_t update_time;           /* Update message received time.        */
  uint   keepalive_in;          /* Keepalive input count                */
  uint   keepalive_out;         /* Keepalive output count               */
  uint   notify_in;             /* Notify input count                   */
  uint   notify_out;            /* Notify output count                  */
  uint   refresh_in;            /* Route Refresh input count            */
  uint   refresh_out;           /* Route Refresh output count           */
  uint   dynamic_cap_in;        /* Dynamic Capability input count.      */
  uint   dynamic_cap_out;       /* Dynamic Capability output count      */
};

/*------------------------------------------------------------------------------
 * The Session structure
 *
 * The session structure represents a peer as far as the BGP Engine (BE) is
 * concerned.  The session is created at the same time as the peer and its
 * peer index entry -- by the Routeing Engine (RE).  When a peer is destroyed,
 * the session and peer index entry are cut off from the peer -- by the RE --
 * and a message is set to the BE to destroy the session.
 *
 * Parts of the session structure are used exclusively by the RE, parts are
 * used exclusively by the BE and others are either protected by atomic
 * operations, or are used by the RE or the BE in different states of same.
 *
 * The RE and BE communicate via messages.  So state at either end depends on
 * when messages are sent, and when they are received.  A (very few) things
 * may change under atomic operation, which may signal things directly.
 *
 * The RE (peer) has a view of the session state, such that:
 *
 *   * psInitial     -- session is being created (by the RE).
 *   * psDown        -- session is down
 *
 *     the session belongs to the Routing Engine.
 *
 *     the BGP Engine will not touch a session in these states and the
 *     Routing Engine may do what it likes with it.
 *
 *     EXCEPT that once the session has been created, the following are
 *     always active in the BE:
 *
 *       cops_config   -- which is used by the acceptor.
 *
 *       acceptor      -- which runs pretty much autonomously.
 *
 *     And the RE may not touch these.
 *
 *   * psUp          -- session has been enabled
 *   * psLimping     -- session has been disabled, but is yet to stop
 *
 *     These are the "active" states:
 *
 *       the session belongs to the BGP Engine.
 *
 *       some items in the session are private to the Routing Engine.
 *
 *     a (very) few items in the session may be accessed by both the Routing
 *     and BGP engines, as noted below -- subject to atomic operations.
 *
 *   * bgp_psDeleted  -- session has gone, from RE perspective
 *
 * Only the Routing Engine creates sessions.  Only the BGP Engine destroys them.
 */
typedef struct bgp_session bgp_session_t ;

struct bgp_session
{
  /* The session->peer and session->peer_ie pointers are set when the peer,
   * session and peer index entry are created, and before the session is
   * passed to the BE.
   *
   * When the peer is deleted (by the RE), the session->peer is set NULL
   * (atomically) to signal that the session is now moribund -- and the
   * peer cuts its pointers to the session and peer index entry, and the peer
   * index entry is removed from its peer name index.  A message is sent to
   * the BE to destroy the session.  (So peer can read this without locking,
   * but BE must read atomically.)
   *
   * The peer_ie pointer is only used by the BE.
   */
  bgp_peer             peer ;
  bgp_peer_index_entry peer_ie ;

  /* These are private to the RE.
   */
//bgp_peer_session_state_t peer_state ;

  int               flow_control ;      /* limits number of updates sent
                                         * by the Routing Engine        */

  bool              xon_awaited ;       /* set when XON is requested    */

  bool              delete_me ;         /* when next goes psDown        */

  bgp_connection_ord_t ordinal_established ;    /* when pEstablished    */

  /* These are private to the RE, and are set each time a session event message
   * is received from the BE.
   *
   * The ordinal returned in the event message identifies which connection
   * the event is for.  In the case of an eEstablished event, the ordinal is
   * the ordinal *before* the session became established.
   */
  bgp_fsm_event_t       fsm_event ;     /* last event                   */
  bgp_notify            notification ;  /* if any sent/received         */
  int                   err ;           /* errno, if any                */
  bgp_connection_ord_t  ordinal ;       /* primary/secondary connection */

  /* The following are set by the RE before a session is enabled, and not
   * changed at any other time by either engine.
   */
  qtime_t           idle_hold_timer_interval ;

  as_t              local_as ;          /* ASN here                     */
  in_addr_t         local_id ;          /* BGP-Id here                  */

  as_t              remote_as ;         /* ASN of the peer              */

  sockunion         su_peer ;           /* address of the peer          */

  bgp_connection_logging_t lox ;

  /* The session arguments and open messages.
   *
   * The Routeing Engine sets the session arguments when the session is
   * enabled.

   *   * args_tx -- transfer from RE to BE.
   *
   *     The args_tx is set by the RE and cleared by the BE -- using an atomic
   *     swap.
   *
   *     These are created when a session is enabled, and set by the RE.
   *     If the arguments are changed, the RE creates a new set of arguments,
   *     sets args_tx.  If args_tx existed before, those are now redundant.
   *     If no args_tx existed before, the BE needs to be kicked.
   *
   *   * args_config -- session configuration -- belong to the BE *ALWAYS*.
   *
   *     The args_config are set from the args_tx when the BE is kicked, or a
   *     session is enabled.  It is copied to connections when a connection is
   *     made or accepted.
   *
   *   * args -- actual session state, once established -- transfer BE to RE.
   *
   *     The args are set from the current connection when a session is
   *     established, and not changed again by the BE.  These are copied to the
   *     peer when the session is established.
   *
   * The BGP Engine sets the state of the OPEN message which was sent and the
   * one received for the session which is now established.
   */
  bgp_session_args  args_tx ;
  bgp_session_args  args_config ;
  bgp_session_args  args ;

  bgp_open_state    open_sent ;         /* set when session Established */
  bgp_open_state    open_recv ;         /* set when session Established */

  /* Session ring-buffers -- created by BE, belong to RE once Established
   *
   * These are created by the BE when the session becomes established, and are
   * then used to transfer UPDATEs in (read_rb) and UPDATEs and Route Refresh
   * out (write_rb).
   *
   * While the session is established, these are shared by the BE and RE.
   * When the session stops, the BE stops using these, and the RE can discard.
   */
  ring_buffer   read_rb ;
  ring_buffer   write_rb ;

  /* Connection options
   *
   *   * cops_tx -- transfer from RE to BE.
   *
   *     The cops_tx is set by the RE and cleared by the BE -- using an atomic
   *     swap.
   *
   *     When the options change, the RE creates a new set of connection
   *     options, and sets cops_tx.  If cops_tx existed before, those are now
   *     redundant.  If no cops_tx existed before, the BE needs to be kicked.
   *
   *   * cops_config -- session configuration -- belong to the BE *ALWAYS*.
   *
   *     The cops_config are set from the cops_tx when the BE is kicked, or a
   *     session is enabled.  It is copied to the acceptor and/or connections
   *     when a connection is accepted or made.
   *
   *   * cops -- actual session state, once established -- transfer BE to RE.
   *
   *     The cops are set from the current connection when a session is
   *     established, and not changed again by the BE.  These are copied to the
   *     peer when the session is established.
   */
  bgp_connection_options  cops_tx ;
  bgp_connection_options  cops_config ;
  bgp_connection_options  cops ;

  /* These values are are private to the BGP Engine.
   *
   * They must be cleared before the session is enabled, but may not be
   * touched by the Routeing Engine at any other time.
   *
   * Before stopping a session the BGP Engine unlinks any connections from
   * the session, and sets the stopped flag.
   *
   * The active flag is set when one or more connections are activated, and
   * cleared when either the BGP Engine stops the session or the Routing
   * Engine disables it.  When not "active" all messages other than disable
   * and enable are ignored.  This deals with the hiatus that exists between
   * the BGP Engine signalling that it has stopped (because of some exception)
   * and the Routing Engine acknowledging that (by disabling the session).
   *
   * The accept flag is set when the secondary connection is completely ready
   * to accept connections.  It is cleared otherwise, or when the active flag
   * is cleared.
   */
  bgp_connection    connections[bc_count] ;

  bgp_session_state_t state ;

  /* The acceptor belongs to the BE *ALWAYS*.  It is created when the session
   * is created and will run while-ever the peer is not shut-down.
   */
  bgp_acceptor  acceptor ;

#if 0
  /* These are cleared by the Routeing Engine before a session is enabled,
   * and set by the BGP Engine when the session is established.
   */
  sockunion         su_local ;          /* set when session Established   */
  sockunion         su_remote ;         /* set when session Established   */
#endif

  /* Statistics -- embedded structure
   *
   * Read by Routeing Engine atomically.
   *
   * Updated by the BGP Engine atomically.
   */
  bgp_session_stats_t stats;
} ;

/*==============================================================================
 * Ring-buffer message types.
 */
typedef enum bgp_rb_msg_in_type bgp_rb_msg_in_type_t ;
enum bgp_rb_msg_in_type
{
  bgp_rbm_in_null   = 0,

  bgp_rbm_in_update,
} ;

typedef enum bgp_rb_msg_out_type bgp_rb_msg_out_type_t ;
enum bgp_rb_msg_out_type
{
  bgp_rbm_out_null   = 0,

  bgp_rbm_out_update,
  bgp_rbm_out_eor,
  bgp_rbm_out_rr,
} ;






/*==============================================================================
 * Mqueue messages related to sessions
 *
 * In all these messages arg0 is the session.
 */
struct bgp_session_enable_args          /* to BGP Engine                */
{
                                        /* no further arguments         */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_enable_args) ;

struct bgp_session_disable_args         /* to BGP Engine                */
{
  bgp_notify    notification ;          /* NOTIFICATION to send         */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_enable_args) ;

struct bgp_session_update_args          /* to and from BGP Engine       */
{
  struct stream*  buf ;
  bgp_size_t size ;
  int xon_kick;                         /* send XON when processed this */

  bgp_connection  is_pending ;          /* used inside the BGP Engine   */
                                        /* set NULL on message creation */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_update_args) ;

struct bgp_session_route_refresh_args   /* to and from BGP Engine       */
{
  bgp_route_refresh  rr ;

  bgp_connection  is_pending ;          /* used inside the BGP Engine   */
                                        /* set NULL on message creation */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_route_refresh_args) ;

struct bgp_session_end_of_rib_args      /* to and from BGP Engine       */
{
  qafx_t qafx ;

  bgp_connection  is_pending ;          /* used inside the BGP Engine   */
                                        /* set NULL on message creation */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_end_of_rib_args) ;

struct bgp_session_event_args           /* to Routeing Engine           */
{
  bgp_fsm_event_t      fsm_event ;      /* what just happened           */
  bgp_notify           notification ;   /* sent or received (if any)    */
  int                  err ;            /* errno if any                 */
  bgp_connection_ord_t ordinal ;        /* primary/secondary connection */
  int                  stopped ;        /* session has stopped          */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_event_args) ;

#if 0
struct bgp_session_XON_args             /* to Routeing Engine           */
{
                                        /* no further arguments         */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_XON_args) ;

enum { BGP_XON_REFRESH     = 40,
       BGP_XON_KICK        = 20,
} ;

struct bgp_session_ttl_args             /* to bgp Engine                */
{
  ttl_t ttl ;
  bool  gtsm ;
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_ttl_args) ;


/*==============================================================================
 * Session mutex lock/unlock
 */

inline static void BGP_SESSION_LOCK(bgp_session session)
{
  qpt_mutex_lock(session->mutex) ;
} ;

inline static void BGP_SESSION_UNLOCK(bgp_session session)
{
  qpt_mutex_unlock(session->mutex) ;
} ;
#endif

/*==============================================================================
 * Functions
 */
extern bgp_session bgp_session_init_new(bgp_peer peer) ;
extern void bgp_session_enable(bgp_peer peer) ;
extern bool bgp_session_disable(bgp_peer peer, bgp_notify notification) ;
extern void bgp_session_delete(bgp_peer peer);
extern void bgp_session_event(bgp_session session, bgp_fsm_event_t fsm_event,
                                       bgp_notify           notification,
                                       int                  err,
                                       bgp_connection_ord_t ordinal,
                                       bool                 stopped) ;
extern void bgp_session_update_send(bgp_session session, stream_fifo fifo) ;
extern void bgp_session_route_refresh_send(bgp_session session,
                                                         bgp_route_refresh rr) ;
extern void bgp_session_end_of_rib_send(bgp_session session,
                                                          qAFI_t afi, qSAFI_t) ;
extern void bgp_session_update_recv(bgp_session session, stream buf,
                                                              bgp_size_t size) ;
extern void bgp_session_route_refresh_recv(bgp_session session,
                                                         bgp_route_refresh rr) ;
extern bool bgp_session_is_XON(bgp_peer peer);
extern bool bgp_session_dec_flow_count(bgp_peer peer) ;
extern void bgp_session_self_XON(bgp_peer peer) ;
extern void bgp_session_set_ttl(bgp_session session, ttl_t ttl, bool gtsm) ;
extern void bgp_session_get_stats(bgp_session session,
                                              struct bgp_session_stats *stats) ;

/*==============================================================================
 * Session data access functions.
 */
extern bool bgp_session_is_active(bgp_session session) ;

#endif /* QUAGGA_BGP_SESSION_H */
