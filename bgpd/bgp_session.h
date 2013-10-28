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
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_fsm.h"

#include "lib/qtimers.h"
#include "lib/qpthreads.h"
#include "lib/sockunion.h"
#include "lib/mqueue.h"
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
 * The state of the session, as far as the session is concerned.
 *
 * The session->state belongs to the BGP Engine (BE), and is updated as
 * messages are sent to and arrive from the Routeing Engine (RE).
 *
 *   * sInitial     -- means that the session has just been created (by the RE)
 *                     and is initialised.
 *
 *                     The session has yet to be sent to the BE, so nothing is
 *                     happening, and the session still belongs to the RE.
 *
 *   * sReady       -- means that all is ready for a new session to start.
 *
 *                     The session is set sReady by the *RE* when it wants a
 *                     new session to start -- which it can do when the
 *                     RE knows that the session is sInitial or sStopped.
 *
 *                     The acceptor will be running if the conn_state allows
 *                     (once the session is prodded for the first time).
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
 *   * sStopped     -- means that the session is stopped, so the fsm(s) are
 *                     not running.
 *
 *                     The acceptor will be running if the conn_state allows.
 *
 *                     Apart from the acceptor, nothing in the BE is running.
 *                     So, once the RE has seen the sStopped state, it may
 *                     push the state round to sReady again when it wishes.
 *
 *                     For the BE, sStopped is a trapping state.
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
  bgp_session_state_min = 0,

  bgp_sInitial          = 0,

  bgp_sReady,
  bgp_sAcquiring,
  bgp_sEstablished,
  bgp_sStopped,

  bgp_sDeleting,

  bgp_session_state_count,
  bgp_session_state_max = bgp_session_state_count - 1,
} ;

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
 * Only the Routing Engine creates sessions.
 * Only the BGP Engine destroys them.
 *
 *
 *
 */
typedef struct bgp_session bgp_session_t ;

struct bgp_session
{
  /* The session->peer pointer is set when the peer, session and peer index
   * entry are created, and before the session is passed to the BE.
   *
   * When the peer is deleted (by the RE), the session->prun is set NULL
   * (atomically) to signal that the session is now moribund -- and the
   * peer cuts its pointers to the session and peer index entry, and the peer
   * index entry is removed from its peer name index.  A message is sent to
   * the BE to destroy the session.  (So peer can read this without locking,
   * but BE must read atomically.)
   */
  bgp_prun              prun ;

  /* These are private to the RE, and are set each time a session event message
   * is received from the BE.
   *
   * The session->state_seen and the prun->state are closely linked and
   * changes in one allow/prompt changes in the other.  When the state_seen
   * is sInitial or sStopped
   *
   * The ordinal returned in the event message identifies which connection
   * the event is for.  In the case of an eEstablished event, the ordinal is
   * the ordinal *before* the session became established.
   */
  bgp_session_state_t   state_seen ;    /* last state seen by RE        */
  bgp_conn_ord_t        ord ;           /* primary/secondary connection */
  bgp_fsm_eqb_t         eqb ;           /* what last happened           */

  bgp_note              note ;          // TODO !!

  /* This is private to the RE, and set when goes pEstablished.
   */
  bgp_conn_ord_t        ord_estd ;

  /* The initial idle_hold_time is set from prun->idle_hold_time when the RE
   * sets the session sReady (so when state_seen is sInitial or sStopped).
   *
   * The prun->idle_hold_time grows/shrinks depending on how long the last
   * established session lasted.  The FSM grows this value if the far end
   * proves vexatious.
   */
  qtime_t               idle_hold_time ;

  /* The logging is set at sInitial time and not changed thereafter.
   *
   * Arguably this should be a cops thing... so that logging can be changed
   * at any time... but that awaits a general improvement in logging.
   */
  bgp_connection_logging_t lox ;

  /* The session arguments configuration -- belong to the BE, and are set
   * from sargs sent when the BE is prodded.
   *
   * These are set NULL at sInitial time, and left in the hands of the BE
   * thereafter.
   */
  bgp_sargs     sargs_conf ;

  /* The session arguments for Established Session (state_seen == sEstablished)
   *
   *   * sargs     -- actual session state, once established
   *                                                    -- transfer BE to RE.
   *
   *   * open_sent -- actual OPEN as sent for session, once established
   *                                                    -- transfer BE to RE.
   *   * open_recv -- actual OPEN as received for session, once established
   *                                                    -- transfer BE to RE.
   *
   * The sargs, open_sent and open_recv copied from the current connection
   * when a session is established, and not changed again by the BE.  (The
   * BE effectively passes these to the RE along with the message that tells
   * the RE that the session is sEstablished -- so is "protected" by the
   * message passing mutex.)
   *
   * So, while sEstablished/pEstablished, these belong to the peer !
   */
  bgp_sargs         sargs ;
  bgp_open_state    open_sent ;
  bgp_open_state    open_recv ;

  /* Session ring-buffers -- created by BE, belong to RE once Established
   *
   * These are created by the BE when the session becomes established, and are
   * then used to transfer UPDATEs in (read_rb) and UPDATEs and Route Refresh
   * out (write_rb).
   *
   * While the session is established, these are shared by the BE and RE.
   * When the session stops, the BE stops using these, and the RE can discard.
   *
   * These too are "protected" by the message passing mutex.
   */
  ring_buffer   read_rb ;
  ring_buffer   write_rb ;

  /* Statistics -- embedded structure
   *
   * Read by Routeing Engine atomically.
   *
   * Updated by the BGP Engine atomically.
   */
  bgp_session_stats_t   stats;

  /* Connection options
   *
   *   * cops_conf   -- session configuration -- belong to the BE *ALWAYS*.
   *
   *     The cops_conf are set from the copy sent when the BE is prodded.
   *
   *   * cops -- actual session state, once established -- transfer BE to RE.
   *
   *     The cops are set from the current connection when a session is
   *     established, and not changed again by the BE.  These are copied to the
   *     peer when the session is established.
   */
  bgp_cops      cops_conf ;
  bgp_cops      cops ;

  /* These values are are private to the BGP Engine.
   *
   * They must be cleared before the session is enabled, but may not be
   * touched by the Routeing Engine at any other time.
   *
   * Before stopping a session the BGP Engine unlinks any connections from
   * the session, and sets the sStopped.
   */
  bgp_connection        connections[bc_count] ;

  bgp_session_state_t   state ;

  /* The acceptor belongs to the BE *ALWAYS*.  It is created when the session
   * is created and will run while-ever the peer is not shut-down.
   */
  bgp_acceptor          acceptor ;
} ;

/*==============================================================================
 * Ring-buffer message types.
 */
typedef enum bgp_rb_msg_in_type bgp_rb_msg_in_type_t ;
enum bgp_rb_msg_in_type
{
  bgp_rbm_in_null   = 0,

  bgp_rbm_in_update,
  bgp_rbm_in_rr,
  bgp_rbm_in_rr_pre,

} ;

typedef enum bgp_rb_msg_out_type bgp_rb_msg_out_type_t ;
enum bgp_rb_msg_out_type
{
  bgp_rbm_out_null   = 0,

  bgp_rbm_out_update_a,
  bgp_rbm_out_update_b,
  bgp_rbm_out_update_c,
  bgp_rbm_out_update_d,
  bgp_rbm_out_eor,
  bgp_rbm_out_rr,
} ;






/*==============================================================================
 * Mqueue messages related to sessions
 *
 * In all these messages arg0 is the session.
 */
struct bgp_session_prod_args            /* to BGP Engine                */
{
  bgp_note      note ;          /* NOTIFICATION to send, if required    */
  bgp_sargs     sargs ;         /* new session arguments, if required   */
  bgp_cops      cops ;          /* new connection options, if required  */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_prod_args) ;

struct bgp_session_event_args           /* to Routeing Engine           */
{
  bgp_session_state_t   state ;
  bgp_conn_ord_t        ord ;           /* primary/secondary connection */
  bgp_fsm_eqb_t         eqb ;           /* what just happened           */
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_event_args) ;

/*==============================================================================
 * Functions
 */
extern void bgp_session_execute(bgp_prun prun, bgp_note note) ;
extern void bgp_session_shutdown(bgp_prun prun, bgp_note note) ;













extern void bgp_session_config(bgp_prun prun) ;
extern bool bgp_session_disable(bgp_prun prun, bgp_note note) ;
extern void bgp_session_delete(bgp_prun prun);



extern void bgp_session_send_event(bgp_session session, bgp_conn_ord_t ord,
                                                              bgp_fsm_eqb eqb) ;

extern void bgp_session_kick_re_read(bgp_session session) ;
extern void bgp_session_kick_be_read(bgp_prun prun) ;
extern void bgp_session_kick_be_write(bgp_prun prun) ;
extern void bgp_session_kick_re_write(bgp_session session) ;

extern void bgp_session_kick_write(bgp_prun prun) ;
extern void bgp_session_kick_read(bgp_prun prun) ;


extern void bgp_session_get_stats(bgp_session_stats stats,
                                                          bgp_session session) ;

#endif /* QUAGGA_BGP_SESSION_H */
