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
 * Only the Routing Engine creates sessions.  Only the BGP Engine destroys them.
 */
typedef struct bgp_session bgp_session_t ;

struct bgp_session
{
  /* The session->peer pointer is set when the peer, session and peer index
   * entry are created, and before the session is passed to the BE.
   *
   * When the peer is deleted (by the RE), the session->peer is set NULL
   * (atomically) to signal that the session is now moribund -- and the
   * peer cuts its pointers to the session and peer index entry, and the peer
   * index entry is removed from its peer name index.  A message is sent to
   * the BE to destroy the session.  (So peer can read this without locking,
   * but BE must read atomically.)
   */
  bgp_peer              peer ;

  /* These are private to the RE, and are set each time a session event message
   * is received from the BE.
   *
   * The ordinal returned in the event message identifies which connection
   * the event is for.  In the case of an eEstablished event, the ordinal is
   * the ordinal *before* the session became established.
   */
  bgp_session_state_t   state_seen ;    /* last state seen by RE        */
  bgp_conn_ord_t        ord ;           /* primary/secondary connection */
  bgp_fsm_eqb_t         eqb ;           /* what last happened           */

  /* This is private to the RE, and set when goes pEstablished.
   */
  bgp_conn_ord_t        ord_estd ;

  /* The following are set by the RE before a session is enabled, and not
   * changed at any other time by either engine.
   */
  qtime_t               idle_hold_time ;

  bgp_connection_logging_t lox ;

  /* The session arguments configuration.
   *
   *   * args_sent   -- last set as sent      -- belong to the RE *ALWAYS*.
   *
   *     This is the reference copy of the last set of session arguments
   *     sent to the BE.
   *
   *   * args_config -- session configuration -- belong to the BE if pssRunning
   *
   *     The args_config are set from the copy sent when the BE is prodded.
   */
  bgp_session_args      args_sent ;
  bgp_session_args      args_config ;

  /* The session arguments for Established Session.
   *
   *   * args -- actual session state, once established -- transfer BE to RE.
   *
   *   * open_sent -- actual OPEN as sent for session, once established
   *                                                    -- transfer BE to RE.
   *   * open_recv -- actual OPEN as received for session, once established
   *                                                    -- transfer BE to RE.
   *
   *     The args, open_sent and open_recv copied from the current connection
   *     when a session is established, and not changed again by the BE.
   *
   *     So, while pEstablished, these belong to the peer !
   */
  bgp_session_args      args ;
  bgp_open_state        open_sent ;
  bgp_open_state        open_recv ;

  /* Session ring-buffers -- created by BE, belong to RE once Established
   *
   * These are created by the BE when the session becomes established, and are
   * then used to transfer UPDATEs in (read_rb) and UPDATEs and Route Refresh
   * out (write_rb).
   *
   * While the session is established, these are shared by the BE and RE.
   * When the session stops, the BE stops using these, and the RE can discard.
   */
  ring_buffer           read_rb ;
  ring_buffer           write_rb ;

  /* Statistics -- embedded structure
   *
   * Read by Routeing Engine atomically.
   *
   * Updated by the BGP Engine atomically.
   */
  bgp_session_stats_t   stats;

  /* Connection options
   *
   *   * cops_sent   -- last set as sent      -- belong to the RE *ALWAYS*.
   *
   *     This is the reference copy of the last set of connection options
   *     sent to the BE.
   *
   *   * cops_config -- session configuration -- belong to the BE *ALWAYS*.
   *
   *     The cops_config are set from the copy sent when the BE is prodded.
   *
   *   * cops -- actual session state, once established -- transfer BE to RE.
   *
   *     The cops are set from the current connection when a session is
   *     established, and not changed again by the BE.  These are copied to the
   *     peer when the session is established.
   */
  bgp_cops              cops_sent ;
  bgp_cops              cops_config ;
  bgp_cops              cops ;

  /* This is for the prodding of the BE.
   *
   *   * args_tx -- transfer from RE to BE, while pssRunning.
   *
   *     The args_tx is set by the RE and cleared by the BE -- using an atomic
   *     swap.
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
   */
  mqueue_block          mqb_tx ;

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
  bgp_note      note ;                  /* NOTIFICATION to send         */
  bool          peer_established ;      /* peer is established          */

  bgp_session_args args ;
  bgp_cops      cops ;
} ;
MQB_ARGS_SIZE_OK(struct bgp_session_prod_args) ;


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


struct bgp_session_event_args           /* to Routeing Engine           */
{
  bgp_session_state_t   state ;
  bgp_conn_ord_t        ord ;           /* primary/secondary connection */
  bgp_fsm_eqb_t         eqb ;           /* what just happened           */
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
extern void bgp_session_start(bgp_session session) ;

extern void bgp_session_prod(bgp_session session, bgp_note note, bool refresh) ;




extern void bgp_session_config(bgp_peer peer) ;
extern bool bgp_session_disable(bgp_peer peer, bgp_note note) ;
extern void bgp_session_delete(bgp_peer peer);



extern void bgp_session_send_event(bgp_session session, bgp_conn_ord_t ord,
                                                              bgp_fsm_eqb eqb) ;

extern void bgp_session_kick_re_read(bgp_session session) ;
extern void bgp_session_kick_be_read(bgp_peer peer) ;
extern void bgp_session_kick_be_write(bgp_peer peer) ;
extern void bgp_session_kick_re_write(bgp_session session) ;
extern void bgp_session_kick_write(bgp_peer peer) ;
extern void bgp_session_kick_read(bgp_peer peer) ;


extern void bgp_session_get_stats(bgp_session_stats stats,
                                                          bgp_session session) ;

#endif /* QUAGGA_BGP_SESSION_H */
