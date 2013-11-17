/* BGP Session -- functions
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
#include "misc.h"

#include "bgpd/bgp_session.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_msg_write.h"
#include "bgpd/bgp_network.h"

#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"

#include "lib/memory.h"
#include "lib/sockunion.h"
#include "lib/log.h"
#include "lib/mqueue.h"
#include "lib/zassert.h"
#include "lib/qfstring.h"

/* prototypes */
static void bgp_session_do_enable(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_update_recv(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_update_send(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_end_of_rib_send(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_route_refresh_send(mqueue_block mqb,
                                                               mqb_flag_t flag);
static void bgp_session_do_disable(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_XON(bgp_session session);
static void bgp_session_do_XON(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_set_ttl(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_route_refresh_recv(mqueue_block mqb, mqb_flag_t flag);

/*==============================================================================
 * BGP Session.
 *
 * Every bgp_peer has (at most) one bgp_session associated with it.
 *
 * A session is shared by the Routeing Engine and the BGP Engine -- so there
 * is a mutex to coordinate access.
 *
 * A session is created some time before it is enabled, and may be destroyed
 * once the session is disabled.
 *
 * A session may be in one of the states:
 *
 *   * bgp_session_sIdle         -- not doing anything
 *   * bgp_session_sEnabled      -- the BGP Engine is trying to connect
 *   * bgp_session_sEstablished  -- the BGP Engine is exchanging updates etc
 *   * bgp_session_sLimping      -- in the process of being disabled
 *   * bgp_session_sDisabled     -- completely disabled
 *
 * NB: in sIdle and sDisabled states the BGP Engine has no interest in the
 *     session.  These are known as the "inactive" states.
 *
 * NB: in sEnabled, sEstablished and sLimping states the BGP Engine is running
 *     connection(s) for the session.  These are known as the "active" states.
 *
 *     While the session is active the Routeing Engine should not attempt to
 *     change any shared item in the session, except under the mutex.  And
 *     even then it may make no sense !
 *
 * NB: a session reaches sDisabled when the Routing Engine has sent a disable
 *     request to the BGP Engine, AND an eDisabled event has come back.
 *
 *     While the Routing Engine is waiting for the eDisabled event, the session
 *     is in sLimping state.
 *
 * The BGP Engine's primary interest is in its (private) bgp_connection
 * structure(s), which (while a session is sEnabled, sEstablished or sLimping)
 * are pointed to by their associated session.
 */

/*==============================================================================
 * BGP Session handling.
 *
 */

/*------------------------------------------------------------------------------
 * Allocate & initialise new session structure.
 *
 * Ties peer and session together.  Sets session sIdle, initialises mutex.
 *
 * Unsets everything else -- mostly by zeroising it.
 *
 * NB: if not allocating, the existing session MUST be sIdle/sDisabled OR never
 *     been kissed.
 *
 * NB: peer MUST NOT have a session set up:
 *
 *      (a) because if there was a session, there would have to be code here
 *          to worry about its state, and tearing it down etc.
 *
 *      (b) so that do not have to worry about BGP Engine reaching the old
 *          session while it was being replaced or whatever.
 */
extern bgp_session
bgp_session_init_new(bgp_peer peer)
{
  bgp_session session ;

  assert(peer->session == NULL) ;

  session = XCALLOC(MTYPE_BGP_SESSION, sizeof(struct bgp_session)) ;

  session->mutex = qpt_mutex_new(qpt_mutex_recursive,
                                        qfs_gen("%s Session", peer->host).str) ;

  session->peer  = peer ;
  bgp_peer_lock(peer) ;             /* Account for the session->peer pointer  */

  session->state = bgp_session_sIdle ;

  /* Zeroising the structure has set:
   *
   *   delete_me      -- 0    -- false
   *
   *   event          -- bgp_session_null_event
   *   notification   -- NULL -- none
   *   err            -- 0    -- none
   *   ordinal        -- 0    -- unset
   *
   *   open_send      -- NULL -- none
   *   open_recv      -- NULL -- none
   *
   *   connect        -- unset, false
   *   listen         -- unset, false
   *
   *   cap_suppress   -- unset, false
   *   cap_override   -- unset, false
   *   cap_strict     -- unset, false
   *
   *   ttl            -- unset
   *   port           -- unset
   *   as_peer        -- unset
   *   su_peer        -- NULL -- none
   *
   *   ifname         -- NULL -- none
   *   ifindex        -- 0    -- none
   *   ifaddress      -- NULL -- none
   *
   *   log            -- NULL -- none
   *   host           -- NULL -- none
   *   password       -- NULL -- none
   *
   *   idle_hold_timer_interval      )
   *   connect_retry_timer_interval  )
   *   open_hold_timer_interval      ) unset
   *   hold_timer_interval           )
   *   keepalive_timer_interval      )
   *
   *   as4            -- unset, false
   *   route_refresh_pre -- unset, false
   *
   *   su_local       -- NULL -- none
   *   su_remote      -- NULL -- none
   *
   *   connections[]  -- NULL -- none
   *   active         -- false, not yet active
   *   accept         -- false, not yet ready to accept()
   */
  confirm(bgp_session_null_event == 0) ;

  /* Once the session is fully initialised, can set peer->session pointer.
   *
   * NB: this is done last and under the Peer Index Mutex, so that the
   *     accept() code does not trip over.
   */
  bgp_peer_index_set_session(peer, session) ;

  return session ;
} ;

/*==============================================================================
 * Routing Engine: delete session for given peer.
 *
 * This is for use when the peer itself is being deleted.  (Peer MUST be in
 * pDeleting state.)
 *
 * Does nothing if there is no session !
 *
 * If the session is active, simply sets delete_me flag, which will be honoured
 * when the session goes dDisabled.  Note, it is the callers responsibility
 * to arrange for that to happen.
 *
 * If the session is not active, it is immediately freed.
 *
 * NB: if the session is freed, the peer may vanish at the same time !
 */
extern void
bgp_session_delete(bgp_peer peer)
{
  bgp_session session = peer->session ;

  if (session == NULL)
    return ;                    /* easy if no session anyway    */

  assert(peer == session->peer) ;

  /* If is active, set flag so that session is deleted when next it becomes
   * sDisabled.
   */
  if (bgp_session_is_active(session))
    {
      session->delete_me = true ;
      return ;
    } ;

  /*--------------------------------------------------------------------------*/
  /* Proceed to free the session structure.                                   */

  /* Make sure that the BGP Engine has, in fact, let go of the session.
   *
   * The LOCK/UNLOCK makes sure that the BGP Engine has unlocked the session.
   *
   * Without this, the qpt_mutex_destroy() can fail horribly, if the BGP
   * Engine sends the disable acknowledge before finally unlocking the session.
   */
  BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/

  session->mutex = qpt_mutex_destroy(session->mutex) ;

  /* Proceed to dismantle the session.                                  */

  bgp_notify_unset(&session->notification);
  bgp_open_state_free(session->open_send);
  bgp_open_state_free(session->open_recv);
  if (session->ifname != NULL)
    free(session->ifname) ;
  sockunion_unset(&session->ifaddress) ;
  sockunion_unset(&session->su_peer) ;
  if (session->host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->host);
  if (session->password != NULL)
    XFREE(MTYPE_PEER_PASSWORD, session->password);
  sockunion_unset(&session->su_local) ;
  sockunion_unset(&session->su_remote) ;

  /* Drop the peer->session and session->peer pointers
   *
   * NB: the peer->session pointer is cleared under the Peer Index Mutex,
   *     so that the accept() code does not trip over.
   *
   * NB: at this point it is possible for the peer structure to suddenly
   *     vanish -- if peer has been deleted, and has been waiting for the
   *     session to go sDisabled.
   */
  bgp_peer_index_set_session(peer, NULL) ;

  session->peer = NULL ;
  bgp_peer_unlock(peer) ;       /* NB: peer->session == NULL    */

  /* Zeroize to catch dangling references asap */
  memset(session, 0, sizeof(struct bgp_session)) ;
  XFREE(MTYPE_BGP_SESSION, session);
} ;

/*==============================================================================
 * Routing Engine: enable session for given peer -- allocate if required.
 *
 * Sets up the session given the current state of the peer.  If the state
 * changes, then need to disable the session and re-enable it again with new
 * parameters -- unless something more cunning is devised.
 */
extern void
bgp_session_enable(bgp_peer peer)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  assert(peer->state = bgp_peer_pIdle) ;

  /* Set up session if required.  Check session if already exists.
   *
   * Only the Routing Engine creates sessions, so it is safe to pick up the
   * peer->session pointer and test it.
   *
   * If session exists, it MUST be inactive.
   *
   * Routing Engine does not require the mutex while the session is inactive.
   */
  session = peer->session ;

  if (session == NULL)
    session = bgp_session_init_new(peer) ;
  else
    {
      assert(session->peer == peer) ;
      assert(!bgp_session_is_active(session)) ;
    } ;

  /* Initialise what we need to make and run connections
   */
  session->state        = bgp_session_sIdle ;
  session->delete_me    = false ;
  session->flow_control = 0 ;
  session->event        = bgp_session_null_event ;
  bgp_notify_unset(&session->notification) ;
  session->err          = 0 ;
  session->ordinal      = 0 ;

  session->open_send = bgp_peer_open_state_init_new(session->open_send, peer) ;
  bgp_open_state_unset(&session->open_recv) ;

  session->connect   = (peer->flags & PEER_FLAG_PASSIVE) == 0 ;
  session->listen    = true ;

  session->ttl       = peer->ttl ;
  session->gtsm      = peer->gtsm ;
  session->port      = peer->port ;

  if (session->ifname != NULL)
    free(session->ifname) ;
  session->ifindex = 0 ;

  if (peer->ifname != NULL)
    {
      session->ifname  = strdup(peer->ifname) ;
      session->ifindex = if_nametoindex(peer->ifname) ;
    } ;

  sockunion_unset(&session->ifaddress) ;
  if      (peer->update_source != NULL)
    session->ifaddress = sockunion_dup(peer->update_source) ;
  else if (peer->update_if != NULL)
    session->ifaddress = bgp_peer_get_ifaddress(peer, peer->update_if,
                                                        peer->su.sa.sa_family) ;
  session->as_peer  = peer->as ;
  sockunion_set_dup(&session->su_peer, &peer->su) ;

  session->log      = peer->log ;

  /* take copies of host and password */
  if (session->host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->host);
  session->host     = (peer->host != NULL)
                        ? XSTRDUP(MTYPE_BGP_PEER_HOST, peer->host)
                        : NULL;
  if (session->password != NULL)
    XFREE(MTYPE_PEER_PASSWORD, session->password);
  session->password = (peer->password != NULL)
                        ? XSTRDUP(MTYPE_PEER_PASSWORD, peer->password)
                        : NULL;

  /* v_start is set to BGP_INIT_START_TIMER when the peer is first created.
   * It is adjusted when a session drops, so that if sessions going up and
   * down rapidly, the IdleHoldTime increases, but after a long lasting
   * session, the IdleHoldTime is reduced.
   *
   * v_connect is set by configuration.
   *
   * v_holdtime and v_keepalive are set by bgp_peer_reset_idle() to either the
   * values configured for the peer, or to the bgp instance defaults.  When a
   * session starts, the negotiated values are set into here -- so that can
   * be output in (eg) bgp_show_peer().
   */
  session->idle_hold_timer_interval     = QTIME(peer->v_start) ;
  session->connect_retry_timer_interval = QTIME(peer->v_connect) ;
  /* TODO: proper value for open_hold_timer_interval    */
  session->open_hold_timer_interval     = QTIME(4 * 60) ;
  session->hold_timer_interval          = QTIME(peer->v_holdtime) ;
  session->keepalive_timer_interval     = QTIME(peer->v_keepalive) ;

  session->as4               = false ;
  session->route_refresh_pre = false ;
  session->orf_prefix_pre    = false ;

  /* su_local set when session Established */
  /* su_remote  set when session Established */

  /* TODO: check whether session stats should persist   */
  memset(&session->stats, 0, sizeof(struct bgp_session_stats)) ;

  memset(&session->connections, 0,
                                sizeof(bgp_connection) * bgp_connection_count) ;

  session->active    = false ;
  session->accept    = false ;

  /* Routeing Engine does the state change now.                         */

  /* Now pass the session to the BGP Engine, which will set about       */
  /* making and running a connection to the peer.                       */

  mqb = mqb_init_new(NULL, bgp_session_do_enable, session) ;

  confirm(sizeof(struct bgp_session_enable_args) == 0) ;

  session->state = bgp_session_sEnabled;

  ++bgp_engine_queue_stats.event ;

  bgp_to_bgp_engine(mqb, mqb_ordinary) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: session enable message action
 */
static void
bgp_session_do_enable(mqueue_block mqb, mqb_flag_t flag)
{
  if (flag == mqb_action)
    {
      bgp_session session = mqb_get_arg0(mqb) ;

      BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

      session->active = true ;
      bgp_fsm_enable_session(session) ;

      BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/
    } ;

  mqb_free(mqb) ;
} ;

/*==============================================================================
 * Routing Engine: disable session for given peer -- if and and if enabled (!).
 *
 * If there is a session and it is sEnabled or sEstablished, send a copy of the
 * given notification to the BGP Engine, and set the session sLimping.
 *
 * Passes any bgp_notify to the BGP Engine, which will dispose of it in due
 * course.
 *
 * If no bgp_notify provided, no notify will be sent.
 *
 * The BGP Engine will stop the session -- unless it is already stopped due to
 * some event in the BGP Engine.  In any case, the BGP Engine will respond with
 * an eDisabled.
 *
 * Returns: true  <=> have sent (copy of) notification to BGP_ENGINE
 *          false  => for whatever reason, the session cannot be disabled
 *
 * NB: caller is responsible for the original notification, if any
 */
extern bool
bgp_session_disable(bgp_peer peer, bgp_notify notification)
{
  bgp_session    session ;
  mqueue_block   mqb ;
  struct bgp_session_disable_args* args ;

  session = peer->session ;

  /* Do nothing if session is not active, or is already limping.        */

  if (session == NULL ||
       ( (session->state != bgp_session_sEnabled) &&
         (session->state != bgp_session_sEstablished) ))
    {
      return false ;
    } ;

  assert(session->peer == peer) ;

  /* Can revoke whatever may be queued already.  Will revoke again when the
   * disable is acknowledged to finally clear the session out of the queue.
   */
  mqueue_revoke(routing_nexus->queue, session, 0) ;

  /* Now change to limping state                                        */
  session->state = bgp_session_sLimping;

  /* Ask the BGP engine to disable the session.
   *
   * NB: the session may already be stopped when the BGP Engine sees this
   *     message:
   *
   *       * the disable is being issued in response to a stopped event from
   *         the BGP Engine.
   *
   *       * the session is stopped, but the message to the Routing Engine is
   *         still in its message queue.
   *
   *       * the session is stopped while the disable message is in the
   *         BGP Engine queue.
   *
   *     in any case, the BGP Engine responds with an eDisabled message to
   *     acknowledge the disable request -- and the session will then be
   *     disabled.
   *
   * NB: The BGP Engine will discard any outstanding work for the session.
   *
   *     The Routing Engine should discard all further messages for this
   *     session up to the eDisabled, and must then discard any other
   *     messages for the session.
   *
   * NB: the Routing Engine MUST not issue any further messages until it sees
   *     the returned eDisabled event.
   */
  mqb = mqb_init_new(NULL, bgp_session_do_disable, session) ;

  args = mqb_get_args(mqb) ;
  args->notification = bgp_notify_dup(notification) ;

  ++bgp_engine_queue_stats.event ;

  bgp_to_bgp_engine(mqb, mqb_priority) ;

  /* We have just disabled the session, sending (a copy of) any notification.
   */
  return true ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: session disable message action
 *
 * NB: either passes the notification to the FSM or frees it here.
 */
static void
bgp_session_do_disable(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session = mqb_get_arg0(mqb) ;
  struct bgp_session_disable_args* args = mqb_get_args(mqb) ;

  if (flag == mqb_action)
    {
      /* Immediately discard any other messages for this session.       */
      mqueue_revoke(bgp_nexus->queue, session, 0) ;

      /* Get the FSM to send any notification and close connections     */
      bgp_fsm_disable_session(session, args->notification) ;
    }
  else
    bgp_notify_free(args->notification) ;

  mqb_free(mqb) ;
}

/*==============================================================================
 * BGP Engine: send session event signal to Routeing Engine
 *
 * NB: is passing responsibility for the notification to the Routing Engine.
 */
extern void
bgp_session_event(bgp_session session, bgp_session_event_t  event,
                                       bgp_notify           notification,
                                       int                  err,
                                       bgp_connection_ord_t ordinal,
                                       bool                 stopped)
{
  struct bgp_session_event_args* args ;
  mqueue_block   mqb ;

  if (stopped)
    {
      session->active  = false ;        /* ignore updates etc           */
      session->accept  = false ;        /* for completeness             */
    } ;

  mqb = mqb_init_new(NULL, bgp_session_do_event, session) ;

  args = mqb_get_args(mqb) ;

  args->event        = event ;
  args->notification = notification ;
  args->err          = err ;
  args->ordinal      = ordinal ;
  args->stopped      = stopped,

  ++routing_engine_queue_stats.event ;

  bgp_to_routing_engine(mqb, stopped ? mqb_priority : mqb_ordinary) ;
} ;

/*==============================================================================
 * Routing Engine: dispatch update(s) to peer -> BGP Engine
 *
 * PRO TEM -- this is being passed the pre-packaged BGP message(s).
 *
 * The BGP Engine takes care of discarding the stream block(s) once dealt with.
 */
extern void
bgp_session_update_send(bgp_session session, struct stream_fifo* fifo)
{
  struct bgp_session_update_args* args ;
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_update_send, session) ;

  args = mqb_get_args(mqb) ;
  args->buf        = stream_fifo_head(fifo) ;
  args->is_pending = NULL ;
  args->xon_kick   = (session->flow_control == BGP_XON_KICK);

  ++bgp_engine_queue_stats.update ;

  bgp_to_bgp_engine(mqb, mqb_ordinary) ;

  stream_fifo_reset(fifo) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: write given BGP update message(s) -- mqb action function.
 *
 * Each connection has a pending queue associated with it, onto which messages
 * are put if the connection's write buffer is unable to absorb any further
 * messages.
 *
 * This function is called both when the mqb is received from the Routing
 * Engine, and when the BGP Engine is trying to empty the connection's pending
 * queue.
 *
 * When the mqb is received from the Routing Engine, then:
 *
 *   -- if the connection's pending queue is empty, try to send the message(s).
 *
 * When the mqb is from connection's pending queue, then:
 *
 *   -- try to send the message(s).
 *
 * In any case, if cannot send all the message(s), add it (back) to the
 * connection's pending queue.
 *
 * If the mqb has been dealt with, it is freed, along with the stream buffer.
 * Also, update the flow control counter, and issue XON if required.
 */
static void
bgp_session_do_update_send(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_update_args* args = mqb_get_args(mqb) ;
  bgp_session session = mqb_get_arg0(mqb) ;

  while (args->buf != NULL)
    {
      struct stream* buf ;

      if ((flag == mqb_action) && session->active)
        {
          bgp_connection connection ;

          connection = session->connections[bgp_connection_primary] ;
          assert(connection != NULL) ;

          /* If established, try and send.                              */
          if (connection->state == bgp_fsm_sEstablished)
            {
              int ret ;
              ret = bgp_connection_no_pending(connection, &args->is_pending) ;

              if (ret != 0)
                ret = bgp_msg_send_update(connection, args->buf) ;

              if (ret == 0)
                {
                  /* Either there is already a pending queue, or the message
                   * could not be sent (and has not failed) -- so add to the
                   * pending queue.
                   */
                  bgp_connection_add_pending(connection, mqb,
                                                            &args->is_pending) ;
                  return ;      /* Quit now, with message intact.       */
                }
            } ;
        } ;

      buf = args->buf ;
      args->buf = buf->next ;

      stream_free(buf) ;
    } ;

  /* If gets to here, then has dealt with all message(s).               */
  if ((flag == mqb_action) && (args->xon_kick))
    bgp_session_XON(session) ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: are we in XON state ?
 */
extern bool
bgp_session_is_XON(bgp_peer peer)
{
  return (peer->session->flow_control > 0) &&
                                        (peer->state == bgp_peer_pEstablished) ;
} ;

/*------------------------------------------------------------------------------
 * Count down flow control -- return true if reached XON point.
 */
extern bool
bgp_session_dec_flow_count(bgp_peer peer)
{
  bgp_session session = peer->session;

  qassert(session->flow_control > 0) ;

  if (session->flow_control > 0)
    return (--session->flow_control == BGP_XON_KICK) ;

  session->flow_control = 0 ;
  return false ;
} ;

/*==============================================================================
 * Routing Engine: dispatch Route Refresh to peer -> BGP Engine
 *
 * The BGP Engine takes care of discarding the bgp_route_refresh once it's been
 * dealt with.
 */
extern void
bgp_session_route_refresh_send(bgp_session session, bgp_route_refresh rr)
{
  struct bgp_session_route_refresh_args* args ;
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_route_refresh_send, session) ;

  args = mqb_get_args(mqb) ;
  args->rr         = rr ;
  args->is_pending = NULL ;

  ++bgp_engine_queue_stats.event ;

  bgp_to_bgp_engine(mqb, mqb_ordinary) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: write given BGP route refresh message -- mqb action function.
 *
 * The logic here is the same as for bgp_session_do_update_send -- except that
 * there is no flow control (!).
 */
static void
bgp_session_do_route_refresh_send(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_route_refresh_args* args = mqb_get_args(mqb) ;
  bgp_session session = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && session->active)
    {
      bgp_connection connection = session->connections[bgp_connection_primary] ;
      assert(connection != NULL) ;

      /* If established, try and send.                                  */
      if (connection->state == bgp_fsm_sEstablished)
        {
          int ret = bgp_connection_no_pending(connection, &args->is_pending) ;

          if (ret != 0)
            ret = bgp_msg_send_route_refresh(connection, args->rr) ;

          if (ret == 0)
            {
              /* Either there is already a pending queue, or the message
               * could not be sent (and has not failed) -- so add to the
               * pending queue.
               */
              bgp_connection_add_pending(connection, mqb, &args->is_pending) ;
              return ;  /* Quit now, with message intact.       */
            } ;
        } ;
    } ;

  bgp_route_refresh_free(args->rr) ;
  mqb_free(mqb) ;
} ;

/*==============================================================================
 * Routing Engine: dispatch End-of-RIB to peer -> BGP Engine
 */
extern void
bgp_session_end_of_rib_send(bgp_session session, qAFI_t afi, qSAFI_t safi)
{
  struct bgp_session_end_of_rib_args* args ;
  mqueue_block   mqb ;
  qafx_num_t     qafx ;

  qafx = qafx_num_from_qAFI_qSAFI(afi, safi) ;

  mqb = mqb_init_new(NULL, bgp_session_do_end_of_rib_send, session) ;

  args = mqb_get_args(mqb) ;
  args->afi        = get_iAFI(qafx) ;
  args->safi       = get_iSAFI(qafx) ;
  args->is_pending = NULL ;

  ++bgp_engine_queue_stats.xon ;

  bgp_to_bgp_engine(mqb, mqb_ordinary) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: write given BGP end-of-RIB message -- mqb action function.
 *
 * The logic here is the same as for bgp_session_do_update_send -- except that
 * there is no flow control (!).
 */
static void
bgp_session_do_end_of_rib_send(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_end_of_rib_args* args = mqb_get_args(mqb) ;
  bgp_session session = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && session->active)
    {
      bgp_connection connection = session->connections[bgp_connection_primary] ;
      assert(connection != NULL) ;

      /* If established, try and send.                                  */
      if (connection->state == bgp_fsm_sEstablished)
        {
          int ret = bgp_connection_no_pending(connection, &args->is_pending) ;

          if (ret != 0)
            ret = bgp_msg_send_end_of_rib(connection, args->afi, args->safi) ;

          if (ret == 0)
            {
              /* Either there is already a pending queue, or the message
               * could not be sent (and has not failed) -- so add to the
               * pending queue.
               */
              bgp_connection_add_pending(connection, mqb, &args->is_pending) ;

              return ;  /* Quit now, with message intact.       */
            } ;
        } ;
    } ;

  mqb_free(mqb) ;
} ;

/*==============================================================================
 * BGP Engine: forward incoming update -> Routing Engine
 *
 * PRO TEM -- this is being passed the raw BGP message.
 *
 * The Routing Engine takes care of discarding the stream block once it's been
 * dealt with.
 */
extern void
bgp_session_update_recv(bgp_session session, struct stream* buf, bgp_size_t size)
{
  struct bgp_session_update_args* args ;
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_update_recv, session) ;

  args = mqb_get_args(mqb) ;
  args->buf = stream_dup(buf) ;
  args->size = size;
  args->xon_kick = 0;

  ++routing_engine_queue_stats.update ;

  bgp_to_routing_engine(mqb, mqb_ordinary) ;
}

/*------------------------------------------------------------------------------
 * Routing Engine: process incoming update message -- mqb action function.
 *
 * Discard the update if the session is not sEstablished.
 */
static void
bgp_session_do_update_recv(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session = mqb_get_arg0(mqb) ;
  struct bgp_session_update_args* args = mqb_get_args(mqb) ;

  if ( (flag == mqb_action) && (session->state == bgp_session_sEstablished) )
    {
      bgp_peer  peer = session->peer;
      stream_free(peer->ibuf);
      peer->ibuf = args->buf;
      bgp_update_receive (peer, args->size);
    }
  else
    stream_free(args->buf) ;

  mqb_free(mqb) ;
}

/*==============================================================================
 * BGP Engine: received Route Refresh to peer
 *
 * The Routing Engine takes care of discarding the bgp_route_refresh once
 *  it's been dealt with.
 */
extern void
bgp_session_route_refresh_recv(bgp_session session, bgp_route_refresh rr)
{
  struct bgp_session_route_refresh_args* args ;
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_route_refresh_recv, session) ;

  args = mqb_get_args(mqb) ;
  args->rr         = rr ;
  args->is_pending = NULL ;

  bgp_to_routing_engine(mqb, mqb_ordinary) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: receive given BGP route refresh message -- mqb action
 * function.
 */
static void
bgp_session_do_route_refresh_recv(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_route_refresh_args* args = mqb_get_args(mqb) ;
  bgp_session session = mqb_get_arg0(mqb) ;

  if ( (flag == mqb_action) && (session->state == bgp_session_sEstablished) )
    bgp_route_refresh_recv(session->peer, args->rr) ;

  bgp_route_refresh_free(args->rr);
  mqb_free(mqb);
}

/*==============================================================================
 * BGP Engine: send XON message to Routing Engine
 *
 * Can be sent more packets now
 */
static void
bgp_session_XON(bgp_session session)
{
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_XON, session) ;

  confirm(sizeof(struct bgp_session_XON_args) == 0) ;

  ++routing_engine_queue_stats.xon ;

  bgp_to_routing_engine(mqb, mqb_ordinary) ;
}

/*------------------------------------------------------------------------------
 * Routing Engine: process incoming XON message -- mqb action function.
 */
static void
bgp_session_do_XON(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session = mqb_get_arg0(mqb) ;

  if ( (flag == mqb_action) && (session->state == bgp_session_sEstablished) )
    {
      int xoff = (session->flow_control <= 0);

      session->flow_control = BGP_XON_REFRESH;
      if (xoff)
        bgp_write (session->peer, NULL) ;
    }

  mqb_free(mqb) ;
}

/*==============================================================================
 * Routing Engine: send set ttl message to BGP Engine, if session is active.
 */
void
bgp_session_set_ttl(bgp_session session, int ttl, bool gtsm)
{
  mqueue_block   mqb ;
  struct bgp_session_ttl_args *args;

  if (bgp_session_is_active(session))
    {
      mqb = mqb_init_new(NULL, bgp_session_do_set_ttl, session) ;

      args = mqb_get_args(mqb) ;
      args->ttl  = ttl ;
      args->gtsm = gtsm ;

      ++bgp_engine_queue_stats.event ;

      bgp_to_bgp_engine(mqb, mqb_ordinary) ;
    } ;
}

/*------------------------------------------------------------------------------
 * BGP Engine: process set ttl message -- mqb action function.
 */
static void
bgp_session_do_set_ttl(mqueue_block mqb, mqb_flag_t flag)
{

  if (flag == mqb_action)
    {
      bgp_session session = mqb_get_arg0(mqb) ;
      struct bgp_session_ttl_args *args = mqb_get_args(mqb) ;

      BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

      session->ttl  = args->ttl ;
      session->gtsm = args->gtsm ;

      bgp_set_new_ttl(session->connections[bgp_connection_primary],
                                                  session->ttl, session->gtsm) ;
      bgp_set_new_ttl(session->connections[bgp_connection_secondary],
                                                  session->ttl, session->gtsm) ;

      BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/
    }

  mqb_free(mqb) ;
}

/*==============================================================================
 * Session data access functions.
 *
 *
 */

/*------------------------------------------------------------------------------
 * Routing Engine: see if session exists and is active.
 *
 * If exists then performs a few checks, just to make sure things are straight.
 *
 * NB: accessing Routing Engine "private" variable  -- no lock required.
 *
 *     checks session->active, only when not active -- no lock required.
 */
extern bool
bgp_session_is_active(bgp_session session)
{
  bool active ;

  if (session == NULL)
    active = false ;
  else
    {
      switch (session->state)
      {
        case bgp_session_sIdle:
        case bgp_session_sDisabled:
          assert(!session->active) ;
          active = false ;
          break ;

        case bgp_session_sEnabled:
        case bgp_session_sEstablished:
        case bgp_session_sLimping:
          active = true ;
          break ;

        default:
          zabort("invalid session->state") ;
      } ;
    } ;

  return active ;
} ;

/*------------------------------------------------------------------------------
 * Get a copy of the session statistics, copied all at once so
 * forms a consistent snapshot
 */
void
bgp_session_get_stats(bgp_session session, struct bgp_session_stats *stats)
{
  if (session == NULL)
    {
      memset(stats, 0, sizeof(struct bgp_session_stats)) ;
      return;
    }

  BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  *stats = session->stats;

  BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->->->*/
}
