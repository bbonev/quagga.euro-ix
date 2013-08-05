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
#include "lib/qatomic.h"

/*==============================================================================
 * BGP Session.
 *
 * Every bgp_peer has (at most) one bgp_session associated with it.
 *
 * A session is shared by the Routeing Engine (RE) and the BGP Engine (BE).
 *
 * A session is created some time before it is enabled, and may be destroyed
 * once the session is disabled.
 *
 * From the peer's perspective a session may be in one of the states:
 *
 *   * psDown         -- not doing anything -- but acceptor may be running
 *   * psUp           -- in the hands of the BGP Engine
 *   * psLimping      -- in the process of going psDown, also with the BE
 *
 * NB: in psDown state the BGP Engine has no interest in the session, except
 *     for the acceptor and the connection options.
 *
 * NB: in psUp and psLimping states the BGP Engine is running connection(s) for
 *     the session.
 *
 *     In psLimping state, a XXX stop message has been sent, but not yet
 *     acknowledged.
 *
 *     While the session is active some items in the structure are shared.
 *
 * NB: a session reaches psDown when the Routing Engine has sent a XXX disable
 *     request to the BGP Engine, AND an eDisabled event has come back.
 */

static void bgp_session_do_enable(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_update_recv(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_update_send(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_end_of_rib_send(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_route_refresh_send(mqueue_block mqb,
                                                               mqb_flag_t flag);
static void bgp_session_do_disable(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_XON(bgp_session session);
static void bgp_session_do_XON(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_self_do_XON(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_set_ttl(mqueue_block mqb, mqb_flag_t flag);
static void bgp_session_do_route_refresh_recv(mqueue_block mqb, mqb_flag_t flag);

/*==============================================================================
 * BGP Session initialisation and tear down.
 *
 */
static void bgp_session_clear(bgp_session session) ;

/*------------------------------------------------------------------------------
 * Allocate & initialise new session structure.
 *
 * Ties peer and session together.  Sets session sInitial.
 *
 * Unsets everything else -- mostly by zeroising it.
 *
 * NB: when a peer is created, its session must also be created and its peer
 *     index entry.  All that must be done before the session is passed to the
 *     BGP Engine.
 *
 * NB: the acceptor is not created until the session is enabled.
 *
 *     While the acceptor is NULL, no connections will be accepted -- RST.
 */
extern bgp_session
bgp_session_init_new(bgp_peer peer)
{
  bgp_session session ;

  assert(peer->state == bgp_pDisabled) ;
  assert(peer->session == NULL) ;

  session = XCALLOC(MTYPE_BGP_SESSION, sizeof(bgp_session_t)) ;

  /* Zeroizing sets:
   *
   *   * peer                   -- X            -- set below
   *   * peer_ie                -- X  ???
   *
   *   * fsm_event              -- feNULL       -- none, yet
   *   * notification           -- NULL         -- ditto
   *   * err                    -- 0            -- ditto
   *   * ordinal                -- 0            -- ditto
   *
   *   * ordinal_established    -- 0            -- N/A until psEstablished
   *
   *   * idle_hold_timer_interval
   *   * local_as               -- X            --
   *   * local_id               -- X            --
   *
   *   * remote_as              -- X
   *   * su_peer                -- X
   *
   *   * lox                    -- X
   *
   *   * args_tx                -- NULL         -- none, yet
   *   * args_config            -- NULL         -- none, yet
   *   * args                   -- NULL         -- none, yet
   *
   *   * open_sent              -- NULL         -- none, yet
   *   * open_recv              -- NULL         -- none, yet
   *
   *   * read_rb                -- NULL         -- none, yet
   *   * write_rb               -- NULL         -- none, yet
   *
   *   * stats                  -- all zero
   *
   *   * cops_tx                -- NULL
   *   * cops_config            -- NULL
   *   * cops                   -- NULL
   *
   *   * connections            -- NULLs        -- none, yet
   *   * state                  -- sInitial
   *
   *   * acceptor               -- NULL         -- none, yet
   */
  session->peer  = peer ;
  bgp_peer_lock(peer) ;         /* Account for the session->peer pointer */

  confirm(bgp_sInitial   == 0) ;

  /* Complete process and return session.
   */
  return peer->session = session ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: delete session for given peer.
 *
 * This is for use when the peer itself is being deleted.  (Peer MUST be in
 * pDeleting state.)
 *
 * Does nothing if there is no session !
 *
 * If the session is active, simply sets delete_me flag, which will be honoured
 * when the session goes sDisabled.  Note, it is the callers responsibility
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

  /* Make sure that the BGP Engine has, in fact, let go of the session.
   *
   * The LOCK/UNLOCK makes sure that the BGP Engine has unlocked the session.
   *
   * Without this, the qpt_mutex_destroy() can fail horribly, if the BGP
   * Engine sends the disable acknowledge before finally unlocking the session.
   */
  qassert(peer == session->peer) ;

  peer->session = NULL ;
  session->peer = NULL ;
  bgp_peer_unlock(peer) ;       /* Account for the session->peer pointer */
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: delete session for given peer.
 *
 * This is for use when the peer itself is being deleted.  (Peer MUST be in
 * pDeleting state.)
 *
 * Does nothing if there is no session !
 *
 * If the session is active, simply sets delete_me flag, which will be honoured
 * when the session goes sDisabled.  Note, it is the callers responsibility
 * to arrange for that to happen.
 *
 * If the session is not active, it is immediately freed.
 *
 * NB: if the session is freed, the peer may vanish at the same time !
 */
extern void
bgp_session_destroy(bgp_peer peer)
{
  bgp_session session = peer->session ;

  if (session == NULL)
    return ;                    /* easy if no session anyway    */

  assert(peer == session->peer) ;

  /* If is active, set flag so that session is deleted when next it becomes
   * sDown.
   */
  if (bgp_session_is_active(session))
    {
      session->delete_me = true ;
      return ;
    } ;

  /*----------------------------------------------------------------------------
   * Proceed to free the session structure.
   */

  /* Make sure that the BGP Engine has, in fact, let go of the session.
   *
   * The LOCK/UNLOCK makes sure that the BGP Engine has unlocked the session.
   *
   * Without this, the qpt_mutex_destroy() can fail horribly, if the BGP
   * Engine sends the disable acknowledge before finally unlocking the session.
   */
  /* Proceed to dismantle the session.
   */
  session->notification = bgp_notify_free(session->notification);
  session->open_sent    = bgp_open_state_free(session->open_sent);
  session->open_recv    = bgp_open_state_free(session->open_recv);

#if 0
  if (session->ifname != NULL)
    free(session->ifname) ;
  sockunion_unset(&session->ifaddress) ;
  if (session->password != NULL)
    XFREE(MTYPE_PEER_PASSWORD, session->password);
#endif

  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host);

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

  /* Zeroize to catch dangling references asap
   */
  memset(session, 0, sizeof(struct bgp_session)) ;
  XFREE(MTYPE_BGP_SESSION, session);
} ;

/*------------------------------------------------------------------------------
 * Clear the given session -- assumes already initialised and may have been
 * enabled.
 *
 * Clears down as follows:
 *
 *   * peer                     -- N/A
 *   * peer_ie                  -- N/A
 *
 *   * state_seen               -- sInitial
 *
 *   * fsm_event                -- feNULL
 *   * notification             -- NULL         -- none, yet
 *   * err                      -- 0            -- none, yet
 *   * ordinal                  -- 0            -- none, yet
 *   * ordinal_established      -- 0            -- none, yet
 *
 *   * idle_hold_timer_interval -- N/A
 *
 *   * local_as                 -- N/A
 *   * local_id                 -- N/A
 *
 *   * remote_as                -- N/A
 *
 *   * lox.log                  -- NULL
 *   * lox.host                 -- NULL
 *
 *   * args_config              -- NULL
 *   * args_tx                  -- NULL
 *   * args                     -- NULL
 *   * open_sent                -- NULL
 *   * open_recv                -- NULL
 *
 *   * read_rb                  -- NULL
 *   * write_rb                 -- NULL
 *
 *   * stats                    -- zeroized
 *
 *   * cops_tx                  -- N/A
 *   * cops_config              -- N/A
 *   * cops                     -- N/A
 *
 *   * connections              -- NULLs
 *
 *   * state                    -- N/A
 *
 *   * acceptor                 -- N/A
 */
static void
bgp_session_clear(bgp_session session)
{
  session->state_seen   = bgp_sInitial ;

  session->fsm_event    = bgp_feNULL ;
  session->notification = bgp_notify_free(session->notification) ;
  session->err          = 0 ;
  session->ordinal      = 0 ;

  session->ordinal_established = 0 ;

  session->lox.log      = NULL;

  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host) ;
                                        /* sets session->lox.host NULL  */

  session->args_config  = bgp_session_args_free(session->args_config) ;
  session->args_tx      = bgp_session_args_free(session->args_tx) ;
  session->args         = bgp_session_args_free(session->args) ;
  session->open_sent    = bgp_open_state_free(session->open_sent) ;

  session->read_rb      = rb_destroy(session->read_rb) ;
  session->write_rb     = rb_destroy(session->write_rb) ;

  memset(&session->stats, 0, sizeof(session->stats)) ;
  memset(session->connections, 0, sizeof(session->connections)) ;
} ;

/*==============================================================================
 * Enabling and disabling sessions and session events
 */
static bgp_session_args bgp_session_args_make(bgp_peer peer) ;

/*------------------------------------------------------------------------------
 *
 *
 */
extern void
bgp_session_prod(bgp_session session)
{

} ;

/*------------------------------------------------------------------------------
 * Routing Engine: enable session for given peer.
 *
 * Sets up the session given the current state of the peer.  If the state
 * changes, then need to disable the session and re-enable it again with new
 * parameters -- unless something more cunning is devised.
 *
 * Constructs a new set of session arguments.
 *
 * The peer MUST be: pDisabled  -- configured, but disabled for some reason
 *
 *
 *
 *                   The session_state may be:
 *
 *                     * bgp_psInitial  -- time to start up the acceptor, at
 *                                         least.
 *
 *                     * bgp_psDown     -- xxx
 *
 *               or: pEnabled   -- ready to run
 *
 *                   The session_state may be:
 *
 *                     * bgp_psInitial  -- time to start up the acceptor, at
 *                                         least.
 *
 *                     * bgp_psDown     -- xxx
 *
 * In these states there is no activity for the peer in the BGP Engine, and
 * there are no messages outstanding to or from the BGP Engine.
 *
 * Moves peer to pEnabled and sends message to BGP Engine to enable the
 * session (set up connections, start the FSM etc.).
 */
extern void
bgp_session_enable(bgp_peer peer)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  qassert( (peer->state == bgp_pDisabled) ||
           (peer->state == bgp_pEnabled) ) ;

  qassert( (peer->session_state == bgp_psInitial) ||
           (peer->session_state == bgp_psDown) ) ;

  session = peer->session ;

  assert(session != NULL) ;

  qassert(session->peer    == peer) ;
  qassert(session->peer_ie == peer->peer_ie) ;

  /* Clears the session and then sets:
   *
   *   * idle_hold_timer_interval XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
   *
   *   * lox.log                -- copy of peer->log
   *   * lox.host               -- copy of peer->host
   *
   *   * args_config            -- initial arguments
   *
   *   * stats                  -- reset to zero   TODO yes ??
   *
   *   * cops_tx                -- iff psInitial -- initial cops.
   *
   *   * state                  -- iff psInitial -- sInitial
   */
  bgp_session_clear(session) ;

  session->lox.log      = peer->log ;
  session->lox.host     = XSTRDUP(MTYPE_BGP_PEER_HOST,
                                    ((peer->host != NULL) ? peer->host
                                                          : "<unknown-host>")) ;

  session->args_config  = bgp_session_args_make(peer) ;

  memset(&session->stats, 0, sizeof(struct bgp_session_stats)) ;

  /* v_start is set to BGP_INIT_START_TIMER when the peer is first created.
   * It is adjusted when a session drops, so that if sessions going up and
   * down rapidly, the IdleHoldTime increases, but after a long lasting
   * session, the IdleHoldTime is reduced.
   *
   * v_connect is set by configuration.
   */
  session->idle_hold_timer_interval  = QTIME(peer->v_start) ;

  memset(&session->connections, 0, sizeof(session->connections)) ;

  /* If this is the very first enable, then we need a copy of the cops_config
   * from the peer, and we make sure the session->state is kosher.
   *
   * Also, need to worry about what state we now go to, depending on whether
   * the peer is
   */
  if (peer->session_state == bgp_psInitial)
    {
      bgp_cops  cops_tx ;

      cops_tx = bgp_cops_copy(NULL, &peer->cops) ;
      cops_tx = qa_swap_ptrs((void**)&session->cops_tx, cops_tx) ;

      qassert(cops_tx               == NULL) ;
      qassert(session->cops_config  == NULL) ;
      qassert(session->cops         == NULL) ;
      qassert(session->state        == bgp_sInitial) ;

      session->state    = bgp_sInitial ;

      qassert(session->acceptor     == NULL) ;
      session->acceptor = bgp_acceptor_init_new(session->acceptor, session) ;
    } ;

  /* Now pass the session to the BGP Engine and change state.
   *
   * There are no other messages for this peer outstanding, but we issue a
   * priority message to jump past any queue of outbound message events.
   */
  if (peer->session_state == bgp_psInitial)
    {

      bgp_session_start(session) ;
    } ;


  mqb = mqb_init_new(NULL, bgp_session_do_enable, session) ;

  confirm(sizeof(struct bgp_session_enable_args) == 0) ;

  ++bgp_engine_queue_stats.event ;

  peer->session_state = bgp_psUp ;
  bgp_to_bgp_engine(mqb, mqb_priority) ;
} ;

/*------------------------------------------------------------------------------
 * Construct new set of session arguments, based on current state of the peer.
 *
 * The session arguments are a direct copy of the peer->args, except:
 *
 *   * remote_id                -- 0
 *   * cap_suppressed           -- false
 *
 * If is !can_capability, flush out what we are not allowed to advertise.
 * NB: if is cap_af_override, we keep the can_af as the families we are
 *     "implicitly" advertising.
 *
 * And the Prefix ORF stuff:
 *
 *   * if we are not actually advertising anything, then we suppress
 *     args->can_orf, so will not send the capability at all.
 *
 *   * if we are willing to send the per-RFC capability, then update the
 *     Prefix ORF types to be advertised.
 *
 *   * make sure we only advertise things in can_af.
 *
 * And the Graceful Restart stuff:            XXX XXX XXX
 *
 *   * gr.can                   -- BGP_FLAG_GRACEFUL_RESTART
 *   * gr.restarting            -- false
 *   * gr.restart_time          -- 0
 *   * gr.can_preserve          -- empty
 *   * gr.has_preserved         -- empty
 *
 * Returns:  address of new bgp_session_args
 */
static bgp_session_args
bgp_session_args_make(bgp_peer peer)
{
  bgp_session_args_t args[1] ;
  qafx_t     qafx ;
  bgp_form_t can_orf ;

  memcpy(args, &peer->args, sizeof(args)) ;

  args->remote_id       = 0 ;
  args->cap_suppressed  = false ;

  if (!args->can_capability)
    bgp_session_args_suppress(args) ;

  /* We have the Prefix ORF wishes -- but not for pre-RFC, if that is being
   * supported.  (If !args->can_capability then the whole thing has been swept
   * away, already, and what follows adds nothing.)
   *
   * NB: if we cannot send MP-Ext, we can only send ORF for IPv4/Unicast.
   */
  can_orf = bgp_form_none ;             /* assume we want nothing.      */

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_orf_cap_bits_t orf_pfx, orf_wish ;

      orf_wish = args->can_orf_pfx[qafx] & (ORF_SM | ORF_RM) ;
      orf_pfx  = 0 ;
      if ((args->can_af & qafx_bit(qafx)) && (orf_wish != 0))
        {
          /* For the families we are going to advertise, see if we wish to
           * send or are prepared to receive Prefix ORF.
           *
           * Note that we set both the RFC Type and the pre-RFC one, so we
           * arrange to send the RFC Capability and the pre-RFC one.
           */
          can_orf = args->can_orf ;

          if (can_orf & bgp_form_rfc)
            orf_pfx = orf_wish ;

          if (can_orf & bgp_form_pre)
            orf_pfx |= (orf_wish << 4) ;

          confirm(ORF_SM_pre == (ORF_SM << 4)) ;
          confirm(ORF_RM_pre == (ORF_RM << 4)) ;
        } ;

      args->can_orf_pfx[qafx] = orf_pfx ;
    } ;

  args->can_orf = can_orf ;

  /* Graceful restart capability
   */
  if ((peer->bgp->flags & BGP_FLAG_GRACEFUL_RESTART) && args->can_capability)
    {
      args->gr.can           = true ;
      args->gr.restart_time  = peer->bgp->restart_time ;
    } ;

  /* TODO: check not has restarted and not preserving forwarding open_send (?)
   */
  args->gr.can_preserve    = 0 ;        /* cannot preserve forwarding   */
  args->gr.has_preserved   = 0 ;        /* has not preserved forwarding */
  args->gr.restarting      = false ;    /* is not restarting            */

  /* Return the new set of arguments.
   */
  return args ;
} ;

/*==============================================================================
 * Sending of messages to the BGP Engine, and the handling of same.
 */

/*------------------------------------------------------------------------------
 * Enable/Refresh/Disable messages
 *
 *   * start     --
 *
 *   * refresh   --
 *
 *   * stop      --
 *
 *   * kill      --
 */
static void
bgp_session_start(bgp_session session)
{

}











/*------------------------------------------------------------------------------
 * BGP Engine: session enable message action
 *
 * This is sent when: (a) peer is first configured and !SHUT_DOWN
 *                    (b) ready to start a new session
 */
static void
bgp_session_do_enable(mqueue_block mqb, mqb_flag_t flag)
{
  if (flag == mqb_action)
    {
      bgp_session session ;

      session = mqb_get_arg0(mqb) ;

      bgp_fsm_enable_session(session) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: disable session for given peer.
 *
 * Do nothing if is not pEnabled or pEstablished.
 *
 * If is pEnabled or pEstablished must be sUp.  So, send a disable message
 * with a copy of the given notification (if any) to the BGP Engine, and set
 * the session sLimping and the peer pLimping.
 *
 * If no bgp_notify provided, no notify will be sent.
 *
 * The BGP Engine will dispose of any notification or return it in due course.
 *
 * The BGP Engine will stop the session -- unless it is already stopped due to
 * some event in the BGP Engine.
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

  /* There can be a session to disable iff peer is pEnabled or pEstablished.
   */
  if( (peer->state != bgp_pEnabled) &&
      (peer->state != bgp_pEstablished) )
    return false ;

  session = peer->session ;

  assert(session->peer == peer) ;
  assert(session->peer_state == bgp_psUp) ;

  /* Ask the BGP engine to disable the session and set sLimping.
   *
   * Enable and disable messages are sent mqb_priority, so they are ordered
   * wrt each other, but take priority over any other messages -- in particular,
   * the disable message takes priority over any UPDATEs etc.
   *
   * NB: the session may already be stopped when the BGP Engine sees this
   *     message:
   *
   *       * the session is stopped, but the message to the Routing Engine is
   *         still in its message queue.
   *
   *       * the session stopped while the disable message was in the BGP
   *         Engine queue.
   *
   *     in any case, the BGP Engine discards the disable message, since it
   *     has already sent a "stopped" event.
   *
   * NB: if the session is not stopped, as it processes the disable it will
   *     discard any outstanding work for the session.
   *
   *     The Routing Engine should discard all further messages for this
   *     session up to the eDisabled, and must then discard any other
   *     messages for the session.
   *
   * NB: the Routing Engine MUST not issue any further messages until it sees
   *     a "stopped" event, and MUST ignore all messages up to and after
   *     that event.
   */
  mqb = mqb_init_new(NULL, bgp_session_do_disable, session) ;

  args = mqb_get_args(mqb) ;
  args->notification = bgp_notify_dup(notification) ;

  ++bgp_engine_queue_stats.event ;

  session->peer_state = bgp_psLimping;
  bgp_to_bgp_engine(mqb, mqb_priority) ;

  /* We have just disabled the session, sending (a copy of) any notification.
   */
  peer->state = bgp_pLimping ;
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
  bgp_session session ;
  struct bgp_session_disable_args* args ;

  session = mqb_get_arg0(mqb) ;
  args    = mqb_get_args(mqb) ;

  if (flag == mqb_action)
    {
      BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

      mqueue_revoke(bgp_nexus->queue, session, 0) ;
      bgp_fsm_disable_session(session, args->notification) ;

      BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/
    }
  else
    bgp_notify_free(args->notification) ;

  mqb_free(mqb) ;
}

/*------------------------------------------------------------------------------
 * BGP Engine: send session event signal to Routeing Engine
 *
 * The message sent contains:
 *
 *   bgp_session_eEstablished,       -- session state -> sEstablished
 *
 *     This is the expected response to a bgp_session_enable()
 *
 *     args->notification   -- X  (NULL)
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false
 *
 *     NB: once established, the connection in question becomes the primary.
 *         The ordinal here is the ordinal *before* became established.
 *
 *   bgp_session_eDisabled
 *
 *     This is the expected response to a bgp_session_disable()
 *
 *     args->notification   -- the notification sent, if any.
 *     args->err            -- X  (0)
 *     args->ordinal        -- X  (0)
 *     args->stopped        -- true
 *
 *     If a notification message is sent to the BGP Engine, then if it is
 *     actually sent, then that is signalled by returning it here.  If, for
 *     whatever reason, no notification is sent, then NULL is returned.
 *
 *   bgp_session_eStart
 *
 *     This tells the Routing Engine that a connection has gone from idle
 *     to either trying to connect (outbound) or ready to accept (inbound).
 *
 *     args->notification   -- X  (NULL)
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false
 *
 *   bgp_session_eRetry
 *
 *     This tells the Routing Engine that a connection has gone from trying
 *     to connect (outbound) or ready to accept (inbound), back round to trying
 *     again.
 *
 *     args->notification   -- X  (NULL)
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false
 *
 *   bgp_session_eOpen_reject
 *
 *     This tells the Routeing Engine that an invalid Open has been received,
 *     on one connection or another.
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false    -- FSM gone idle and will restart
 *
 *   bgp_session_eInvalid_msg
 *
 *     This tells the Routeing Engine that an invalid message has been received,
 *     on one connection or another.
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eFSM_error
 *
 *     This tells the Routeing Engine that something has gone wrong in the FSM
 *     sequencing... possibly an unexpected message from the other end.
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eNOM_recv
 *
 *     This tells the Routeing Engine that a NOTIFICATION has been received
 *     from the other end.
 *
 *     args->notification   -- the notification that was *received*
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eExpired
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_dropped
 *
 *     This tells the Routeing Engine that some TCP event has caused the
 *     connection to drop (eg ECONNRESET).
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_failed
 *
 *     This tells the Routeing Engine that a connect() or an accept() operation
 *     have failed to establish connection.
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_error
 *
 *     This tells the Routeing Engine that I/O error (which does not count
 *     as either bgp_session_eTCP_dropped or bgp_session_eTCP_failed) has
 *     occurred.
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eInvalid
 *
 *     Something has gone badly wrong.
 *
 *     args->notification   -- NULL
 *     args->err            -- X  (0)
 *     args->ordinal        -- X  (0)
 *     args->stopped        -- true
 *
 * NB: makes a copy of the notification for the Routing Engine.
 */
extern void
bgp_session_event(bgp_session session, bgp_fsm_event_t      event,
                                       bgp_notify           notification,
                                       int                  err,
                                       bgp_conn_ord_t ordinal,
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

  args->fsm_event    = event ;
  args->notification = bgp_notify_dup(notification) ;
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
bgp_session_update_send(bgp_session session, stream_fifo fifo)
{
  struct bgp_session_update_args* args ;
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_update_send, session) ;

  /* Zeroising message block sets:
   *
   *   args->buf             -- X         -- set below
   *   args->is_pending      -- NULL      -- isn't
   *   args->xon_kick        -- false     -- set below, if required
   */
  args = mqb_get_args(mqb) ;
  args->buf = stream_fifo_head(fifo) ;

  if (session->flow_control == BGP_XON_KICK)
    args->xon_kick = session->xon_awaited = true ;

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
  struct bgp_session_update_args* args ;
  bgp_session session ;

  args    = mqb_get_args(mqb) ;
  session = mqb_get_arg0(mqb) ;

  while (args->buf != NULL)
    {
      struct stream* buf ;

      if ((flag == mqb_action) && session->active)
        {
          bgp_connection connection ;

          connection = session->connections[bc_estd] ;
          assert(connection != NULL) ;

          /* If established, try and send.
           */
          if (connection->fsm_state == bgp_fsEstablished)
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

//    session->written += stream_get_len(buf) ;

      stream_free(buf) ;
    } ;

  /* If gets to here, then has dealt with all message(s).
   */
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
  return peer->session->flow_control > 0 ;
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
      bgp_connection connection = session->connections[bc_estd] ;
      assert(connection != NULL) ;

      /* If established, try and send.                                  */
      if (connection->state == bgp_fsEstablished)
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
  qafx_t     qafx ;

  qafx = qafx_from_q(afi, safi) ;

  mqb = mqb_init_new(NULL, bgp_session_do_end_of_rib_send, session) ;

  args = mqb_get_args(mqb) ;
  args->qafx       = qafx ;
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
      bgp_connection connection = session->connections[bc_estd] ;
      assert(connection != NULL) ;

      /* If established, try and send.                                  */
      if (connection->state == bgp_fsEstablished)
        {
          int ret = bgp_connection_no_pending(connection, &args->is_pending) ;

          if (ret != 0)
            ret = bgp_msg_send_end_of_rib(connection, args->qafx) ;

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
bgp_session_update_recv(bgp_session session, stream buf, bgp_size_t size)
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
 *
 * NB: The RE clears the session->peer pointer when the peer is deleted,
 *     but there may be messages in flight for the session... so we check
 *     for NULL session->peer pointer and discard (now) unwanted messages.
 *
 *     We are in the RE and *only* the RE clears the session->peer pointer.
 */
static void
bgp_session_do_update_recv(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_update_args* args ;
  bgp_session session ;
  bgp_peer    peer ;

  session = mqb_get_arg0(mqb) ;
  args    = mqb_get_args(mqb) ;
  peer    = session->peer ;

  if ( (flag == mqb_action) && (peer != NULL) )
    {
      qassert(peer->session == session) ;

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
 *
 * NB: The RE clears the session->peer pointer when the peer is deleted,
 *     but there may be messages in flight for the session... so we check
 *     for NULL session->peer pointer and discard (now) unwanted messages.
 *
 *     We are in the RE and *only* the RE clears the session->peer pointer.
 */
static void
bgp_session_do_route_refresh_recv(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_route_refresh_args* args  ;
  bgp_session session ;
  bgp_peer    peer ;

  session = mqb_get_arg0(mqb) ;
  args    = mqb_get_args(mqb) ;
  peer    = session->peer ;

  if ( (flag == mqb_action) && (peer != NULL) )
    {
      qassert(peer->session == session) ;

      bgp_route_refresh_recv(peer, args->rr) ;
    } ;

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
 *
 * NB: The RE clears the session->peer pointer when the peer is deleted,
 *     but there may be messages in flight for the session... so we check
 *     for NULL session->peer pointer and discard (now) unwanted messages.
 *
 *     We are in the RE and *only* the RE clears the session->peer pointer.
 */
static void
bgp_session_do_XON(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_route_refresh_args* args  ;
  bgp_session session ;
  bgp_peer    peer ;

  session = mqb_get_arg0(mqb) ;
  args    = mqb_get_args(mqb) ;
  peer    = session->peer ;

  if ( (flag == mqb_action) && (peer != NULL) )
    {
      int xoff = (session->flow_control <= 0);

      session->flow_control = BGP_XON_REFRESH;
      if (xoff)
        bgp_write (peer, NULL) ;
    }

  mqb_free(mqb) ;
}

/*==============================================================================
 * Routing Engine: send self an XON if one is not awaited.
 */
extern void
bgp_session_self_XON(bgp_peer peer)
{
  if ((peer->state == bgp_pEstablished) && !peer->session->xon_awaited)
    {
      mqueue_block   mqb ;

      peer->session->xon_awaited = true ;       /* prevent further kicks */

      mqb = mqb_init_new(NULL, bgp_session_self_do_XON, peer) ;

      confirm(sizeof(struct bgp_session_XON_args) == 0) ;

      bgp_to_routing_engine(mqb, mqb_ordinary) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: process incoming XON message -- mqb action function.
 */
static void
bgp_session_self_do_XON(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_peer peer ;

  peer = mqb_get_arg0(mqb) ;
  peer->session->xon_awaited = false ;

  if ( (flag == mqb_action) && (peer->state == bgp_pEstablished) )
    bgp_write (peer, NULL) ;

  mqb_free(mqb) ;
}

/*==============================================================================
 * Routing Engine: send set ttl message to BGP Engine, if session is active.
 */
extern void
bgp_session_set_ttl(bgp_session session, ttl_t ttl, bool gtsm)
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

      bgp_set_new_ttl(session->connections[bc_connect],
                                                  session->ttl, session->gtsm) ;
      bgp_set_new_ttl(session->connections[bc_accept],
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
      switch (session->peer_state)
      {
        case bgp_psDown:
          assert(!session->active) ;
          active = false ;
          break ;

        case bgp_psUp:
        case bgp_psLimping:
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
extern void
bgp_session_get_stats(bgp_session_stats stats, bgp_session session)
{
  if (session == NULL)
    memset(stats, 0, sizeof(bgp_session_stats_t)) ;
  else
    qa_memcpy(stats, &session->stats, sizeof(bgp_session_stats_t)) ;
}

/*==============================================================================
 * BGP Engine end of the transfer of cops and/or session arguments.
 */

/*------------------------------------------------------------------------------
 * Update the current session->cops_config, if required.
 *
 * If the session is sAcquiring, then this may (well) affect the accept and/or
 * connect connections that are trying to acquire a session.
 *
 * If is sEstablished and sEstablished, then will stop the session if required
 * by the 'stop_established' argument, IF there is a material change in the
 * cops.
 *
 * NB: !cops->accept && !cops->connect <=> SHUTDOWN
 *
 *     ...which affects sEstablished whether or not 'stop_established'
 *
 * NB: in sEstablished, provided is cops->accept || cops->connect, does not
 *     care what is now set, or whether the current session was accepted or
 *     connected.
 *
 * Will cope early in the morning, when is not sAcquiring and no current
 * cops_config.
 *
 * NB: caller remains responsible for the given notification.
 */
static void
bgp_session_cops_update(bgp_session session, bool stop_established,
                                                        bgp_notify notification)
{
  bgp_cops  cops_new ;

  cops_new = qa_swap_ptrs((void**)&session->cops_tx, NULL) ;

  if (cops_new == NULL)
    return ;

  /* Pass the new cops to the acceptor, which may or may not care, and will
   * take a copy if it wants.
   */
  bgp_acceptor_set_options(session->acceptor, cops_new) ;

  /* Now worry about whether the cops changes have any effect on the making of
   * connection(s).
   *
   * We bring down an sEstablished session iff required by 'stop_established'
   * and a change in the cops.
   *
   *   su_remote              -- change => restart accept/connect/session
   *   su_local               -- change => restart connect/session
   *
   *   port                   -- change => restart accept/connect/session
   *
   *   conn_state             -- if now !bc_is_enabled, stop session
   *                             if is now bc_is_enabled, but was not, start
   *
   *   conn_let               -- if is and was bc_is_enabled, then:
   *
   *                               if is sAcquiring: change => stop/start
   *                                                             accept/connect
   *
   *                               if is sEstablished: no effect, keep existing
   *                                                                    session
   *
   *   can_notify_before_open -- change affects next connection
   *
   *   connect_retry_secs     -- change affects the next timer
   *   accept_retry_secs      -- affects acceptor, only
   *
   *   ttl                    -- change => restart accept/connect/session
   *   gtsm                   -- change => restart accept/connect/session
   *
   *   ttl_out                -- N/A
   *   ttl_gtsm               -- N/A
   *
   *   password               -- change => restart accept/connect/session
   *
   *   ifname                 -- change => restart connect/session
   *   ifindex                -- N/A
   */
  if ( (session->state == bgp_sAcquiring) ||
       (session->state == bgp_sEstablished) )
    {
      bgp_cops  cops_config ;

      qassert(session->cops_config != NULL) ;
      cops_config = session->cops_config ;

      if      (cops_new->conn_state != bc_is_enabled)
        {
          /* SHUTDOWN or Disable -- affecting sAcquiring and sEstablished
           * equally.
           */
          if (cops_config->conn_state == bc_is_enabled)
            {
              if (cops_new->conn_state == bc_is_shutdown)
                bgp_fsm_disable_session(session,
                                   bgp_notify_dup_default(notification,
                                         BGP_NOMC_CEASE, BGP_NOMS_C_SHUTDOWN)) ;
              else
                bgp_fsm_disable_session(session,
                                       bgp_notify_dup_default(notification,
                                            BGP_NOMC_CEASE, BGP_NOMS_C_RESET)) ;
            } ;
        }
      else if (cops_new->conn_state != bc_is_enabled)
        {
          /* Now bc_enabled, but was not... so fire up the session.
           */
          bgp_fsm_enable_session(session) ;
        }
      else if ((session->state == bgp_sAcquiring) || stop_established)
        {
          /* Is not and was not SHUTDOWN or disabled, so start/stop/restart
           * connection(s) or session if required:
           *
           *   If we are sAcquiring, then:
           *
           *     * may start/stop accept and or connect.
           *
           *       NB: we have to make sure we start connection before stopping
           *           any, because stopping the only connection for a session
           *           brings it to sStopped !
           *
           *     * will restart connections if something material has changed.
           *
           *   If we are sEstablished, then we restart the current connection,
           *   if something material has changed.
           */
          bool  restart_accept, restart_connect ;

          /* For accept we need to restart if any of these are true.
           */
          restart_accept =
                !sockunion_same(&cops_new->su_remote, &cops_config->su_remote)
             || (cops_new->port != cops_config->port)
             || (cops_new->ttl  != cops_config->ttl)
             || (cops_new->gtsm != cops_config->gtsm)
             || (strcmp(cops_new->password, cops_config->password) != 0) ;

          /* There are a few more things which can cause a restart for connect
           * or for established session.
           */
          restart_connect = restart_accept
             || !sockunion_same(&cops_new->su_local, &cops_config->su_local)
             || (strcmp(cops_new->ifname, cops_config->ifname) != 0) ;

          /* If we are acquiring, may need to start/stop accept/connect.
           *
           * NB: does starts before stops.
           */
          if ((session->state == bgp_sAcquiring)
                               && (cops_new->conn_let != cops_config->conn_let))
            {
              bool will_accept,  did_accept ;
              bool will_connect, did_connect ;

              will_accept  = (cops_new->conn_let    & bc_can_accept) ;
              will_connect = (cops_new->conn_let    & bc_can_connect) ;

              did_accept   = (cops_config->conn_let & bc_can_accept) ;
              did_connect  = (cops_config->conn_let & bc_can_connect) ;

              /* If will but did not, start accept/connect
               */
              if (will_accept && !did_accept)
                {
                  qassert(session->connections[bc_accept] == NULL) ;
                  bgp_fsm_enable_connection(session, bc_accept) ;
                  restart_accept = false ;
                } ;

              if (will_connect && !did_connect)
                {
                  qassert(session->connections[bc_connect] == NULL) ;
                  bgp_fsm_enable_connection(session, bc_connect) ;
                  restart_connect = false ;
                } ;

              /* If did but will not, stop accept/connect.
               *
               * We are continuing with session... so don't really have a very
               * specific notification to send, if none is already given.
               */
              if (!will_accept && did_accept)
                {
                  qassert(session->connections[bc_accept] != NULL) ;
                  bgp_fsm_disable_connection(session->connections[bc_accept],
                                      bgp_notify_dup_default(notification,
                                         BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;
                  restart_accept = false ;
                } ;

              if (!will_connect && did_connect)
                {
                  qassert(session->connections[bc_connect] != NULL) ;
                  bgp_fsm_disable_connection(session->connections[bc_connect],
                                      bgp_notify_dup_default(notification,
                                         BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;
                  restart_connect = false ;
                } ;
            } ;

          /* Now, if we need to restart accept/connect/session, now is the
           * time to do so.
           */
          if (restart_accept && (session->state == bgp_sAcquiring))
            {
              bgp_connection connection ;

              connection = session->connections[bc_accept] ;

              qassert( (cops_new->conn_let    & bc_can_accept) ==
                       (cops_config->conn_let & bc_can_accept) ) ;
              qassert( (cops_config->conn_let & bc_can_accept) ==
                                                         (connection != NULL)) ;
              if (connection != NULL)
                bgp_fsm_restart_connection(connection,
                                        bgp_notify_dup_default(notification,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            } ;

          if (restart_connect)
            {
              bgp_connection connection ;

              if (session->state == bgp_sAcquiring)
                {
                  connection = session->connections[bc_connect] ;

                  qassert( (cops_new->conn_let    & bc_can_connect) ==
                           (cops_config->conn_let & bc_can_connect) ) ;
                  qassert( (cops_config->conn_let & bc_can_connect) ==
                                                         (connection != NULL)) ;
                }
              else
                {
                  connection = session->connections[bc_connect] ;
                  qassert(connection != NULL) ;
                } ;

              if (connection != NULL)
                bgp_fsm_restart_connection(connection,
                                        bgp_notify_dup_default(notification,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            } ;
        } ;
    } ;

  /* All set, can now discard any previous configuration and replace it.
   */
  bgp_cops_free(session->cops_config) ;
  session->cops_config = cops_new ;
} ;

/*------------------------------------------------------------------------------
 * Update the current session->args_config, if required.
 *
 * If the session is sAcquiring, then this may (well) affect the accept and/or
 * connect connections that are trying to acquire a session.
 *
 * It is assumed that if the session is being shut-down, then that will be by
 * an explicit disable... so not use this stuff, which is designed for running
 * or runnable sessions.  However, will disable the session if finds that
 * neither accept nor connect are now enabled, and is sAcquiring !
 *
 * Will cope early in the morning, when is not sAcquiring and no current
 * cops_config.
 *
 * NB: caller remains responsible for the given notification.
 */
static void
bgp_session_args_update(bgp_session session, bgp_notify notification)
{
  bgp_session_args  args_new ;

  args_new = qa_swap_ptrs((void**)&session->args_tx, NULL) ;

  if (args_new == NULL)
    return ;

  /* Now worry about whether the args changes have any effect on the session,
   * which (unless nothing has changed) is extremely likely, for connections
   * at fsOpenSent and beyond.
   *                                         fsOpenSent or
   *                                         fsOpenConfirm  |  fsEstablished
   *   * local_as               -- change =>    restart     |     restart
   *   * local_id               -- change =>    restart     |      keep
   *
   *   * remote_as              -- change =>    restart     |     restart
   *   * remote_id              -- N/A
   *
   *   * cap_af_override        -- change =>    restart     |     restart
   *   * cap_strict             -- change =>    restart     |     restart
   *
   *   * cap_suppressed         -- N/A
   *
   *   * can_capability         -- change =>    restart     |     restart
   *   * can_mp_ext             -- change =>    restart     |     restart
   *   * can_as4                -- change =>    restart     |     restart
   *
   *   * can_af                 -- change =>    restart     |     restart
   *
   *   * can_rr                 -- change =>    restart     |     restart
   *
   *   * gr.can                 -- change =>    restart     |      keep
   *   * gr.restarting          -- change =>    restart     |      keep
   *   * gr.restart_time        -- change =>    restart     |      keep
   *   * gr.can_preserve        -- change =>    restart     |      keep
   *   * gr.has_preserved       -- change =>    restart     |      keep
   *
   *   * can_orf                -- change =>    restart     |     restart
   *   * can_orf_pfx[]          -- change =>    restart     |     restart
   *
   *   * can_dynamic            -- change =>    restart     |      keep
   *   * can_dynamic_dep        -- change =>    restart     |      keep
   *
   *   * holdtime_secs          -- change =>    restart     |      keep
   *   * keepalive_secs         -- change =>                               XXX
   */
  if ( (session->state == bgp_sAcquiring) ||
       (session->state == bgp_sEstablished) )
    {
      bgp_session_args  args_config ;
      bool restart ;

      args_config = session->args_config ;

      /* In all cases, we need to restart if any of these are true.
       */
      restart = (args_new->local_as        != args_config->local_as)
             || (args_new->remote_as       != args_config->remote_as)
             || (args_new->cap_af_override != args_config->cap_af_override)
             || (args_new->cap_strict      != args_config->cap_strict)
             || (args_new->can_capability  != args_config->can_capability)
             || (args_new->can_mp_ext      != args_config->can_mp_ext)
             || (args_new->can_as4         != args_config->can_as4)
             || (args_new->can_af          != args_config->can_af)
             || (args_new->can_rr          != args_config->can_rr)
             || (args_new->can_orf         != args_config->can_orf)
             || (memcmp(args_new->can_orf_pfx, args_config->can_orf_pfx,
                                          sizeof(args_new->can_orf_pfx)) != 0) ;

      if (session->state == bgp_sEstablished)
        {
          /* Stop the current session, if restart is required.
           */
          if (restart)
            bgp_fsm_disable_session(session, notification) ;
        }
      else
        {
          /* Restart the accept and/or connect connections, if they are
           * fsOpenSent or fsOpenConfirm.
           *
           * In these states a few more things require a restart.
           */
          restart = restart
                 || (args_new->local_id        != args_config->local_id)
                 || (args_new->gr.can          != args_config->gr.can)
                 || (args_new->can_dynamic     != args_config->can_dynamic)
                 || (args_new->can_dynamic_dep != args_config->can_dynamic_dep)
                 || (args_new->holdtime_secs   != args_config->holdtime_secs) ;

          if (!restart && args_new->gr.can)
            restart =
                 (args_new->gr.restarting    != args_config->gr.restarting)
              || (args_new->gr.restart_time  != args_config->gr.restart_time)
              || (args_new->gr.can_preserve  != args_config->gr.can_preserve)
              || (args_new->gr.has_preserved != args_config->gr.has_preserved) ;

          if (restart)
            {
              bgp_conn_ord_t ord ;

              for (ord = bc_first ; ord <= bc_last ; ++ord)
                {
                  bgp_connection connection ;

                  connection = session->connections[ord] ;
                  if (connection == NULL)
                    continue ;

                  if ( (connection->fsm_state == bgp_fsOpenSent) ||
                       (connection->fsm_state == bgp_fsOpenConfirm) )
                    bgp_fsm_restart_connection(connection, notification) ;
                } ;
            } ;
        } ;
    } ;

  /* All set, can now discard any previous configuration and replace it.
   */
  bgp_session_args_free(session->args_config) ;
  session->args_config = args_new ;
} ;

