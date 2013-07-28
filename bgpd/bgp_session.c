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

/*------------------------------------------------------------------------------
 * Allocate & initialise new session structure.
 *
 * Ties peer and session together.  Sets session psDown and sInitial.
 * Initialises mutex.
 *
 * Unsets everything else -- mostly by zeroising it.
 *
 * NB: when a peer is created, its session must also be created and its peer
 *     index entry.  All that must be done before the session is passed to the
 *     BGP Engine.
 */
extern bgp_session
bgp_session_init_new(bgp_peer peer)
{
  bgp_session session ;

  assert(peer->state == bgp_pDisabled) ;
  assert(peer->session == NULL) ;

  session = XCALLOC(MTYPE_BGP_SESSION, sizeof(bgp_session_t)) ;

  /*
   *
   *   * peer                   -- X         -- set below
   *   * mutex                  -- X         -- set below
   *
   *   * flow_control           -- 0
   *   * xon_awaited            -- false
   *
   *   * delete_me              -- false
   *
   *   * ordinal_established    -- X         -- not established
   *
   *   * event                  -- bgp_session_null_event )
   *   * notification           -- NULL                   ) nothing, yet
   *   * err                    -- 0                      )
   *   * ordinal                -- 0                      )
   *
   *   * open_sent              -- NULL      )
   *   * open_recv              -- NULL      )
   *   * connect                -- false     ) set when session enabled
   *   * listen                 -- false     )
   *
   *   * cap_af_override        -- false     )
   *   * cap_strict             -- false     )
   *   * ttl                    -- 0         )
   *   * gtsm                   -- false     )
   *   * port                   -- X         )
   *   * ifname                 -- NULL      )
   *   * ifindex                -- X         )
   *   * ifaddress              -- NULL      )
   *   * remote_as                -- X         )
   *   * su_peer                -- NULL      )
   *   * log                    -- NULL      )
   *   * host                   -- NULL      )
   *   * password               -- NULL      )
   *
   *   * idle_hold_timer_interval      -- X  ) set when session enabled


   *   * as4                    -- false     )
   *   * af_adv                 -- 0         )
   *   * af_use                 -- 0         )
   *   * r_refresh              -- 0         )
   *   * orf_pfx_in_rfc         -- 0         )
   *   * orf_pfx_out_rfc        -- 0         )
   *   * orf_pfx_in_pre         -- 0         )
   *   * orf_pfx_out_pre        -- 0         )
   *   * su_local               -- NULL      )
   *   * su_remote              -- NULL      )
   *
   *   * stats                  -- all zero
   *
   *   * connections            -- NULLs
   *   * active                 -- false
   *   * accept                 -- false
   */
  session->mutex = qpt_mutex_new(qpt_mutex_recursive,
                                        qfs_gen("%s Session", peer->host).str) ;

  session->peer  = peer ;
  bgp_peer_lock(peer) ;             /* Account for the session->peer pointer  */

  confirm(bgp_sInitial   == 0) ;
  confirm(bgp_session_null_event == 0) ;

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
  BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  qassert(peer == session->peer) ;

  session->peer    = NULL ;

  BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/

  peer->session = NULL ;
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
  BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/

  session->mutex = qpt_mutex_destroy(session->mutex) ;

  /* Proceed to dismantle the session.
   */
  bgp_notify_unset(&session->notification);
  bgp_open_state_free(session->open_sent);
  bgp_open_state_free(session->open_recv);

#if 0
  if (session->ifname != NULL)
    free(session->ifname) ;
  sockunion_unset(&session->ifaddress) ;
  if (session->password != NULL)
    XFREE(MTYPE_PEER_PASSWORD, session->password);
#endif

  sockunion_unset(&session->su_peer) ;

  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host);

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

  /* Zeroize to catch dangling references asap
   */
  memset(session, 0, sizeof(struct bgp_session)) ;
  XFREE(MTYPE_BGP_SESSION, session);
} ;

/*==============================================================================
 * Enabling and disabling sessions and session events
 */
static void bgp_session_args_set(bgp_peer peer, bgp_session session) ;

/*------------------------------------------------------------------------------
 * Routing Engine: enable session for given peer -- allocate if required.
 *
 * Sets up the session given the current state of the peer.  If the state
 * changes, then need to disable the session and re-enable it again with new
 * parameters -- unless something more cunning is devised.
 *
 * The peer MUST be: pDisabled  -- all quiet
 *               or: pDown      -- was up and is tidying up afterwards
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
           (peer->state == bgp_pDown) ) ;

  qassert(peer->session_state == bgp_psDown) ;

  session = peer->session ;

  assert(session != NULL) ;

  /* Initialise what we need to make and run connections
   */
  session->flow_control = 0 ;
  session->xon_awaited  = false ;
  session->ordinal_established = 0 ;

  session->delete_me    = false ;
  session->event        = bgp_session_null_event ;
  bgp_notify_unset(&session->notification) ;
  session->err          = 0 ;
  session->ordinal      = 0 ;


  bgp_session_args_set(peer, session) ;

#if 0
  session->open_send = bgp_peer_open_state_init_new(session->open_send, peer) ;
  bgp_open_state_unset(&session->open_recv) ;





  session->connect   = !(peer->flags & PEER_FLAG_PASSIVE) ;
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
#endif

  /* Set the ASN and BGP-Id we are peering as.
   *
   * For iBGP and Confederation peers, this will be bgp->as.
   *
   * For eBGP this will be peer->change_local_as, or bgp->confed_id or bgp->as
   * in that order.
   */
  session->local_as  = peer->local_as ;
  session->local_id  = peer->local_id ;

  /* Identity of the peer.
   */
  session->remote_as  = peer->as ;
  sockunion_set_dup(&session->su_peer, &peer->su_name) ;

  /* take copies of peer's logging and host name string
   */
  session->lox.log    = peer->log ;

  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host);
  session->lox.host   = (peer->host != NULL)
                                 ? XSTRDUP(MTYPE_BGP_PEER_HOST, peer->host)
                                 : NULL;

#if 0
  if (session->password != NULL)
    XFREE(MTYPE_PEER_PASSWORD, session->password);
  session->password = (peer->password != NULL)
                        ? XSTRDUP(MTYPE_PEER_PASSWORD, peer->password)
                        : NULL;
#endif

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
   *
   * TODO -- sort out relationship peer->holdtime & peer->v_holdtime etc.
   *
   * TODO -- signalling change of timer values to a running session...
   *         ...probably only the connect_retry_timer_interval...
   *         ...except for sessions which are not up yet.
   */
  session->idle_hold_timer_interval     = QTIME(peer->v_start) ;

  /* su_local set when session Established
   * su_remote  set when session Established
   *
   * TODO: check whether session stats should persist
   */
  memset(&session->stats, 0, sizeof(struct bgp_session_stats)) ;
  memset(&session->connections, 0, sizeof(session->connections)) ;

  session->active  = false ;
  session->accept  = false ;

  /* Now pass the session to the BGP Engine and change state.
   *
   * There are no other messages for this peer outstanding, but we issue a
   * priority message to jump past any queue of outbound message events.
   */
  mqb = mqb_init_new(NULL, bgp_session_do_enable, session) ;

  confirm(sizeof(struct bgp_session_enable_args) == 0) ;

  ++bgp_engine_queue_stats.event ;

  session->peer_state = bgp_psUp ;
  bgp_to_bgp_engine(mqb, mqb_priority) ;
} ;






/*------------------------------------------------------------------------------
 * Construct new bgp_open_state for the given peer -- allocate if required.
 *
 * Initialises the structure according to the current peer state.
 *
 * Sets: peer->cap        -- to what we intend to advertise, clearing
 *                           all the received state.
 *       peer->af_adv     -- to what we intend to advertise
 *       peer->af_rcv     -- cleared
 *       peer->af_use     -- cleared
 *
 * TODO: if we are pEstablished or pEnabled... what to do with the peer->xxx ???
 *
 * NB: if is PEER_FLAG_DONT_CAPABILITY, sets what would like to advertise, if
 *     could.
 *
 *     When (if) session becomes established, then if either
 *     PEER_FLAG_DONT_CAPABILITY or
 *
 * Returns:  address of existing or new bgp_open_state, initialised as required
 */
static void
bgp_session_args_set(bgp_peer peer, bgp_session session)
{
  bgp_session_args args ;
  qafx_t  qafx ;
  bool    can_capability ;

  args = &session->args ;
  memset(args, 0, sizeof(bgp_session_args_t)) ;

  /* Zeroizing the args sets:
   *
   */

#if 0
  /* Allocate if required.  Zeroise in any case.
   */
  open_send = bgp_open_state_init_new(open_send) ;
#endif

  /* Reset what we expect to advertise and clear received and usable
   * capabilities.
   */
  peer->caps_adv = 0 ;
  peer->caps_rcv = 0 ;
  peer->caps_use = 0 ;

  peer->af_adv   = qafx_set_empty ;
  peer->af_rcv   = qafx_set_empty ;
  peer->af_use   = qafx_set_empty ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib   prib ;
      qafx_bit_t qb ;

      prib = peer->prib[qafx] ;
      qb   = qafx_bit(qafx) ;

      qassert((prib != NULL) == (peer->af_configured & qb)) ;

      if (prib == NULL)
        qassert(!(peer->af_enabled & qb)) ;
      else
        {
          prib->af_caps_adv    = 0 ;
          prib->af_caps_rcv    = 0 ;
          prib->af_caps_use    = 0 ;
          prib->af_orf_pfx_adv = 0 ;
          prib->af_orf_pfx_rcv = 0 ;
          prib->af_orf_pfx_use = 0 ;
        } ;
    } ;

  /* Set address families to announce/accept and whether we are sending
   * any capabilities at all.
   *
   * PEER_FLAG_DONT_CAPABILITY
   *
   * This is set to avoid sending capabilities to a peer which is so broken
   * that it will crash if it receives same.
   *
   * The effect is to force the open_state, peer->caps_adv, peer->af_adv etc.
   * to the basic "No Capabilities" open_send, ie:
   *
   *   * IPv4 Unicast enabled
   *
   *   * nothing else
   *
   * The expectation is that the peer will not send any capabilities, so
   * the result will the most basic session.
   *
   * If peer->af_enabled does not include IPv4 Unicast, then there is not
   * much point bringing up the session... but it will try, and then drop.
   *
   * Except, if PEER_FLAG_OVERRIDE_CAPABILITY, when:
   *
   *   * the peer is deemed to behave as if peer->af_enabled afi/safi had been
   *     advertised.
   *
   *   * and the peer is deemed to have advertised those afi/safi.
   *
   * So... we set the defaults and then adjust as required.
   */
  can_capability = !(peer->flags & PEER_FLAG_DONT_CAPABILITY) ;

  args->can_capability  = can_capability ;
  args->can_mp_ext      = can_capability ;

  args->cap_af_override = (peer->flags & PEER_FLAG_OVERRIDE_CAPABILITY) ;
  args->cap_strict      = (peer->flags & PEER_FLAG_STRICT_CAP_MATCH) ;

  /* We expect to say we can handle all the address families we are enabled
   * for.
   *
   * But, if not sending capabilities and not overriding the MP-Ext, then we
   * are (effectively) only advertising IPv4 Unicast.
   */
  args->can_af = peer->af_enabled ;

  if (!can_capability && !args->cap_af_override)
    args->can_af &= qafx_ipv4_unicast_bit ;

  /* Get timer values -- these follow the configuration for the peer or the
   * default for the bgp instance.
   *
   * NB: the current_holdtime and current_keepalive are significant only when
   *     the peer is pEnabled or pEstablished.
   *
   *     TODO ???  should we be dicking with this when pEstablished ???
   *
   */
  args->holdtime_secs      = peer_get_holdtime(peer, false /* config */) ;
  args->keepalive_secs     = peer_get_keepalive(peer, false /* config */) ;

  peer->current_holdtime   = args->holdtime_secs ;
  peer->current_keepalive  = args->holdtime_secs / 3 ;

  args->connect_retry_secs = peer_get_connect_retry_time(peer) ;
  args->accept_retry_secs  = peer_get_accept_retry_time(peer) ;
  args->open_hold_secs     = peer_get_open_hold_time(peer) ;

  /* Announce self as AS4 speaker if required
   */
  if (!bm->as2_speaker && can_capability)
    {
      peer->caps_adv |= PEER_CAP_AS4 ;
      args->can_as4 = true ;
    } ;

  /* Fill in the supported AFI/SAFI and the ORF capabilities.
   *
   * If we want to send one or both forms of ORF capability, we collect that
   * in args->can_orf.
   *
   * NB: if we cannot send MP-Ext, we can only send ORF for IPv4/Unicast.
   */
  args->can_orf = bgp_form_none ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib   prib ;
      qafx_bit_t qb ;

      prib = peer->prib[qafx] ;

      if (prib == NULL)
        continue ;

      if (!args->can_mp_ext && (qafx != qafx_ipv4_unicast))
        continue ;

      qb = qafx_bit(qafx) ;

      if ((args->can_af & qb) && can_capability)
        {
          /* For the families we are going to advertise, see if we wish to send
           * or are prepared to receive Prefix ORF.
           *
           * Note that we set both the RFC Type and the pre-RFC one, so we
           * arrange to end the RFC Capability and the pre-RFC one.
           */
          bgp_orf_cap_bits_t orf_pfx ;

          orf_pfx = 0 ;

          if (prib->af_flags & PEER_AFF_ORF_PFX_SM)
            orf_pfx |= ORF_SM | ORF_SM_pre ;
          if (prib->af_flags & PEER_AFF_ORF_PFX_RM)
            orf_pfx |= ORF_RM | ORF_RM_pre;

          args->can_orf_pfx[qafx] = prib->af_orf_pfx_adv = orf_pfx ;

          if (orf_pfx & (ORF_SM | ORF_RM))
            args->can_orf |= bgp_form_rfc ;
          if (orf_pfx & (ORF_SM_pre | ORF_RM_pre))
            args->can_orf |= bgp_form_pre ;
        } ;
    } ;

  /* Route refresh -- always advertise both forms
   */
  if (can_capability)
    {
      peer->caps_adv |= PEER_CAP_RR | PEER_CAP_RR_old ;
      args->can_r_refresh = bgp_form_pre | bgp_form_rfc ;
    } ;

  /* Dynamic Capabilities
   *
   * TODO: currently not supported, no how.
   */
  args->can_dynamic_dep = false && can_capability ;
  if (args->can_dynamic_dep)
    peer->caps_adv |= PEER_CAP_DYNAMIC_dep ;

  args->can_dynamic     = false && can_capability;
  if (args->can_dynamic)
    peer->caps_adv |= PEER_CAP_DYNAMIC ;

  /* Graceful restart capability
   */
  if ((peer->bgp->flags & BGP_FLAG_GRACEFUL_RESTART) && can_capability)
    {
      peer->caps_adv |= PEER_CAP_GR ;
      args->gr.can           = true ;
      args->gr.restart_time  = peer->bgp->restart_time ;
    }
  else
    {
      args->gr.can           = false ;
      args->gr.restart_time  = 0 ;
    } ;

  /* TODO: check not has restarted and not preserving forwarding open_send (?)
   */
  args->gr.can_preserve    = 0 ;        /* cannot preserve forwarding   */
  args->gr.has_preserved   = 0 ;        /* has not preserved forwarding */
  args->gr.restarting      = false ;    /* is not restarting            */

  /* After all that... if PEER_FLAG_DONT_CAPABILITY we should be advertising
   *                   nothing at all, capabilities-wise !
   */
  if (!can_capability)
    qassert(peer->caps_adv == PEER_CAP_NONE) ;
} ;








/*------------------------------------------------------------------------------
 * BGP Engine: session enable message action
 */
static void
bgp_session_do_enable(mqueue_block mqb, mqb_flag_t flag)
{
  if (flag == mqb_action)
    {
      bgp_session session ;

      session = mqb_get_arg0(mqb) ;

      BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

      session->active = true ;
      bgp_fsm_enable_session(session) ;

      BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->->*/
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
void
bgp_session_get_stats(bgp_session session, struct bgp_session_stats *stats)
{
  if (session == NULL)
    {
      memset(stats, 0, sizeof(struct bgp_session_stats)) ;
      return;
    }

  qa_memcpy(stats, session->stats, sizeof(struct bgp_session_stats)) ;
}
