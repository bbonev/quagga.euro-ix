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
#include "bgpd/bgp_peer_index.h"

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
 */

/*==============================================================================
 * BGP Session initialisation and tear down.
 *
 */
static void bgp_session_clear(bgp_session session) ;
static void bgp_session_set_lox(bgp_session session) ;
static void bgp_session_send_delete(bgp_session session) ;

/*------------------------------------------------------------------------------
 * Allocate & initialise new session structure.
 *
 * Ties peer and session together.  Sets session sReset.
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

  assert(peer->state == bgp_pDown) ;
  assert(peer->session == NULL) ;

  session = XCALLOC(MTYPE_BGP_SESSION, sizeof(bgp_session_t)) ;

  /* Zeroizing sets:
   *
   *   * peer                   -- X            -- set below
   *
   *   * state_seen             -- sReset       -- starting state
   *   * ord                    -- 0            -- none, yet
   *   * eqb.fsm_event          -- feNULL       -- ditto
   *   * eqb.note               -- NULL         -- ditto
   *   * eqb.err                -- 0            -- ditto
   *
   *   * ord_estd               -- 0            -- N/A until psEstablished
   *
   *   * idle_hold_time         -- 0            -- set when session started
   *
   *   * lox                    -- X            -- set from peer, below
   *
   *   * args_sent              -- NULL         -- none, yet
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
   *   * cops_sent              -- X            -- set below -- csDown
   *   * cops_config            -- X            -- set below -- csDown
   *   * cops                   -- NULL
   *
   *   * mqb_tx                 -- NULL         -- none, yet

   *   * connections            -- NULLs        -- none, yet
   *   * state                  -- sReset
   *
   *   * acceptor               -- NULL         -- none, yet
   */
  session->peer  = peer ;
  bgp_peer_lock(peer) ;         /* Account for the session->peer pointer */

  confirm(bgp_sReset   == 0) ;
  confirm(bgp_feNULL   == 0) ;

  bgp_session_set_lox(session) ;

  session->cops_sent   = bgp_cops_init_new(NULL) ;
  session->cops_config = bgp_cops_init_new(NULL) ;

  qassert(session->cops_config->conn_state == bgp_csDown) ;

  /* Register the peer and set: peer->peer_ie and peer->session.
   */
  bgp_peer_index_register(peer, session);

  return peer->session = session ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: deregister and delete session for given peer.
 *
 * This is for use when the peer itself is being deleted.  (Peer MUST be in
 * pDeleting state.)
 *
 * NB: the session is pssInitial or pssStopped, so there should be no events
 *     or other messages waiting to be processed.
 *
 *     We set session->peer = NULL, which *immediately* stops the session
 *     from generating any more messages for the peer.  XXX XXX XXX XXX XXX XXX XXX XXX
 *
 *
 */
extern void
bgp_session_delete(bgp_peer peer)
{
  bgp_session session ;

  session = peer->session ;
  qassert(peer == session->peer) ;

  qassert(  (peer->session_state == bgp_pssInitial)     /* not started  */
         || (peer->session_state == bgp_pssStopped) ) ; /* now stopped  */

  /* Deregister the peer -- so accept() can no longer find address.
   *
   * NB: after deregistering, will send a message to the BE to stop and
   *     dismantle the session and acceptor and any listener and password.
   *
   *     If a peer with the same address is invented, a new session will be
   *     created, but the acceptor, listener and password are set up by the
   *     BE on receipt of another *later* message.
   */
  bgp_peer_index_deregister(peer);

  /* Unhook the session and the peer from each other.
   *
   * Sets the session->peer to NULL -- BE will cannot generate any further
   * messages for the session from this instant on.  Then makes damn sure
   * there are none hanging around by revoking them.  Note that messages
   * to the RE point to the peer -- messages to the BE point to the session.
   */
  peer->session = NULL ;

  qa_set_ptr((void**)&session->peer, NULL) ;
  mqueue_revoke(re_nexus->queue, peer, 0) ;

  peer->session_state = bgp_pssDeleted ;        /* from peer's pov      */

  bgp_peer_unlock(peer) ;       /* Account for the session->peer pointer */

  /* Clear out everything we can do on this side of the house, set final
   * state of session, and send message to tell BE to finish the job.
   */
  bgp_session_clear(session) ;

  session->cops_sent = bgp_cops_free(session->cops_sent) ;

  session->state = bgp_sDeleting ;
  bgp_session_send_delete(session) ;
} ;

/*------------------------------------------------------------------------------
 * Clear the given session -- assumes already initialised and may have been
 * started, but is now stopped.
 *
 * Clears down as follows:
 *
 *   * peer                     -- preserved
 *
 *   * state_seen               -- sReset       -- starting state
 *   * ord                      -- 0            -- none, yet
 *   * eqb.fsm_event            -- feNULL       -- ditto
 *   * eqb.note                 -- NULL         -- ditto
 *   * eqb.err                  -- 0            -- ditto
 *
 *   * ord_estd                 -- 0            -- N/A until psEstablished
 *
 *   * idle_hold_time           -- 0            -- set when session started
 *
 *   * lox.log                  -- NULL
 *     log.host                 -- NULL
 *
 *   * args_sent                -- NULL         -- none
 *   * args_config              -- NULL         -- none
 *   * args                     -- NULL         -- none
 *   * open_sent                -- NULL         -- none
 *   * open_recv                -- NULL         -- none
 *
 *   * read_rb                  -- NULL         -- none
 *   * write_rb                 -- NULL         -- none
 *
 *   * stats                    -- all zero
 *
 *   * cops_sent                -- preserved
 *   * cops_config              -- preserved
 *   * cops                     -- NULL         -- last session gone
 *
 *   * mqb_tx                   -- preserved
 *
 *   * connections              -- NULLs
 *   * state                    -- preserved
 *
 *   * acceptor                 -- preserved
 */
static void
bgp_session_clear(bgp_session session)
{
  session->state_seen   = bgp_sReset ;

  session->eqb.fsm_event = bgp_feNULL ;
  session->eqb.note     = bgp_note_free(session->eqb.note) ;
  session->eqb.err      = 0 ;
  session->ord          = 0 ;

  session->ord_estd     = 0 ;

  session->lox.log      = NULL;
  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host) ;
                                        /* sets session->lox.host NULL  */

  session->args_sent    = bgp_session_args_free(session->args_sent) ;
  session->args_config  = bgp_session_args_free(session->args_config) ;
  session->args         = bgp_session_args_free(session->args) ;
  session->open_sent    = bgp_open_state_free(session->open_sent) ;

  session->read_rb      = rb_destroy(session->read_rb) ;
  session->write_rb     = rb_destroy(session->write_rb) ;

  memset(&session->stats, 0, sizeof(session->stats)) ;

  session->cops         = bgp_cops_free(session->cops) ;

  memset(session->connections, 0, sizeof(session->connections)) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: destroy session.
 *
 * Final part of process which started with bgp_session_delete().
 */
static void
bgp_session_destroy(bgp_session session)
{
  qassert(session->peer  == NULL) ;
  qassert(session->state == bgp_sDeleting) ;

  /* What we have left are:
   *
   *   * cops_config                -- now discard
   *
   *   * mqb_tx                     -- should be NULL
   *
   *   * connections                -- should be NULL
   *
   *   * acceptor                   -- now discard
   */
  session->cops_config = bgp_cops_free(session->cops_config) ;

  qassert(session->mqb_tx == NULL) ;
  qassert(session->connections[bc_estd]    == NULL) ;
  qassert(session->connections[bc_connect] == NULL) ;
  qassert(session->connections[bc_accept]  == NULL) ;

  session->acceptor = bgp_acceptor_free(session->acceptor) ;

  /* All done.
   */
  XFREE(MTYPE_BGP_SESSION, session);
} ;

/*------------------------------------------------------------------------------
 * Set session->lox from peer->lox (if any)
 */
static void
bgp_session_set_lox(bgp_session session)
{
  bgp_peer peer ;

  peer = session->peer ;

  session->lox.log = (peer != NULL) ? peer->log : NULL ;

  if (session->lox.host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, session->lox.host) ;

  session->lox.host = XSTRDUP(MTYPE_BGP_PEER_HOST,
              ( ((peer != NULL) && (peer->host != NULL)) ? peer->host
                                                         : "<unknown-host>" )) ;
} ;

/*==============================================================================
 * Enabling and disabling sessions and session events
 */
static bool bgp_session_args_make(bgp_session session, bool refresh) ;
static bool bgp_session_cops_make(bgp_session session, bool refresh) ;

/*------------------------------------------------------------------------------
 * Routeing Engine: start session -- as possible
 *
 * This is for use:
 *
 *   (a) after reading of configuration, for all sessions, to:
 *
 *         * start the Acceptor -- unless is pisDown
 *
 *         * start the Session  -- if is pisRunnable
 *
 *       Will be:  pssInitial/sReset
 *
 *   (b) when has been pisDown, and is now not.
 *
 *       This is essentially the same as (a), indeed if the peer is pisDown
 *       after reading the configuration, will be in this state .
 *
 *       Will be:  pssInitial/sReset    -- if never been started
 *
 *                 pssStopped/sStopped  -- previous session stopped
 *
 *                 pssStopped/sReset    -- previous session started, but was not
 *                                         pisRunnable/csRun
 *
 *   (c) when has been !pisDown and !pisRunnable, and is now pisRunnable
 *
 *       Will be:  pssStopped/sStopped  -- previous session stopped
 *
 *                 pssStopped/sReset    -- previous session started, but was not
 *                                         pisRunnable/csRun
 * In these states there is no activity for the peer in the BGP Engine, and
 * there are no messages outstanding to or from the BGP Engine.
 *
 * Does nothing if reading configuration -- stays bgp_pssInitial/sReset.
 *
 * Does nothing if the session is pisDown -- stays in current state
 *
 * Otherwise: refresh the cops_tx and the args_tx and send a prod message.
 *
 *            Sets: sReset     -- the last session (if any) is now completely
 *                                forgotten.
 *
 *                  pssRunning -- iff pisRunnable
 *                  pssStopped        otherwise
 */
extern void
bgp_session_start(bgp_session session)
{
  bgp_peer      peer ;
  qtime_t       idle_hold_time ;

  peer = session->peer ;

  qassert(session          == peer->session) ;

  if      (peer->session_state == bgp_pssInitial)
    qassert(session->state == bgp_sReset) ;
  else if (peer->session_state == bgp_pssStopped)
    qassert((session->state == bgp_sReset) ||
            (session->state == bgp_sStopped)) ;
  else
    qassert(false) ;

  if (bm->reading_config || (peer->idle & bgp_pisDown))
    return ;

  /* Clear the session and set:
   *
   *   * idle_hold_time         -- to current value
   *
   *   * lox.log                -- copy of peer->log
   *   * lox.host               -- copy of peer->host
   *
   *   * stats                  -- reset to zero   TODO yes ??
   *
   *   * state                  -- sReset, FSM yet to get going
   *
   * ...we're assuming we are going to start the session, so we make sure
   * we are all set for that.
   */
  bgp_session_clear(session) ;

  session->state = bgp_sReset ;

  idle_hold_time = peer->idle_hold_time ;

  if (idle_hold_time > QTIME(peer->bgp->default_idle_hold_max_secs))
    idle_hold_time = QTIME(peer->bgp->default_idle_hold_max_secs) ;
  if (idle_hold_time < QTIME(peer->bgp->default_idle_hold_min_secs))
    idle_hold_time = QTIME(peer->bgp->default_idle_hold_min_secs) ;

  session->idle_hold_time = idle_hold_time ;

  bgp_session_set_lox(session) ;

  /* Now pass the session to the BGP Engine and change state.
   *
   * There are no other messages for this peer outstanding, but we issue a
   * priority message to jump past any queue of outbound message events.
   */
  peer->session_state = (peer->idle == bgp_pisRunnable) ? bgp_pssRunning
                                                        : bgp_pssStopped ;
  bgp_session_prod(session, NULL, true /* refresh */) ;
} ;

/*------------------------------------------------------------------------------
 * Construct new set of connection options, based on current state of the peer.
 *
 * The connection options are a direct copy of the peer->cops, except:
 *
 *   * ttl_out          -- set zero
 *   * ttl_min          -- set zero
 *   * ifindex          -- set zero
 *
 * Since those are of no interest to the peer, we simply ensure they are
 * zero in the peer->cops.
 *
 * Returns:  true <=> cops changed since session->cops_sent or 'refresh'
 */
static bool
bgp_session_cops_make(bgp_session session, bool refresh)
{
  bgp_peer   peer ;
  bgp_cops   p_cops ;
  bgp_cops_t cops_dummy ;
  bgp_conn_state_t conn_state ;

  peer = session->peer ;

  if (peer != NULL)
    {
      /* We have an attached peer.
       *
       * Clear down the unused entries in the original peer->cops.
       */
      p_cops = &peer->cops ;

      p_cops->ttl_out = p_cops->ttl_min = 0 ;
      p_cops->ifindex = 0 ;

      /* Update the: bgp_csTrack  -- ! pisDown
       *             bgp_csRun    --   pisRunnable
       */
      conn_state = p_cops->conn_state  ;

      if (peer->idle == bgp_pisRunnable)
        conn_state =  conn_state |  (bgp_csTrack | bgp_csRun) ;
      else
        conn_state = (conn_state & ~(bgp_csTrack | bgp_csRun))
                                 | ((peer->idle == bgp_pisDown) ? 0
                                                                : bgp_csTrack) ;
    }
  else
    {
      /* We do not have an attached peer -- must be shutdown.
       *
       * Arrange for a dummy set of new cops... either a copy of those last
       * sent, but bgp_csDown, or a completely empty set.
       */
      p_cops = &cops_dummy ;

      if (session->cops_sent == NULL)
        bgp_cops_reset(p_cops) ;
      else
        bgp_cops_copy(p_cops, session->cops_sent) ;

      conn_state = bgp_csDown ;
    } ;

  p_cops->conn_state = conn_state ;

  /* Now... if a refresh is not required, and the result is the same as the
   * last cops_sent, we are done.
   */
  if (!refresh && (session->cops_sent != NULL)
               && memsame(p_cops, session->cops_sent, sizeof(*p_cops)))
    return false ;

  /* Update (or create) session->cops_sent
   */
  session->cops_sent = bgp_cops_copy(session->cops_sent, p_cops) ;
  return true ;                        /* changed or refreshed  */
} ;

/*------------------------------------------------------------------------------
 * If the arguments have changed, update peer->args_sent.
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
 * Returns:  true <=> args changed since session->args_sent or 'refresh'
 */
static bool
bgp_session_args_make(bgp_session session, bool refresh)
{
  bgp_peer   peer ;
  bgp_session_args_t args[1] ;
  qafx_t     qafx ;
  bgp_form_t can_orf ;

  peer = session->peer ;

  if (peer != NULL)
    {
      /* We have an attached peer... so copy it's current arguments, clearing
       * down stuff which does not apply.
       *
       * Then transfer in the Graceful Restart flag.
       *
       * If !can_capability, flush out everything that depends on same !
       */
      memcpy(args, &peer->args, sizeof(args)) ;

      args->remote_id       = 0 ;
      args->cap_suppressed  = false ;

      args->gr.can = (peer->bgp->flags & BGP_FLAG_GRACEFUL_RESTART) ;

      if (!args->can_capability)
        bgp_session_args_suppress(args) ;
    }
  else
    {
      /* We do not have an attached peer... must be closing down the session.
       *
       * Treat as having a very empty set of arguments.
       */
      bgp_session_args_reset(args) ;
    } ;

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
  if (args->gr.can)
    args->gr.restart_time  = peer->bgp->restart_time ;

  /* TODO: check not has restarted and not preserving forwarding open_send (?)
   */
  args->gr.can_preserve    = 0 ;        /* cannot preserve forwarding   */
  args->gr.has_preserved   = 0 ;        /* has not preserved forwarding */
  args->gr.restarting      = false ;    /* is not restarting            */

  /* Now... if the result differs from the args_sent, we need to prepare
   * a copy to replace same.
   */
  if (!refresh && (session->args_sent != NULL)
               && memsame(args, session->args_sent, sizeof(args)))
    return false ;                      /* no change            */

  /* Update (or create) session->args_sent.
   */
  session->args_sent = bgp_session_args_copy(session->args_sent, args) ;
  return true ;                        /* changed or refreshed  */
} ;

/*==============================================================================
 * Sending of messages to the BGP Engine, and the handling of same.
 */
static void bgp_session_do_prod(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_delete(mqueue_block mqb, mqb_flag_t flag) ;

static void bgp_session_cops_update(bgp_session session, bgp_cops cops_new,
                                         bgp_note note, bool peer_established) ;

static void bgp_session_args_update(bgp_session session,
                                     bgp_session_args args_new, bgp_note note) ;

/*------------------------------------------------------------------------------
 * Routeing Engine: prod the session if required.
 *
 * This can be called when the peer cops and/or args may have changed, or when
 * the session has been detached from the peer.
 *
 * Does nothing at all if reading_config.
 *
 * Works out what cops and/or args should be passed to the session, and if
 * those have changed since what we last sent, we send them.
 *
 * If the peer is pEstablished, then we (a) do not send any changes to the
 * args -- once we are pEstablished, changes here require a full reset of
 * the session; and (b) any changes to cops are passed with the
 * 'peer_established' flag set -- which inhibits the application of the cops
 * to the session, unless is !csRun.
 */
extern void
bgp_session_prod(bgp_session session, bgp_note note, bool refresh)
{
  mqueue_block mqb ;
  bgp_session_args args_new, args_swap ;
  bgp_cops         cops_new, cops_swap ;
  bool             send ;
  bool             peer_established ;

  if (bm->reading_config)
    return ;

  peer_established = (session->peer != NULL)
                                 && (session->peer->state == bgp_pEstablished) ;

  /* See if we need to send an update for the connection options.
   *
   * And, if we are not peer_established and are (now) csRun, the same for
   * arguments.
   *
   * If there is nothing to change, leave.
   */
  if (bgp_session_cops_make(session, refresh))
    cops_new = bgp_cops_dup(session->cops_sent) ;
  else
    cops_new = NULL ;

  if (!peer_established && (session->cops_sent->conn_state & bgp_csRun)
                        && bgp_session_args_make(session, refresh))
    args_new = bgp_session_args_dup(session->args_sent) ;
  else
    args_new = NULL ;

  send = ((cops_new != NULL) || (args_new != NULL)) ;

  if (!send)
    return ;                    /* nothing to update            */

  /* If there is a prod message in flight, then if it agrees
   * peer_established'-wise then we update its contents.
   *
   * Otherwise, we will send a new message.
   *
   * NB: LOCK_/UNLOCK_QATOMIC()/ synchronises memory.
   */
  cops_swap = NULL ;
  args_swap = NULL ;

  LOCK_QATOMIC() ;

  if (session->mqb_tx != NULL)
    {
      struct bgp_session_prod_args* mqba ;

      mqba = mqb_get_args(session->mqb_tx) ;

      if (mqba->peer_established == peer_established)
        {
          if (mqba->note == NULL)
            {
              mqba->note = note ;
              note = NULL ;
            } ;

          if (cops_new != NULL)
            {
              cops_swap  = mqba->cops ;
              mqba->cops = cops_new ;
            } ;

          if (args_new != NULL)
            {
              args_swap  = mqba->args ;
              mqba->args = args_new ;
            } ;

          send = false ;
        } ;
    } ;

  UNLOCK_QATOMIC() ;

  /* Now send the message, or tidy up after having updated the message that
   * is in flight already.
   */
  if (send)
    {
      /* Prepare and send 'prod' message
       */
      struct bgp_session_prod_args* mqba ;

      mqb = mqb_init_new(NULL, bgp_session_do_prod, session) ;

      mqba = mqb_get_args(mqb) ;

      mqba->note    = bgp_note_dup(note) ;
      mqba->peer_established = peer_established ;

      mqba->args    = bgp_session_args_dup(session->args_sent) ;
      mqba->cops    = bgp_cops_dup(session->cops_sent) ;

      qa_set_ptr((void**)&session->mqb_tx, mqb) ;

      bgp_to_bgp_engine(mqb, mqb_priority, bgp_engine_log_event) ;
    }
  else
    {
      bgp_session_args_free(args_swap) ;
      bgp_cops_free(cops_swap) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: process "prod" message
 *
 * This is sent when: (a) session->cops_sent is updated
 *            and/or: (b) session->args_sent is updated -- if !peer_established
 *
 * The running session->cops_config and session->args_config are updated,
 * as required.
 *
 * In particular, changes to cops_config->conn_state may bring up or take down
 * session and/or connections.
 */
static void
bgp_session_do_prod(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session ;
  struct bgp_session_prod_args* mqba ;

  session = mqb_get_arg0(mqb) ;
  mqba    = mqb_get_args(mqb) ;

  /* If this is the current "in-flight" prod, we take ownership.
   *
   * Note that we do this even if the message is being revoked.
   *
   * NB: LOCK_/UNLOCK_QATOMIC()/ synchronises memory.
   */
  LOCK_QATOMIC() ;

  if (session->mqb_tx == mqb)
    session->mqb_tx = NULL ;

  UNLOCK_QATOMIC() ;

  /* Now we update the session to the latest cops/args.
   */
  if (flag == mqb_action)
    {
      if (mqba->peer_established)
        qassert((mqba->cops != NULL) && (mqba->args != NULL)) ;

      if (mqba->cops != NULL)
        {
          bgp_session_cops_update(session, mqba->cops, mqba->note,
                                                       mqba->peer_established) ;
          mqba->cops = NULL ;
        } ;

      if ((mqba->args != NULL) && !mqba->peer_established)
        {
          bgp_session_args_update(session, mqba->args, mqba->note) ;
          mqba->args = NULL ;
        } ;
    } ;

  /* Done... noting that we need to discard any remaining payload.
   */
  bgp_cops_free(mqba->cops) ;
  bgp_session_args_free(mqba->args) ;

  bgp_note_free(mqba->note) ;
  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: send message to BE to finish off the session.
 *
 * The session was pssInitial or pssStopped, and is now pssDeleted/sDeleting.
 * So not much is going on, other than the Acceptor, which now needs to be
 * closed, listeners tidied up and passwords undone.
 */
static void
bgp_session_send_delete(bgp_session session)
{
  mqueue_block   mqb ;

  qassert(session->state == bgp_sDeleting) ;

  mqb = mqb_init_new(NULL, bgp_session_do_delete, session) ;

  bgp_to_bgp_engine(mqb, mqb_priority, bgp_engine_log_event) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: session delete message action
 *
 * Finish off session: dismantle acceptor, listener(s), password, cops etc.
 * and then free the session structure.
 */
static void
bgp_session_do_delete(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session ;

  session = mqb_get_arg0(mqb) ;

  if (flag == mqb_action)
    {
      bgp_peer peer ;

      peer = qa_get_ptr((void**)&session->peer) ;

      qassert((peer == NULL) && (session->state == bgp_sDeleting)) ;

      /* There should not be any other messages for this session, but we
       * clear them out if there are.
       */
      mqueue_revoke(be_nexus->queue, session, 0) ;

      /* Finally, destroy the session
       */
      bgp_session_destroy(session) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: send session event signal to Routeing Engine
 *
 * NB: passes any given note to the RE.
 */
extern void
bgp_session_send_event(bgp_session session, bgp_conn_ord_t ord, bgp_fsm_eqb eqb)
{
  struct bgp_session_event_args* args ;
  mqueue_block   mqb ;
  bgp_peer       peer ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  peer = qa_get_ptr((void**)&session->peer) ;

  if (peer == NULL)
    return ;

  /* All is well, send message.
   */
  mqb = mqb_init_new(NULL, bgp_session_do_event, peer) ;

  args = mqb_get_args(mqb) ;

  args->state   = session->state ;
  args->ord     = ord ;
  args->eqb     = *eqb ;

  eqb->note     = NULL ;                /* transfer to Routeing Engine  */

  bgp_to_routing_engine(mqb, mqb_priority, bgp_engine_log_event) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine: deal with session event -- mqueue_action function.
 *
 * Receives notifications from the BGP Engine a session event occurs.
 *
 * -- arg0  = session
 *    args  =  bgp_session_event_args
 */
static void
bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_event_args* args ;
  bgp_peer    peer ;
  bgp_session session ;

  args  = mqb_get_args(mqb) ;
  peer  = mqb_get_arg0(mqb) ;

  session = peer->session ;

  if ((flag == mqb_action) && (session != NULL))
    {
      /* Pull stuff into Routing Engine *private* fields in the session
       */
      bgp_peer_session_state_t  pss ;

      pss = peer->session_state ;

      switch (args->state)
        {
          /* If now Established, then the BGP Engine has exchanged BGP Open
           * messages, and received the KeepAlive that acknowledges our Open.
           *
           * The args->ordinal gives which connection it was that became the
           * established one.  The established connection becomes the
           * "primary".
           *
           * Ignore this, however, if the session is sLimping -- which can
           * happen when the session has been disabled, but it became
           * established before the BGP Engine had seen the disable message.
           */
          case bgp_sReset:
            ;
            break ;

          case bgp_sAcquiring:
            if (pss == bgp_pssLimping)
              break ;

            qassert(pss == bgp_pssRunning) ;
            break ;

          case bgp_sEstablished:
            if (pss == bgp_pssLimping)
              break ;

            qassert(pss == bgp_pssRunning) ;

            if (session->state_seen != bgp_sEstablished)
              {
                session->state_seen = args->state ;
                session->ord_estd   = args->ord ;

                bgp_session_has_established(session) ;
              } ;

          default:
            qassert(false) ;
            fall_through ;

          case bgp_sStopped:
            if (args->eqb.note != NULL)
              {
                bgp_session_has_stopped(session, args->eqb.note) ;
                args->eqb.note = NULL ;
              } ;

          case bgp_sDeleting:
            break ;
        } ;
    } ;

  bgp_note_free(args->eqb.note) ;       /* Discard any unused note      */
  mqb_free(mqb) ;
} ;

/*==============================================================================
 * Routeing Engine prompting the BGP Engine for rb_read/rb_write, and
 * BGP Engine prompting the Routeing Engine likewise.
 */

static void bgp_session_do_kick_re_read(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_be_read(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_read(bgp_peer peer) ;
static void bgp_session_do_kick_be_write(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_re_write(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_write(bgp_peer peer) ;

/*------------------------------------------------------------------------------
 * BGP Engine send message: kick the RE to empty out the read_rb.
 */
extern void
bgp_session_kick_re_read(bgp_session session)
{
  bgp_peer       peer ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  peer = qa_get_ptr((void**)&session->peer) ;

  if (peer == NULL)
    bgp_session_do_kick_read(peer) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message to self, if required: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
extern void
bgp_session_kick_read(bgp_peer peer)
{
  if (rb_put_kick(peer->session->read_rb))
    bgp_session_do_kick_read(peer) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine or BGP Engine, send message RE: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
static void
bgp_session_do_kick_read(bgp_peer peer)
{
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_kick_re_read, peer) ;
  bgp_to_routing_engine(mqb, mqb_ordinary, bgp_engine_log_xon) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine receive message: signal to the reader that there is more
 *                                   stuff in the read_rb ready to be processed.
 *
 * NB: does nothing if the peer is no longer pEstablished.
 *
 *     If a session stop message is sent, it is sent 'priority', so it is
 *     possible for that to jump the queue ahead of a kick message.
 */
static void
bgp_session_do_kick_re_read(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_peer peer ;

  peer = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (peer->state == bgp_pEstablished))
    {
      ring_buffer rb ;

      rb = peer->session->read_rb ;

      rb_get_prompt_clear(rb) ;
      bgp_packet_read_stuff(peer, rb) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message: kick the BE to put more into the read_rb.
 */
extern void
bgp_session_kick_be_read(bgp_peer peer)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  /* Belt and braces -- do nothing if no session !!
   */
  session = peer->session ;
  if (session == NULL)
    return ;

  /* Send the message
   */
  mqb = mqb_init_new(NULL, bgp_session_do_kick_be_read, session) ;
  bgp_to_bgp_engine(mqb, mqb_ordinary, bgp_engine_log_xon) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine receive message: signal to the reader that there is more space in
 *                                           the read_rb ready to be read into.
 *
 * NB: does nothing if the session is no longer sEstablished.
 */
static void
bgp_session_do_kick_be_read(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session ;

  session = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (session->state == bgp_sEstablished))
    {
      rb_put_prompt_clear(session->read_rb) ;
      bgp_fsm_io_event(session->connections[bc_estd]) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message: kick the BE to empty out the write_rb.
 */
extern void
bgp_session_kick_be_write(bgp_peer peer)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  /* Belt and braces -- do nothing if no session !!
   */
  session = peer->session ;
  if (session == NULL)
    return ;

  /* Send the message
   */
  mqb = mqb_init_new(NULL, bgp_session_do_kick_be_write, session) ;
  bgp_to_bgp_engine(mqb, mqb_ordinary, bgp_engine_log_xon) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine receive message: signal to the writer that there is more in the
 *                                                  write_rb ready to be output.
 *
 * NB: does nothing if the session is no longer sEstablished.
 */
static void
bgp_session_do_kick_be_write(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session ;

  session = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (session->state == bgp_sEstablished))
    {
      rb_get_prompt_clear(session->write_rb) ;
      bgp_fsm_io_event(session->connections[bc_estd]) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine send message: kick the RE to put more into the write_rb.
 */
extern void
bgp_session_kick_re_write(bgp_session session)
{
  bgp_peer       peer ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  peer = qa_get_ptr((void**)&session->peer) ;

  if (peer != NULL)
    bgp_session_do_kick_write(peer) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message to self, if required: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
extern void
bgp_session_kick_write(bgp_peer peer)
{
  if (rb_put_kick(peer->session->write_rb))
    bgp_session_do_kick_write(peer) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine or BGP Engine, send message RE: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
static void
bgp_session_do_kick_write(bgp_peer peer)
{
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_kick_re_write, peer) ;
  bgp_to_routing_engine(mqb, mqb_ordinary, bgp_engine_log_xon) ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine receive message: signal to the writer that there is more
 *                                          space the write_rb ready to be used.
 *
 * NB: does nothing if the peer is no longer pEstablished
 */
static void
bgp_session_do_kick_re_write(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_peer peer ;

  peer = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (peer->state == bgp_pEstablished))
    {
      ring_buffer rb ;

      rb = peer->session->write_rb ;

      rb_put_prompt_clear(rb) ;
      bgp_packet_write_stuff(peer, rb) ;
    } ;

  mqb_free(mqb) ;
} ;

/*==============================================================================
 * Session data access functions.
 */

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
 * BGP Engine: update the current session->cops_config.
 *
 * Updates the Acceptor.
 *
 * If the session is sAcquiring, then this may (well) affect the accept and/or
 * connect connections that are trying to acquire a session.
 *
 * If is sEstablished, then will stop the session if is no longer csRun, or if
 * the change requires and is not peer_established.  What this means is, that
 * up to the moment the *peer* is established, changes to the cops will
 * cause a (brand new) session to be stopped, and the peer will have to
 * restart it.  (Has to stop, because an established message is in flight
 * towards the peer.)
 *
 * NB: caller remains responsible for the given notification.
 *
 * NB: takes responsibility for the given connection options.
 */
static void
bgp_session_cops_update(bgp_session session, bgp_cops cops_new, bgp_note note,
                                                          bool peer_established)
{
  bgp_cops  cops_were ;

  cops_were = session->cops_config ;
  session->cops_config = cops_new ;

  /* Pass the new cops to the acceptor, which may or may not care, and will
   * take a copy if it wants.
   *
   * First time through, we'll create an acceptor.
   */
  bgp_acceptor_set_cops(session, cops_new) ;

  /* If the session is neither sAcquiring nor sEstablished, then we can simply
   * copy in the new connection options and may set the session going.
   *
   * If the session is sAcquiring or sEstablishe, need to worry.
   */
  if (session->state == bgp_sAcquiring)
    qassert(!peer_established) ;

  if      ( (session->state != bgp_sAcquiring) &&
            (session->state != bgp_sEstablished) )
    {
      /* There is no active session.
       *
       * We have updated the cops_config, so if we were reset we can now
       * start a session -- if csRun, csMayAccept and csMayConnect allow.
       */
      if (session->state == bgp_sReset)
        bgp_fsm_start_session(session) ;
    }
  else if (!(cops_new->conn_state & bgp_csRun))
    {
      /* The active session cannot continue to run -- affects sAcquiring and
       * sEstablished equally.
       *
       * If no notification has been provided, we make a (wild) guess...
       * ...but we expect a notification to be provided.
       */
      bgp_nom_subcode_t subcode ;

      if      (cops_new->conn_state == bgp_csDown)
        subcode = BGP_NOMS_C_DECONFIG ;
      else if (cops_new->conn_state & bgp_csTrack)
        subcode = BGP_NOMS_C_CONFIG ;
      else
        subcode = BGP_NOMS_C_SHUTDOWN ;

      bgp_fsm_stop_session(session, bgp_note_dup_default(note,
                                                    BGP_NOMC_CEASE, subcode)) ;
    }
  else if (!peer_established)
    {
      /* Have active session which may continue to run.
       *
       * MUST have have cops_were and MUST be runnable !
       *
       * Now worry about whether the cops changes have any effect on the making
       * of connection(s) or the running of the session.
       *
       * We bring down an sEstablished session iff !peer_established and there
       * is a material change in the cops.
       *
       *   su_remote            -- change => restart accept/connect
       *   su_local             -- change => restart connect
       *
       *   port                 -- change => restart accept/connect
       *
       *   conn_state           -- csRun already dealt with.
       *                           csMayAccept/csMayConnect -> accept/connect
       *
       *   can_notify_before_open -- change affects next connection
       *
       *   idle_hold_max_secs   -- change affects the next timer
       *   connect_retry_secs   -- change affects the next timer
       *   accept_retry_secs    -- affects acceptor, only
       *   open_hold_secs       -- change affects the next timer
       *
       *   ttl                  -- change => restart accept/connect
       *   gtsm                 -- change => restart accept/connect
       *
       *   ttl_out              -- N/A
       *   ttl_min              -- N/A
       *
       *   password             -- change => restart accept/connect
       *
       *   ifname               -- change => restart connect
       *
       *   ifindex              -- N/A
       *
       * NB: the things which will restart accept are a subset of things which
       *     will restart connect.
       *
       *     the things which will restart connect are the things which will
       *     stop an established session, if not peer_established.  Except,
       *     that for sEstablished we ignore csMayAccept/csMayConnect !
       */
      bool  restart_accept, restart_connect, may_changed ;

      /* For accept we need to restart if any of these are true.
       */
      restart_accept =
            !sockunion_same(&cops_new->su_remote, &cops_were->su_remote)
         || (cops_new->port != cops_were->port)
         || (cops_new->ttl  != cops_were->ttl)
         || (cops_new->gtsm != cops_were->gtsm)
         || (strcmp(cops_new->password, cops_were->password) != 0) ;

      /* There are a few more things which can cause a restart for connect
       * or for established session.
       */
      restart_connect = restart_accept
         || !sockunion_same(&cops_new->su_local, &cops_were->su_local)
         || (strcmp(cops_new->ifname, cops_were->ifname) != 0) ;

      /* Check if how we may make connections has changed.
       */
      may_changed = (cops_new->conn_state  & bgp_csMayMask) !=
                    (cops_were->conn_state & bgp_csMayMask) ;

      /* If sEstablished, may stop the current session unless peer_established.
       *
       * Otherwise, may start/restart/stop accept/connect in sAcquiring
       */
      if (session->state == bgp_sEstablished)
        {
          /* We are established, but the news did not reach the peer before
           * it made a change to the cops.
           *
           * So... an 'established' message is somewhere in transit, so we
           * are stick with bringing the (brand new) session to a sudden stop.
           */
          if (may_changed || restart_connect)
            {
              qassert(session->connections[bc_estd] != NULL) ;

              bgp_fsm_stop_connection(session->connections[bc_estd],
                                         bgp_note_dup_default(note,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            } ;
        }
      else
        {
          /* We are acquiring.  May need to start/restart/stop accept/connect.
           *
           * NB: does starts before stops.
           */
          if (may_changed)
            {
              bool will_accept,  did_accept ;
              bool will_connect, did_connect ;

              will_accept  = (cops_new->conn_state  & bgp_csMayAccept) ;
              will_connect = (cops_new->conn_state  & bgp_csMayConnect) ;

              did_accept   = (cops_were->conn_state & bgp_csMayAccept) ;
              did_connect  = (cops_were->conn_state & bgp_csMayConnect) ;

              /* If will but did not, start accept/connect
               */
              if (will_accept && !did_accept)
                {
                  qassert(session->connections[bc_accept] == NULL) ;
                  bgp_fsm_start_connection(session, bc_accept) ;
                  restart_accept = false ;
                } ;

              if (will_connect && !did_connect)
                {
                  qassert(session->connections[bc_connect] == NULL) ;
                  bgp_fsm_start_connection(session, bc_connect) ;
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
                  bgp_fsm_stop_connection(session->connections[bc_accept],
                                      bgp_note_dup_default(note,
                                         BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;
                  restart_accept = false ;
                } ;

              if (!will_connect && did_connect)
                {
                  qassert(session->connections[bc_connect] != NULL) ;
                  bgp_fsm_stop_connection(session->connections[bc_connect],
                                      bgp_note_dup_default(note,
                                         BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;
                  restart_connect = false ;
                } ;
            } ;

          /* Now, if we need to restart accept/connect/session, now is the
           * time to do so.
           */
          if (restart_accept && (cops_new->conn_state & bgp_csMayAccept))
            {
              qassert(cops_were->conn_state & bgp_csMayAccept) ;
              qassert(session->connections[bc_accept] != NULL) ;

              bgp_fsm_restart_connection(session->connections[bc_accept],
                                         bgp_note_dup_default(note,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            } ;

          if (restart_connect && (cops_new->conn_state & bgp_csMayConnect))
            {
              qassert(cops_were->conn_state & bgp_csMayConnect) ;
              qassert(session->connections[bc_connect] != NULL) ;

              bgp_fsm_restart_connection(session->connections[bc_connect],
                                         bgp_note_dup_default(note,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            } ;
        } ;
    } ;

  /* All set, can now discard any previous configuration and replace it.
   */
  bgp_cops_free(cops_were) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: update the current session->args_config.
 *
 * If the session is sAcquiring, then this may (well) affect the accept and/or
 * connect connections that are trying to acquire a session.
 *
 * If the session is sEstablished, then this may (well) stop the session.
 *
 * NB: caller remains responsible for the given notification.
 *
 * NB: takes responsibility for the given session arguments.
 */
static void
bgp_session_args_update(bgp_session session, bgp_session_args args_new,
                                                                  bgp_note note)
{
  bgp_session_args args_old ;

  /* Swap in the new configuration -- suppressing items which are not part of
   * the configuration.
   */
  args_old = session->args_config ;
  session->args_config = args_new ;

  args_new->remote_id      = 0 ;
  args_new->cap_suppressed = false ;

  if ( (session->state == bgp_sAcquiring) ||
       (session->state == bgp_sEstablished) )
    {
      /* If the arguments have changed, may need to do something with them.
       */
      qassert(args_old != NULL) ;

      /* Make sure irrelevant items are suppressed in the old arguments,
       * and then compare old and new.
       */
      args_old->remote_id      = 0 ;
      args_old->cap_suppressed = false ;

      if (!memsame(args_new, args_old, sizeof(*args_new)))
        {
          if (session->state == bgp_sEstablished)
            {
              /* Stop the current session.
               */
              qassert(session->connections[bc_estd]->fsm_state
                                                         == bgp_fsEstablished) ;
              bgp_fsm_stop_session(session,
                                    bgp_note_dup_default(note,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
            }
          else
            {
              /* Restart any sessions which have sent OPEN.
               */
              bgp_conn_ord_t ord ;

              for (ord = bc_first ; ord <= bc_last ; ++ord)
                {
                  bgp_connection connection ;

                  connection = session->connections[ord] ;
                  if (connection == NULL)
                    continue ;

                  if ( (connection->fsm_state == bgp_fsOpenSent) ||
                       (connection->fsm_state == bgp_fsOpenConfirm) )
                    bgp_fsm_restart_connection(connection,
                                       bgp_note_dup_default(note,
                                           BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
                } ;
            } ;
        } ;
    } ;

  bgp_session_args_free(args_old) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine: decide whether session arguments change warrants a session
 *                                                                        reset.
 *
 * If the peer is pEstablished, then some session arguments....
 */
static bool
bgp_peer_args_update(bgp_peer peer)
{
  bgp_session_args  args_new, args_were ;
  bool restart ;

  args_new = args_were = NULL ;
  restart = false ;

  /* Now worry about whether the args changes have any effect on the session,
   * which (unless nothing has changed) is extremely likely, for connections
   * at fsOpenSent and beyond.
   *
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
   *   * keepalive_secs         -- change =>    restart     |      keep
   */
  if (peer->state == bgp_pEstablished)
    {
      qassert(args_were != NULL) ;

      /* In all cases, we need to restart if any of these are true.
       */
      restart = (args_new->local_as        != args_were->local_as)
             || (args_new->remote_as       != args_were->remote_as)
             || (args_new->cap_af_override != args_were->cap_af_override)
             || (args_new->cap_strict      != args_were->cap_strict)
             || (args_new->can_capability  != args_were->can_capability)
             || (args_new->can_mp_ext      != args_were->can_mp_ext)
             || (args_new->can_as4         != args_were->can_as4)
             || (args_new->can_af          != args_were->can_af)
             || (args_new->can_rr          != args_were->can_rr)
             || (args_new->can_orf         != args_were->can_orf)
             || (memcmp(args_new->can_orf_pfx, args_were->can_orf_pfx,
                                          sizeof(args_new->can_orf_pfx)) != 0) ;
    } ;

  return restart ;
} ;
