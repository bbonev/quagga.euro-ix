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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
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
static bgp_session bgp_session_init_new(bgp_prun prun) ;
static void bgp_session_restart(bgp_session session) ;

static void bgp_session_prod(bgp_session session, bgp_note note) ;



static void bgp_session_clear(bgp_session session) ;
static void bgp_session_set_lox(bgp_session session) ;
static void bgp_session_send_delete(bgp_session session) ;

/*------------------------------------------------------------------------------
 * Execute session for the given prun.
 *
 * If no session exists, create one and set it going.
 *
 */
extern void
bgp_session_execute(bgp_prun prun, bgp_note note)
{
  bgp_session       session ;

  /* If no session exists, this is a brand new prun.
   */
  session = prun->session ;

  if (session == NULL)
    {
      /* Create a brand new session and prod it into life.
       */
      session = bgp_session_init_new(prun) ;
      prun->idle = bgp_pisReady ;               /* can go       */
    }
  else
    {
      /* Session exists, so the prun->delta dictates what to do with it:
       *
       *   * brd_restart   -- if for any reason whatsoever an existing session
       *                      needs to be dropped and restarted.
       *
       *                      This includes changes to sargs.
       *
       *   * brd_renew     -- something in either the cops or the args has
       *                      changed -- but it is not necessary to drop
       *                      an Established session.
       *
       *   * neither of the above => no change to the current session, none.
       *
       * NB: *cannot* at this point be brd_shutdown !!
       */
      switch (prun->delta & (brd_restart | brd_renew))
        {
          case brd_delete:
            return ;                    /* no change, no action */

          case brd_renew:
            break ;

          case brd_restart:
          case brd_restart | brd_renew:
            bgp_session_restart(prun->session) ;
            break ;
        } ;
    } ;

  /* Either new session or something has changed -- prod the session to
   * bring it up to date.
   */
  bgp_session_prod(session, note) ;
} ;







extern void
bgp_session_shutdown(bgp_prun prun, bgp_note note)
{

  ;
}





















/*------------------------------------------------------------------------------
 * Allocate & initialise new session structure.
 *
 * Requires the prun to be pInitial.
 *
 * Ties peer and session together.  Inter alia, sets:
 *
 *   prun:     state         = pIdle
 *             idle          = pisIdle
 *
 *   session:  state_seen    = bgp_sInitial
 *             state         = bgp_sInitial
 *
 * So the prun and the session appear in much the same state as if a session
 * had been stopped and all clearing has been completed.
 *
 * Unsets everything else -- mostly by zeroising it.
 *
 * NB: the acceptor is not created until the session is enabled.
 *
 *     While the acceptor is NULL, no connections will be accepted -- RST.
 */
static bgp_session
bgp_session_init_new(bgp_prun prun)
{
  bgp_session session ;

  qassert(prun->state   == bgp_pInitial) ;
  qassert(prun->session == NULL) ;

  session = XCALLOC(MTYPE_BGP_SESSION, sizeof(bgp_session_t)) ;

  /* Zeroizing sets:
   *
   *   * prun                   -- X            -- set below
   *
   *   * state_seen             -- sInitial     -- starting state
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
   *   * sargs_conf             -- NULL         -- none, yet
   *   * sargs                  -- NULL         -- none, yet
   *   * open_sent              -- NULL         -- none, yet
   *   * open_recv              -- NULL         -- none, yet
   *
   *   * read_rb                -- NULL         -- none, yet
   *   * write_rb               -- NULL         -- none, yet
   *
   *   * stats                  -- all zero
   *
   *   * cops_conf              -- X            -- set below -- csDown
   *   * cops                   -- NULL
   *
   *   * connections            -- NULLs        -- none, yet
   *   * state                  -- sInitial
   *
   *   * acceptor               -- NULL         -- none, yet
   */
  session->prun  = prun ;

  confirm(bgp_sInitial == 0) ;
  confirm(bgp_feNULL   == 0) ;

  bgp_session_set_lox(session) ;

  session->cops_conf = bgp_cops_init_new(NULL) ;

  qassert(session->cops_conf->conn_state == bgp_csDown) ;

  /* Set the prun and session "running" in the peer-index.
   *
   * Set the prun pIdle but avoid setting it pisReady (not our decision)
   */
  bgp_peer_index_set_running(prun, session) ;

  prun->state = bgp_pIdle ;
  prun->idle  = bgp_pisIdle ;

  return prun->session = session ;
} ;

/*------------------------------------------------------------------------------
 * Routing Engine: deregister and delete session for given peer.
 *
 * This is for use when the peer itself is being deleted.  (Peer MUST be in
 * pDeleting state.)
 *
 * NB: the peer is XXX XXX XXX XXX, so there should be no events
 *     or other messages waiting to be processed.
 *
 *     We set session->peer = NULL, which *immediately* stops the session
 *     from generating any more messages for the peer.  XXX XXX XXX XXX XXX XXX XXX XXX
 *
 *
 */
extern void
bgp_session_delete(bgp_prun prun)
{
  bgp_session session ;

  session = prun->session ;
  qassert(prun == session->prun) ;

  /* Deregister the peer -- so accept() can no longer find address.
   *
   * NB: after deregistering, will send a message to the BE to stop and
   *     dismantle the session and acceptor and any listener and password.
   *
   *     If a peer with the same address is invented, a new session will be
   *     created, but the acceptor, listener and password are set up by the
   *     BE on receipt of another *later* message.
   */
//bgp_peer_index_deregister(prun);      TODO ???

  /* Unhook the session and the peer from each other.
   *
   * Sets the session->peer to NULL -- BE will cannot generate any further
   * messages for the session from this instant on.  Then makes damn sure
   * there are none hanging around by revoking them.  Note that messages
   * to the RE point to the peer -- messages to the BE point to the session.
   */
  prun->session = NULL ;

  qa_set_ptr((void**)&session->prun, NULL) ;
  mqueue_revoke(re_nexus->queue, prun, 0) ;

  /* Clear out everything we can do on this side of the house, set final
   * state of session, and send message to tell BE to finish the job.
   */
  bgp_session_clear(session) ;

  session->state = bgp_sDeleting ;
  bgp_session_send_delete(session) ;
} ;

/*------------------------------------------------------------------------------
 * Push the session into a restart, if possible
 */
static void
bgp_session_restart(bgp_session session)
{



} ;

/*------------------------------------------------------------------------------
 * Clear the given session -- must be sInitial or sStopped.
 *
 * This is in preparation for sending sReady or sDeleting, but does not change
 * either state_seen or state.
 *
 * Since state_seen must be sInitial or sStopped, the state must be the same !
 *
 * Clears down as follows:
 *
 *   * prun                     -- preserved
 *
 *   * state_seen               -- preserved
 *   * ord                      -- 0            -- none, yet
 *   * eqb.fsm_event            -- feNULL       -- ditto
 *   * eqb.note                 -- NULL         -- ditto
 *   * eqb.err                  -- 0            -- ditto
 *
 *   * ord_estd                 -- 0            -- N/A until sEstablished
 *
 *   * idle_hold_time           -- 0            -- set when session started
 *
 *   * lox                      -- preserved
 *
 *   * sargs_config             -- NULL         -- none
 *   * sargs                    -- NULL         -- none
 *   * open_sent                -- NULL         -- none
 *   * open_recv                -- NULL         -- none
 *
 *   * read_rb                  -- NULL         -- none
 *   * write_rb                 -- NULL         -- none
 *
 *   * stats                    -- all zero
 *
 *   * cops_conf                -- preserved
 *   * cops                     -- NULL         -- last session gone
 *
 *   * connections              -- NULLs        -- for tidiness
 *   * state                    -- preserved
 *
 *   * acceptor                 -- preserved
 */
static void
bgp_session_clear(bgp_session session)
{
  qassert( (session->state_seen == bgp_sInitial) ||
           (session->state_seen == bgp_sStopped) ) ;
  qassert( (session->state_seen == session->state)) ;

  session->eqb.fsm_event = bgp_feNULL ;
  session->eqb.note     = bgp_note_free(session->eqb.note) ;
  session->eqb.err      = 0 ;
  session->ord          = 0 ;

  session->ord_estd     = 0 ;

  session->sargs_conf   = bgp_sargs_free(session->sargs_conf) ;
  session->sargs        = bgp_sargs_free(session->sargs) ;
  session->open_sent    = bgp_open_state_free(session->open_sent) ;
  session->open_recv    = bgp_open_state_free(session->open_recv) ;

  session->read_rb      = rb_destroy(session->read_rb) ;
  session->write_rb     = rb_destroy(session->write_rb) ;

  qa_memset(&session->stats, 0, sizeof(session->stats)) ;

  session->cops         = bgp_cops_free(session->cops) ;

  memset(session->connections, 0, sizeof(session->connections)) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: destroy session.
 *
 * Final part of process which started with bgp_session_delete(), which did
 * bgp_session_clear() as above.
 */
static void
bgp_session_destroy(bgp_session session)
{
  qassert(session->prun  == NULL) ;
  qassert(session->state == bgp_sDeleting) ;

  /* What we have left after bgp_session_clear() are:
   *
   *   * cops_conf
   *   * lox
   *   * connections -- should be NULL
   *   * acceptor
   */
  session->lox.log      = NULL;
  if (session->lox.name != NULL)
    XFREE(MTYPE_BGP_NAME, session->lox.name) ;
                                        /* sets session->lox.host NULL  */

  session->cops_conf = bgp_cops_free(session->cops_conf) ;

  qassert(session->connections[bc_estd]    == NULL) ;
  qassert(session->connections[bc_connect] == NULL) ;
  qassert(session->connections[bc_accept]  == NULL) ;

  session->acceptor = bgp_acceptor_free(session->acceptor) ;

  /* All done.
   */
  XFREE(MTYPE_BGP_SESSION, session);
} ;

/*------------------------------------------------------------------------------
 * Set session->lox from prun->lox (if any)
 */
static void
bgp_session_set_lox(bgp_session session)
{
  bgp_prun prun ;

  prun = session->prun ;

  session->lox.log = (prun != NULL) ? prun->log : NULL ;

  if (session->lox.name != NULL)
    XFREE(MTYPE_BGP_NAME, session->lox.name) ;

  session->lox.name = XSTRDUP(MTYPE_BGP_NAME,
              ( ((prun != NULL) && (prun->name != NULL)) ? prun->name
                                                         : "<unknown-host>" )) ;
} ;

/*==============================================================================
 * Prodding the BGP Engine.
 *
 * This is the mechanism for starting, updating and stopping sessions in the
 * BGP Engine.
 *
 */
static bgp_cops bgp_session_cops_make(bgp_session session, bgp_cops_c cops_conf,
                                                   bgp_prun_idle_state_t idle) ;
static bgp_sargs bgp_session_sargs_make(bgp_session session,
                                                       bgp_sargs_c sargs_conf) ;

static void bgp_session_do_prod(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_cops_update(bgp_session session, bgp_cops cops_new,
                                                                bgp_note note) ;
static void bgp_session_sargs_update(bgp_session session,
                                 bgp_sargs sargs_new, bgp_note note, bool run) ;

/*------------------------------------------------------------------------------
 * Routeing Engine: prod the session.
 *
 * Constructs a new set of cops and sargs, and prods the BGP Engine with them.
 *
 * The deep magic here is that the current prun->idle state is reflected into
 * the cops->conn_state, so that:
 *
 *   * if the prun is bgp_pisDown, or the session is no longer attached
 *     to a prun, the conn_state will be csDown, and the BGP Engine will
 *     bring everything down with a bump.
 *
 *   * otherwise, the conn_state will:
 *
 *      * have csTrack set -- which enables in-bound connection acceptance.
 *
 *      * have csRun set   -- iff is pisReady.
 *
 * If the prun is pIdle, then if is pisReady, this is the right moment
 * to step up to pStarted -- and that happens here.
 *
 * Sends the sargs iff is (now) pStarted.  In pEstablised it is too late to
 * change the sargs -- the prun must go through a full session reset.  In all
 * other states the sargs are irrelevant.
 *
 * NB: takes responsibility for the note, if any.
 */
static void
bgp_session_prod(bgp_session session, bgp_note note)
{
  bgp_prun      prun ;
  mqueue_block  mqb ;
  struct bgp_session_prod_args* mqba ;

  /* This is a Routeing-Engine operation, so strictly speaking don't need
   * to fetch the prun point atomically -- but does no harm !
   *
   * If the prun is pIdle but pisReady, then NOW is the moment to change up
   * to pStarted and set the session sReady.
   */
  prun = qa_get_ptr((void**)&session->prun) ;

  if ( (prun != NULL) && (prun->state == bgp_pIdle) &&
                         (prun->idle  == bgp_pisReady) )
    {
      /* pIdle with pisReady means we are ready to change up to pStarted.
       *
       * pIdle => sInitial or sStopped -- so we may clear the session, and then
       * set:
       *
       *   * idle_hold_time         -- to current value
       *
       *   * stats                  -- reset to zero   TODO yes ??
       *
       * ...we're assuming we are going to start the session, so we make sure
       * we are all set for that.
       */
      qtime_t   idle_hold_time ;

      bgp_session_clear(session) ;

      idle_hold_time = prun->idle_hold_time ;

      if (idle_hold_time > QTIME(prun->brun->rp.defs.idle_hold_max_secs))
        idle_hold_time   = QTIME(prun->brun->rp.defs.idle_hold_max_secs) ;
      if (idle_hold_time < QTIME(prun->brun->rp.defs.idle_hold_min_secs))
        idle_hold_time   = QTIME(prun->brun->rp.defs.idle_hold_min_secs) ;

      session->idle_hold_time = prun->idle_hold_time = idle_hold_time ;

      /* Change states.
       *
       * The session is sInitial or sStopped (and the RE knows this), so the
       * RE can move the state on to sReady.
       */
      prun->state         = bgp_pStarted ;

      session->state      = bgp_sReady ;
      session->state_seen = bgp_sReady ;
    } ;

  /* Prepare 'prod' message
   *
   * If the session is no longer attached to the prun, then it is about to be
   * shut-down, and we send in empty cops and empty args.
   */
  mqb  = mqb_init_new(NULL, bgp_session_do_prod, session) ;
  mqba = mqb_get_args(mqb) ;

  mqba->note  = note ;
  mqba->sargs = NULL ;          /* default              */
  mqba->cops  = NULL ;          /* iff prun == NULL !   */

  /* Unless we have no prun, construct the cops to be sent to the BE.
   *
   * If the session is pStarted, then we send in the current sargs.  If the
   * session is in the process of establishing, or has recently established,
   * then sending in sargs may cause connections and/or session to be dropped.
   */
  if (prun != NULL)
    {
      mqba->cops = bgp_session_cops_make(session, &prun->rp.cops_conf,
                                                                   prun->idle) ;
      if (prun->state == bgp_pStarted)
        {
          /* pStarted state means that we now want a session to come up.
           *
           * Must be pisReady and hence the conn_state must be csRun.
           *
           * The session should be in any of the following states:
           *
           *    sReady      -- which means that the RE has set the BE ready
           *                   to acquire a new session.
           *
           *                   Sending the sargs will prompt the BE to start
           *                   the session and proceed to sAcquiring.
           *
           *    sAcquiring  -- which means that the BE/FSM has started, but not
           *                   yet established a session.
           *
           *                   Sending the sargs will affect the current
           *                   efforts to establish a session, and may cause
           *                   connections to be dropped and opened again.
           *
           *    sEstablished -- which means the BE/FSM has established a
           *                   session, but the RE has not noticed, yet.
           *
           *                   Sending the sargs may cause the session to be
           *                   dropped.  A message from the BE signalling the
           *                   established session is "in flight", so the BE
           *                   has no choice but to drop the just established
           *                   session and signal that too.
           *
           *    sStopped    -- which means that the BE/FSM has reached a dead
           *                   stop, but the RE has not noticed, yet.
           *
           *                   Sending the cops and sargs will have no effect
           *                   on the session.
           *
           *                   The BE never leaves leaves sStopped of its own
           *                   accord.  So, nothing happens until the RE
           *                   picks up the sStopped message and proceeds via
           *                   pResetting to pIdle etc.
           */
          qassert(prun->idle == bgp_pisReady) ;
          qassert(mqba->cops->conn_state & bgp_csRun) ;

          mqba->sargs = bgp_session_sargs_make(session, &prun->rp.sargs_conf) ;
        } ;
    } ;

  bgp_to_bgp_engine(mqb, mqb_priority, bgp_engine_log_event) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: process "prod" message
 *
 * This is sent when: (a) prun->rp.cops_conf is updated
 *            and/or: (b) prun->rp.sargs_conf is updated -- if pStarted
 *            and/or: (c) becomes pStarted
 *
 * The running session->cops_conf and session->sargs_conf are updated,
 * as required.
 *
 * In particular, changes to cops_conf->conn_state may bring up or take down
 * session and/or connections.
 */
static void
bgp_session_do_prod(mqueue_block mqb, mqb_flag_t flag)
{
  bgp_session session ;
  bgp_cops    cops_new ;

  struct bgp_session_prod_args* mqba ;

  session = mqb_get_arg0(mqb) ;
  mqba    = mqb_get_args(mqb) ;

  /* Now we update the session to the latest cops/sargs.
   */
  if (flag == mqb_action)
    {
      bool run ;
      cops_new = mqba->cops ;

      if (cops_new != NULL)
        {
          mqba->cops = NULL ;           /* taken what was given */

          run = (cops_new->conn_state & bgp_csRun) ;
        }
      else
        {
          /* A NULL set of cops is our signal to down the session completely.
           *
           * We construct an empty set of cops, for the convenience of
           * bgp_session_cops_update().
           */
          cops_new = bgp_cops_init_new(NULL) ;

          cops_new->conn_state = bgp_csDown ;
          run = false ;
        } ;

      /* If we have sargs, that implies the prun is pStarted, which is only
       * true if is csRun -- so should be 'run'.
       *
       * We process the sargs before the cops, so that if the cops change
       * starts session acquisition, we have the sargs_conf set up.
       */
      if (mqba->sargs != NULL)
        {
          qassert(run) ;

          bgp_session_sargs_update(session, mqba->sargs, mqba->note, run) ;
          mqba->sargs = NULL ;
        } ;

      /* Now update the cops, which may start/change/stop connections/session.
       *
       * Also may start/change/stop the acceptor.
       */
      bgp_session_cops_update(session, cops_new, mqba->note) ;
    } ;

  /* Done... noting that we need to discard any remaining payload.
   */
  bgp_cops_free(mqba->cops) ;
  bgp_sargs_free(mqba->sargs) ;
  bgp_note_free(mqba->note) ;
  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * From the given sargs_conf, construct sargs to be sent to the BGP Engine.
 *
 * The session arguments are a direct copy of given sargs, except:
 *
 *   * remote_id                -- 0
 *   * cap_suppressed           -- false
 *
 *   * and the Prefix ORF stuff:
 *
 *       * if we are not actually advertising anything, then we suppress
 *         args_r->can_orf, so will not send the capability at all.
 *
 *       * if we are willing to send the per-RFC capability, then update the
 *         Prefix ORF types to be advertised.
 *
 *       * make sure we only advertise things in can_af.
 *
 *   * and the Graceful Restart stuff:
 *
 *       * gr.can               -- used as given
 *       * gr.restarting        -- false        TODO
 *       * gr.restart_time      -- used as given
 *       * gr.can_preserve      -- empty        TODO
 *       * gr.has_preserved     -- empty        TODO
 *
 * NB: if !can_capability, then the rp.sargs_conf reflect that already.
 *
 * Returns:  the sargs constructed
 */
static bgp_sargs
bgp_session_sargs_make(bgp_session session, bgp_sargs_c sargs_conf)
{
  bgp_sargs  sargs ;
  qafx_t     qafx ;
  bgp_form_t can_orf ;

  /* Start with a copy of the current params.
   */
  sargs = bgp_sargs_copy(NULL, sargs_conf) ;

  sargs->remote_id       = 0 ;
  sargs->cap_suppressed  = false ;

  /* If we wish to send or are prepared to receive ORF in any address family,
   * then we now:
   *
   *   a) discard any setting for any af we are not going to advertise.
   *
   *   b) set the "can_orf_pfx" to bgp_form_rfc and/or bgp_form_pre as
   *      allowed by "can_orf".
   *
   *   c) if we end up with no orf requirements at all, clear can_orf.
   *
   * If can_orf is already bgp_form_none, this will clear down any (spurious)
   * orf settings.
   */
  can_orf = bgp_form_none ;             /* assume we want nothing.      */

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_orf_cap_bits_t orf_pfx, orf_wish ;

      orf_wish = sargs->can_orf_pfx.af[qafx] & (ORF_SM | ORF_RM) ;
      orf_pfx  = 0 ;

      if ((sargs->can_af & qafx_bit(qafx)) && (orf_wish != 0))
        {
          /* For the families we are going to advertise, see if we wish to
           * send or are prepared to receive Prefix ORF.
           *
           * Note that we set both the RFC Type and the pre-RFC one, so we
           * arrange to send the RFC Capability and the pre-RFC one.
           */
          can_orf = sargs->can_orf ;

          if (can_orf & bgp_form_rfc)
            orf_pfx |= orf_wish ;

          if (can_orf & bgp_form_pre)
            orf_pfx |= (orf_wish << 4) ;

          confirm(ORF_SM_pre == (ORF_SM << 4)) ;
          confirm(ORF_RM_pre == (ORF_RM << 4)) ;
        } ;

      sargs->can_orf_pfx.af[qafx] = orf_pfx ;
    } ;

  sargs->can_orf = can_orf ;

  /* Graceful restart capability
   */
  if (sargs->gr.can)
    {
      /* TODO: sort out graceful restart
       */
      sargs->gr.can_preserve    = qafx_empty_set ;      /* cannot       */
      sargs->gr.has_preserved   = qafx_empty_set ;      /* has not      */
      sargs->gr.restarting      = false ;               /* is not       */
    } ;

  /* Done
   */
  return sargs ;
} ;

/*------------------------------------------------------------------------------
 * Construct new set of connection options, based on current state of the prun.
 *
 * The connection options are a direct copy of the prun->pr.cops_conf, except:
 *
 *   * ttl_out          -- set zero
 *   * ttl_min          -- set zero
 *   * ifindex          -- set zero
 *
 *     Since those are of no interest to the peer, we simply ensure they are
 *      zero in the peer->cops.
 *
 *   * conn_state       -- from which we take only the "may" bits
 *
 *     The conn_state for the session includes the csRun and csTrack bits,
 *     which are manufactured from the given prun-idle-state.
 *
 * NB: csRun and csTrack bits are the mechanism used to start/stop connections.
 *
 *     In particular, clearing csRun will bring down an existing session.
 *
 * Returns:  new cops
 */
static bgp_cops
bgp_session_cops_make(bgp_session session, bgp_cops_c cops_conf,
                                                     bgp_prun_idle_state_t idle)
{
  bgp_cops   cops ;
  bgp_conn_state_t conn_state ;

  /* Copy the cops_conf and clear down the unused entries.
   */
  cops = bgp_cops_copy(NULL, cops_conf) ;

  cops->ttl_out = cops->ttl_min = 0 ;
  cops->ifindex = 0 ;

  /* Set the: bgp_csTrack  -- ! pisDown
   *          bgp_csRun    --   pisReady
   */
  if (idle & bgp_pisDown)
    conn_state = bgp_csDown ;
  else
    {
      conn_state = (cops->conn_state & bgp_csMayMask) | bgp_csTrack ;

      if (idle == bgp_pisReady)
        conn_state |= bgp_csRun ;
    } ;

  cops->conn_state = conn_state ;

  /* Done
   */
  return cops ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: update the current session->sargs_conf.
 *
 * If is 'run', then there may be side effects:
 *
 *   sAcquiring    -- may (well) affect the accept and/or connect connections
 *                    that are trying to acquire a session.
 *
 *   sEstablished  -- may (well) stop the session.
 *
 * NB: caller remains responsible for the given notification.
 *
 * NB: takes responsibility for the given session arguments.
 */
static void
bgp_session_sargs_update(bgp_session session, bgp_sargs sargs_new,
                                                        bgp_note note, bool run)
{
  bgp_sargs     sargs_old ;

  /* Swap in the new configuration -- suppressing items which are not part of
   * the configuration.
   */
  sargs_new->remote_id      = 0 ;
  sargs_new->cap_suppressed = false ;

  sargs_old = session->sargs_conf ;
  session->sargs_conf = sargs_new ;

  /* Worry about side effects
   */
  if (run && ( (session->state == bgp_sAcquiring) ||
               (session->state == bgp_sEstablished) ))
    {
      bool changed ;

      if (sargs_old == NULL)
        changed = true ;
      else
        {
          /* Make sure the irrelevant parts are suppressed, then see if the
           * sargs are the same or not.
           *
           * NB: the sargs that reach here are copies of the sargs_conf in the
           *     assembled parameters, which started with a bgp_sargs_init_new(),
           *     which starts by zeroizing the structure.  So memsame() should do
           *     the job.
           */
          sargs_old->remote_id      = 0 ;
          sargs_old->cap_suppressed = false ;

          changed = !memsame(sargs_new, sargs_old, sizeof(bgp_sargs_t)) ;
        } ;

      if (changed)
        {
          bgp_conn_ord_t ord ;

          switch (session->state)
            {
              /* sAcquiring: need to restart any connection which has sent OPEN.
               */
              case bgp_sAcquiring:
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
                break ;

              /* sEstablished: no choice but to drop the (new) session.
               */
              case bgp_sEstablished:
                qassert(session->connections[bc_estd]->fsm_state
                                                    == bgp_fsEstablished) ;
                bgp_fsm_stop_session(session, bgp_note_dup_default(note,
                                      BGP_NOMC_CEASE, BGP_NOMS_C_CONFIG)) ;
                break ;

              /* Cannot be anything else !
               */
              default:
                qassert(false) ;
                break ;
            } ;
        } ;
    } ;

  /* Done with the old sargs and done.
   */
  bgp_sargs_free(sargs_old) ;
} ;

/*------------------------------------------------------------------------------
 * BGP Engine: update the current session->cops_conf.
 *
 * Updates the Acceptor and creates it if required.
 *
 * This is done after any update of the sargs_conf, so that if is sReady then
 * the sargs_conf are set up.
 *
 * If the session is sReady, then this may (well) start a new session
 * acquisition process and change to sAcquiring.
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
 *
 * NB: first time through, cops_conf may be NULL !
 */
static void
bgp_session_cops_update(bgp_session session, bgp_cops cops_new, bgp_note note)
{
  bgp_cops  cops_were ;

  cops_were = session->cops_conf ;
  session->cops_conf = cops_new ;

  qassert((cops_were != NULL) || (session->state == bgp_sReady)) ;

  /* Pass the new cops to the acceptor, which may or may not care, and will
   * take a copy if it wants.
   *
   * First time through, we'll create an acceptor.
   */
  bgp_acceptor_set_cops(session, cops_new) ;

  /* If the session is neither sAcquiring nor sEstablished, then we can simply
   * copy in the new connection options and may set the session going.
   *
   * If the session is sAcquiring or sEstablished, need to worry whether any
   * change in the cops should interrupt things.
   */
  if      ( (session->state != bgp_sAcquiring) &&
            (session->state != bgp_sEstablished) )
    {
      /* There is no active session.
       *
       * We have updated the cops_conf, so if we are sReady we can now start
       * a session and proceed to sAcquiring -- if csRun, csMayAccept and
       * csMayConnect allow.
       */
      if (session->state == bgp_sReady)
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
  else if (cops_were != NULL)           /* belt and braces      */
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
       *   remote_su            -- change => restart accept/connect
       *   local_su             -- change => restart connect
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
            !sockunion_same(&cops_new->remote_su, &cops_were->remote_su)
         || (cops_new->port != cops_were->port)
         || (cops_new->ttl  != cops_were->ttl)
         || (cops_new->gtsm != cops_were->gtsm)
         || (strcmp(cops_new->password, cops_were->password) != 0) ;

      /* There are a few more things which can cause a restart for connect
       * or for established session.
       */
      restart_connect = restart_accept
         || !sockunion_same(&cops_new->local_su, &cops_were->local_su)
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
                  bgp_connection_start(session, bc_accept) ;
                  restart_accept = false ;
                } ;

              if (will_connect && !did_connect)
                {
                  qassert(session->connections[bc_connect] == NULL) ;
                  bgp_connection_start(session, bc_connect) ;
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

















/*==============================================================================
 *
 */
static void bgp_session_do_delete(mqueue_block mqb, mqb_flag_t flag) ;

/*------------------------------------------------------------------------------
 * Routing Engine: send message to BE to finish off the session.
 *
 *
 * XXX XXX XXX XXX

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
      bgp_prun prun ;

      prun = qa_get_ptr((void**)&session->prun) ;

      qassert((prun == NULL) && (session->state == bgp_sDeleting)) ;

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

/*==============================================================================
 * BGP Engine sending events to Routeing Engine.
 */
static void bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag) ;

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
  bgp_prun       prun ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  prun = qa_get_ptr((void**)&session->prun) ;

  if (prun == NULL)
    return ;

  /* All is well, send message.
   */
  mqb = mqb_init_new(NULL, bgp_session_do_event, prun) ;

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
  bgp_prun    prun ;
  bgp_session session ;

  args    = mqb_get_args(mqb) ;
  session = mqb_get_arg0(mqb) ;

  prun = session->prun ;

  if ((flag == mqb_action) && (prun != NULL))
    {
      /* Pull stuff into Routing Engine *private* fields in the session
       */
      switch (args->state)
        {
          /* sReady, waiting to start to make connection(s).
           *
           * We are not much interested in the events in this state.
           */
          case bgp_sReady:
            ;
            break ;

          case bgp_sAcquiring:
            break ;

          case bgp_sEstablished:
            if (prun->state == bgp_pStarted)
              break ;

            if (session->state_seen != bgp_sEstablished)
              {
                session->state_seen = args->state ;
                session->ord_estd   = args->ord ;

                bgp_session_has_established(session) ;
              } ;

          case bgp_sInitial:
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
static void bgp_session_do_kick_read(bgp_prun prun) ;
static void bgp_session_do_kick_be_write(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_re_write(mqueue_block mqb, mqb_flag_t flag) ;
static void bgp_session_do_kick_write(bgp_prun prun) ;

/*------------------------------------------------------------------------------
 * BGP Engine send message: kick the RE to empty out the read_rb.
 */
extern void
bgp_session_kick_re_read(bgp_session session)
{
  bgp_prun       prun ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  prun = qa_get_ptr((void**)&session->prun) ;

  if (prun == NULL)
    bgp_session_do_kick_read(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message to self, if required: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
extern void
bgp_session_kick_read(bgp_prun prun)
{
  if (rb_put_kick(prun->session->read_rb))
    bgp_session_do_kick_read(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine or BGP Engine, send message RE: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
static void
bgp_session_do_kick_read(bgp_prun prun)
{
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_kick_re_read, prun) ;
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
  bgp_prun prun ;

  prun = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (prun->state == bgp_pEstablished))
    {
      ring_buffer rb ;

      rb = prun->session->read_rb ;

      rb_get_prompt_clear(rb) ;
      bgp_packet_read_stuff(prun, rb) ;
    } ;

  mqb_free(mqb) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message: kick the BE to put more into the read_rb.
 */
extern void
bgp_session_kick_be_read(bgp_prun prun)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  /* Belt and braces -- do nothing if no session !!
   */
  session = prun->session ;
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
bgp_session_kick_be_write(bgp_prun prun)
{
  bgp_session    session ;
  mqueue_block   mqb ;

  /* Belt and braces -- do nothing if no session !!
   */
  session = prun->session ;
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
  bgp_prun       prun ;

  /* Belt and braces: if peer has been deleted, the peer pointer will have been
   * cleared, and we can no longer send any messages !!
   *
   * This should never happen, because the session will be sReset or sStopped
   * at the moment the peer is deleted -- but there is no harm in being
   * careful.
   *
   * The qa_get_ptr() synchronises memory.
   */
  prun = qa_get_ptr((void**)&session->prun) ;

  if (prun != NULL)
    bgp_session_do_kick_write(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine send message to self, if required: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
extern void
bgp_session_kick_write(bgp_prun prun)
{
  if (rb_put_kick(prun->session->write_rb))
    bgp_session_do_kick_write(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Routeing Engine or BGP Engine, send message RE: kick the writer.
 *
 * NB: if the peer is not pEstablished when the message arrives, the message
 *     will be ignored.
 */
static void
bgp_session_do_kick_write(bgp_prun prun)
{
  mqueue_block   mqb ;

  mqb = mqb_init_new(NULL, bgp_session_do_kick_re_write, prun) ;
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
  bgp_prun prun ;

  prun = mqb_get_arg0(mqb) ;

  if ((flag == mqb_action) && (prun->state == bgp_pEstablished))
    {
      ring_buffer rb ;

      rb = prun->session->write_rb ;

      rb_put_prompt_clear(rb) ;
      bgp_packet_write_stuff(prun, rb) ;
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

#if 0
/*------------------------------------------------------------------------------
 * Routeing Engine: decide whether session arguments change warrants a session
 *                                                                        reset.
 *
 * If the peer is pEstablished, then some session arguments....  TODO !!!
 */
static bool
bgp_peer_sargs_update(bgp_prun prun)
{
  bgp_sargs  sargs_new, sargs_were ;
  bool restart ;

  sargs_new = sargs_were = NULL ;
  restart = false ;

  /* Now worry about whether the sargs changes have any effect on the session,
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
   *   * can_orf_pfx            -- change =>    restart     |     restart
   *
   *   * can_dynamic            -- change =>    restart     |      keep
   *   * can_dynamic_dep        -- change =>    restart     |      keep
   *
   *   * holdtime_secs          -- change =>    restart     |      keep
   *   * keepalive_secs         -- change =>    restart     |      keep
   */
  if (prun->state == bgp_pEstablished)
    {
      qassert(sargs_were != NULL) ;

      /* In all cases, we need to restart if any of these are true.
       */
      restart = (sargs_new->local_as        != sargs_were->local_as)
             || (sargs_new->remote_as       != sargs_were->remote_as)
             || (sargs_new->cap_af_override != sargs_were->cap_af_override)
             || (sargs_new->cap_strict      != sargs_were->cap_strict)
             || (sargs_new->can_capability  != sargs_were->can_capability)
             || (sargs_new->can_mp_ext      != sargs_were->can_mp_ext)
             || (sargs_new->can_as4         != sargs_were->can_as4)
             || (sargs_new->can_af          != sargs_were->can_af)
             || (sargs_new->can_rr          != sargs_were->can_rr)
             || (sargs_new->can_orf         != sargs_were->can_orf)
             || (memcmp(&sargs_new->can_orf_pfx, &sargs_were->can_orf_pfx,
                                                 sizeof(bgp_orf_caps_t)) != 0) ;
    } ;

  return restart ;
} ;
#endif
