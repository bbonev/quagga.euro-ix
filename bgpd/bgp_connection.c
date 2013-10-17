/* BGP Connection Handling -- functions
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
#include <zebra.h>

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_notification.h"
#include "bgpd/bgp_msg_read.h"
#include "bgpd/bgp_msg_write.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_names.h"

#include "lib/memory.h"
#include "lib/mqueue.h"
#include "lib/vhash.h"
#include "lib/sockunion.h"
#include "lib/list_util.h"
#include "lib/qfstring.h"
#include "lib/qpselect.h"
#include "lib/qtimers.h"

/*==============================================================================
 * BGP Connections.
 *
 * Each BGP Connection has its own:
 *
 *   * BGP Finite State Machine (FSM)
 *   * socket and related qpselect file
 *   * input/output buffers and I/O management
 *   * timers to support the above
 *
 * Each BGP Session is associated with at most two BGP Connections, a 'connect'
 * and an 'accept'.  In addition there is an acceptor, which looks after the
 * initial stages of an incoming connection, and which will accept same even
 * while the sesssion is disabled.
 *
 * The bgp_connection structure is private to the BGP Engine, and is accessed
 * directly, without the need for any mutex.
 *
 * Each connection is closely tied to its parent bgp_session.  The bgp_session
 * is shared between the Routeing Engine and the BGP Engine, and access to
 * parts of that require more care -- though while connections are running,
 * the session belongs (largely) to the BGP Engine.
 */

/*==============================================================================
 * List of known connections -- for walking same.
 */
static struct dl_base_pair (bgp_connection) bgp_connections ;
                                        /* list of known connections    */

/*==============================================================================
 * Managing bgp_connection stuctures.
 */
static const char* bgp_connection_tags[] =
{
  [bc_estd]    = "",            /* established          */
  [bc_connect] = "(c)",         /* outbound connect()   */
  [bc_accept]  = "(a)",         /* inbound accept()     */
} ;

static void bgp_connection_init_host(bgp_connection connection,
                                                           bgp_conn_ord_t ord) ;
static char* bgp_connection_host_string(char* host_was, bgp_session session,
                                                           bgp_conn_ord_t ord) ;
static char* bgp_connection_host_string_free(char* host) ;

static bgp_note bgp_connection_make_args(bgp_connection connection,
                                                        bgp_session_args args) ;

/*------------------------------------------------------------------------------
 * Initialise the connection handling.
 */
extern void
bgp_connections_init(void)
{
  ddl_init(bgp_connections) ;

  bgp_fsms_init() ;
} ;

/*------------------------------------------------------------------------------
 * Terminate all known connections.
 *
 * TODO: for bringing the BGP Engine to a dead halt.
 *
 * Problem: can it be assumed that all sessions have been closed ?
 *
 *          if not... how are all the connections to be persuaded to adopt
 *          an appropriate posture ?
 */
extern void
bgp_connections_stop(void)
{
  bgp_fsms_stop() ;
} ;

/*------------------------------------------------------------------------------
 * Initialise connection structure -- allocate if required.
 *
 * If does not allocate, assumes is so far unused -- and can be zeroized.
 *
 * Copies information required by the connection from the parent session.
 */
extern bgp_connection
bgp_connection_init_new(bgp_connection connection, bgp_session session,
                                                             bgp_conn_ord_t ord)
{
  assert( (ord == bc_connect) ||
          (ord == bc_accept) ) ;
  assert(session->connections[ord] == NULL) ;

  if (connection == NULL)
    connection = XCALLOC(MTYPE_BGP_CONNECTION, sizeof(struct bgp_connection)) ;
  else
    memset(connection, 0, sizeof(struct bgp_connection)) ;

  /* Structure is zeroized, so the following are implictly initialised:
   *
   *   * exist                  -- NULLs    -- pointer pair, set below
   *   * session                -- X        -- set below
   *
   *   * ordinal                -- X        -- set below
   *
   *   * lox.host               -- X        -- set below
   *   * lox.log                -- X        -- set below
   *
   *   * event_ring             -- NULLs    -- not on the event ring
   *
   *   * meta_events            -- bgp_fmStop
   *
   *   * admin_event            -- bgp_feNULL
   *   * admin_note             -- NULL
   *
   *   * socket_event           -- bgp_feNULL;
   *   * socket_err             -- 0
   *
   *   * fsm_state              -- bgp_feNULL
   *   * io_state               -- qfDown
   *
   *   * holdtimer_suppressed   -- false
   *   * delaying_open          -- false
   *
   *   * idling_state           -- fisNULL
   *   * idle_time_pending      -- 0
   *
   *   * qf                     -- none     -- none
   *   * cops                   -- NULL     -- none
   *
   *   * open_sent              -- NULL     -- none
   *   * open_recv              -- NULL     -- none
   *
   *   * local_id               -- X        -- set below
   *   * remote_as              -- X        -- set below
   *
   *   * cap_suppress           -- false
   *   * idle_hold_time         -- X      -- set below
   *
   *   * hold_timer             -- X        -- set below
   *   * keepalive_timer        -- X        -- set below
   *
   *   * reader                 -- NULL     -- none
   *   * read_rb                -- NULL     -- none
   *
   *   * writer                 -- NULL     -- none
   *   * write_rb               -- NULL     -- none
   */
  confirm(bgp_fsNULL    == 0) ;
  confirm(bgp_fmStop    == 0) ;
  confirm(qfDown        == 0) ;
  confirm(bgp_fisNULL   == 0) ;

  /* Put on the connections that exist list
   */
  ddl_append(bgp_connections, connection, exist) ;

  /* Link back to session and set ordinal
   */
  connection->session           = session ;
  connection->ord               = ord ;
  session->connections[ord]     = connection ;

  /* Controls and other information required for trying to open a connection.
   */
  connection->cap_suppress      = false ;
  connection->idle_hold_time    = session->idle_hold_time ;

  /* Initialise all the timers
   */
  bgp_fsm_timer_init(connection->hold_timer, connection) ;
  bgp_fsm_timer_init(connection->keepalive_timer, connection) ;

  /* Copy log destination and make host name + (c)/(a)
   *
   * Makes complete copies so that connection may continue to run, even
   * after the session has stopped, and may have been destroyed.
   *
   * This also names the timers -- so done after the timers are created.
   */
  qassert(connection->lox.name == NULL) ;
  bgp_connection_init_host(connection, ord) ;
  connection->lox.log  = session->lox.log ;

  return connection ;
} ;

/*------------------------------------------------------------------------------
 * Start connection for session, trying to connect() or accept()
 *
 * Creates new connection object, sets that into the session and then sets the
 * FSM going.
 */
extern void
bgp_connection_start(bgp_session session, bgp_conn_ord_t ord)
{
  bgp_connection connection ;

  qassert(session->connections[ord] == NULL) ;

  connection = bgp_connection_init_new(NULL, session, ord) ;
  bgp_fsm_start_connection(connection) ;
} ;

/*------------------------------------------------------------------------------
 * Set the host field for the connection to session->host + given tag.
 *
 * Also name any existing timers if DEBUG_FSM
 *
 * NB: requires the session to be LOCKED.
 */
static void
bgp_connection_init_host(bgp_connection connection, bgp_conn_ord_t ord)
{
  connection->lox.name = bgp_connection_host_string(connection->lox.name,
                                                     connection->session, ord) ;

  if (BGP_DEBUG(fsm, FSM))
    {
      qfb_gen_t QFB_QFS(qfb, qfs) ;     /* "general" string     */

      if (connection->hold_timer->qtr != NULL)
        {
          qfs_reset(qfs) ;
          qfs_printf(qfs, "%s-%s", connection->lox.name, "Hold") ;
          qtimer_set_name(connection->hold_timer->qtr, qfs_string(qfs)) ;
        } ;

      if (connection->keepalive_timer->qtr != NULL)
        {
          qfs_reset(qfs) ;
          qfs_printf(qfs, "%s-%s", connection->lox.name, "KeepA") ;
          qtimer_set_name(connection->keepalive_timer->qtr, qfs_string(qfs)) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Construct host string -- discards previous (if any).
 */
static char*
bgp_connection_host_string(char* host_was, bgp_session session,
                                                             bgp_conn_ord_t ord)
{
  char* host ;
  qfb_gen_t QFB_QFS(qfb, qfs) ;         /* "general" string     */

  host_was = bgp_connection_host_string_free(host_was) ;

  qfs_reset(qfs) ;
  qfs_printf(qfs, "%s%s", session->lox.name, bgp_connection_tags[ord]) ;
  qfs_term(qfs) ;

  host = XMALLOC(MTYPE_BGP_PEER_HOST, qfs_len(qfs) + 1) ;
  qassert(qfs_len(qfs) == strlen(qfs_string(qfs))) ;

  strcpy(host, qfs_string(qfs)) ;

  return host ;
} ;

/*------------------------------------------------------------------------------
 * Discard given host string (if any).
 *
 * Returns:  NULL
 */
static char*
bgp_connection_host_string_free(char* host)
{
  if (host != NULL)
    XFREE(MTYPE_BGP_PEER_HOST, host) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get sibling (if any) for given connection.
 *
 * NB: requires the session to be LOCKED.
 */
extern bgp_connection
bgp_connection_get_sibling(bgp_connection connection)
{
  bgp_session session = connection->session ;

  qassert( (connection->ord == bc_connect) ||
           (connection->ord == bc_accept) ) ;

  if (session == NULL)
    return NULL ;               /* no sibling if no session             */

  confirm(bc_connect   == (bc_accept  ^ 3)) ;
  confirm(bc_accept    == (bc_connect ^ 3)) ;

  return session->connections[connection->ord ^ 3] ;
} ;

/*------------------------------------------------------------------------------
 * Make given connection the established one.
 *
 * Returns:  NULL <=> OK all set -- connection established.
 *           otherwise -- note
 */
extern bgp_note
bgp_connection_establish(bgp_connection connection)
{
  bgp_note      note ;
  bgp_session   session ;

  session = connection->session ;

  qassert(session->connections[connection->ord] == connection) ;
  qassert(session->connections[bc_estd]             == NULL) ;

  /* Make sure the session has a nice clean set of result 'args', then make
   * the result arguments.
   */
  session->args = bgp_session_args_reset(session->args) ;
  note = bgp_connection_make_args(connection, session->args) ;

  if (note != NULL)
    return note ;

  /* We can now go fsEstablished !
   *
   * We have already set the negotiated session arguments.
   *
   *   * move the open_sent and open_recv to the session.
   *
   *   * copy the connection options to the session.
   */
  session->open_sent = bgp_open_state_set_mov(session->open_sent,
                                                       &connection->open_sent) ;
  session->open_recv = bgp_open_state_set_mov(session->open_recv,
                                                       &connection->open_recv) ;

  session->cops = bgp_cops_copy(session->cops, connection->cops) ;

  /* Set the bc_estd, update the host name and set the session sEstablished.
   */
  session->connections[bc_estd] = connection ;
  session->state = bgp_sEstablished ;

  bgp_connection_init_host(connection, bc_estd) ;

  /* Finally... now is the time to construct the ring-buffers.
   */
  connection->read_rb  = rb_create(MTYPE_BGP_RING_BUFF, bgp_read_rb_size,
                                                        true /* shared */) ;

  connection->write_rb = rb_create(MTYPE_BGP_RING_BUFF, bgp_write_rb_size,
                                                        true /* shared */) ;

  session->read_rb  = connection->read_rb ;
  session->write_rb = connection->write_rb ;

  /* We are all set
   */
  return NULL ;                 /* OK !         */
} ;

/*------------------------------------------------------------------------------
 * Free connection.
 *
 * Connection must be fsStop -- no longer attached to a session.
 */
extern void
bgp_connection_free(bgp_connection connection)
{
  assert( (connection->fsm_state == bgp_fsStop) &&
          (connection->session   == NULL) ) ;

  /* Make sure is down, so no active file all I/O stopped
   */
  bgp_connection_down(connection) ;

  /* Discard any unprocessed events and remove from the event ring.
   */
  bgp_fsm_events_flush(connection) ;

  /* Free any components which still exist
   */
  connection->lox.name = bgp_connection_host_string_free(connection->lox.name) ;
  connection->lox.log  = NULL ;

  connection->qf   = qfile_free(connection->qf) ;
  connection->cops = bgp_cops_free(connection->cops) ;

  connection->open_sent = bgp_open_state_free(connection->open_sent) ;
  connection->open_recv = bgp_open_state_free(connection->open_recv) ;

  bgp_fsm_timer_free(connection->hold_timer) ;
  bgp_fsm_timer_free(connection->keepalive_timer) ;

  connection->reader = bgp_msg_reader_free(connection->reader) ;
  connection->writer = bgp_msg_writer_free(connection->writer) ;

  /* Note that any ring-buffers are not our responsibility.
   */
  connection->read_rb  = NULL ;
  connection->write_rb = NULL ;

  /* Free the body
   */
  ddl_del(bgp_connections, connection, exist) ;

  XFREE(MTYPE_BGP_CONNECTION, connection) ;
} ;

/*==============================================================================
 * Making the effective session arguments for a session.
 */
static void bgp_add_qafx_set_to_notification(bgp_note note, qafx_set_t set) ;
static void bgp_add_orf_to_notification(bgp_note note,
                         bgp_orf_caps orf_pfx_missing, bgp_orf_cap_bits_t mode,
                                           uint8_t cap_type, uint8_t orf_type) ;

/*------------------------------------------------------------------------------
 * Make a set of session arguments, taking into account:
 *
 *   * session->args_config
 *   * connection->open_sent    -- args_sent
 *   * connection->open_recv    -- args_recv
 *
 * NB: requires a freshly reset set of args to fill in.
 *
 * This if for when is about to change from fsOpenConfirm to fsEstablished.
 * That can happen only while sAcquiring, and to only one connection !
 *
 * By the time we get to here we have parsed the incoming OPEN, and that was
 * OK.  We can fail here if we don't have any afi/safi in common, or the
 * "strict capability" check, if any, fails.
 *
 *   * args->local_as           -- as args_sent
 *     args_sent                -- as args_config
 *     args_recv                -- N/A
 *
 *   * args->local_id           -- as args_sent
 *     args_sent                -- as args_config
 *     args_recv                -- N/A
 *
 *   * args->remote_as          -- as args_recv
 *     args_sent                -- N/A
 *     args_recv                -- as received -- must be as args_config
 *
 *   * args->local_id           -- as args_recv
 *     args_sent                -- N/A
 *     args_recv                -- as received
 *
 *   * args->can_capability     -- args_sent && args_recv
 *     args_sent                -- as args_config, unless cap_suppressed
 *     args_recv                -- as received
 *
 *     NB: !can_capability => all capabilities are unavailable, except for
 *                            can_af, where the implied IPv4_Unicast is set,
 *                            and cap_af_override may have an effect.
 *
 *     NB: !can_capability => !can_mp_ext (in particular).
 *
 *   * args->can_mp_ext         -- args_sent && args_recv
 *     args_sent                -- as args_config, unless cap_suppressed
 *     args_recv                -- as received
 *
 *     NB: if args_recv->can_mp_ext, then args_config->cap_af_override is
 *         ignored.
 *
 *   * args->can_as4            -- args_sent && args_recv
 *     args_sent                -- as args_config, unless cap_suppressed
 *     args_recv                -- as received
 *
 *   * args->cap_suppressed     -- args_sent
 *     args_sent                -- set if that is the case
 *     args_recv                -- not set
 *
 *     NB: cap_suppressed => !can_capability and the rest of args_sent will
 *                                                                 reflect that.
 *
 *   * args->cap_af_override    -- set if actually forced something
 *     args_sent                -- copied from args_config
 *     args_recv                -- not set
 *
 *     NB: args->cap_af_override is true iff:
 *
 *         args_sent->caps_af_override == args_config->caps_af_override == true
 *
 *       AND
 *
 *         args_recv->can_mp_ext is false.
 *
 *         Since cap_af_override is applicable only where the far end does not
 *         do mp_ext !
 *
 *       AND
 *
 *         we here actually turn on some af in args->cap_af which is not set
 *         in both args_sent and args_recv.
 *
 *   * args->cap_strict         -- args_sent
 *     args_sent                -- as args_config
 *     args_recv                -- not set
 *
 *   * args->can_af             -- args_sent && args_recv, but see below
 *     args_sent                -- as sent, if args_recv->can_mp_ext
 *                                          otherwise, the implied IPv4_Unicast
 *     args_recv                -- as received, if args_recv->can_mp_ext
 *                                          otherwise, the implied IPv4_Unicast
 *
 *       For args_sent and args_recv, can_af is is what was said by mp_ext or
 *       what was implied by an absence of mp_ext.
 *
 *       For args->can_af, if we have args_sent->caps_af_override, AND we do
 *       NOT have args_recv->can_mp_ext, then the result is forced to
 *       args_config->can_af... and args->cap_af_override will be set iff this
 *       makes any difference.
 *
 *   * args->can_rr             -- as args_recv (whether and how)
 *     args_sent->can_rr        -- as sent
 *     args_sent->can_rr        -- as received
 *
 *     NB: even if we are not willing to support Route Refresh requests from
 *         the other end, we may send Route Refresh requests from the other
 *         end.
 *
 *         If we advertised support for Route Refresh, we must support it even
 *         if the far end is not willing to receive same.
 *
 *   * args->gr                 -- see below
 *     args_sent->gr            -- as sent
 *     args_recv->gr            -- as received
 *
 *     For args->gr:
 *
 *       gr.can             -- set if both ends support (can expect EoR)
 *       gr.restarting      -- set if far end is
 *       gr.restart_time    -- set to what far end said
 *       gr.can_preserve    -- what far end said, masked by args->can_af
 *       gr.has_preserved   -- what far end said, masked by args->can_af
 *
 *       TODO should gr.can be split or unilateral ???  Currently always sent !
 *
 *   * args->can_orf            -- whether and how,
 *                                  intersection of args_sent and args_received
 *     args_sent->can_orf       -- as sent
 *     args_recv->can_orf       -- as received
 *
 *   * args->can_orf_pfx        -- intersection of args_sent and args_received,
 *                                  masked by args->can_af
 *     args_sent->can_orf_pfx   -- as sent
 *     args_recv->can_orf_pfx   -- as received
 *
 *   * args->can_dynamic        -- currently false
 *     args_sent                -- currently false
 *     args_recv                -- as received
 *
 *   * args->can_dynamic_dep    -- currently false
 *     args_sent                -- currently false
 *     args_recv                -- as received
 *
 *   * args->holdtime_secs      -- as negotiated
 *     args_sent                -- as sent
 *     args_recv                -- as received
 *
 *   * args->keepalive_secs     -- as negotiated
 *     args_sent                -- as sent
 *     args_recv                -- as received
 *
 * Returns:  NULL <=> OK
 *           otherwise -- note for unacceptable session arguments
 */
static bgp_note
bgp_connection_make_args(bgp_connection connection, bgp_session_args args)
{
  bgp_session_args_c args_config, args_sent, args_recv ;
  bgp_session   session ;
  bgp_note      note ;
  qafx_t     qafx ;
  qafx_set_t real_af ;
  uint       holdtime, keepalive ;

  session = connection->session ;
  note    = NULL ;                      /* so far, so good      */

  qassert(session->state == bgp_sAcquiring) ;

  /* We are going to construct the "negotiated" arguments in the temporary
   * 'args' -- and in the process we need the (current) args_config, the
   * args as sent and those as received.
   *
   * Note that all these args are embedded structures.  We have a temporary
   * args structure here, which will be copied to the session if all goes well.
   */
  args_config  = session->args_config ;
  args_sent    = connection->open_sent->args ;
  args_recv    = connection->open_recv->args ;

  /* Pull in the local_/remote_  _as/_id
   */
  args->local_as  = args_sent->local_as ;
  args->local_id  = args_sent->local_id ;

  args->remote_as = args_recv->remote_as ;
  args->remote_id = args_recv->remote_id ;

  qassert(args->local_as  == args_config->local_as) ;
  qassert(args->local_id  == args_config->local_id) ;
  qassert(args->remote_as == args_config->remote_as) ;

  /* Decide which afi/safi, if any, this session will carry.
   *
   * NB: in the (unlikely) event that we do apply the cap_af_override, the
   *     'real_af' does NOT include any "forced" af -- we *really* restrict the
   *     scope of cap_af_override to the (ancient) case of a peer which does
   *     not really do *any* Capability stuff.
   */
  args->can_af = real_af = args_recv->can_af & args_sent->can_af ;

  if (args_sent->cap_af_override)
    {
      if (args_recv->can_mp_ext)
        {
          zlog_info ("%s got MP-Ext Capability, so ignoring "
                                  "override-capability", connection->lox.name) ;
        }
      else if (real_af != args_config->can_af)
        {
          args->can_af          = args_config->can_af ;
          args->cap_af_override = true ;
        }
    } ;

  if (args->can_af == 0)
    {
      /* We end up with no afi/safi at all.
       *
       * Drop session, complaining that the other end does not support the
       * afi/safi we *originally* wanted.
       */
      plog_err (connection->lox.log, "%s [Error] No common capability",
                                                         connection->lox.name) ;

      note = bgp_note_new(BGP_NOMC_OPEN, BGP_NOMS_O_CAPABILITY) ;
      bgp_add_qafx_set_to_notification(note, args_config->can_af) ;

      return note ;
    } ;

  /* Now complete the set-up of the args to reflect the negotiated session
   * arguments.
   */
  args->cap_strict     = args_sent->cap_strict ;
  args->cap_suppressed = args_sent->cap_suppressed ;

  args->can_capability = args_sent->can_capability &&
                         args_recv->can_capability ;
  args->can_mp_ext     = args_sent->can_mp_ext &&
                         args_recv->can_mp_ext ;
  args->can_as4        = args_recv->can_as4 &&
                         args_sent->can_as4 ;

  args->can_rr         = args_recv->can_rr ;

  args->gr             = args_recv->gr ;
  args->gr.can           &= args_sent->gr.can ;
  args->gr.can_preserve  &= real_af ;
  args->gr.has_preserved &= real_af ;

  args->can_orf        = args_recv->can_orf &
                         args_sent->can_orf ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      /* Accept only those afi/safi which we really negotiated -- exclude any
       * which are cap_af_override.
       */
      bgp_orf_cap_bits_t orf, orf_sent, orf_recv ;

      if (!(real_af & qafx_bit(qafx)))
        continue ;

      orf_sent = args_sent->can_orf_pfx.af[qafx] ;
      orf_recv = args_recv->can_orf_pfx.af[qafx] ;

      orf = 0 ;

      if ((orf_sent & ORF_SM)     && (orf_recv & ORF_RM))
        orf |= ORF_SM ;
      if ((orf_sent & ORF_SM_pre) && (orf_recv & ORF_RM_pre))
        orf |= ORF_SM_pre ;

      if ((orf_sent & ORF_RM)     && (orf_recv & ORF_SM))
        orf |= ORF_RM ;
      if ((orf_sent & ORF_RM_pre) && (orf_recv & ORF_SM_pre))
        orf |= ORF_RM_pre ;

      args->can_orf_pfx.af[qafx] = orf ;
    } ;

  args->can_dynamic     = args_recv->can_dynamic && args_sent->can_dynamic ;
  args->can_dynamic_dep = !args->can_dynamic && args_recv->can_dynamic_dep
                                             && args_sent->can_dynamic_dep ;

  /* Negotiation of HoldTime and setting of KeepaliveTime.
   *
   *   * holdtime_secs      -- set to min of args_recv and args_sent
   *
   *                           (The args_sent value is copied from the
   *                            args_config... but in principle this is a
   *                            negotiation, so we work from what we actually
   *                            sent !)
   *
   *   * keepalive_secs     -- set to min of holdtime_secs / 3 and the
   *                           keepalive in the args_config.
   *
   * The effect of this on the KeepaliveTime is that:
   *
   *   * the maximum value is the negotiated HoldTime / 3.
   *
   *   * the minimum value is the configured value, or 1 if the HoldTime > 0.
   */
  if (args_recv->holdtime_secs <= args_sent->holdtime_secs)
    holdtime = args_recv->holdtime_secs ;
  else
    holdtime = args_sent->holdtime_secs ;

  if ((holdtime < 3) && (holdtime != 0))
    holdtime = 3 ;              /* more paranoia        */

  keepalive = holdtime / 3 ;
  if ((keepalive > args_config->keepalive_secs)
                                           && (args_config->keepalive_secs > 0))
    keepalive = args_config->keepalive_secs ;

  args->holdtime_secs   = holdtime ;
  args->keepalive_secs  = keepalive ;

  /* Do "strict" capability checks:
   *
   * What we mean by this is that where we want a particular capability,
   * the far end had better agree, or we stop now.  Note that any extra
   * capabilities which the other end may have offered, we simply ignore.
   * This means that for completeness, both ends should configure "strict".
   *
   * NB: we work from the session->args... so, if the connection has been hit
   *     by cap_suppress, then this checks what was originally asked for.
   *
   *   1) if we support AS4, if our ASN is not represented in AS2, then
   *      "strict" means we require the other end to understand AS4.
   *
   *      Generally we support AS4.
   *
   *      Mostly it does not matter if the other end does or does not support
   *      AS4 -- the mechanics of AS4_PATH etc. does the job.  However, if
   *      our ASN requires AS4, then it really would be best if the other
   *      end supported it.  (An AS2 speaker peering with an AS4 ASN peer is
   *      problematic, so rejecting it seems like a reasonable interpretation
   *      of "strict".)
   *
   *   2) check that all afi/safi are supported.
   *
   *   3) check that the far end supports receiving ORF where this end
   *      requires sending.
   *
   *      If this end depends on the far end supporting ORF, then "strict"
   *      will enforce that.  If the session fails the "strict" test, then the
   *      configuration can be changed at this end to no longer depend on
   *      ORF.
   *
   * FWIW, "strict" does not check:
   *
   *   1) Route Refresh
   *
   *      Currently we always support Route Refresh.
   *
   *      Supporting Route Refresh does not imply either a need or a desire for
   *      the other end to support it (or use it).
   *
   *      So there isn't any basis for "strict".
   *
   *   2) Graceful Restart
   *
   *      Currently we always support Graceful Restart -- though do not
   *      advertise any preservation of forwarding state.
   *
   *      Supporting Graceful Restart does not imply either a need or a desire
   *      for the other end to support it (or use it).
   *
   *      So there isn't any basis for "strict".
   *
   *   3) Dynamic Capabilities -- of either kind.
   *
   *      We don't support these, in any case.
   */
  if (args->cap_strict)
    {
      bgp_orf_caps_t orf_pfx_missing ;
      bgp_form_t     orf_cap_missing ;

      /* Check that we got AS4 if we wanted it and need it.
       */
      if (args_config->can_as4 && (args->local_as > BGP_AS2_MAX)
                               && !args->can_as4)
        {
          /* Note that we complain about the capability we wanted to see !
           */
          ptr_t p ;

          if (note == NULL)
            note = bgp_note_new(BGP_NOMC_OPEN,
                                          BGP_NOMS_O_CAPABILITY) ;

          p = bgp_note_prep_data(note, 2 + BGP_CAP_AS4_L) ;

          store_b( &p[0], BGP_CAN_AS4) ;
          store_b( &p[1], BGP_CAP_AS4_L) ;
          store_nl(&p[2], args->remote_as) ;

          confirm(BGP_CAP_AS4_L == 4) ;
        } ;

      /* Check that we got all the families we wanted.
       */
      if (args_config->can_af != args->can_af)
        {
          if (note == NULL)
            note = bgp_note_new(BGP_NOMC_OPEN,
                                          BGP_NOMS_O_CAPABILITY) ;

          bgp_add_qafx_set_to_notification(note,
                                          args_config->can_af & ~args->can_af) ;
        } ;

      /* Check that we got the ability to send Prefix ORF where we wanted
       * it.  (We don't care what the far end wanted, or what we offered.)
       */
      orf_cap_missing = bgp_form_none ;
      memset(&orf_pfx_missing, 0 , sizeof(bgp_orf_caps_t)) ;

      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_orf_cap_bits_t orf_want ;

          orf_want = args_config->can_orf_pfx.af[qafx] & (ORF_SM | ORF_SM_pre) ;

          if (orf_want == 0)
            continue ;

          qassert(args_config->can_af & qafx_bit(qafx)) ;

          /* For Prefix ORF we have two equivalent Types.  Assuming we wanted
           * one or both: if we did not get at least one of what we wanted,
           * then we complain -- and mention all the Types we wanted.
           *
           * Note that args->can_orf_pfx[] has ORF_SM set iff asked for one
           * or both AND received permission of one or both.
           *
           * Note that we complain about ORF_RM to the far end... so, the
           * capability from *their* perspective.
           */
          if (!(args->can_orf_pfx.af[qafx] & ORF_SM))
            {
              if (orf_want & ORF_SM)
                {
                  orf_pfx_missing.af[qafx] |= ORF_RM ;
                  orf_cap_missing          |= bgp_form_rfc ;
                } ;

              if (orf_want & ORF_SM_pre)
                {
                  orf_pfx_missing.af[qafx] |= ORF_RM_pre ;
                  orf_cap_missing          |= bgp_form_pre ;
                } ;
            } ;
        } ;

      if (orf_cap_missing != bgp_form_none)
        {
          if (note == NULL)
            note = bgp_note_new(BGP_NOMC_OPEN, BGP_NOMS_O_CAPABILITY) ;

          if (orf_cap_missing & bgp_form_rfc)
            bgp_add_orf_to_notification(note, &orf_pfx_missing,
                                           ORF_RM, BGP_CAN_ORF, BGP_ORF_T_PFX) ;

          if (orf_cap_missing & bgp_form_pre)
            bgp_add_orf_to_notification(note, &orf_pfx_missing,
                               ORF_RM_pre, BGP_CAN_ORF_pre, BGP_ORF_T_PFX_pre) ;
        } ;
    } ;

  return note ;
} ;

/*------------------------------------------------------------------------------
 * Append all the qafx in the given set as MP-Ext capabilities to the given
 * note.
 */
static void
bgp_add_qafx_set_to_notification(bgp_note note, qafx_set_t set)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      if (set & qafx_bit(qafx))
        {
          ptr_t p ;

          p = bgp_note_prep_data(note, 2 + BGP_CAP_MPE_L) ;

          store_b( &p[0], BGP_CAN_MP_EXT) ;
          store_b( &p[1], BGP_CAP_MPE_L) ;
          store_ns(&p[2], get_iAFI(qafx)) ;
          store_b( &p[4], 0) ;
          store_b( &p[5], get_iSAFI(qafx)) ;

          confirm((2 + BGP_CAP_MPE_L) == 6) ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Append ORF capability to reflect lack of Prefix ORF in some qafx.  Sending
 * the given Capability Type and the given ORF Type.
 */
static void
bgp_add_orf_to_notification(bgp_note note,
                         bgp_orf_caps orf_pfx_missing, bgp_orf_cap_bits_t mode,
                                            uint8_t cap_type, uint8_t orf_type)
{
  qafx_t qafx ;
  byte   cap[2 + ((BGP_CAP_ORFE_MIN_L + BGP_CAP_ORFT_L) * qafx_count)] ;
  byte*  ptr ;

  ptr   = cap ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      if (orf_pfx_missing->af[qafx] & mode)
        {
          if (ptr == cap)
            {
              *ptr++  = cap_type ;
              *ptr++  = 0 ;
            } ;

          assert(ptr <= (cap + sizeof(cap) -
                                       (BGP_CAP_ORFE_MIN_L + BGP_CAP_ORFT_L))) ;

          store_ns(ptr, get_iAFI(qafx)) ;
          ptr[2]  = 0 ;
          ptr[3]  = get_iSAFI(qafx) ;

          ptr[4]  = 1 ;                 /* 1 ORF Type   */

          confirm(BGP_CAP_ORFE_MIN_L == 5) ;

          ptr[5] = orf_type ;
          ptr[6]  = BGP_CAP_ORFT_M_RECV ;

          confirm((BGP_CAP_ORFE_MIN_L + BGP_CAP_ORFT_L) == 7) ;

          ptr += BGP_CAP_ORFE_MIN_L + BGP_CAP_ORFT_L ;

          assert(ptr <= (cap + sizeof(cap))) ;
        } ;
    } ;

  if (ptr != cap)
    {
      cap[1] = ptr - cap - 2 ;
      bgp_note_append_data(note, cap, ptr - cap) ;
    } ;
} ;

/*==============================================================================
 * Opening and closing Connection I/O stuff
 */
static bool bgp_acceptor_co_opt(bgp_connection connection) ;
static void bgp_connection_read_action(qfile qf, void* file_info) ;
static void bgp_connection_write_action(qfile qf, void* file_info) ;

/*------------------------------------------------------------------------------
 * Prepare to start a connect() connection.
 *
 * Returns:  address of the connection->cops.
 */
extern bgp_cops
bgp_connection_prepare(bgp_connection connection)
{
  /* Make sure that everything is in a quiescent state.
    */
  bgp_connection_down(connection) ;

  /* Now we want a bang up to date copy of the connection options.
   */
  connection->cops = bgp_cops_copy(connection->cops,
                                             connection->session->cops_config) ;

  return connection->cops ;
} ;

/*------------------------------------------------------------------------------
 * We have a connect() running, so need to set up the connection->qf for it.
 *
 * Note that although we have a running qfile, the connection is down.
 *
 * Returns:  address of the qf.
 */
extern qfile
bgp_connection_connecting(bgp_connection connection, int sock_fd)
{
  qfile qf ;

  qf = connection->qf = qfile_init_new(connection->qf, NULL) ;
  qps_add_qfile(be_nexus->selection, qf, sock_fd, connection) ;

  connection->io_state = qfDown ;

  return qf ;
} ;

/*------------------------------------------------------------------------------
 * Start I/O for connection which has just come up -- connect() or accept()
 *
 * Make sure now have reader and writer with the required action functions,
 * enable read and write to kick things off.
 *
 * Returns:  true <=> OK
 *          false  => is accept() and acceptor state no longer OK
 */
extern bool
bgp_connection_io_start(bgp_connection connection)
{
  /* If this is a connect() connection, we have a qfile, but we need to set up
   * a reader.
   *
   * Otherwise, this is an accept() connection, so we need co-opt the
   * acceptor's qfile and reader, if we can.
   */
  if (connection->ord == bc_connect)
    connection->reader = bgp_msg_reader_reset_new(connection->reader,
                                                             &connection->lox) ;
  else
    {
      bool co_opted ;

      co_opted = bgp_acceptor_co_opt(connection) ;

      if (!co_opted)
        return false ;
    }

  /* For both types of connection, we now set up the writer, and enable
   * both read-ready and write-ready.
   */
  connection->writer = bgp_msg_writer_reset_new(connection->writer,
                                                             &connection->lox) ;

  qfile_enable_mode(connection->qf, qps_read_mnum, bgp_connection_read_action) ;
  qfile_enable_mode(connection->qf, qps_write_mnum,
                                                  bgp_connection_write_action) ;

  /* We are all set !
   */
  connection->io_state = qfUp ;         /* fully up     */

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Down connection -- close qfile.
 *
 *   * sets qfDown
 *   * if there is a qfile, close it
 *   * if there is a reader, stop it
 *   * if there is a writer, stop it
 *
 * NB: does not affect any timers.
 */
extern void
bgp_connection_down(bgp_connection connection)
{
  qfile_close(connection->qf) ;
  connection->io_state = qfDown ;

  if (connection->reader != NULL)
    bgp_msg_read_stop(connection->reader) ;

  if (connection->writer != NULL)
    bgp_msg_write_stop(connection->writer) ;
} ;

/*------------------------------------------------------------------------------
 * Connection level SHUT_RD/SHUT_WR.
 *
 * Make sure that the qfile is shut in the same way -- most likely is.
 *
 * Returns:  qfDown     -- the connection is down, but has not closed the
 *                         qfile.
 *       or: qfUp_RD    -- the connection is still up for reading.
 *                         the qfile, we do not speak for.
 *       or: qfUp_WR    -- the connection is still up for writing.
 *                         the qfile, we do not speak for.
 *
 * NB: if the connection was already qfDown, then qf may be NULL or
 *     qf->fd may be undefined -- ie the connection may be closed, but qf->err
 *     may still be set.
 *
 *     if the connection was not qfDown, then preserves qf->fd and qf->err,
 *     even if is now qfDown.
 */
static void
bgp_connection_shutdown(bgp_connection connection, qfile_state_t shut)
{
  qfile_shutdown(connection->qf, shut) ;

  connection->io_state &= (shut ^ qfUp_RDWR) ;
} ;

/*------------------------------------------------------------------------------
 * Connection level SHUT_RD -- stops the associated reader.
 *
 * See bgp_connection_shutdown()
 */
extern void
bgp_connection_shut_rd(bgp_connection connection)
{
  bgp_msg_read_stop(connection->reader) ;
  bgp_connection_shutdown(connection, qfUp_RD) ;
} ;

/*------------------------------------------------------------------------------
 * Connection level SHUT_WR -- stops the associated writer.
 *
 * See bgp_connection_shutdown()
 */
extern void
bgp_connection_shut_wr(bgp_connection connection)
{
  bgp_msg_write_stop(connection->writer) ;
  bgp_connection_shutdown(connection, qfUp_WR) ;
} ;

/*==============================================================================
 * Reading/Writing BGP connection -- once TCP connection has come up.
 *
 * Nothing is read/written directly -- all actual I/O is qpselect driven.
 */

/*------------------------------------------------------------------------------
 * Read Action for BGP connection
 */
static void
bgp_connection_read_action(qfile qf, void* file_info)
{
  bgp_connection connection ;
  bool kick ;

  connection = file_info ;
  qassert(qf == connection->qf) ;

  /* Deal with the I/O side of things -- turns off the reader if get a failure
   * or the buffer is full already.
   */
  kick = bgp_msg_read_raw(connection->reader, qf) ;

  /* If we have something we can do, make sure we have an I/O event.
   */
  if (kick)
    bgp_fsm_io_event(connection) ;
} ;

/*------------------------------------------------------------------------------
 * Write Action for bgp connection.
 */
static void
bgp_connection_write_action(qfile qf, void* file_info)
{
  bgp_connection connection ;
  bool kick ;

  connection = file_info ;
  qassert(qf == connection->qf) ;

  /* Deal with the I/O side of things -- turns off the writer if get a failure
   * or the buffer is empty already.
   */
  kick = bgp_msg_write_raw(connection->writer, connection->qf) ;

  /* If we have something we can do, make sure we have an I/O event.
   */
  if (kick)
    bgp_fsm_io_event(connection) ;
} ;

/*==============================================================================
 * Connection options.
 *
 */

/*------------------------------------------------------------------------------
 * Initialise a set of connection options -- allocate if required.
 */
extern bgp_cops
bgp_cops_init_new(bgp_cops cops)
{
  if (cops == NULL)
    cops = XMALLOC(MTYPE_BGP_CONNECTION_OPS, sizeof(bgp_cops_t)) ;

  /* At present there is no difference between 'init' (never kissed) and
   * 'reset' (clear down).
   */
  return bgp_cops_reset(cops) ;
} ;

/*------------------------------------------------------------------------------
 * Copy one set of connection options over another -- allocating if required.
 */
extern bgp_cops
bgp_cops_copy(bgp_cops dst, bgp_cops_c src)
{
  dst = bgp_cops_init_new(dst) ;
  *dst = *src ;
  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Duplicate a set of connection options -- allocating a new set.
 */
extern bgp_cops
bgp_cops_dup(bgp_cops_c src)
{
  return bgp_cops_copy(NULL, src) ;
} ;

/*------------------------------------------------------------------------------
 * Reset a set of connection options -- down unusable state !
 */
extern bgp_cops
bgp_cops_reset(bgp_cops cops)
{
  memset(cops, 0, sizeof(bgp_cops_t)) ;         /* flush        */

  /* Zeroising sets:
   *
   *   * su_remote              -- AF_UNSPEC
   *   * su_local               -- AF_UNSPEC
   *
   *   * port                   -- 0        -- invalid !
   *
   *   * conn_state             -- bgp_csDown
   *
   *   * can_notify_before_open -- false    -- default
   *
   *   * idle_hold_max_secs     -- 0        )
   *   * connect_retry_secs     -- 0        ) unset
   *   * accept_retry_secs      -- 0        )
   *   * open_hold_secs         -- 0        )
   *
   *   * ttl                    -- X        -- set, below
   *   * gtsm                   -- false    -- default
   *
   *   * ttl_out                -- 0        -- nothing set, yet
   *   * ttl_min                -- 0        -- nothing set -- not GTSM
   *
   *   * password               -- empty    -- embedded string
   *
   *   * ifname                 -- empty    -- embedded string
   *   * ifindex                -- 0        -- none
   */
  confirm(AF_UNSPEC == 0) ;
  confirm(bgp_csDown == 0) ;

  cops->ttl = TTL_MAX ;

  return cops ;
} ;

/*------------------------------------------------------------------------------
 * Free a set of connection options.
 */
extern bgp_cops
bgp_cops_free(bgp_cops cops)
{
  if (cops != NULL)
    XFREE(MTYPE_BGP_CONNECTION_OPS, cops) ;

  return NULL ;
} ;

/*==============================================================================
 * Inbound connection tracking.
 *
 * RFC4271 requires inbound connections to be "tracked" up to receiving an
 * OPEN message in a number of states.
 *
 * For outbound connections Quagga only has one connect() running at any time,
 * so no "tracking" is required.
 *
 * For Collision Detection, Section 6.8 of RFC4271 says:
 *
 *    Upon receipt of an OPEN message, the local system MUST examine all of
 *    its connections that are in the OpenConfirm state. ... If, among
 *    these connections, there is a connection to a remote BGP speaker
 *    whose BGP Identifier equals the one in the OPEN message, and this
 *    connection collides with the connection over which the OPEN message
 *    is received, then the local system performs the following collision
 *    resolution procedure:
 *
 *    ....
 *
 *      2) If the value of the local BGP Identifier is less than the
 *         remote one, the local system closes the BGP connection that
 *         already exists (the one that is already in the OpenConfirm
 *         state), and accepts the BGP connection initiated by the remote
 *         system.
 *
 *      3) Otherwise, the local system closes the newly created BGP
 *         connection (the one associated with the newly received OPEN
 *         message), and continues to use the existing one (the one that
 *         is already in the OpenConfirm state).
 *
 * The "this connection collides" means that the IP-local and the IP-remote
 * are the same -- as far as the RFC is concerned the name of the session is
 * IP-local + IP-remote.  For Quagga, the IP-local is not necessarily known,
 * and may depend on what connect() and accept() decided or were given.  So,
 * for Quagga "this connection collides" means that the IP-remote address is
 * the same.
 *
 * Further, Quagga will not accept() from or connect() to any address which
 * is not a known and "active" neighbour.  So the the examination of all
 * connections described by the RFC need only consider the state of one
 * session.  And, in a session, only one connection can be in OpenConfirm
 * at any moment.  So the examination is limited to one connection.
 *
 * The RFC carefully describes a process in which it only considers for
 * collision those connections with the same "name" AND with the same BGP-Id.
 * What it does NOT do, is discuss what to do with connections with the same
 * "name" BUT different BGP-Id :-(
 *
 * In the collision resolution, if the remote BGP-Id is less than the local one,
 * then the current (and only) OpenConfirm connection is shut, and the new
 * connection becomes the OpenConfirm one, otherwise the new connection is
 * discarded.  So, assuming that both ends of connections with the same name
 * are sensible, and send the same BGP-Id in all OPEN messages, then:
 * multiple inbound connections will either keep the latest or discard them
 * all.
 *
 * So, for inbound connection tracking we track only one connection.  If a
 * new connection arrives while a previous one is being tracked, the previous
 * one is unceremoniously dumped.  There is every reason to expect that if the
 * peer opens another connection then it has already closed the previous one,
 * or is about to... so discarding the older connection feels correct.  It is
 * also RFC compliant:
 *
 *   a) if the BGP speaker knows the BGP-Id, it can apply the collision
 *      detection when the connection comes up (not wait for incoming OPEN).
 *
 *      We are assuming here that the BGP-Id will be the same for two
 *      connections from the same peer (!), so even though we don't know what
 *      the BGP-Id is, either both connections will be discarded or only the
 *      earlier one.
 *
 *   b) the RFC does not specify what to do with different BGP-Id !!
 *
 *      If the two connections (eventually) carry different BGP-Id, then
 *      we assume the later one is the (now) valid one, and discard the
 *      previous.
 *
 *------------------------------------------------------------------------------
 * While a given peer is "active" (ie, exists and is not shut down) there
 * exists a session -- even if the session is disabled.  The acceptor object
 * belongs to the session, and will accept connections independently, unless
 * the peer is set "out-bound only" (the opposite of "passive").
 *
 * The acceptor mechanics are designed so that an incoming connection from
 * a peer:
 *
 *   * will be accepted and held on to if a session is yet to be enabled, or
 *     is in the process of being disabled and restarting.
 *
 *     If an incoming connection is rejected, the other end will wait for
 *     120 seconds before trying again.  And, if this end is not passive, it
 *     will initiate an outbound connection in due course.
 *
 *     However, if this end is "passive", then it may be a while before the
 *     other end tries again.
 *
 *     Also, some test-gear is not really tolerant of failing to make a
 *     connection, so rejecting incoming stuff unnecessarily is a Bad Thing.
 *
 *   * can do RFC 4724 compatible Graceful Restart handling... which requires
 *     an incoming connection to signal the termination of an established
 *     session, followed by restarting using the new connection.
 *
 *     So need to be able to hold on to the incoming connection while the
 *     existing session is disabled and re-enabled.
 *
 *   * can do RFC 4271 compatible "tracking of incoming connections", which
 *     while a session is fsEstablished, requires an inbound connection to
 *     be tracked to OPEN received, and then to drop the current session and
 *     restart with the new connection.
 *
 *   * but, where a connection becomes established on an out-bound connection,
 *     discard any in-coming stuff and reject any for a brief period -- to
 *     avoid immediately tearing down a perfectly good connection.
 *
 * The acceptor states are:
 *
 *   * bacs_unset         -- not prepared to accept (eg out-bound only)
 *
 *   * bacs_idle          -- not currently willing to accept (on timer)
 *
 *   * bacs_listening     -- ready to accept a connection
 *
 *   * bacs_open_awaited  -- accepted and waiting for OPEN
 *
 *   * bacs_open_received -- accepted and received OPEN
 *
 *   * bacs_bust          -- accepted but received a so far incomplete message,
 *                           either before or after OPEN.
 *
 * Plus the 'hold' flag, which is significant in bacs_open_awaited/_received.
 *
 * The acceptor interacts with the FSM when the session is enabled.
 *
 * In the following states, the acceptor proceeds independently of any FSM:
 *
 *   * no FSM at all -- ie the session is disabled.
 *   * fsInitial     -- for any secondary connection
 *   * fsIdle        -- for any secondary connection -- whether stopping or not
 *   * fsStop        -- which the acceptor cannot see, because a stopped
 *                      connection is detached from the parent session !
 *
 * and fsConnect, which the acceptor will never see, because it never looks
 * at the primary connection, except when it is fsEstablished.
 *
 * The following FSM transitions are key:
 *
 *   * fsIdle -> fsActive
 *
 *     If the acceptor is bacs_open_awaited or bacs_open_received, then the
 *     connection will co-opt the reader and the acceptor goes bacs_listening
 *     and the 'hold' flag is cleared.
 *
 *   * collision resolution.
 *
 *     If the dropped connection is the incoming (secondary), the acceptor will
 *     be forced bacs_idle for a few (10) seconds.
 *
 * So,
 *
 *   * bacs_listening     -- ready to accept a connection
 *
 *     the only event that can occur is that accept() rolls up, and then,
 *     depending of on the FSM:
 *
 *         - fsActive       -- secondary
 *
 *           If the FSM is not delaying_open (ie the DelayOpenTimer is not
 *           running):
 *
 *             the FSM will co-opt the reader etc. and the acceptor
 *             stays in bacs_listening.
 *
 *           Otherwise, the FSM has a previous connection in its hands:
 *
 *             the FSM will drop the current connection and fall back to
 *             fsIdle... so the accepted connection will be picked up as it
 *             returns to fsActive.
 *
 *             Acceptor proceeds to bacs_open_awaited.
 *
 *         - fsOpenSent     -- secondary
 *         - fsOpenConfirm  -- secondary
 *
 *           The FSM has a previous connection in its hands, which it will
 *           now drop etc, as above.
 *
 *           Acceptor proceeds to bacs_open_awaited.
 *
 *         - fsEstablished  -- must be the primary !
 *
 *           If Graceful Restart, the FSM will drop the session etc., otherwise
 *           it will do nothing until an OPEN arrives (per RFCs).
 *
 *           Acceptor proceeds to bacs_open_awaited.
 *
 *         - all other FSM states -- including fsIdle
 *
 *           Acceptor proceeds to bacs_open_awaited.
 *
 *   * bacs_open_awaited  -- accepted and waiting for OPEN
 *
 *     this implies that the FSM has not co-opted the reader, so either it
 *     is busy dealing with another connection, or is otherwise not ready for
 *     a new one.  So, with one exception, the acceptor proceeds independently.
 *
 *     The exception is: if an OPEN arrives, and is in fsEstablished, and is
 *     not Graceful Restart, then the FSM will drop the session and proceed
 *     to fsIdle (eventually).  While the FSM is doing this, the acceptor will
 *     hold on to the OPEN.
 *
 *     So for the acceptor we have:
 *
 *       (1) OPEN arrives:
 *
 *           In all cases will proceed to bacs_open_received.
 *
 *           Tell FSM in case is fsEstablished etc.
 *
 *       (2) if something other than OPEN arrives, the incoming connection is
 *           busted.
 *
 *           In all cases will log and fall to bacs_listening.
 *
 *           Does not need to tell the FSM anything, since whatever it is doing,
 *           it is unaffected by a failed in-coming connection.
 *
 *       (3) if get EOF or I/O error, the connection is busted.
 *
 *           as (2)
 *
 *   * bacs_open_received -- accepted and received OPEN
 *
 *     If something else arrives or I/O fails, as (2) and (3) above.
 *
 *   * bacs_bust          -- accepted but received a so far incomplete message,
 *                           either before or after OPEN.
 *
 *     An intermediate step before (2) or (3).  If a partial NOTIFICATION rolls
 *     up before or after an OPEN, then waits until it all arrives (or 5
 *     seconds), before falling back to bacs_listening.
 */
static void bgp_acceptor_read_action(qfile qf, void* file_info) ;
static void bgp_acceptor_reset(bgp_acceptor acceptor,
                                                    bgp_nom_subcode_t subcode) ;

static void bgp_acceptor_set_timer(bgp_acceptor acceptor, uint secs) ;
static void bgp_acceptor_stop_timer(bgp_acceptor acceptor) ;
static void bgp_acceptor_time_out(qtimer qtr, void* timer_info,
                                                            qtime_mono_t when) ;
static void  bgp_acceptor_set_open_awaited(bgp_acceptor acceptor, int sock_fd) ;
static void bgp_acceptor_close_current(bgp_acceptor acceptor, uint when,
                                                                bgp_note note) ;
static void bgp_acceptor_pending_close(bgp_acceptor acceptor, int sock_fd,
                                                     uint when, bgp_note note) ;
static void bgp_acceptor_actual_close(bgp_acceptor acceptor) ;
static void bgp_acceptor_do_close(int sock_fd, bgp_note note) ;

/*------------------------------------------------------------------------------
 * Initialise an empty acceptor (unset) -- allocating as required.
 *
 * Returns:  address of acceptor, in bacs_unset state.
 *
 * NB: if does not allocate, then assumes the given acceptor has never been
 *     kissed.
 */
static bgp_acceptor
bgp_acceptor_new(bgp_session session)
{
  bgp_acceptor acceptor ;

  acceptor = XCALLOC(MTYPE_BGP_ACCEPTOR, sizeof(bgp_acceptor_t)) ;

  /* Zeroizing the bgp_acceptor has set:
   *
   *   * session                -- NULL     -- set below
   *   * lox                    -- NULLs    -- set below
   *
   *   * state                  -- bacs_unset
   *   * pending                -- bacp_none
   *   * sock_fd_pending        -- X        -- set below
   *
   *   * note           -- NULL     -- none, yet
   *   * cops                   -- NULL     -- ditto
   *   * su_password            -- NULL     -- ditto
   *   * qf                     -- NULL     -- ditto
   *   * reader                 -- NULL     -- ditto
   *
   *   * open_received          -- false
   *   * timer_running          -- false
   *
   *   * timer                  -- NULL     -- ditto
   */
  confirm(bacs_unset == 0) ;
  confirm(bacp_none  == 0) ;

  acceptor->sock_fd_pending  = fd_undef ;

  /* These are essentially constant.
   */
  acceptor->session  = session ;
  acceptor->lox.log  = session->lox.log ;
  acceptor->lox.name = bgp_connection_host_string(acceptor->lox.name, session,
                                                                    bc_accept) ;

  return session->acceptor = acceptor ;
} ;

/*------------------------------------------------------------------------------
 * Reset the given session's acceptor -- unless is bacs_unset.
 *
 * Completes any pending close, closes any pending open and closes any
 * active connection.  Stops any timer.
 *
 * We do not expect to have an active connection very often, so we here
 * discard:
 *
 *   * note
 *   * timer
 *   * qfile
 *   * reader
 *
 * Drops to bacs_listening.
 */
static void
bgp_acceptor_reset(bgp_acceptor acceptor, bgp_nom_subcode_t subcode)
{
  if (acceptor->state != bacs_unset)
    {
      /* Deal with any pending close or open or current connection.
       */
      switch (acceptor->pending)
        {
          default:
          qassert(false) ;
          fall_through ;

          case bacp_none:
            break ;

          case bacp_close:
            qassert( (acceptor->state == bacs_idle) ||
                     (acceptor->state == bacs_paused) ) ;

            bgp_acceptor_actual_close(acceptor) ;
            break ;

          case bacp_open:
            qassert(acceptor->state == bacs_paused) ;
            qassert(acceptor->sock_fd_pending >= 0) ;

            bgp_acceptor_do_close(acceptor->sock_fd_pending,
                                      bgp_note_new(BGP_NOMC_CEASE, subcode)) ;
            break ;
        } ;

      qassert(acceptor->pending = bacp_none) ;
      qassert(acceptor->sock_fd_pending < 0) ;

      if (qfile_fd_get(acceptor->qf) >= fd_first)
        {
          qassert( (acceptor->state == bacs_open_awaited) ||
                   (acceptor->state == bacs_open_received) ||
                   (acceptor->state == bacs_busted) ) ;

          bgp_acceptor_close_current(acceptor, 0 /* now */,
                                    bgp_note_new(BGP_NOMC_CEASE, subcode)) ;
        } ;

      bgp_acceptor_stop_timer(acceptor) ;

      acceptor->note = bgp_note_free(acceptor->note) ;
      acceptor->qf           = qfile_free(acceptor->qf) ;
      acceptor->reader       = bgp_msg_reader_free(acceptor->reader) ;

      bgp_acceptor_cops_reset(acceptor) ;
      acceptor->state = bacs_listening ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Reset the acceptor->cops
 *
 * This is done when a new accept() connection is made, or when the acceptor
 * is reset.
 *
 * Clears out the:
 *
 *   su_remote              -- to be filled in by the accept() action
 *   su_local               -- to be filled in by the accept() action
 *
 *   connect_retry_secs     -- N/A
 *
 *   ttl_out                -- to be filled in by the accept() action
 *   ttl_min                -- to be filled in by the accept() action
 *
 *   ifname                 -- N/A
 *   ifindex                -- N/A
 */
extern void
bgp_acceptor_cops_reset(bgp_acceptor acceptor)
{
  qassert((acceptor->state != bacs_unset) && (acceptor->cops != NULL)) ;

  sockunion_clear(&acceptor->cops->su_remote) ;
  sockunion_clear(&acceptor->cops->su_local) ;

  acceptor->cops->connect_retry_secs = 0 ;
  acceptor->cops->ttl_out            = 0 ;
  acceptor->cops->ttl_min            = 0 ;      /* no gtsm, yet */

  memset(acceptor->cops->ifname, 0, sizeof(acceptor->cops->ifname)) ;
  acceptor->cops->ifindex            = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Free acceptor -- unset, undo logging, unhook from session and deallocate.
 *
 * Returns:  NULL.
 */
extern bgp_acceptor
bgp_acceptor_free(bgp_acceptor acceptor)
{
  if (acceptor != NULL)
    {
      qassert(acceptor->session->acceptor == acceptor) ;

      if (acceptor->state != bacs_unset)
        bgp_listen_unset(acceptor->su_password, acceptor->cops) ;

      bgp_acceptor_reset(acceptor, BGP_NOMS_C_DECONFIG) ;

      acceptor->cops        = bgp_cops_free(acceptor->cops) ;
      acceptor->su_password = sockunion_free(acceptor->su_password) ;

      acceptor->lox.log  = NULL ;
      acceptor->lox.name = bgp_connection_host_string_free(acceptor->lox.name) ;

      acceptor->session->acceptor = NULL ;

      XFREE(MTYPE_BGP_ACCEPTOR, acceptor) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set connection options -- creates and/or starts acceptor if required.
 *
 * When a new accept() connection is made, the acceptor->cops are reset and
 * acted on.
 *
 * This function is used to initialise or change the accept->cops.  If a change
 * is made which invalidates any current connection, then that is reset.
 *
 * NB: it is not expected that the su_remote in the session->cops_config will
 *     *ever* change.
 *
 *     However, keep a copy of the session->cops_config->su_remote as the
 *     acceptor->su_password.  So that if we set a password, we have a separate
 *     record of what we set the password for.
 *
 *     If arrives here with an su_remote which is not the same as the current
 *     su_password, then will reset the current listening arrangement.
 *
 * Most of the acceptor->cops are unaffected when a new accept connection
 * is made.  All of the settings which could cause a connection to be reset are
 * read-only -- with the exception of the su_remote, as above.  (What this
 * means is we don't need an acceptor->cops_config to run this comparison
 * against -- the acceptor->cops contains both config and current.)
 *
 * The acceptor configuration options are:
 *
 *   su_remote              -- N/A  -- filled in for actual connection
 *   su_local               -- N/A  -- filled in for actual connection
 *
 *   port                   -- if not the same as current, then must unset
 *                             current and start again.
 *
 *   conn_state             -- if is csCanTrack, we run the acceptor,
 *                             otherwise, not.
 *
 *   can_notify_before_open -- can change at any time
 *
 *   connect_retry_secs     -- N/A
 *   accept_retry_secs      -- change affects the next timer
 *   open_hold_secs         -- change affects connection when comes up
 *
 *   ttl                    -- if changed must reset
 *   gtsm                   -- if changed must reset
 *
 *   ttl_out                -- N/A  -- filled in for actual connection
 *   ttl_min                -- N/A  -- filled in for actual connection
 *
 *   password               -- if changed must reset and update password
 *
 *   ifname                 -- N/A
 *   ifindex                -- N/A
 */
extern void
bgp_acceptor_set_cops(bgp_session session, bgp_cops_c new_config)
{
  bgp_acceptor acceptor ;
  bool can_track, set_new ;

  can_track = (new_config->conn_state & bgp_csCanTrack) == bgp_csCanTrack ;
  acceptor = session->acceptor ;
  if (acceptor == NULL)
    {
      if (!can_track)
        return ;                /* no point creating acceptor ! */

      acceptor = bgp_acceptor_new(session) ;
    } ;

  set_new = false ;

  /* If the acceptor is currently running, we may need to change that.
   */
  if (acceptor->state != bacs_unset)
    {
      bgp_cops cops ;
      bool  unset, new_passw, drop ;

      cops = acceptor->cops ;
      qassert(cops != NULL) ;
      qassert((cops->conn_state & bgp_csCanTrack) == bgp_csCanTrack) ;

      unset     = !can_track || (cops->port != new_config->port)
                             || !sockunion_same(acceptor->su_password,
                                                       &new_config->su_remote) ;

      new_passw = !strsame(cops->password, new_config->password) ;

      drop      =   (cops->ttl  != new_config->ttl)
                 || (cops->gtsm != new_config->gtsm) ;

      set_new = (unset || new_passw || drop) ;

      if (set_new)
        {
          /* If we have a current acceptor running, then something has changed,
           * configuration-wise, so any current accepted connection must
           * be dropped, and then the listener may need to be unset or a new
           * password set.
           *
           * It's possible that is because the peer is now shutdown or
           * deconfigured, but since this connection is being snuffed out
           * early in its sad little existence, we just say config-change.
           */
          bgp_acceptor_reset(acceptor, BGP_NOMS_C_CONFIG) ;
          qassert(acceptor->state == bacs_listening) ;

          if      (unset)
            {
              /* Note that unsetting and setting again implicitly updates the
               * password (if any).
               */
              bgp_listen_unset(acceptor->su_password, cops) ;
              acceptor->state = bacs_unset ;    /* implicitly   */
            }
          else if (new_passw)
            {
              /* Not reset, so need to implement the new password directly.
               *
               * Updates su_password, below.
               */
              bgp_listen_set_password(new_config) ;
            } ;
        }
      else
        {
          /* We have a current acceptor running, and if anything in the
           * configuration has changed, then it does not affect any currently
           * tracked connection.
           *
           * We copy across:
           *
           *   * conn_state             -- for completeness
           *
           *   * can_notify_before_open -- can change at any time
           *
           *   * accept_retry_secs      -- change affects the next timer
           *   * open_hold_secs         -- change affects connection
           *
           * but otherwise do nothing at all.
           */
          cops->conn_state             = new_config->conn_state ;
          cops->can_notify_before_open = new_config->can_notify_before_open ;
          cops->accept_retry_secs      = new_config->accept_retry_secs ;
          cops->open_hold_secs         = new_config->open_hold_secs ;
        } ;
    } ;

  /* If we are (still or now) bacs_unset, and can_track, then we need to fire
   * up the acceptor (again).
   */
  if (can_track && (acceptor->state == bacs_unset))
    {
      set_new = bgp_listen_set(new_config) ;

      if (set_new)
        acceptor->state = bacs_listening ;
      else
        acceptor->cops  = bgp_cops_free(acceptor->cops) ;
    } ;

  /* Keep the su_password up to date.
   */
  if      ((acceptor->state == bacs_unset) || (new_config->password[0] == '\0'))
    acceptor->su_password = sockunion_free(acceptor->su_password) ;
  else if (set_new)
    acceptor->su_password = sockunion_copy(acceptor->su_password,
                                                       &new_config->su_remote) ;

  /* If we (still) have a running acceptor, update the cops if required.
   */
  if (set_new)
    {
      qassert(acceptor->state == bacs_listening) ;

      bgp_cops_copy(acceptor->cops, new_config) ;
      bgp_acceptor_cops_reset(acceptor) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Deal with a newly minted in-coming connection.
 *
 * By the time we get here, we are dealing with a configured peer, which we
 * assume is friendly, if not thoroughly competent.  The use of MD5 and
 * such should be used to avoid bad-people impersonating known peers.
 *
 * There are here some delaying tactics:
 *
 *   * if the previous connection was closed because an outbound connection
 *     reached fsEstablished, then we will be set to bacs_idle, and will
 *     blank (reject) in-coming connections for a while.
 *
 *   * where something goes wrong with a connection at this end, we delay
 *     sending any NOTIFICATION and closing the connection, in the hope/
 *     expectation that the other end will not close the connection before we
 *     do, and will not open another connection before closing the previous
 *     one.
 *
 *     This allows us to place a small limit on how quickly incoming
 *     connections arrive, if we have some persistent problem at this end.
 *     (The other end ought to back-off with increasing IdleHoldTime... but
 *     if they don't, we have this plan B.)
 *
 *   * where the peer sends something it shouldn't, we also delay the close
 *     and NOTIFICATION... for rather longer.
 *
 * We cannot afford to hang on to multiple incoming connections -- using up
 * file handles.  We assume that the far end will not be vexatious and open
 * many outbound connections at the same time, or rapidly open and close
 * connections -- but if it does, there is not much we can do about it, except
 * close the previous one as quickly as possible.
 */
extern void
bgp_acceptor_accept(bgp_acceptor acceptor, int sock_fd, bool ok,
                                                            sockunion_c sock_su)
{
  bgp_cops cops_config, cops ;

  qassert( (sock_fd >= 0) && (acceptor != NULL)
                          && (acceptor->state != bacs_unset) ) ;

  /* There should be consensus about the address of the peer !
   *
   * This BOUND to be OK... but if not, best not to go any further !
   */
  cops_config = acceptor->session->cops_config ;
  cops        = acceptor->cops ;

  if (ok && !sockunion_same(&cops_config->su_remote, sock_su))
    {
      plog_err(acceptor->lox.log, "[FSM] BGP accept() for %s"
                                " -- accept gave address %s ?? (expected %s)",
            acceptor->lox.name, sutoa(sock_su).str,
                                sutoa(&cops_config->su_remote).str) ;
      ok = false ;
    } ;

  if (ok && !sockunion_same(&cops->su_remote, sock_su))
    {
      plog_err(acceptor->lox.log, "[FSM] BGP accept() for %s"
                       " -- accept gave address %s but getpeername() gave %s",
           acceptor->lox.name, sutoa(sock_su).str,
                               sutoa(&cops->su_remote).str) ;
      ok = false ;
    } ;

  /* If we cannot accept the connection, now is the time to say so.
   */
  if ((cops->conn_state & bgp_csCanTrack) != bgp_csCanTrack)
    {
      if (BGP_DEBUG(fsm, FSM))
        plog_debug(acceptor->lox.log, "[FSM] BGP accept() rejected %s"
                            " -- peer not (currently) prepared to accept()",
                                                         acceptor->lox.name) ;
      ok = false ;
    } ;

  /* Decide how to proceed, on the basis of the current state.
   */
  switch (acceptor->state)
    {
      /* Unknown or unexpected state -- reject connection.
       */
      default:
      case bacs_unset:
        qassert(false) ;

        bgp_acceptor_do_close(sock_fd, NULL) ;
        break ;

      /* bacs_idle => waiting for short pause after out-bound connection
       *              became established.
       *
       * No current connection, no pending close (any more), no pending open,
       * timer running.
       *
       * We reject the connection, either when another one arrives, or when
       * the short pause expires, and we leave bacs_idle.
       *
       * Have already cleared away any previous pending close, so now we set
       * the new connection straight into pending close state.
       *
       * We don't much care at this stage whether is OK or not.
       *
       * NB: leaves the time running.
       */
      case bacs_idle:
        bgp_acceptor_actual_close(acceptor) ;   /* if any       */

        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  < fd_first) ;
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;
        qassert(acceptor->timer != NULL) ;

        bgp_acceptor_pending_close(acceptor, sock_fd, 0 /* leave timer */,
                          bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;
        break ;

      /* bacs_listening => waiting for an in-bound connection -- hurrah !
       *
       * No current connection, no pending close, no timer running.
       *
       * If the connection is OK, set it and proceed to open_awaited.
       *
       * If the connection is not OK, reject it immediately, but proceed to
       * bacs_paused with a time-out, so that will not respond again for a
       * while.
       */
      case bacs_listening:
        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  < fd_first) ;
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;
        qassert(acceptor->timer == NULL) ;

        if (ok)
          bgp_acceptor_set_open_awaited(acceptor, sock_fd) ;
        else
          {
            bgp_acceptor_do_close(sock_fd,
                          bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_REJECTED)) ;
            bgp_acceptor_set_timer(acceptor, 10) ;
            acceptor->state = bacs_paused ;
          } ;

        break ;

      /* bacs_paused        => waiting for short pause after a previous
       *                       connection was closed by a new in-coming one.
       *
       * Can be in any of the three bacp_xxx states.
       *
       * No current connection, timer is running.
       *
       * Close any close pending or open pending, now.  If new connection is
       * OK, set it as the open pending, otherwise reject it.
       *
       * NB: the timer continues to run.
       */
      case bacs_paused:
        qassert(acceptor->timer != NULL) ;
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;

        switch (acceptor->pending)
          {
            default:
              qassert(false) ;
              fall_through ;

            case bacp_none:
              break ;

            case bacp_close:
              bgp_acceptor_actual_close(acceptor) ;
              break ;

            case bacp_open:
              qassert(acceptor->sock_fd_pending >= 0) ;

              bgp_acceptor_do_close(acceptor->sock_fd_pending,
                         bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_COLLISION)) ;

              acceptor->sock_fd_pending = fd_undef ;
              acceptor->pending = bacp_none ;
              break ;
          } ;

        qassert(acceptor->pending = bacp_none) ;
        qassert(acceptor->sock_fd_pending < 0) ;

        if (ok)
          {
            acceptor->pending = bacp_open ;
            acceptor->sock_fd_pending = sock_fd ;
          }
        else
          {
            bgp_acceptor_pending_close(acceptor, sock_fd, 0 /* leave timer */,
                          bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_REJECTED)) ;
          } ;

        break ;

      /* bacs_open_awaited  => waiting for an OPEN
       * bacs_open_received => received OPEN, waiting for FSM to pick up
       * bacs_busted        => failed, but waiting for message to complete
       *
       * In all these cases we have a current connection.
       *
       * No close pending, no open pending, timer running.
       *
       * We treat the in-coming connection as a collision, and:
       *
       *   * push the current connection into a pending close.
       *
       *   * we then set up the new current connection, but do not start it,
       *     and wait for the new time-out.
       *
       *   * fall back to, or stay in bacs_paused.
       *
       * NB: this sets a new close pending time-out.
       */
      case bacs_open_awaited:
      case bacs_open_received:
      case bacs_busted:
        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  <  fd_first) ;
        qassert(qfile_fd_get(acceptor->qf) >= fd_first) ;
        qassert(acceptor->timer != NULL) ;

        bgp_acceptor_close_current(acceptor, 0 /* now */,
                        bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_COLLISION)) ;

        if (ok)
          {
            acceptor->pending = bacp_open ;
            acceptor->sock_fd_pending = sock_fd ;
          }
        else
          {
            bgp_acceptor_do_close(sock_fd,
                          bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_REJECTED)) ;
          } ;

        bgp_acceptor_set_timer(acceptor, 10) ;
        acceptor->state = bacs_paused ;
        break ;
   } ;
} ;

/*------------------------------------------------------------------------------
 * Set the acceptor into bacs_open_awaited, telling the FSM the good news.
 *
 * At this point the qfile has been set, but not yet read-enabled.
 */
static void
bgp_acceptor_set_open_awaited(bgp_acceptor acceptor, int sock_fd)
{
  /* Tidy up the acceptor->pending etc -- useful for bacs_paused.
   */
  if    (acceptor->pending == bacp_open)
    qassert(sock_fd == acceptor->sock_fd_pending) ;
  else
    qassert((acceptor->pending == bacp_none)
                                           && (acceptor->sock_fd_pending < 0)) ;

  acceptor->pending         = bacp_none ;
  acceptor->sock_fd_pending = fd_undef ;

  /* Set up the qfile and reader and set read-ready.
   */
  qassert(qfile_fd_get(acceptor->qf) < fd_first) ;
  qassert(sock_fd >= fd_first) ;

  acceptor->qf = qfile_init_new(acceptor->qf, NULL) ;
  qps_add_qfile(be_nexus->selection, acceptor->qf, sock_fd, acceptor) ;

  acceptor->reader = bgp_msg_reader_reset_new(acceptor->reader,
                                                               &acceptor->lox) ;
  qfile_enable_mode(acceptor->qf, qps_read_mnum, bgp_acceptor_read_action) ;

  /* Set the timer and change state
   */
  bgp_acceptor_set_timer(acceptor, acceptor->cops->accept_retry_secs) ;

  acceptor->state = bacs_open_awaited ;

  /* Finally: tell any FSM the good news.
   */
  bgp_fsm_accept_event(acceptor->session, bgp_feAccepted) ;
} ;

/*------------------------------------------------------------------------------
 * Set a pending close with NOTIFICATION
 *
 * If when == 0, leaves the timer running, otherwise sets the given time.
 *
 * NB: does not change state.
 */
static void
bgp_acceptor_pending_close(bgp_acceptor acceptor, int sock_fd, uint when,
                                                                  bgp_note note)
{
  if (acceptor->sock_fd_pending >= 0)   /* belt and braces      */
    bgp_acceptor_actual_close(acceptor) ;

  bgp_note_free(acceptor->note) ;       /* make sure            */

  if (sock_fd >= 0)
    {
      /* This is what we expect
       */
      acceptor->pending         = bacp_close ;
      acceptor->sock_fd_pending = sock_fd ;
      acceptor->note            = note ;
    }
  else
    {
      /* This should not happen -- but if it does, we don't need the
       * note (if any)
       */
      acceptor->pending = bacp_none ;
      acceptor->note    = bgp_note_free(note) ;
    } ;

  if (when != 0)
    bgp_acceptor_set_timer(acceptor, when) ;
} ;

/*------------------------------------------------------------------------------
 * Close the current connection, with NOTIFICATION (if any), now or pending
 *
 * If when == 0, closes the connection now, but leaves any timer running.
 *
 * If when != 0, sets the close pending and the timer to the given value.
 *
 * Must be in one of these states:
 *
 *   * bacs_open_awaited
 *   * bacs_open_received
 *   * bacs_busted
 *
 * And cannot have a close pending !
 *
 * NB: does not change state.
 */
static void
bgp_acceptor_close_current(bgp_acceptor acceptor, uint when, bgp_note note)
{
  int sock_fd ;

  qassert( (acceptor->state == bacs_open_awaited) ||
           (acceptor->state == bacs_open_received) ||
           (acceptor->state == bacs_busted) ) ;
  qassert(acceptor->pending == bacp_none) ;
  qassert(acceptor->sock_fd_pending  < 0) ;

  qps_remove_qfile(acceptor->qf) ;
  sock_fd = qfile_fd_unset(acceptor->qf) ;

  if (when == 0)
    bgp_acceptor_do_close(sock_fd, note) ;
  else
    bgp_acceptor_pending_close(acceptor, sock_fd, when, note) ;
} ;

/*------------------------------------------------------------------------------
 * Set acceptor->timer going with given interval -- create timer if required
 */
static void
bgp_acceptor_set_timer(bgp_acceptor acceptor, uint secs)
{
  acceptor->timer = qtimer_init_new(acceptor->timer,
                                              be_nexus->pile, NULL, acceptor) ;
  qtimer_set_interval(acceptor->timer, QTIME(secs), bgp_acceptor_time_out) ;
} ;

/*------------------------------------------------------------------------------
 * Stop acceptor->timer and free it, if any
 */
static void
bgp_acceptor_stop_timer(bgp_acceptor acceptor)
{
  acceptor->timer = qtimer_free(acceptor->timer) ;
} ;

/*------------------------------------------------------------------------------
 * Whatever we were waiting for, the time has come.
 */
static void
bgp_acceptor_time_out(qtimer qtr, void* timer_info, qtime_mono_t when)
{
  bgp_acceptor acceptor ;

  acceptor = timer_info ;
  qassert(qtr == acceptor->timer) ;

  switch (acceptor->state)
    {
      /* bacs_unset => not doing anything -- no idea why timer was running
       *
       * unknown state... likewise
       */
      case bacs_unset:
      default:
        qassert(false) ;
        break ;

      /* bacs_idle  => waiting for short pause after session was established.
       *               if have close pending, complete it.
       *               change up to bacs_listening.
       *
       * No current connection or pending open in bacs_idle.
       */
      case bacs_idle:
        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  < fd_first) ;
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;

        bgp_acceptor_actual_close(acceptor) ;   /* if any       */
        acceptor->state = bacs_listening ;      /* change up    */
        break ;

      /* bacs_listening => timer not relevant -- no idea why timer was running
       *
       * No pending close, no current connection, no timer while bacs_listening.
       */
      case bacs_listening:
        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  < 0) ;
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;
        qassert(false) ;
        break ;

      /* bacs_paused => either: waiting to complete a pending close...
       *                        ... which now do and proceed to bacs_listening.
       *                    or: waiting after a bad connection, which we
       *                        immediately closed...
       *                        ... so can now proceed to bacs_listening
       *                    or: have an incoming connection ready but paused
       *                        waiting for a previous close timer to expire...
       *                        ... change up to bacs_open_awaited.
       *
       * So... if there is any pending close, we do that, then if there is
       * a pending current connection, we do that too.
       */
      case bacs_paused:
        qassert(qfile_fd_get(acceptor->qf) < fd_first) ;

        switch (acceptor->pending)
          {
            default:
              qassert(false) ;
              fall_through ;

            case bacp_none:
              qassert(acceptor->sock_fd_pending  < 0) ;
              fall_through ;

            case bacp_close:
              bgp_acceptor_actual_close(acceptor) ;     /* if any       */
              acceptor->state = bacs_listening ;        /* change down  */
              break ;

            case bacp_open:
              qassert(acceptor->sock_fd_pending >= 0) ;

              bgp_acceptor_set_open_awaited(acceptor,
                         acceptor->sock_fd_pending) ;  /* change up    */
              break ;
          } ;
        break ;

      /* bacs_open_awaited
       * bacs_open_received => have an incoming connection in progress...
       *
       * bacs_busted        => have an incoming connection which has failed on
       *                       some incomplete message, which we are hoping
       *                       will complete...
       *
       *                    ...but that has now timed out.
       *                       close the current connection immediately,
       *                       and fall back to bacs_listening.
       *
       * Have current connection, but no pending close or open in any of these
       * states.
       */
      case bacs_open_awaited:
      case bacs_open_received:
      case bacs_busted:
        qassert(acceptor->pending == bacp_none) ;
        qassert(acceptor->sock_fd_pending  < 0) ;

        bgp_acceptor_close_current(acceptor, 0 /* now */,
                          bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC)) ;

        acceptor->state = bacs_listening ;      /* change down  */
        break ;
   } ;

  if (!qtimer_is_active(qtr))
    bgp_acceptor_stop_timer(acceptor) ;
} ;

/*------------------------------------------------------------------------------
 * Do pending close (if any) with NOTIFICATION (if any).
 *
 * NB: does not unset the timer and does not change state.
 */
static void
bgp_acceptor_actual_close(bgp_acceptor acceptor)
{
  if (acceptor->pending == bacp_close)
    {
      qassert(acceptor->sock_fd_pending >= 0) ;

      bgp_acceptor_do_close(acceptor->sock_fd_pending, acceptor->note) ;

      acceptor->pending         = bacp_none ;
      acceptor->sock_fd_pending = fd_undef ;
      acceptor->note    = NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Do an actual close (if any) with NOTIFICATION (if any).
 *
 * NB: does not unset the timer.
 */
static void
bgp_acceptor_do_close(int sock_fd, bgp_note note)
{
  if (sock_fd >= 0)
    {
      if (note != NULL)
        bgp_note_put(sock_fd, note) ;

      close(sock_fd) ;
    } ;

  bgp_note_free(note) ;
} ;

/*------------------------------------------------------------------------------
 * Check state of acceptor -- in particular whether can be co-opted.
 *
 * Returns:  bgp_feNULL       -- nothing doing
 *           bgp_feAccepted   -- waiting for OPEN
 *           bgp_feAcceptOPEN -- OPEN has arrived already
 */
extern bgp_fsm_event_t
bgp_acceptor_state(bgp_acceptor acceptor)
{
  switch (acceptor->state)
    {
    case bacs_open_awaited:
      return bgp_feAccepted ;

    case bacs_open_received:
      return bgp_feAcceptOPEN ;

    default:
      return bgp_feNULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Co-opt the current acceptor reader and such, if possible.
 *
 * Returns:  true <=> successfully co-opted
 *
 * NB: it is the caller's responsibility to ensure that the existing
 *     connection->reader and connection->qf are surplus to requirements.
 */
static bool
bgp_acceptor_co_opt(bgp_connection connection)
{
  bgp_acceptor acceptor ;

  acceptor = connection->session->acceptor ;

  if ( (acceptor->state != bacs_open_awaited) &&
       (acceptor->state != bacs_open_received) )
    return false ;

  /* Co-opt now already.
   *
   * Discard any previous connection->reader and qf.
   */
  bgp_msg_reader_free(connection->reader) ;
  qfile_free(connection->qf) ;

  /* Transfer qfile and reader and change it's plox.  Also transfer cops.
   *
   * Note that we deliver the qfile all modes disabled, caller will want to
   * set new action functions.
   */
  qfile_disable_modes(acceptor->qf, qps_write_mbit | qps_read_mbit) ;

  connection->reader       = acceptor->reader ;
  connection->qf           = acceptor->qf ;
  qfile_info_set(connection->qf, connection) ;

  connection->reader->plox = &connection->lox ;

  connection->cops         = bgp_cops_copy(connection->cops, acceptor->cops) ;
  acceptor->reader = NULL ;
  acceptor->qf     = NULL ;

  /* Push acceptor down to bacs_listening -- unsetting the timer.
   *
   * We don't have to worry about close pending, because there can be no close
   * pending in bacs_open_awaited/_received.
   */
  qassert(acceptor->pending = bacp_none) ;
  qassert(acceptor->sock_fd_pending < 0) ;

  bgp_acceptor_reset(acceptor, BGP_NOMS_UNSPECIFIC) ;

  return true ;                 /* done !       */
} ;

/*------------------------------------------------------------------------------
 * Squelch acceptor -- primary connection has just established.
 *
 * Resets the acceptor as BGP_NOMS_C_COLLISION, and then sets bacs_idle for
 * 10 seconds.
 */
extern void
bgp_acceptor_squelch(bgp_acceptor acceptor)
{
   bgp_acceptor_reset(acceptor, BGP_NOMS_C_COLLISION) ;

   bgp_acceptor_set_timer(acceptor, 10) ;
   acceptor->state = bacs_idle ;
} ;

/*------------------------------------------------------------------------------
 * Read Action for BGP acceptor
 */
static void
bgp_acceptor_read_action(qfile qf, void* file_info)
{
  bgp_acceptor   acceptor ;
  bgp_msg_reader reader ;
  bgp_note       note ;
  bool           done ;
  bool           stop ;

  acceptor = file_info ;
  assert(qf == acceptor->qf) ;

  /* Get and process message(s).
   */
  reader = acceptor->reader ;

  bgp_msg_read_raw(reader, qf) ;

  stop  = false ;               /* not yet      */
  done  = false ;               /* ditto        */
  note  = NULL ;                /* ditto        */

  while (!done)
    {
      bgp_fsm_event_t fsm_event ;

      /* Deal with the (new) state of the reader, generate an fsm_event and/or
       * change state.
       */
      fsm_event = bgp_feNULL ;          /* default      */

      switch (reader->msg_state)
        {
          /* Nothing more to be done if we are waiting for a header to be
           * completed => we are waiting for the initial OPEN, or for a
           * subsequent message header.
           */
          case bms_await_header:
            break ;

          /* If we are bms_partial, then we have at least the header for a
           * message -- and the header is valid.
           *
           * If we are bms_complete, then we have a complete message in
           * our hands -- but we may have more than that.
           */
          case bms_partial:
          case bms_complete:
            switch (acceptor->state)
              {
                /* Waiting for a complete OPEN, or anything else.
                 *
                 * If the partial message is not an OPEN, then we give up right
                 * now.
                 */
                case bacs_open_awaited:
                  if (reader->msg_qtype == qBGP_MSG_OPEN)
                    {
                      /* We have at least the start of an OPEN.
                       *
                       * Don't change state until we have all of it.
                       */
                      if (reader->msg_state == bms_complete)
                        {
                          /* We have a complete OPEN -- which we will signal
                           * to the FSM, before looping back to worry about
                           * whether something follows the OPEN.
                           */
                          if (BGP_DEBUG (io, IO_IN))
                            bgp_msg_read_log(reader) ;

                          acceptor->state = bacs_open_received ;
                          fsm_event       = bgp_feAcceptOPEN ;
                        } ;
                    }
                  else
                    {
                      /* We have something other than an OPEN.
                       *
                       * Even if the message is incomplete, we now change state
                       * to 'bust', and will loop back to see whether the
                       * message is complete.
                       */
                      fsm_event       = bgp_feIO ;
                      acceptor->state = bacs_busted ;

                      bgp_acceptor_set_timer(acceptor, 10) ;
                    } ;

                  break ;

                /* We have already received an OPEN, so all is well unless
                 * something else also arrives.
                 */
                case bacs_open_received:
                  qassert(reader->msg_qtype == qBGP_MSG_OPEN) ;

                  if (reader->in_hand > reader->msg_body_length)
                    {
                      /* Something has arrived after the OPEN :-(
                       *
                       * Throw away the OPEN.  Then, even if the next message
                       * is incomplete, we now change state to 'bust', and will
                       * loop back to see whether the message is complete.
                       */
                      qassert(reader->msg_state == bms_complete) ;

                      bgp_msg_read_done(reader) ;

                      fsm_event       = bgp_feIO ;
                      acceptor->state = bacs_busted ;

                      bgp_acceptor_set_timer(acceptor, 10) ;
                    } ;

                  break ;

                /* We are already bust, but we are waiting for the current
                 * message to complete or for timer.
                 *
                 * If the message is now complete, we can log the issue.
                 *
                 * In general we expect the message that broke things to
                 * arrive in short order... but we will wait a short while.
                 * When the message does complete, we can log it, if required,
                 * and we then do a delayed close in the usual way.
                 *
                 * If the buffer fills or the message does not complete, the
                 * time-out will fall on us and close things immediately.
                 */
                case bacs_busted:
                  if (reader->msg_awaited != 0)
                    break ;             /* incomplete           */

                  if (BGP_DEBUG (io, IO_IN))
                    bgp_msg_read_log(reader) ;

                  if (reader->msg_qtype == qBGP_MSG_NOTIFICATION)
                    fsm_event = bgp_feNotifyMsg ;
                  else
                    fsm_event = bgp_feUnexpected ;

                  break ;

                /* Invalid states while reading !!
                 */
                default:
                  fsm_event = bgp_feInvalid ;
                  break ;
              } ;
            break ;

          /* Down already... stay down.
           */
          case bms_fail_down:
            qassert(false) ;
            fsm_event    = bgp_feDown ;
            break ;

          /* EOF or some failure
           *
           * Log and classify as feError or feDown.
           */
          case bms_fail_eof:
          case bms_fail_io:
            fsm_event = bgp_msg_read_failed(reader, qf) ;

            qassert( (fsm_event == bgp_feDown) ||
                     (fsm_event == bgp_feError) ) ;

            stop = true ;               /* ensure we stop       */
            break ;

          /* Don't like the look of the message !
           *
           * Log and create note and classify as bgp_feBGPHeaderErr.
           */
          case bms_fail_bad_length:
          case bms_fail_bad_marker:
          case bms_complete_too_short:
          case bms_complete_too_long:
            note = bgp_msg_read_bad(reader, qf) ;
            fsm_event    = bgp_feBGPHeaderErr ;
            break ;

          /* No idea what is going on here -- give up.
           */
          default:
            qassert(false) ;

            fsm_event    = bgp_feInvalid ;
            break ;
        } ;

      /* Now deal with the event we have identified -- if any.
       */
      switch (fsm_event)
        {
          /* Nothing more to be done -- though there may be a notification
           * set, which will stop everything.
           */
          case bgp_feNULL:
            done = true ;
            break ;

          /* Nothing more required, but need to reassess things after a state
           * change in the acceptor.
           */
          case bgp_feIO:
            break ;

          /* Have just seen an OPEN message complete.
           *
           * Note that we proceed with notify == NULL and done == false, so
           * loops back to check that there is nothing after the OPEN.
           */
          case bgp_feAcceptOPEN:
            qassert(acceptor->state == bacs_open_received) ;

            bgp_fsm_accept_event(acceptor->session, bgp_feAcceptOPEN) ;
            break ;

          /* Have just received a NOTIFICATION -- before or after the expected
           * OPEN -- so we are done and must stop!
           *
           * Or, the connection has failed or been closed by the far end.
           */
          case bgp_feNotifyMsg:
          case bgp_feDown:
          case bgp_feError:
            stop = true ;
            break ;

          /* We have an unexpected message
           *
           * TODO ... logging
           */
          case bgp_feUnexpected:
            note = bgp_note_new(BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC) ;
            break ;

          /* Something has gone wrong... so give up, now
           *
           * TODO ... logging.
           */
          case bgp_feInvalid:
            note = bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
            break ;

          /* For everything else, we stop !
           *
           * If not already established that, then we just cease/unspecified.
           *
           * NB: this includes expected and unexpected cases.
           */
          default:
            if (!stop && (note == NULL))
              note = bgp_note_new(BGP_NOMC_CEASE,
                                                          BGP_NOMS_UNSPECIFIC) ;
            break ;
        } ;

      /* Now, if we need to stop, do so, with or without NOTIFICATION.
       *
       * Drops to bacs_paused.
       */
      if (stop || (note != NULL))
        {
          bgp_acceptor_close_current(acceptor, 10 /* not now */, note) ;
          acceptor->state = bacs_paused ;
          done = true ;
        } ;
    } ;
} ;

