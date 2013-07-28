/* BGP Open State -- functions
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

#include "zebra.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_open_state.h"

#include "lib/memory.h"

/*==============================================================================
 * BGP Open State.
 *
 * This structure encapsulates all the information that may be sent/received
 * in a BGP OPEN Message.
 *
 */

/*------------------------------------------------------------------------------
 * Initialise new bgp_open_state structure -- allocate if required.
 *
 * If does not allocate, assumes never been kissed.
 *
 * Returns:  a bgp_open_state object which has been zeroized vectors set empty.
 *
 * Zeroizing sets:
 *
 *   * my_as                -- BGP_ASN_NULL
 *   * my_as2               -- BGP_ASN_NULL
 *   * bgp_id               -- 0
 *
 *   * args                 -- see bgp_session_args_init_new() below
 *
 *   * afi_safi             -- empty vector -- embedded
 *   * unknowns             -- empty vector -- embedded
 */
extern bgp_open_state
bgp_open_state_init_new(bgp_open_state state)
{
  if (state == NULL)
    state = XCALLOC(MTYPE_BGP_OPEN_STATE, sizeof(bgp_open_state_t)) ;
  else
    memset(state, 0, sizeof(bgp_open_state_t)) ;

  confirm(BGP_ASN_NULL == 0) ;
  confirm(sizeof(state->afi_safi) == sizeof(vector_t)) ;    /* embedded */
  confirm(sizeof(state->unknowns) == sizeof(vector_t)) ;    /* embedded */
  confirm(VECTOR_INIT_ALL_ZEROS) ;

  state->args = bgp_session_args_init_new(NULL) ;

  return state ;
} ;

/*------------------------------------------------------------------------------
 * Reset bgp_open_state structure -- allocate if required.
 *
 * If structure already exists
 *
 * Returns:  existing or new structure which has been reset.
 *
 * Sets:
 *
 *   * my_as                -- BGP_ASN_NULL
 *   * my_as2               -- BGP_ASN_NULL
 *   * bgp_id               -- 0
 *
 *   * args                 -- see bgp_session_args_reset() below
 *
 *   * afi_safi             -- empty vector
 *   * unknowns             -- empty vector
 */
extern bgp_open_state
bgp_open_state_reset(bgp_open_state state)
{
  if (state == NULL)
    return bgp_open_state_init_new(NULL) ;

  state->my_as    = BGP_ASN_NULL ;
  state->my_as2   = BGP_ASN_NULL ;
  state->bgp_id   = 0 ;

  state->args     = bgp_session_args_reset(state->args) ;

  vector_clear(state->afi_safi, 0) ;
  vector_clear(state->unknowns, 0) ;

  return state ;
} ;

/*------------------------------------------------------------------------------
 * Free bgp_open_state structure (if any)
 *
 * Returns NULL.
 */
extern bgp_open_state
bgp_open_state_free(bgp_open_state state)
{
  if (state != NULL)
    {
      bgp_cap_afi_safi  afi_safi ;
      bgp_cap_unknown   unknown ;

      state->args = bgp_session_args_free(state->args) ;

      while ((afi_safi = vector_ream(state->afi_safi, keep_it)) != NULL)
        XFREE(MTYPE_BGP_OPEN_STATE, afi_safi) ;

      while ((unknown = vector_ream(state->unknowns, keep_it)) != NULL)
        XFREE(MTYPE_BGP_OPEN_STATE, unknown) ;

      XFREE(MTYPE_BGP_OPEN_STATE, state) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Initialise new set of session arguments -- allocate if required.
 *
 * If does not allocate, assumes never been kissed.
 */
extern bgp_session_args
bgp_session_args_init_new(bgp_session_args args)
{
  if (args == NULL)
    args = XCALLOC(MTYPE_BGP_SESSION_ARGS, sizeof(bgp_session_args_t)) ;
  else
    memset(args, 0, sizeof(bgp_session_args_t)) ;

  return args ;
} ;

/*------------------------------------------------------------------------------
 * Unset a set of session arguments.
 *
 * Currently does nothing -- but if session arguments grow any pointers to
 * things, then this will take care of same.
 */
static void
bgp_session_args_unset(bgp_session_args args)
{

} ;

/*------------------------------------------------------------------------------
 * Reset a set of session arguments.
 *
 * Zeroizes everything, leaving it in the base state -- as when no capabilities
 * at all are enabled... indeed as when not capable for sending capabilities.
 *
 * The args are already initialised to zero:
 *
 *   * cap_override           -- false
 *   * cap_strict             -- false
 *
 *   * can_capability         -- false
 *   * can_mp_ext             -- false
 *   * can_as4                -- false
 *
 *   * can_af                 -- empty
 *
 *   * can_r_refresh          -- bgp_form_none
 *
 *   * gr.can                 -- false
 *   * gr.restarting          -- false
 *   * gr.restart_time        -- 0
 *   * gr.can_preserve        -- empty
 *   * gr.has_preserved       -- empty
 *
 *   * can_orf                -- bgp_form_none
 *   * can_orf_pfx[]          -- all empty
 *
 *   * can_dynamic            -- false
 *   * can_dynamic_dep        -- false
 *
 *   * holdtime_secs          -- 0
 *   * keepalive_secs         -- 0
 */
extern bgp_session_args
bgp_session_args_reset(bgp_session_args args)
{
  if (args == NULL)
    return bgp_session_args_init_new(args) ;

  bgp_session_args_unset(args) ;

  memset(args, 0, sizeof(bgp_session_args_t)) ;

  return args ;
} ;

/*------------------------------------------------------------------------------
 * Copy one set of session args to another.
 *
 * Currently pretty trivial.  But if session args grows pointers to other
 * structures, then this will take care of things.
 */
extern bgp_session_args
bgp_session_args_copy(bgp_session_args dst, bgp_session_args_c src)
{
  if (dst == NULL)
    dst = bgp_session_args_init_new(NULL) ;

  *dst = *src ;

  return dst ;
} ;

/*------------------------------------------------------------------------------
 * Free a set of session arguments -- if any
 *
 * Returns:  NULL
 */
extern bgp_session_args
bgp_session_args_free(bgp_session_args args)
{
  if (args != NULL)
    {
      bgp_session_args_unset(args) ;
      XFREE(MTYPE_BGP_SESSION_ARGS, args) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set pointer to open_state and unset source pointer
 *
 * Frees any existing open_state at the destination.
 *
 * NB: responsibility for the open_state structure passes to the destination.
 */
extern bgp_open_state
bgp_open_state_set_mov(bgp_open_state dst, bgp_open_state* p_src)
{
  if (dst == NULL)
    dst  = *p_src ;
  else
    *dst = **p_src ;

  *p_src = NULL ;

  return dst ;
} ;

/*==============================================================================
 * Construction of bgp_open_state for sending OPEN message
 */

#if 0
/*------------------------------------------------------------------------------
 * Construct new bgp_open_state for the given peer -- allocate if required.
 *
 * Initialises the structure according to the current peer state.
 *
 * Sets: peer->cap         -- to what we intend to advertise, clearing
 *                            all the received state.
 *       peer->af_adv     -- to what we intend to advertise
 *       peer->af_rcv     -- cleared
 *       peer->af_use     -- cleared
 *
 * NB: if is PEER_FLAG_DONT_CAPABILITY, sets what would like to advertise, if
 *     could.
 *
 *     When (if) session becomes established, then if either
 *     PEER_FLAG_DONT_CAPABILITY or
 *
 * Returns:  address of existing or new bgp_open_state, initialised as required
 */
extern bgp_open_state
bgp_peer_open_state_init_new(bgp_open_state open_send, bgp_peer peer)
{
  qafx_t  qafx ;

  /* Allocate if required.  Zeroise in any case.
   */
  open_send = bgp_open_state_init_new(open_send) ;

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
          prib->af_caps_adv = 0 ;
          prib->af_caps_rcv = 0 ;
          prib->af_caps_use = 0 ;
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
  open_send->can_capability = true ;
  open_send->can_mp_ext     = true ;
  open_send->can_af         = peer->af_enabled ;

  if (peer->flags & PEER_FLAG_DONT_CAPABILITY)
    {
      /* Turning off the sending of capabilities, as required by configuration.
       *
       * If is not also PEER_FLAG_OVERRIDE_CAPABILITY, then this means we
       * are effectively only advertising IPv4 Unicast.
       */
      open_send->can_capability = false ;
      open_send->can_mp_ext     = false ;

      if (!(peer->flags & PEER_FLAG_OVERRIDE_CAPABILITY))
        open_send->can_af &= qafx_ipv4_unicast_bit ;
    } ;

  /* Set the ASN we are peering as.
   *
   * For iBGP and Confederation peers, this will be bgp->as.
   *
   * For eBGP this will be peer->change_local_as, or bgp->confed_id or bgp->as
   * in that order.
   */
  open_send->my_as  = peer->local_as ;
  open_send->my_as2 = (peer->local_as > BGP_AS2_MAX ) ? BGP_ASN_TRANS
                                                      : peer->local_as ;

  /* Choose the appropriate hold time -- this follows the peer's configuration
   * or the default for the bgp instance.
   *
   * It is probably true already, but enforces a minimum of 3 seconds for the
   * hold time (if it is is not zero) -- per RFC4271.
   */
  open_send->holdtime = peer_get_holdtime(peer) ;

  if ((open_send->holdtime < 3) && (open_send->holdtime != 0))
    open_send->holdtime = 3 ;

  /* Choose the appropriate keepalive time -- this follows the peer's
   * configuration or the default for the bgp instance.
   *
   * It is probably true already, but enforces a maximum of holdtime / 3 for
   * the keepalive time -- noting that holdtime cannot be 1 or 2 !
   */
  open_send->keepalive = peer_get_keepalive(peer) ;

  if (open_send->keepalive > (open_send->holdtime / 3))
    open_send->keepalive = (open_send->holdtime / 3) ;

  /* Announce self as AS4 speaker if required
   */
  if (!bm->as2_speaker && open_send->can_capability)
    {
      peer->caps_adv |= PEER_CAP_AS4 ;
      open_send->can_as4 = true ;
    } ;

  /* Fill in the supported AFI/SAFI and the RFC ORF capabilities.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib   prib ;
      qafx_bit_t qb ;

      prib = peer->prib[qafx] ;

      if (prib == NULL)
        continue ;

      qb = qafx_bit(qafx) ;

      if ((open_send->can_af & qb) && (open_send->can_capability))
        {
          /* For the families we are going to advertise, see if we wish to send
           * or are prepared to receive Prefix ORF.
           *
           * At this stage we set the RFC Type -- deal with pre-RFC below.
           */
          if (prib->af_flags & PEER_AFF_ORF_PFX_SM)
            open_send->can_orf_pfx_send_rfc |= qb ;
          if (prib->af_flags & PEER_AFF_ORF_PFX_RM)
            open_send->can_orf_pfx_recv_rfc |= qb ;
        } ;
    } ;

  /* Arrange to send both RFC and pre forms of the ORF capability, as and
   * where required...
   *
   * ...sends RFC capability if wishes to send and/or is willing to receive the
   * Prefix ORF RFC Type, in at least one advertised family.
   *
   * ...sends pre-RFC capability if wishes to send and/or is willing to receive
   * the Prefix ORF pre-RFC Type, in at least one advertised family.
   */
  open_send->can_orf_pfx_send_pre = open_send->can_orf_pfx_send_rfc ;
  open_send->can_orf_pfx_recv_pre = open_send->can_orf_pfx_recv_rfc ;

  open_send->can_orf = bgp_form_none ;
  if (open_send->can_orf_pfx_send_rfc | open_send->can_orf_pfx_recv_rfc)
    open_send->can_orf |= bgp_form_rfc ;
  if (open_send->can_orf_pfx_send_pre | open_send->can_orf_pfx_recv_pre)
    open_send->can_orf |= bgp_form_pre ;

  /* Route refresh -- always advertise both forms
   */
  if (open_send->can_capability)
    {
      peer->caps_adv |= PEER_CAP_RR | PEER_CAP_RR_old ;
      open_send->can_r_refresh = bgp_form_pre | bgp_form_rfc ;
    } ;

  /* Dynamic Capabilities
   *
   * TODO: currently not supported, no how.
   */
  open_send->can_dynamic_dep = false && open_send->can_capability ;
  if (open_send->can_dynamic_dep)
    peer->caps_adv |= PEER_CAP_DYNAMIC_dep ;

  open_send->can_dynamic = false && open_send->can_capability;
  if (open_send->can_dynamic)
    peer->caps_adv |= PEER_CAP_DYNAMIC ;

  /* Graceful restart capability
   */
  if ((peer->bgp->flags & BGP_FLAG_GRACEFUL_RESTART) &&
                                                      open_send->can_capability)
    {
      peer->caps_adv |= PEER_CAP_GR ;
      open_send->can_g_restart    = true ;
      open_send->gr.restart_time  = peer->bgp->restart_time ;
    }
  else
    {
      open_send->can_g_restart    = false ;
      open_send->gr.restart_time  = 0 ;
    } ;

  /* TODO: check not has restarted and not preserving forwarding open_send (?)
   */
  open_send->gr.can_preserve    = 0 ;   /* cannot preserve forwarding     */
  open_send->gr.has_preserved   = 0 ;   /* has not preserved forwarding   */
  open_send->gr.restarting      = false ;       /* is not restarting      */

  /* After all that... if PEER_FLAG_DONT_CAPABILITY we should be advertising
   *                   nothing at all, capabilities-wise !
   */
  if (peer->flags & PEER_FLAG_DONT_CAPABILITY)
    qassert(peer->caps_adv == PEER_CAP_NONE) ;

  return open_send;
} ;
#endif

/*==============================================================================
 * Unknown capabilities handling.
 *
 */

/*------------------------------------------------------------------------------
 * Add given unknown capability and its value to the given open_state.
 */
extern void
bgp_open_state_unknown_add(bgp_open_state state, uint8_t code,
                                               void* value, bgp_size_t length)
{
  bgp_cap_unknown unknown ;

  unknown = XCALLOC(MTYPE_BGP_OPEN_STATE, sizeof(bgp_cap_unknown_t) + length) ;

  unknown->code   = code ;
  unknown->length = length ;

  if (length != 0)
    memcpy(unknown->value, value, length) ;

  vector_push_item(state->unknowns, unknown) ;
} ;

/*------------------------------------------------------------------------------
 * Get count of number of unknown capabilities in given open_state.
 */
extern int
bgp_open_state_unknown_count(bgp_open_state state)
{
  return vector_end(state->unknowns) ;
} ;

/*------------------------------------------------------------------------------
 * Get n'th unknown capability -- if exists.
 */
extern bgp_cap_unknown
bgp_open_state_unknown_cap(bgp_open_state state, unsigned index)
{
  return vector_get_item(state->unknowns, index) ;
} ;

/*==============================================================================
 * Generic afi/safi capabilities handling.
 *
 */
static int bgp_open_state_afi_safi_cmp(const cvp* pp_val, const cvp* item) ;

/*------------------------------------------------------------------------------
 * Find afi/safi capability entry in the given open_state -- create one if
 * not found.
 */
extern bgp_cap_afi_safi
bgp_open_state_afi_safi_find(bgp_open_state state, iAFI_SAFI mp)
{
  bgp_cap_afi_safi cap ;
  uint i ;
  int  r ;

  i = vector_bsearch(state->afi_safi, bgp_open_state_afi_safi_cmp, &mp, &r) ;

  if (r == 0)
    cap = vector_get_item(state->afi_safi, i) ;
  else
    {
      cap = XCALLOC(MTYPE_BGP_OPEN_STATE, sizeof(bgp_cap_afi_safi_t)) ;

      cap->qafx    = qafx_from_i(mp->afi, mp->safi) ;
      cap->mp.afi  = mp->afi ;
      cap->mp.safi = mp->safi ;

      vector_insert_item_here(state->afi_safi, i, r, cap) ;
    } ;

  return cap ;
} ;

/*------------------------------------------------------------------------------
 * Get count of number of afi/safi capabilities in given open_state.
 */
extern uint
bgp_open_state_afi_safi_count(bgp_open_state state)
{
  return vector_end(state->afi_safi) ;
} ;

/*------------------------------------------------------------------------------
 * Get i'th afi_safi capability -- if exists.
 *
 * Note that the capabilities are returned in ascending afi/safi order.
 *
 * Returns:  address of capabilities, or NULL if no i'th entry.
 */
extern bgp_cap_afi_safi
bgp_open_state_afi_safi_cap(bgp_open_state state, uint i)
{
  return vector_get_item(state->afi_safi, i) ;
} ;

/*------------------------------------------------------------------------------
 * Drop i'th afi_safi capability -- if exists.
 *
 * Note that the capabilities are returned in ascending afi/safi order.
 *
 * Returns:  address of capabilities, or NULL if no i'th entry.
 */
extern void
bgp_open_state_afi_safi_drop(bgp_open_state state, uint i)
{
  bgp_cap_afi_safi cap ;

  cap = vector_get_item(state->afi_safi, i) ;
  if (cap != NULL)
    {
      vector_delete(state->afi_safi, i, 1) ;
      XFREE(MTYPE_BGP_OPEN_STATE, cap) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Compare the given afi/safi (pp_val) with those
 *                                       in the given bgp_cap_afi_safi_c (item).
 */
static int
bgp_open_state_afi_safi_cmp(const cvp* pp_val, const cvp* item)
{
  iAFI_SAFI_c        mp ;
  bgp_cap_afi_safi_c cap ;

  mp  = *pp_val ;
  cap = *item ;

  if (mp->afi != cap->mp.afi)
    return (mp->afi < cap->mp.afi) ? -1 : +1 ;

  if (mp->safi != cap->mp.safi)
    return (mp->safi < cap->mp.safi) ? -1 : +1 ;

  return 0 ;
} ;

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Received an open, update the peer's state
 *
 * Takes the: peer->session->open_sent  ) these are set when the session is
 *            peer->session->open_recv  ) established, and not changed again
 *            peer->session->args       ) by the BE.
 *
 * and fills in:
 *
 *   peer->current_holdtime    ) per negotiated values
 *   peer->current_keepalive   )
 *
 *   peer->remote_id
 *
 *   peer->cap_adv          -- as *actually* advertised
 *   peer->cap_rcv          -- as received
 *   peer->cap_use          -- result
 *
 *   peer->af_adv           -- as *actually* advertised (perhaps implicitly)
 *   peer->af_rcv           -- as received (perhaps implicitly)
 *   peer->af_use           -- result
 *   peer->af_running       -- copy of af_use
 *
 * and for each configured address family
 *
 *   prib->af_caps_adv      -- as *actually* advertised
 *   prib->af_caps_rcv      -- as received
 *   prib->af_caps_use      -- result
 */
void
bgp_peer_open_state_receive(bgp_peer peer)
{
  bgp_session        session ;
  bgp_open_state_c   open_recv, open_sent ;
  bgp_session_args_c session_args, args_sent, args_recv ;
  qafx_t             qafx ;

  session      = peer->session;
  session_args = session->args ;

  open_recv    = session->open_recv ;
  args_recv    = open_recv->args ;

  open_sent    = session->open_sent ;
  args_sent    = open_sent->args ;

  /* Prepare received capabilities and those we therefore expect to use.
   *
   * We also set the advertised capabilities to what were actually advertised.
   * This should not change anything, unless we had to suppress capabilities
   * (because the far end refused).  Note:
   *
   *   * if PEER_FLAG_DONT_CAPABILITY, then we will end up with
   *     peer->caps_adv == PEER_CAP_NONE, so signal that we set out to
   *     advertise nothing.
   *
   *   * peer->caps_use will have PEER_CAP_NONE to signal that outbound
   *     capabilities were suppressed.
   *
   *     But note that some inbound capabilities will still be usable
   *     (e.g. Route Refresh).
   */
  if      (args_sent->can_capability)
    {
      peer->caps_adv  = 0 ;
      peer->caps_use  = 0 ;
    }
  else if (args_sent->cap_suppressed)
    {
      peer->caps_adv  = 0 ;
      peer->caps_use  = PEER_CAP_NONE ;
    }
  else
    {
      peer->caps_adv  = PEER_CAP_NONE ;
      peer->caps_use  = 0 ;
    } ;

  if (args_recv->can_capability)
    peer->caps_rcv = 0 ;
  else
    peer->caps_rcv = PEER_CAP_NONE ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib   prib ;
      qafx_bit_t qb ;

      prib = peer->prib[qafx] ;
      qb   = qafx_bit(qafx) ;

      qassert((prib != NULL) == (peer->af_configured & qb)) ;

      if (prib == NULL)
        continue ;

      prib->af_caps_adv = 0 ;
      prib->af_caps_rcv = 0 ;
      prib->af_caps_use = 0 ;

      prib->af_orf_pfx_adv = 0 ;
      prib->af_orf_pfx_rcv = 0 ;
      prib->af_orf_pfx_use = 0 ;
    } ;

  /* The BGP Engine sets the session's HoldTimer and KeepaliveTimer intervals
   * to the values negotiated when the OPEN messages were exchanged.
   */
  peer->current_holdtime  = session_args->holdtime_secs ;
  peer->current_keepalive = session_args->keepalive_secs ;

  /* Set remote router-id
   */
  peer->remote_id = open_recv->bgp_id;

  /* AS4
   */
  if (args_sent->can_as4)
    peer->caps_adv |= PEER_CAP_AS4 ;

  if (args_recv->can_as4)
    peer->caps_rcv |= PEER_CAP_AS4 ;

  if (session_args->can_as4)
    peer->caps_use |= PEER_CAP_AS4 ;

  /* AFI/SAFI -- as received, or assumed or overridden
   *
   * TODO is it possible that afc_use now includes stuff which has been
   *      deactivated or disabled ??
   */
  if (args_sent->can_mp_ext)
    peer->caps_adv |= PEER_CAP_MP_EXT ;

  if (args_recv->can_mp_ext)
    peer->caps_rcv |= PEER_CAP_MP_EXT ;

  if (session_args->can_mp_ext)
    peer->caps_use |= PEER_CAP_MP_EXT ;

  if (!args_recv->can_mp_ext)
    qassert(args_recv->can_af == qafx_ipv4_unicast_bit) ;

  peer->af_adv     = args_sent->can_af ;
  peer->af_rcv     = args_recv->can_af ;
  peer->af_use     = session_args->can_af ;
  peer->af_running = session_args->can_af ;

  /* Route Refresh.
   */
  if (args_sent->can_r_refresh & bgp_form_rfc)
    peer->caps_adv |= PEER_CAP_RR ;
  if (args_sent->can_r_refresh & bgp_form_pre)
    peer->caps_adv |= PEER_CAP_RR_old ;

  if (args_recv->can_r_refresh & bgp_form_rfc)
    peer->caps_rcv |= PEER_CAP_RR ;
  if (args_recv->can_r_refresh & bgp_form_pre)
    peer->caps_rcv |= PEER_CAP_RR_old ;

  if      (session_args->can_r_refresh & bgp_form_rfc)
    peer->caps_use |= PEER_CAP_RR ;
  else if (session_args->can_r_refresh & bgp_form_pre)
    peer->caps_use |= PEER_CAP_RR | PEER_CAP_RR_old ;

  /* Graceful restart
   *
   * NB: appear not to care about args_recv->restarting !
   */
  if (args_sent->gr.can)
    peer->caps_adv |= PEER_CAP_GR ;
  if (args_recv->gr.can)
    peer->caps_rcv |= PEER_CAP_GR ;
  if (session_args->gr.can)
    peer->caps_use |= PEER_CAP_GR ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib prib ;
      qafx_bit_t qb ;

      qb = qafx_bit(qafx) ;

      if (!(peer->af_configured & qb))
        continue ;

      prib = peer->prib[qafx] ;
      qassert(prib != NULL) ;

      if (qb & args_sent->gr.can_preserve)
        {
          prib->af_caps_adv |= PEER_AF_CAP_GR_CAN_PRESERVE ;
          if (qb & args_sent->gr.has_preserved)
            prib->af_caps_adv |= PEER_AF_CAP_GR_HAS_PRESERVED ;
        } ;

      if (qb & args_recv->gr.can_preserve)
        {
          prib->af_caps_rcv |= PEER_AF_CAP_GR_CAN_PRESERVE ;
          if (qb & args_recv->gr.has_preserved)
            prib->af_caps_rcv |= PEER_AF_CAP_GR_HAS_PRESERVED ;
        } ;

      if (qb & session_args->gr.can_preserve)
        {
          prib->af_caps_use |= PEER_AF_CAP_GR_CAN_PRESERVE ;
          if (qb & session_args->gr.has_preserved)
            prib->af_caps_use |= PEER_AF_CAP_GR_HAS_PRESERVED ;
        } ;
    }

  peer->v_gr_restart = args_recv->gr.restart_time;
  /* TODO: should we do anything with this? */
#if 0
  int         restarting ;            /* Restart State flag                 */
#endif
  /* ORF
   *
   * There are two Capabilities for ORF -- RFC and pre-RFC.  There are two
   * types for Prefix ORF -- also RFC and pre-RFC.  There are, therefore,
   * four possible settings for "wish to send" and "willing to receive", but
   * we rather expect that only the RFC type will be advertised by the RFC
   * capability, and only the pre-RFC type will be advertised by the pre-RFC
   * capability.  However:
   *
   *   * any setting provided by the RFC capability takes precedence over any
   *     setting provided by the pre-RFC capability.
   *
   *     The capability handling code does this, and issues suitable logging
   *     message(s) if there are any inconsistent settings.
   *
   *   * any setting provided for an RFC type takes precedence over any
   *     setting provided for a pre-RFC type.
   *
   *     We do that here, and issue suitable logging message(s) if there are
   *     inconsistent settings.
   *
   * We record exactly what we advertised and what we received.  This is
   * tedious, but improves the diagnostic and other information.
   *
   * For actual use we record whether to send or receive Prefix ORF, and if
   * we did not receive the RFC type, set pre-RFC so that we use that.  (So,
   * use RFC Type for preference.)
   */
  if (args_sent->can_orf & bgp_form_rfc)
    peer->caps_adv |= PEER_CAP_ORF ;
  if (args_sent->can_orf & bgp_form_pre)
    peer->caps_adv |= PEER_CAP_ORF_pre ;

  if (args_recv->can_orf & bgp_form_rfc)
    peer->caps_rcv |= PEER_CAP_ORF ;
  if (args_recv->can_orf & bgp_form_pre)
    peer->caps_rcv |= PEER_CAP_ORF_pre ;

  if      (session_args->can_orf & bgp_form_rfc)
    peer->caps_use |= PEER_CAP_ORF ;
  else if (session_args->can_orf & bgp_form_rfc)
    peer->caps_use |= PEER_CAP_ORF | PEER_CAP_ORF_pre ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib prib ;

      if (!(peer->af_configured & qafx_bit(qafx)))
        continue ;

      prib = peer->prib[qafx] ;
      qassert(prib != NULL) ;

      prib->af_orf_pfx_adv = args_sent->can_orf_pfx[qafx] ;
      prib->af_orf_pfx_rcv = args_recv->can_orf_pfx[qafx] ;
      prib->af_orf_pfx_use = session_args->can_orf_pfx[qafx] ;
    } ;

  /* Dynamic Capabilities -- never used !!
   */
  if (args_sent->can_dynamic)
    peer->caps_adv |= PEER_CAP_DYNAMIC ;
  if (args_sent->can_dynamic_dep)
    peer->caps_adv |= PEER_CAP_DYNAMIC_dep ;

  if (args_recv->can_dynamic)
    peer->caps_rcv |= PEER_CAP_DYNAMIC ;
  if (args_recv->can_dynamic_dep)
    peer->caps_rcv |= PEER_CAP_DYNAMIC_dep ;

  if      (session_args->can_dynamic)
    peer->caps_use |= PEER_CAP_DYNAMIC ;
  else if (session_args->can_dynamic_dep)
    peer->caps_use |= PEER_CAP_DYNAMIC | PEER_CAP_DYNAMIC_dep ;
} ;

/*==============================================================================
 * Functions for constructing various OPEN Message Capabilities
 *
 * Unpacked here so can be used when constructing an OPEN message and when
 * sending a BGP_NOMS_O_CAPABILITY Notification message
 */

/*------------------------------------------------------------------------------
 * Start Capabilities section of OPEN message.
 *
 * If 'one_option', then lay down the start of a single OPEN Option item, which
 * will contain all the Capabilities.  (The alternative, which RFC5492 says
 * SHOULD NOT be used, is to have multiple Capability Option items -- for
 * example wrapping each Capability in its own Option.)
 */
extern void
bgp_open_make_cap_option(blower sbr, blower br, bool one_option)
{
  if (one_option)
    blow_b(br, BGP_OPT_CAPS) ;

  blow_sub_init(sbr, br, (one_option ? 1 : 0), 0, 255) ;
} ;

/*------------------------------------------------------------------------------
 * End Capabilities section of OPEN message.
 *
 * If 'one_option', then:
 *
 *   * if no capabilities have, in fact, been written, discard the OPEN Option
 *     item, which was created in bgp_open_make_cap_option().
 *
 *   * otherwise, if has not overflowed, set the length of the OPEN Option.
 */
extern void
bgp_open_make_cap_end(blower br, blower sbr, bool one_option)
{
  if (one_option)
    {
      uint length ;

      length = blow_sub_end_b(br, sbr) ;
      if ((length == 0) && blow_is_ok(br))
        blow_step(br, - 2) ;    /* discard the empty capability option  */
    }
  else
    blow_sub_end(br, sbr) ;
} ;

/*------------------------------------------------------------------------------
 * Create AS4 capability.
 */
extern void
bgp_open_make_cap_as4(blower br, as_t my_as, bool wrap)
{
  blow_has_not_overrun(br) ;
  confirm(((1 + 1) + 1 + 1 + 4) < blow_buffer_safe)

  if (wrap)
    {
      blow_b(br, BGP_OPT_CAPS) ;
      blow_b(br, 2 + BGP_CAP_AS4_L) ;
    } ;

  blow_b(br, BGP_CAN_AS4);
  blow_b(br, BGP_CAP_AS4_L);
  blow_l(br, my_as) ;

  blow_has_not_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Create one BGP_CAN_MP_EXT Capability for each of the qafx in the given set.
 *
 * Do nothing if the set is empty.
 */
extern void
bgp_open_make_cap_mp_ext(blower br, qafx_set_t mp, bool wrap)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      if (mp & qafx_bit(qafx))
        {
          iAFI_t  afi  = get_iAFI(qafx) ;
          iSAFI_t safi = get_iSAFI(qafx) ;

          if (!have_ipv6 && (afi == iAFI_IP6))
            continue ;

          blow_has_not_overrun(br) ;
          confirm(((1 + 1) + 1 + 1 + 2 + 1 + 1) < blow_buffer_safe)

          if (wrap)
            {
              blow_b(br, BGP_OPT_CAPS) ;
              blow_b(br, 2 +BGP_CAP_MPE_L) ;
            } ;

          blow_b(br, BGP_CAN_MP_EXT);
          blow_b(br, BGP_CAP_MPE_L);
          blow_w(br, afi);
          blow_b(br, 0);
          blow_b(br, safi);
        } ;
    } ;

  blow_has_not_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Create Route Refresh capability or capabilities.
 */
extern void
bgp_open_make_cap_r_refresh(blower br, bgp_form_t form, bool wrap)
{
  if (form & bgp_form_pre)
    {
      blow_has_not_overrun(br) ;
      confirm(((1 + 1) + 1 + 1 ) < blow_buffer_safe)

      if (wrap)
        {
          blow_b(br, BGP_OPT_CAPS) ;
          blow_b(br, 2 + BGP_CAP_RRF_L) ;
        } ;

      blow_b(br, BGP_CAN_R_REFRESH) ;
      blow_b(br, BGP_CAP_RRF_L) ;
    } ;

  if (form & bgp_form_pre)
    {
      blow_has_not_overrun(br) ;
      confirm(((1 + 1) + 1 + 1 ) < blow_buffer_safe)

      if (wrap)
        {
          blow_b(br, BGP_OPT_CAPS) ;
          blow_b(br, 2 + BGP_CAP_RRF_L) ;
        } ;

      blow_b(br, BGP_CAN_R_REFRESH_pre) ;
      blow_b(br, BGP_CAP_RRF_L) ;
    } ;

  blow_has_not_overrun(br) ;
} ;

/*------------------------------------------------------------------------------
 * Prepare a given orf_type object -- for RFC or pre-RFC capability.
 *
 * Sets the given type of ORF.
 *
 * Then scans the given vector for any address family for which we wish to
 * advertise the given type of ORF, in the given form(s).
 *
 * If !can_mp_ext, only considers IPv4/Unicast.
 *
 * For an RFC orft will usually specify bgp_form_rfc, and for a pre-RFC orft,
 * a bgp_form_pre.
 *
 * Returns:  true <=> at least one ORF required.
 */
extern bool
bgp_open_prepare_orf_type(bgp_open_orf_type orf_type, uint8_t orft,
                          bgp_orf_cap_v modes, bgp_form_t form, bool can_mp_ext)
{
  bgp_orf_cap_bits_t want ;
  qafx_t qafx, last ;

  orf_type->type = orft ;
  orf_type->sm   = 0 ;
  orf_type->rm   = 0 ;

  want = 0 ;
  if (form & bgp_form_rfc)
    want |= ORF_SM | ORF_RM ;
  if (form & bgp_form_pre)
    want |= ORF_SM_pre | ORF_RM_pre ;

  if (can_mp_ext)
    last = qafx_last ;
  else
    last = qafx_ipv4_unicast ;

  confirm(qafx_ipv4_unicast == qafx_first) ;

  for (qafx = qafx_first ; qafx <= last ; ++qafx)
    {
      bgp_orf_cap_bits_t have ;

      have = modes[qafx] & want ;

      if (have & (ORF_SM | ORF_SM_pre))
        orf_type->sm |= qafx_bit(qafx) ;
      if (have & (ORF_RM | ORF_RM_pre))
        orf_type->rm |= qafx_bit(qafx) ; ;
    } ;

  return ((orf_type->sm | orf_type->rm) != 0) ;
} ;

/*------------------------------------------------------------------------------
 * Create Prefix ORF capability -- BGP_CAN_ORF or BGP_CAN_ORF_pre.
 *
 * Although it would appear possible for (the RFC) BGP_CAN_ORF to carry both
 * the RFC and the pre-RFC Prefix ORF types, and for BGP_CAN_ORF_pre to also
 * do so... we here send the RFC type in the RFC Capability, and the pre-RFC
 * type in the pre-RFC Capabilitity.
 *
 * Does nothing if no send or recv afi/safi.  Noting that if cannot send MP-Ext
 * will only consider IPv4/Unicast.
 */
extern void
bgp_open_make_cap_orf(blower br, uint8_t cap_code, uint count,
                        bgp_open_orf_type_t types[], bool can_mp_ext, bool wrap)
{
  uint       i ;
  qafx_set_t set ;
  qafx_t     qafx ;
  blower_t   sbr[1], cbr[1] ;

  /* Discover the set of qafx for which there is at least one type of ORF
   * which needs to be advertised for each one.
   */
  set = 0 ;
  for (i = 0 ; i < count ; ++i)
    set |= types[i].sm | types[i].rm ;

  if (!can_mp_ext)
    set &= qafx_ipv4_unicast_bit ;

  if (set == 0)
    return ;

  /* The leading part of the capability
   */
  blow_has_not_overrun(br) ;
  confirm(((1 + 1) + 1 + 1 ) < blow_buffer_safe)

  if (wrap)
    blow_b(br, BGP_OPT_CAPS) ;
  blow_sub_init(sbr, br, (wrap ? 1 : 0), 0, 255) ;

  blow_b(br, cap_code) ;       /* Capability Code              */
  blow_sub_init(cbr, sbr, 1, 0, 255) ;

  /* Now, one entry per AFI/SAFI
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      qafx_bit_t qb ;
      ptr_t numberp ;
      uint  number_of_orfs ;

      qb = qafx_bit(qafx) ;

      if (!(set & qb))
        continue ;

      blow_has_not_overrun(cbr) ;
      confirm((2 + 1 + 1 + 1) < blow_buffer_safe)

      blow_w(cbr, get_iAFI(qafx));
      blow_b(cbr, 0);
      blow_b(cbr, get_iSAFI(qafx));

      numberp = blow_ptr(cbr) ;
      blow_b(br, 0);            /* Number of ORFs       */
      number_of_orfs = 0 ;

      for (i = 0 ; i < count ; ++i)
        {
          uint8_t    mode ;

          mode = 0 ;

          if (types[i].sm & qb)
            mode |= BGP_CAP_ORFT_M_SEND ;

          if (types[i].rm & qb)
            mode |= BGP_CAP_ORFT_M_RECV ;

          confirm((BGP_CAP_ORFT_M_SEND | BGP_CAP_ORFT_M_RECV)
                                                       == BGP_CAP_ORFT_M_BOTH) ;
          if (mode == 0)
            continue ;

          blow_has_not_overrun(cbr) ;
          confirm((1 + 1) < blow_buffer_safe)

          blow_b(cbr, types[i].type) ;
          blow_b(cbr, mode) ;

          number_of_orfs++;
        } ;

      store_b(numberp, number_of_orfs) ;
    } ;

  blow_sub_end_b(sbr, cbr) ;    /* complete the capability      */

  if (wrap)
    blow_sub_end_b(br, sbr) ;   /* complete the option wrapper  */
  else
    blow_sub_end(br, sbr) ;     /* back to main blower          */
} ;

/*------------------------------------------------------------------------------
 * Create Graceful Restart capability
 */
extern void
bgp_open_make_cap_gr(blower br, bgp_session_args_gr cap_gr, bool can_mp_ext,
                                                                      bool wrap)
{
  uint16_t restart_state ;
  qafx_t   qafx, last ;
  blower_t sbr[1], cbr[1] ;

  /* The leading part of the capability
   */
  blow_has_not_overrun(br) ;
  confirm(((1 + 1) + 1 + 1 + 2) < blow_buffer_safe)

  if (wrap)
    blow_b(br, BGP_OPT_CAPS) ;
  blow_sub_init(sbr, br, (wrap ? 1 : 0), 0, 255) ;

  blow_b(br, BGP_CAN_G_RESTART) ;       /* Capability Code      */
  blow_sub_init(cbr, sbr, 1, 0, 255) ;

  if (cap_gr->restarting)
    restart_state = BGP_CAP_GR_T_R_FLAG ;
  else
    restart_state = 0 ;

  if (cap_gr->restart_time <= BGP_CAP_GR_T_MASK)
    restart_state |= cap_gr->restart_time ;
  else
    restart_state |= BGP_CAP_GR_T_MASK ;

  blow_w(cbr, restart_state);

  /* Now, one entry per AFI/SAFI for which can_preserve forwarding.
   *
   * Noting that if we cannot do NP-Ext, we can only do IPv4/Unicast
   */
  if (can_mp_ext)
    last = qafx_last ;
  else
    last = qafx_ipv4_unicast ;

  confirm(qafx_ipv4_unicast == qafx_first) ;

  for (qafx = qafx_first ; qafx <= last ; ++qafx)
    {
      qafx_bit_t qb ;

      qb = qafx_bit(qafx) ;

      if (!(cap_gr->can_preserve & qb))
        continue ;

      blow_has_not_overrun(cbr) ;
      confirm((2 + 1 + 1) < blow_buffer_safe)

      blow_w(cbr, get_iAFI(qafx));
      blow_b(cbr, get_iSAFI(qafx));

      if (cap_gr->has_preserved & qb)
        blow_b(cbr, BGP_CAP_GRE_F_FORW) ;
      else
        blow_b(cbr, 0) ;
    } ;

  blow_sub_end_b(sbr, cbr) ;    /* complete the capability      */

  if (wrap)
    blow_sub_end_b(br, sbr) ;   /* complete the option wrapper  */
  else
    blow_sub_end(br, sbr) ;     /* back to main blower          */
} ;

