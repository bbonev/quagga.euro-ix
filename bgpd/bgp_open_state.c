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

#include "misc.h"

#include "bgpd/bgp_open_state.h"
#include "bgpd/bgp_session.h"

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
 *   * args                 -- see bgp_session_args_init_new() below
 *
 *   * my_as2               -- BGP_ASN_NULL
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
 *   * args                 -- see bgp_session_args_reset() below
 *
 *   * my_as2               -- BGP_ASN_NULL
 *   * afi_safi             -- empty vector
 *   * unknowns             -- empty vector
 */
extern bgp_open_state
bgp_open_state_reset(bgp_open_state state)
{
  if (state == NULL)
    return bgp_open_state_init_new(NULL) ;

  state->args     = bgp_session_args_reset(state->args) ;

  state->my_as2   = BGP_ASN_NULL ;

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
 *   * local_as                 -- BGP_ASN_NULL
 *   * local_id                 -- 0
 *
 *   * remote_as                -- BGP_ASN_NULL
 *   * remote_id                -- 0
 *
 *   * can_capability           -- false
 *   * can_mp_ext               -- false
 *   * can_as4                  -- false
 *
 *   * cap_suppressed           -- false
 *
 *   * cap_af_override          -- false
 *   * cap_strict               -- false
 *
 *   * can_af                   -- empty
 *
 *   * can_rr                   -- bgp_form_none
 *
 *   * gr.can                   -- false
 *   * gr.restarting            -- false
 *   * gr.restart_time          -- 0
 *   * gr.can_preserve          -- empty
 *   * gr.has_preserved         -- empty
 *
 *   * can_orf                  -- bgp_form_none
 *   * can_orf_pfx[]            -- all empty
 *
 *   * can_dynamic              -- false
 *   * can_dynamic_dep          -- false
 *
 *   * holdtime_secs            -- 0
 *   * keepalive_secs           -- 0
 */
extern bgp_session_args
bgp_session_args_reset(bgp_session_args args)
{
  if (args == NULL)
    return bgp_session_args_init_new(args) ;

  bgp_session_args_unset(args) ;

  memset(args, 0, sizeof(bgp_session_args_t)) ;

  confirm(BGP_ASN_NULL == 0) ;

  return args ;
} ;

/*------------------------------------------------------------------------------
 * Suppress a set of session arguments for not sending capabilities.
 *
 * Forces:
 *
 *   * cap_strict               -- false iff !can_capability
 *
 *                                 This means that cap_strict is suppressed if
 *                                 capability negotiation is turned off by
 *                                 configuration, but not by failure of the far
 *                                 end to accept capabilities.
 *
 *   * can_af                   -- if !cap_af_override, mask qafx_ipv4_unicast
 *
 *   * can_capability           -- false
 *   * can_mp_ext               -- false
 *   * can_as4                  -- false
 *
 *   * can_rr                   -- bgp_form_none
 *
 *   * gr.can                   -- false
 *   * gr.restarting            -- false
 *   * gr.restart_time          -- 0
 *   * gr.can_preserve          -- empty
 *   * gr.has_preserved         -- empty
 *
 *   * can_orf                  -- bgp_form_none
 *   * can_orf_pfx[]            -- all empty
 *
 *   * can_dynamic              -- false
 *   * can_dynamic_dep          -- false
 *
 * But retains: cap_suppressed  -- so we know what is going on.
 *
 *              cap_af_override -- and any overridden can_af.
 *
 *              cap_strict      -- unless oriinally can_capability.
 */
extern void
bgp_session_args_suppress(bgp_session_args args)
{
  if (!args->can_capability)
    args->cap_strict     = false ;

  if (!args->cap_af_override)
    args->can_af        &= qafx_ipv4_unicast ;

  args->can_capability   = false ;
  args->can_mp_ext       = false ;
  args->can_as4          = false ;

  args->can_rr           = bgp_form_none ;

  memset(&args->gr, 0, sizeof(args->gr)) ;

  args->can_orf          = bgp_form_none ;
  memset(&args->can_orf_pfx, 0, sizeof(args->can_orf_pfx)) ;

  args->can_dynamic      = false ;
  args->can_dynamic_dep  = false ;
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
 * Duplicate a set of session args -- creating a new set
 *
 * Currently pretty trivial.  But if session args grows pointers to other
 * structures, then this will take care of things.
 */
extern bgp_session_args
bgp_session_args_dup(bgp_session_args_c src)
{
  return bgp_session_args_copy(NULL, src) ;
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

      cap->qafx      = qafx_from_i(mp->i_afi, mp->i_safi) ;
      cap->mp.i_afi  = mp->i_afi ;
      cap->mp.i_safi = mp->i_safi ;

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

  if (mp->i_afi != cap->mp.i_afi)
    return (mp->i_afi < cap->mp.i_afi) ? -1 : +1 ;

  if (mp->i_safi != cap->mp.i_safi)
    return (mp->i_safi < cap->mp.i_safi) ? -1 : +1 ;

  return 0 ;
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
  blow_overrun_check(br) ;
  confirm(((1 + 1) + 1 + 1 + 4) < blow_buffer_safe)

  if (wrap)
    {
      blow_b(br, BGP_OPT_CAPS) ;
      blow_b(br, 2 + BGP_CAP_AS4_L) ;
    } ;

  blow_b(br, BGP_CAN_AS4);
  blow_b(br, BGP_CAP_AS4_L);
  blow_l(br, my_as) ;

  blow_overrun_check(br) ;
} ;

/*------------------------------------------------------------------------------
 * Create one BGP_CAN_MP_EXT Capability for each of the qafx in the given set.
 *
 * Do nothing if the set is empty.
 */
extern void
bgp_open_make_cap_mp_ext(blower br, const qafx_set_t mp, bool wrap)
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

          blow_overrun_check(br) ;
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

  blow_overrun_check(br) ;
} ;

/*------------------------------------------------------------------------------
 * Create Route Refresh capability or capabilities.
 */
extern void
bgp_open_make_cap_r_refresh(blower br, bgp_form_t form, bool wrap)
{
  if (form & bgp_form_pre)
    {
      blow_overrun_check(br) ;
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
      blow_overrun_check(br) ;
      confirm(((1 + 1) + 1 + 1 ) < blow_buffer_safe)

      if (wrap)
        {
          blow_b(br, BGP_OPT_CAPS) ;
          blow_b(br, 2 + BGP_CAP_RRF_L) ;
        } ;

      blow_b(br, BGP_CAN_R_REFRESH_pre) ;
      blow_b(br, BGP_CAP_RRF_L) ;
    } ;

  blow_overrun_check(br) ;
} ;

/*------------------------------------------------------------------------------
 * Prepare a given orf_type object -- for RFC or pre-RFC capability.
 *
 * Sets the given type of ORF.
 *
 * Then scans the given vector for any address family for which we wish to
 * advertise the given type of ORF, in the given form(s).
 *
 * Discards anything not included in the given can_af.
 *
 * For an RFC orft will usually specify bgp_form_rfc, and for a pre-RFC orft,
 * a bgp_form_pre.
 *
 * Returns:  true <=> at least one ORF required.
 */
extern bool
bgp_open_prepare_orf_type(bgp_open_orf_type orf_type, uint8_t orft,
                         bgp_orf_caps modes, bgp_form_t form, qafx_set_t can_af)
{
  bgp_orf_cap_bits_t want ;
  qafx_t qafx ;

  orf_type->type = orft ;
  orf_type->sm   = 0 ;
  orf_type->rm   = 0 ;

  want = 0 ;
  if (form & bgp_form_rfc)
    want |= ORF_SM | ORF_RM ;
  if (form & bgp_form_pre)
    want |= ORF_SM_pre | ORF_RM_pre ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      qafx_bit_t qb ;
      bgp_orf_cap_bits_t have ;

      qb = qafx_bit(qafx) ;

      if (!(can_af & qb))
        continue ;

      have = modes->af[qafx] & want ;

      if (have & (ORF_SM | ORF_SM_pre))
        orf_type->sm |= qb ;
      if (have & (ORF_RM | ORF_RM_pre))
        orf_type->rm |= qb ; ;
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
 * Does nothing if no send or recv afi/safi -- masked down to the given can_af.
 */
extern void
bgp_open_make_cap_orf(blower br, uint8_t cap_code, uint count,
                      bgp_open_orf_type_t types[], qafx_set_t can_af, bool wrap)
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

  set &= can_af ;

  if (set == 0)
    return ;

  /* The leading part of the capability
   */
  blow_overrun_check(br) ;
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

      blow_overrun_check(cbr) ;
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

          blow_overrun_check(cbr) ;
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
bgp_open_make_cap_gr(blower br, bgp_session_args_gr cap_gr, qafx_set_t can_af,
                                                                      bool wrap)
{
  uint16_t restart_state ;
  qafx_t   qafx ;
  blower_t sbr[1], cbr[1] ;

  /* The leading part of the capability
   */
  blow_overrun_check(br) ;
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
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      qafx_bit_t qb ;

      qb = qafx_bit(qafx) ;

      if (!(cap_gr->can_preserve & qb & can_af))
        continue ;

      blow_overrun_check(cbr) ;
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

