/* BGP packet management routine.
   Copyright (C) 1999 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "network.h"
#include "prefix.h"
#include "prefix_id.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "linklist.h"
#include "ring_buffer.h"

#include "bgpd/bgpd.h"

#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_adj_out.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgp_attr.h"

#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_route_refresh.h"
#include "bgpd/bgp_names.h"
#include "bgpd/bgp_msg_write.h"

/*==============================================================================
 * Construction and output of UPDATE and other messages.
 */
static bool bgp_packet_write_announce(bgp_prib prib, ring_buffer rb,
                                                      route_out_parcel parcel) ;
static bool bgp_packet_write_withdraw(bgp_prib prib, ring_buffer rb,
                                                      route_out_parcel parcel) ;
static bool bgp_packet_write_eor(bgp_prib prib, ring_buffer rb,
                                                      route_out_parcel parcel) ;
static bool bgp_packet_write_rr(bgp_prun prun, ring_buffer rb) ;

static qstring bgp_packet_attrs_string(bgp_prib prib, route_out_parcel parcel) ;
static qstring bgp_packet_prefix_string(qstring qs_pfx, bgp_prib prib,
                                                      route_out_parcel parcel) ;
static bool bgp_packet_write_rr_orf_part(blower br, bgp_route_refresh rr,
                                               bgp_form_t form, bgp_prun prun) ;

/*------------------------------------------------------------------------------
 * Write what can be written from adj-out to the given peer.
 *
 * This is driven by prompt messages in the Routing Engine message queue.
 *
 * Each time this is called will take as much as is available from the adj-out,
 * and try to fill the write_rb ring-buffer.
 */
extern void
bgp_packet_write_stuff(bgp_prun prun, ring_buffer rb)
{
  bgp_prib     prib ;
  bgp_prib     running[qafx_count] ;
  bool         full, first ;
  uint         i, n ;
  route_out_parcel_t parcel_s ;
  route_out_parcel   parcel ;

  full = false ;
  memset(&parcel_s, 0, sizeof(parcel_s)) ;      /* tidy */

  /* Flush any pending Route Refresh requests.
   *
   * These take precedence over everything else, which requires some
   * justification:
   *
   *   a) even if we busy sending lots of updates to the given peer, it
   *      is probably best for us to refresh what we know sooner rather than
   *      later... it might affect what we are currently queuing as updates.
   *
   *   b) if a large ORF table is being transmitted, this ensures that all
   *      messages required for it will be sent together, even if has to break
   *      off part way through because the ringg-buffer is full.
   *
   *      This is certainly convenient.
   */
  while ((dsl_head(prun->rr_pending) != NULL) && !full)
    full = bgp_packet_write_rr(prun, rb) ;

  /* Flush withdraw queues for all qafx, before considering announcements.
   *
   * Collect the running pribs.
   *
   * Note that this will flush out all withdraws for the first running address
   * family, then all withdraws from the next and so on.
   *
   * We will remain in this loop, sending out withdraws, until there are no
   * more or the ring-buffer fills.
   */
  n = prun->prib_running_count ;
  for (i = 0 ; (i <= n) && !full ; ++i)
    {
      prib = prun->prib_running[i] ;

      running[i] = prib ;               /* copy for announcements       */

      while (1)
        {
          /* Get the next withdraw from the queue, if any.
           */
          parcel = bgp_adj_out_next_withdraw(prib, &parcel_s) ;
          if (parcel == NULL)
            break ;

          /* Eat the current and then as many other withdraws as possible in
           * a single message.
           */
          full = bgp_packet_write_withdraw(prib, rb, parcel) ;
        } ;
    } ;

  /* Now flush any updates we can for the running pribs.
   *
   * This loop runs round-robin around the running pribs, until there are
   * none left, or the ring-buffer fills.
   */
  first = true ;
  i     = 0 ;
  while ((n > 0) && !full)
    {
      prib = running[i] ;

      if (first)
        bgp_adj_out_start_updates(prib) ;

      parcel = bgp_adj_out_next_update(prib, &parcel_s) ;
      if (parcel == NULL)
        {
          /* Nothing more for this prib, so drop it from our local list of
           * running prib.
           */
          uint j ;

          n -= 1 ;

          for (j = i ; j < n ; ++j)
            running[j] = running[j+1] ;
        }
      else
        {
          /* We have something for this prib, so create the required packet.
           *
           * We processed all withdraws for all address families already.  But
           * it is (just) possible that an announce would not fit into an
           * UPDATE message, and has been turned into a withdraw !
           */
          switch (parcel->action)
            {
              case ra_out_withdraw:
                full = bgp_packet_write_withdraw(prib, rb, parcel) ;
                break ;

              case ra_out_initial:
              case ra_out_update:
                full = bgp_packet_write_announce(prib, rb, parcel) ;
                break ;

              case ra_out_eor:
                full = bgp_packet_write_eor(prib, rb, parcel) ;
                break ;

              default:
                qassert(false) ;
                full = true ;
                break ;
            } ;

          /* Step to the next address family -- round robin
           */
          i += 1 ;
          if (i >= n)
            {
              i = 0 ;
              first = false ;
            } ;
        } ;
    } ;

  /* If the BGP Engine is waiting for stuff to send, and the ring-buffer is
   * not now empty, prompt the BGP Engine.
   */
  if (rb_get_prompt(rb, false /* not if empty */))
    bgp_session_kick_be_write(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Construct an update from the given route_out_parcel, and then eat as many
 * further prefixes as possible which share the same attributes.
 *
 * Generates any BGP UPDATE message in peer->session->rb_write ring buffer.
 *
 * NB: the maximum size of a BGP message is fixed and limited.  If the
 *     attributes are large:
 *
 *       * where the attributes themselves overflow the message.
 *
 *         so it is impossible to send any prefix with the attributes, so we
 *         have to withdraw them all.
 *
 *       * where the attributes do not overflow the message, but do not leave
 *         enough room for some or all prefixes we wish to send.
 *
 *         so some prefixes can be sent, and others have to be withdrawn.
 *
 * The mechanics here construct the attributes and the leading portion of any
 * MP_REACH attribute.  Then, any prefix which will fit in, we add to the
 * UPDATE.  Any prefix which does not fit in, and would not fit on its own,
 * we re-schedule to be withdrawn (or dropped, if it has never been announced).
 * When there are no more prefixes, or we have one which does not fit, but
 * would fit in a new UPDATE message, we stop and send this one.
 *
 * Returns: true <=> ring-buffer is full     -- wait for prompt from BE
 *          false -> ring-buffer is not full -- can keep going !
 */
static bool
bgp_packet_write_announce(bgp_prib prib, ring_buffer rb,
                                                        route_out_parcel parcel)
{
  bgp_rb_msg_out_type_t rb_type ;
  ptr_t     p_seg, p_red_tape ;
  ulen      attrs_len ;
  ulen      body_len, start_body_len ;
  ulen      mp_len,   start_mp_len ;
  bool      mp_reach ;
  blower_t  br[1] ;
  qstring   qs_attrs, qs_updates, qs_withdraws ;
  uint      count, no_count ;

  qassert( (parcel->action == ra_out_initial) ||
           (parcel->action == ra_out_update) ) ;
  qassert(parcel->qafx   == prib->qafx) ;
  qassert(parcel->attr   != NULL) ;

  /* We put the update packet directly into the session->write_rb.  So, we
   * start by demanding enough space for the maximum size message body, plus
   * the extra bytes we may use.
   *
   * See bgp_msg_write_update() for how we lay out the message parts in the
   * ring-buffer -- we may need 0, 2 or 3 extra bytes.
   */
  p_seg = rb_put_open(rb, BGP_MSG_BODY_MAX_L + 3, true /* set_waiting */) ;
  if (p_seg == NULL)
    return true ;                       /* full !               */

  rb_set_blower(br, rb) ;
  qassert(blow_ptr(br)   == p_seg) ;
  qassert(blow_total(br) >= (BGP_MSG_BODY_MAX_L + 3)) ;

  /* We do the attributes first
   *
   * If we require an mp_reach attribute, we generate a 2 part update in the
   * ring-buffer.  Otherwise, a conventional 1 part.
   *
   * Sets: attrs_len   = length of the attributes so far.
   *       body_len    = length of red-tape + length of attributes so far.
   *
   * By red-tape we mean the UPDATE message red-tape, which is 4 bytes for
   * (a) the total withdrawn NLRI length, and (b) the total attributes length.
   */
  mp_reach = (prib->qafx != qafx_ipv4_unicast) ||
                                      (parcel->attr->next_hop.type != nh_ipv4) ;

  if (!mp_reach)
    {
      rb_type = bgp_rbm_out_update_a ;
      blow_step(br, BGP_UPM_ATTR) ;     /* space for the red-tape       */
    }
  else
    {
      rb_type = bgp_rbm_out_update_b ;  /* assume not extended length   */
      blow_step(br, 2) ;                /* space for part2 length       */
    } ;

  attrs_len = bgp_packet_write_attribute(br, prib, parcel->attr) ;
  body_len  = BGP_UPM_ATTR + attrs_len ;        /* so far               */

  confirm(BGP_UPM_ATTR == 4) ;          /* well known ! */

  /* Set pointer to the message red-tape.
   *
   * For mp_reach, prepare the "part 1", including leading part of the
   * MP_REACH_NLRI attribute and spare byte in case Extended Length required.
   */
  if (!mp_reach)
    {
      /* For not mp_reach, we have no "part 2", and we have already reserved
       * space for the red-tape.
       */
      p_red_tape = p_seg ;
      mp_len     = 256 ;                /* no MP_REACH attribute        */
    }
  else
    {
      /* For mp_reach, what we have so far is the "part 2", so we set
       * the length of that, and then break out the start of "part 1",
       * which begins with the message red-tape.
       *
       * Construct the start of the MP_REACH attribute.
       *
       * Update body_len to include the MP_REACH so far.
       *
       * Set mp_len so we can know if or when we need to change up to the
       * Extended Length.
       *
       * NB: at this point we are expect Not Extended Length MP_REACH, but we
       *     leave a 1 byte gap to accommodate Extended Length.
       */
      store_s(&p_seg[0], attrs_len) ;

      blow_b(br, 0) ;                   /* spare byte                   */
      p_red_tape = blow_step(br, BGP_UPM_ATTR) ;

      mp_len    = bgp_reach_attribute(br, prib, parcel->attr) ;
      body_len += mp_len ;              /* total attribute length       */
      mp_len   -= 3 ;                   /* attribute body length        */

      if (mp_len > 255)                 /* not likely, but make sure    */
        body_len += 1 ;                 /* need Extended Length         */
    } ;

  /* We have everything we need, except for the prefix(es).
   *
   * Eat the prefix we rode in on, and then eat as many further prefixes as we
   * can which share the attributes and will fit in the message.
   */
  if (BGP_DEBUG (update, UPDATE_OUT))
    qs_attrs = bgp_packet_attrs_string(prib, parcel) ;
  else
    qs_attrs = NULL ;

  qs_updates = qs_withdraws = NULL ;

  blow_overrun_check(br) ;              /* make sure                    */

  start_body_len = body_len ;           /* with no NLRI at all, at all  */
  start_mp_len   = mp_len ;             /* likewise                     */

  count = no_count = 0 ;
  do
    {
      ulen pfx_len ;
      uint extend ;

      /* Generate NLRI at the current buffer position, and check for a fit.
       */
      pfx_len = bgp_blow_prefix(br, prib, parcel->pfx_id, parcel->tag) ;

      if ((mp_len <= 255) && ((mp_len + pfx_len) > 255))
        extend = 1 ;
      else
        extend = 0 ;

      if ((body_len + pfx_len + extend) <= BGP_MSG_BODY_MAX_L)
        {
          /* The prefix fits -- hurrah.
           */
          body_len += pfx_len + extend ;
          mp_len   += pfx_len ;

          count += 1 ;
          if (parcel->action == ra_out_initial)
            prib->pcount_sent += 1 ;

          if (BGP_DEBUG (update, UPDATE_OUT))
            qs_updates = bgp_packet_prefix_string(qs_updates, prib, parcel) ;

          parcel = bgp_adj_out_done_announce(prib, parcel) ;
        }
      else
        {
          /* The prefix we have will not fit.
           *
           * If prefix will fit if we start a new UPDATE message, then we
           * are done, here.
           */
          if ((start_mp_len <= 255) && ((start_mp_len + pfx_len) > 255))
            extend = 1 ;
          else
            extend = 0 ;

          if ((start_body_len + pfx_len + extend) <= BGP_MSG_BODY_MAX_L)
            {
              qassert(count != 0) ;
              break ;
            } ;

          /* The prefix we have will NEVER fit.
           */
          no_count += 1 ;

          if (qs_attrs == NULL)
            qs_attrs = bgp_packet_attrs_string(prib, parcel) ;

          qs_withdraws = bgp_packet_prefix_string(qs_withdraws, prib, parcel) ;

          parcel = bgp_adj_out_done_no_announce(prib, parcel) ;
        } ;
    }
  while (parcel != NULL) ;

  /* Collected everything for the UPDATE message, if any.
   */
  if (count != 0)
    {
      /* We have at least one prefix in the UPDATE we have constructed.
       *
       * Need to fill in the message red-tape, and complete any MP_REACH
       * attribute.
       *
       * Then close the rb-segment at its true size, which dispatches it.
       */
      ptr_t p_put ;
      uint  rb_len ;

      rb_len = blow_ptr(br) - p_seg ;

      if (!mp_reach)
        {
          /* Simple IPv4/Unicast
           *
           * We have: rb_type    = bgp_rbm_out_update_a
           *          p_red_tape = address of the red-tape
           *          attrs_len  = true length of attributes
           *          body_len   = length of the rb segment.
           */
          qassert(rb_type == bgp_rbm_out_update_a) ;
          qassert(rb_len == body_len) ;
        }
      else
        {
          /* MP_REACH form.
           *
           * We have: rb_type    = bgp_rbm_out_update_b
           *          p_red_tape = address of the red-tape -- so far
           *          attrs_len  = length of Part 2 of attributes
           *          body_len   = true length of attributes + red_tape
           *
           * Adjust the MP_REACH attribute if not need Extended Length, and
           * then insert the attribute length.
           */
          qassert(rb_type == bgp_rbm_out_update_b) ;
          qassert(mp_len  == (blow_ptr(br) - (p_red_tape + BGP_UPM_ATTR + 3))) ;
          qassert(p_red_tape[BGP_UPM_ATTR + 0] == BGP_ATF_OPTIONAL) ;
          qassert(p_red_tape[BGP_UPM_ATTR + 1] == BGP_ATT_MP_REACH_NLRI) ;

          if (mp_len <= 255)
            {
              /* We do not need to extend the MP_REACH attribute.
               */
              qassert(rb_len == (body_len + 3)) ;

              p_red_tape[BGP_UPM_ATTR + 2] = mp_len ;
            }
          else
            {
              /* We do need to extend the MP_REACH attribute.
               */
              qassert(rb_len == (body_len + 2)) ;

              rb_type = bgp_rbm_out_update_c ;

              p_red_tape -= 1 ;             /* use up the spare byte        */

              store_b( &p_red_tape[BGP_UPM_ATTR + 0],
                                          BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED) ;
              store_b( &p_red_tape[BGP_UPM_ATTR + 1], BGP_ATT_MP_REACH_NLRI) ;
              store_ns(&p_red_tape[BGP_UPM_ATTR + 2], mp_len) ;
            } ;

          attrs_len = body_len - BGP_UPM_ATTR ;
        } ;

      store_ns(&p_red_tape[0], 0) ;         /* no withdraws         */
      store_ns(&p_red_tape[2], attrs_len) ; /* total attributes     */

      /* Complete the ring-buffer message.
       */
      p_put = rb_put_close(rb, rb_len, rb_type) ;

      qassert((p_put + rbrt_off_body) == p_seg) ;

      /* For qdebug... quick check on the validity of what we just created.
       */
      if (qdebug)
        {
          qassert(load_s(&p_put[rbrt_off_len])  == rb_len) ;
          qassert(load_b(&p_put[rbrt_off_type]) == rb_type) ;

          // XXX XXX XXX XXX XXX



        } ;
    }
  else
    {
      /* We have not a single prefix in the UPDATE we have constructed.
       *
       * Discard the rb-segment.
       */
      rb_put_drop(rb) ;
    } ;

  /* Log stuff as required.
   */
  if (qs_attrs != NULL)
    {
      if (qs_updates != NULL)
        {
          zlog (prib->prun->log, LOG_DEBUG, "%s send %u UPDATE(S) %s/%s:%s%s",
                prib->prun->name, count,
                map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                   qs_string(qs_attrs), qs_string(qs_updates)) ;
          qs_free(qs_updates) ;
        } ;

      if (qs_withdraws != NULL)
        {
          zlog (prib->prun->log, LOG_WARNING,
                 "%s unable to send %u UPDATE(S) - %u bytes of attributes"
                                                               " - %s/%s:%s%s",
                prib->prun->name, no_count, start_body_len - BGP_UPM_ATTR,
                map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                 qs_string(qs_attrs), qs_string(qs_withdraws)) ;
          qs_free(qs_withdraws) ;
        } ;

      qs_free(qs_attrs) ;
    } ;

  return false ;                /* not full     */
} ;

/*------------------------------------------------------------------------------
 * Construct qstring containing the attributes to be announced.
 */
static qstring
bgp_packet_attrs_string(bgp_prib prib, route_out_parcel parcel)
{
  attr_next_hop_t* next_hop, * mp_next_hop ;

  next_hop = mp_next_hop = NULL ;
  if (prib->qafx == qafx_ipv4_unicast)
    next_hop    = &parcel->attr->next_hop ;
  else
    mp_next_hop = &parcel->attr->next_hop ;

  return bgp_dump_attr(prib->prun, parcel->attr, next_hop, mp_next_hop) ;
} ;

/*------------------------------------------------------------------------------
 * Construct qstring containing the attributes to be announced.
 */
static qstring
bgp_packet_prefix_string(qstring qs_pfx, bgp_prib prib,
                                                route_out_parcel parcel)
{
  prefix_id_entry pie ;

  pie = prefix_id_get_entry(parcel->pfx_id) ;

  qs_pfx = qs_append_str(qs_pfx, " ") ;

  if (prib->is_mpls)
    qs_pfx = qs_printf_a(qs_pfx, " %s/%s/",
                            stgtoa(parcel->tag).str,
                            srdtoa(prefix_rd_id_get_val(pie->pfx->rd_id)).str) ;
  else
    qs_pfx = qs_append_str(qs_pfx, " ") ;

  return qs_append_str(qs_pfx, spfxtoa(pie->pfx).str) ;
} ;

/*------------------------------------------------------------------------------
 * Construct a withdraw update starting with the given parcel, and then eating
 * as much as possible of the prib's withdraw queue.
 *
 * Generates any BGP UPDATE message in peer->session->rb_write ring buffer.
 *
 * Returns: true <=> ring-buffer is full     -- wait for prompt from BE
 *          false -> ring-buffer is not full -- can keep going !
 */
static bool
bgp_packet_write_withdraw(bgp_prib prib, ring_buffer rb,
                                                        route_out_parcel parcel)
{
  bgp_rb_msg_out_type_t type ;
  ptr_t     p_seg, p_red_tape ;
  ulen      body_len, mp_len ;
  bool      mp_unreach ;
  blower_t  br[1] ;
  uint      count ;
  qstring   qs_withdraws ;

  qassert(parcel->action == ra_out_withdraw) ;
  qassert(parcel->qafx   == prib->qafx) ;
  qassert(parcel->attr   == NULL) ;

  /* We put the update packet directly into the session->write_rb.  So, we
   * start by demanding enough space for the maximum size message body, plus
   * the extra bytes we may use.
   *
   * See bgp_msg_write_update() for how we lay out the message parts in the
   * ring-buffer -- we may need 1 extra bytes.
   */
  p_seg = rb_put_open(rb, BGP_MSG_BODY_MAX_L + 1, true /* set_waiting */) ;
  if (p_seg == NULL)
    return true ;                       /* full !               */

  rb_set_blower(br, rb) ;
  qassert(blow_ptr(br)   == p_seg) ;
  qassert(blow_total(br) >= (BGP_MSG_BODY_MAX_L + 1)) ;

  /* Prepare the red_tape and the start of the attribute for MP_UNREACH
   *
   * Sets: p_red_tape  = address for the red_tape, so far.
   *       body_len    = length of red-tape + length of attribute so far.
   *       mp_len      = length of body of attribute (if required)
   *
   * By red-tape we mean the UPDATE message red-tape, which is 4 bytes for
   * (a) the total withdrawn NLRI length, and (b) the total attributes length.
   */
  mp_unreach = (prib->qafx != qafx_ipv4_unicast) ;

  if (!mp_unreach)
    {
      type = bgp_rbm_out_update_a ;
      p_red_tape = blow_step(br, BGP_UPM_A_LEN) ;
      confirm(BGP_UPM_A_LEN == 2) ;     /* space for withdraw length    */

      body_len  = BGP_UPM_ATTR ;        /* so far                       */
      mp_len    = 256 ;                 /* none !                       */
    }
  else
    {
      type = bgp_rbm_out_update_d ;     /* assume not extended length   */
      blow_step(br, 1) ;                /* one spare byte               */
      p_red_tape = blow_step(br, BGP_UPM_ATTR) ;
      confirm(BGP_UPM_ATTR == 4) ;      /* space for red_tape           */

      mp_len    = bgp_unreach_attribute(br, prib) ;
      body_len  = BGP_UPM_ATTR + mp_len ;       /* so far               */
      mp_len   -= 3 ;                   /* attribute body length        */

      if (mp_len > 255)                 /* not likely, but make sure    */
        body_len += 1 ;                 /* need Extended Length         */
    } ;

  /* We have everything we need, except for the prefix(es).
   *
   * Eat the prefix we rode in on, and then eat as many further prefixes as we
   * can which share the attributes and will fit in the message.
   */
  blow_overrun_check(br) ;              /* make sure                    */

  qs_withdraws = NULL ;
  count = 0 ;
  do
    {
      ulen pfx_len ;
      uint extend ;

      /* Generate NLRI at the current buffer position, and check for a fit.
       */
      pfx_len = bgp_blow_prefix(br, prib, parcel->pfx_id, parcel->tag) ;

      if ((mp_len <= 255) && ((mp_len + pfx_len) > 255))
        extend = 1 ;
      else
        extend = 0 ;

      if ((body_len + pfx_len + extend) > BGP_MSG_BODY_MAX_L)
        break ;                         /* withdraw message is full     */

      /* The prefix fits -- hurrah.
       */
      body_len += pfx_len + extend ;
      mp_len   += pfx_len ;

      count += 1 ;

      if (BGP_DEBUG (update, UPDATE_OUT))
        qs_withdraws = bgp_packet_prefix_string(qs_withdraws, prib, parcel) ;

      parcel = bgp_adj_out_done_withdraw(prib, parcel) ;
    }
  while (parcel != NULL) ;

  /* Collected everything for the UPDATE message, if any.
   */
  if (count != 0)
    {
      /* We have at least one prefix in the UPDATE we have constructed.
       *
       * Need to fill in the message red-tape, and complete any MP_UNREACH_NLRI
       * attribute.
       *
       * Then close the rb-segment at its true size, which dispatches it.
       */
      ptr_t p_put ;
      uint  rb_len ;

      prib->pcount_sent -= count ;

      if (!mp_unreach)
        {
          /* Simple IPv4/Unicast
           *
           * Need to fill in: length of the withdraw NLRI
           *      and append: 0 == length of attributes.
           *
           * We have: type       = bgp_rbm_out_update_a
           *          p_red_tape = address of the red-tape
           *          body_len   = true length of attributes + red_tape
           */
          qassert(type == bgp_rbm_out_update_a) ;

          store_ns(p_red_tape, body_len - BGP_UPM_ATTR) ;
                                        /* withdraw length      */
          blow_w(br, 0) ;               /* zero attributes      */
        }
      else
        {
          /* MP_REACH form.
           *
           * We have: type       = bgp_rbm_out_update_d
           *          p_red_tape = address of the red-tape -- so far
           *          body_len   = true length of attributes + red_tape
           *
           * Adjust the MP_REACH attribute if need Extended Length, and insert
           * the attribute length.
           */
          qassert(type == bgp_rbm_out_update_d) ;
          qassert(mp_len == (blow_ptr(br) - (p_red_tape + BGP_UPM_ATTR + 3))) ;
          qassert(p_red_tape[BGP_UPM_ATTR + 0] == BGP_ATF_OPTIONAL) ;
          qassert(p_red_tape[BGP_UPM_ATTR + 1] == BGP_ATT_MP_UNREACH_NLRI) ;

          if (mp_len <= 255)
            {
              /* We do not need to extend the MP_UNREACH_NLRI attribute.
               */
              p_red_tape[BGP_UPM_ATTR + 2] = mp_len ;
            }
          else
            {
              /* We do need to extend the MP_UNREACH_NLRI attribute.
               */
              type = bgp_rbm_out_update_a ;

              p_red_tape -= 1 ;             /* use up the spare byte        */

              store_b( &p_red_tape[BGP_UPM_ATTR + 0],
                                          BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED) ;
              store_b( &p_red_tape[BGP_UPM_ATTR + 1], BGP_ATT_MP_UNREACH_NLRI) ;
              store_ns(&p_red_tape[BGP_UPM_ATTR + 2], mp_len) ;
            } ;

          store_ns(&p_red_tape[0], 0) ;         /* no withdraws         */
          store_ns(&p_red_tape[2], body_len - BGP_UPM_ATTR) ;
                                                /* total attributes     */
        } ;

      rb_len = blow_ptr(br) - p_seg ;
      qassert(rb_len == (body_len + (type == bgp_rbm_out_update_d ? 1 : 0))) ;

      /* Complete the ring-buffer message.
       */
      p_put = rb_put_close(rb, rb_len, type) ;

      qassert((p_put + rbrt_off_body) == p_seg) ;

      /* For qdebug... quick check on the validity of what we just created.
       */
      if (qdebug)
        {
          qassert(load_s(&p_put[rbrt_off_len])  == rb_len) ;
          qassert(load_b(&p_put[rbrt_off_type]) == type) ;

          // XXX XXX XXX XXX XXX

        } ;
    }
  else
    {
      /* We have not a single prefix in the UPDATE we have constructed.
       *
       * This should be impossible !  Discard the rb-segment.
       */
      rb_put_drop(rb) ;
    } ;

  /* Log stuff as required.
   */
  if (qs_withdraws != NULL)
    {
      zlog (prib->prun->log, LOG_DEBUG, "%s send %u WITHDRAW(S) %s/%s:%s",
                prib->prun->name, count,
                map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                                      qs_string(qs_withdraws)) ;
      qs_free(qs_withdraws) ;
    } ;

  return false ;                /* not full     */
} ;

/*------------------------------------------------------------------------------
 * Construct an EoR.
 *
 * Generates a BGP UPDATE message in peer->session->rb_write ring buffer.
 *
 * Returns: true <=> ring-buffer is full     -- wait for prompt from BE
 *          false -> ring-buffer is not full -- can keep going !
 */
static bool
bgp_packet_write_eor(bgp_prib prib, ring_buffer rb, route_out_parcel parcel)
{
  ulen        eor_msg_len ;
  ptr_t       p_seg, p_put ;

  qassert(parcel->action == ra_out_eor) ;
  qassert(parcel->qafx   == prib->qafx) ;
  qassert(parcel->attr   == NULL) ;

  /* For IPv4/Unicast we are sending an UPDATE with no Withdrawn Routes and no
   * Attributes.
   *
   * For all other afi/safi we are sending an UPDATE with no Withdrawn Routes
   * and an empty MP_UNREACH_NLRI.
   */
  enum
    {
      empty_mp_unreach_nlri = 1 + 1 + 1 + 2 + 1,

      min_eor_msg_len       = 2 + 2,
      max_eor_msg_len       = 2 + 2 + empty_mp_unreach_nlri,
    } ;

  /* BGP_UPM_W_LEN      == offset of withdrawn routes length
   * BGP_UPM_A_LEN      == offset of attributes length, if no Withdrawn Routes
   * BGP_UPM_ATTR       == offset of attributes, if no Withdrawn Routes
   * BGP_ATTR_MIN_L     == length of minimum size (empty) attribute
   * BGP_ATT_MPU_MIN_L  == length of body of minimum size MP_UNREACH_NLRI
   */
  confirm(empty_mp_unreach_nlri == (BGP_ATTR_MIN_L + BGP_ATT_MPU_MIN_L)) ;
  confirm(min_eor_msg_len       == (uint)BGP_UPM_ATTR) ;
  confirm(max_eor_msg_len       == (BGP_UPM_ATTR   + empty_mp_unreach_nlri)) ;

  eor_msg_len = (prib->qafx == qafx_ipv4_unicast) ? min_eor_msg_len
                                                  : max_eor_msg_len ;

  /* Allocate what we need for this.
   */
  p_seg = rb_put_open(rb, eor_msg_len, true /* set_waiting */) ;
  if (p_seg == NULL)
    return true ;                       /* full !               */

  /* Set the UPDATE message red-tape.
   */
  store_ns(&p_seg[BGP_UPM_W_LEN], 0) ;
  store_ns(&p_seg[BGP_UPM_A_LEN], eor_msg_len - BGP_UPM_ATTR) ;

  confirm((BGP_UPM_W_LEN    == 0) && (sizeof(BGP_UPM_W_LEN_T)    == 2)) ;
  confirm((BGP_UPM_A_LEN    == 2) && (sizeof(BGP_UPM_A_LEN_T)    == 2)) ;
  confirm((BGP_UPM_ATTR     == 4)) ;

  if (prib->qafx != qafx_ipv4_unicast)
    {
      store_b( &p_seg[BGP_UPM_ATTR + 0],     BGP_ATF_OPTIONAL) ;
      store_b( &p_seg[BGP_UPM_ATTR + 1],     BGP_ATT_MP_UNREACH_NLRI) ;
      store_b( &p_seg[BGP_UPM_ATTR + 2],     2 + 1);
      store_ns(&p_seg[BGP_UPM_ATTR + 3 + 0], prib->i_afi) ;
      store_b( &p_seg[BGP_UPM_ATTR + 3 + 2], prib->i_safi) ;

      confirm((BGP_ATTR_FLAGS   == 0) && (sizeof(BGP_ATTR_FLAGS_T)   == 1)) ;
      confirm((BGP_ATTR_TYPE    == 1) && (sizeof(BGP_ATTR_TYPE_T)    == 1)) ;
      confirm((BGP_ATTR_LEN     == 2) && (sizeof(BGP_ATTR_LEN_T)     == 1)) ;
      confirm((BGP_ATT_MPU_AFI  == 0) && (sizeof(BGP_ATT_MPU_AFI_T)  == 2)) ;
      confirm((BGP_ATT_MPU_SAFI == 2) && (sizeof(BGP_ATT_MPU_SAFI_T) == 1)) ;
    } ;

  p_put = rb_put_close(rb, eor_msg_len, bgp_rbm_out_eor) ;

  qassert((p_put + rbrt_off_body) == p_seg) ;

  bgp_adj_out_done_eor(prib) ;

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("send End-of-RIB for %s to %s", get_qafx_name(prib->qafx),
                                                           prib->prun->name) ;

  return false ;                /* not full     */
} ;

/*------------------------------------------------------------------------------
 * Construct a Route Refresh Message, eating as many ORF as possible.
 *
 * Generates a BGP ROUTE_REFRESH message in peer->session->rb_write ring buffer.
 *
 * Returns: true <=> ring-buffer is full     -- wait for prompt from BE
 *          false -> ring-buffer is not full -- can keep going !
 */
static bool
bgp_packet_write_rr(bgp_prun prun, ring_buffer rb)
{
  bgp_route_refresh rr ;
  ulen        msg_size ;
  ptr_t       p_seg, p, p_put ;
  bgp_orf_cap_bits_t orf_cap_bits ;
  blower_t br[1] ;
  bgp_form_t form ;
  bool      done ;

  /* Pick up the first pending Route-Refresh, if any.
   */
  rr = ddl_head(prun->rr_pending) ;
  if (rr == NULL)
    return false ;                      /* not full             */

  /* We prefer the RFC ORF Prefix type, if we allowed to send any at all.
   */
  orf_cap_bits = prun->session->args->can_orf_pfx.af[rr->qafx] ;

  if      (orf_cap_bits & ORF_SM)
    form = bgp_form_rfc ;
  else if (orf_cap_bits & ORF_SM_pre)
    form = bgp_form_pre ;
  else
    form = bgp_form_none ;

  /* If we have ORF, then we want a full size BGP message otherwise a small
   * one.
   */
  if ((form != bgp_form_none) && (vector_length(rr->entries) > rr->next_index))
    msg_size = BGP_MSG_BODY_MAX_L ;
  else
    msg_size = BGP_RRM_BODY_MIN_L ;

  /* Allocate what we need for this.
   *
   * Note that if we cannot get a buffer big enough, we have left the rr object
   * where it was, for later consideration.
   */
  p_seg = rb_put_open(rb, msg_size, true /* set_waiting */) ;
  if (p_seg == NULL)
    return true ;                       /* full !               */

  rb_set_blower(br, rb) ;
  qassert(blow_ptr(br)   == p_seg) ;
  qassert(blow_total(br) == BGP_MSG_BODY_MAX_L) ;

  /* Encode leading/minimum/simple Route Refresh message.
   */
  p = blow_step(br, BGP_RRM_MIN_L) ;

  confirm((BGP_RRM_AFI   == 0) && (sizeof(BGP_RRM_AFI_T)  == 2)) ;
  confirm((BGP_RRM_RES   == 2) && (sizeof(BGP_RRM_RES_T)  == 1)) ;
  confirm((BGP_RRM_SAFI  == 3) && (sizeof(BGP_RRM_SAFI_T) == 1)) ;
  confirm(BGP_RRM_BODY_MIN_L  == 4) ;

  store_ns(&p[BGP_RRM_AFI], rr->i_afi) ;
  store_b (&p[BGP_RRM_RES], 0);
  store_b (&p[BGP_RRM_RES], rr->i_safi);

  /* Append as many (remaining) ORF entries as can into message
   */
  if (form != bgp_form_none)
    done = bgp_packet_write_rr_orf_part(br, rr, form, prun) ;
  else
    done = true ;

  /* Close and dispatch the message
   */
  p_put = rb_put_close(rb, blow_length(br), bgp_rbm_out_rr) ;

  qassert((p_put + rbrt_off_body) == p_seg) ;

  /* If we are 'done', we can release the current bgp_route_refresh object.
   */
  if (done)
    {
      dsl_del_head(prun->rr_pending, next) ;
      bgp_route_refresh_free(rr) ;
    } ;

  return false ;                /* not full     */
} ;

/*------------------------------------------------------------------------------
 * Set the length of the current collection, if any.
 *
 * NB: if the collection is zero length, crashes the blow pointer back to the
 *     before the collection.
 */
inline static ptr_t
bgp_packet_write_rr_orf_part_length(ptr_t p_collection, ptr_t p_end)
{
  confirm(BGP_ORF_MIN_L == 3) ;         /* collection header    */

  if ((p_collection + BGP_ORF_MIN_L) < p_end)
    store_ns(&p_collection[BGP_ORF_LEN], p_end - (p_collection + BGP_ORF_MIN_L)) ;
  else
    p_end = p_collection ;

  return p_end ;
} ;

/*------------------------------------------------------------------------------
 * Put ORF entries to the given blower until run out of entries or run out
 * of room.
 *
 * There MUST BE at least one ORF entry to go.
 *
 * Returns true <=> done all available entries.
 */
static bool
bgp_packet_write_rr_orf_part(blower br, bgp_route_refresh rr, bgp_form_t form,
                                                                  bgp_prun prun)
{
  bgp_orf_entry entry ;
  uint  next_index ;

  uint8_t orf_type ;

  ptr_t p_when ;                /* where the "when" byte is             */
  ptr_t p_collection ;          /* start of the latest collection       */
  ptr_t p_end ;                 /* where we got to successfully         */

  bool  done ;

  /* Heading for Prefix-Address ORF type section -- pro tem, set defer.
   */
  p_when = blow_ptr(br) ;        /* position of "when"           */
  blow_b(br, BGP_ORF_WTR_DEFER) ;

  /* Process ORF entries until run out of entries or space
   */
  p_collection = blow_ptr(br) ; /* no collection, yet           */
  orf_type   = 0 ;              /* no ORF type, yet             */

  next_index = rr->next_index ; /* where we started             */
  while (1)
    {
      p_end = blow_ptr(br) ;    /* so far, so good              */

      entry = bgp_orf_get_entry(rr, next_index) ;
      done = (entry == NULL) ;

      if (done)
        break ;

      if ((p_end == p_collection) || (orf_type != entry->orf_type))
        {
          /* Finish any previous collection and start a new one..
           */
          uint8_t orf_type_send ;

          /* fill in length of previous ORF entries, if any
           */
          bgp_packet_write_rr_orf_part_length(p_collection, p_end) ;

          /* set type and dummy entries length.
           */
          orf_type      = entry->orf_type ;
          orf_type_send = entry->orf_type ;

          if ((orf_type == BGP_ORF_T_PFX) && (form == bgp_form_pre))
            orf_type_send = BGP_ORF_T_PFX_pre ;

          /* Start a new collection.
           *
           * Sets p_collection -> type byte
           *                      length word
           *
           * Leaves p_end == p_collection, so if do not actually have room for
           * the first entry of the collection, the collection is discarded.
           */
          p_collection = blow_step(br, BGP_ORF_MIN_L) ; /* type & length */

          store_b(&p_collection[BGP_ORF_TYPE], orf_type_send) ;
        } ;

      /* Insert the entry, if will fit.
       *
       * sets done <=> fitted
       */
      if (entry->unknown)
        {
          if (blow_left(br) < entry->body.orf_unknown.length)
            break ;                     /* entry does not fit   */

            blow_n(br, entry->body.orf_unknown.data,
                       entry->body.orf_unknown.length) ;
        }
      else
        {
          if (entry->remove_all)
            {
              /* Put remove all ORF entry to stream -- if possible.
               */
              if (blow_left(br) < 1)    /* just the one byte    */
                break ;

              blow_b(br, BGP_ORF_EA_RM_ALL) ;
            }
          else
            {
              uint8_t   action ;
              orf_prefix_value orfpv ;
              uint      blen ;
              ptr_t     p ;

              qassert(entry->orf_type == BGP_ORF_T_PFX) ;
              qassert(entry->deny == (entry->body.orfpv.type == PREFIX_DENY)) ;

              orfpv = &entry->body.orfpv ;

              blen = PSIZE(orfpv->pfx.prefixlen) ;

              if (blow_left(br) < (int)(BGP_ORF_E_P_MIN_L + blen))
                break ;

              action = (entry->remove ? BGP_ORF_EA_REMOVE
                                      : BGP_ORF_EA_ADD)
                     | (entry->deny   ? BGP_ORF_EA_DENY
                                      : BGP_ORF_EA_PERMIT) ;

              p = blow_step(br, BGP_ORF_E_P_MIN_L) ;

              store_b( &p[0], action) ;
              store_nl(&p[1], orfpv->seq) ;
              store_b( &p[5], orfpv->ge) ;        /* aka min      */
              store_b( &p[6], orfpv->le) ;        /* aka max      */
              store_b( &p[7], orfpv->pfx.prefixlen) ;

              confirm(BGP_ORF_E_P_MIN_L == (1 + 4 + 1 + 1 + 1)) ;

              blow_n(br, &orfpv->pfx.u.prefix, blen) ;
            } ;
        } ;

      /* Done ORF entry.  Step to the next.  NB: done == true
       */
      next_index += 1 ;
    } ;

  /* Set the length of what we have collected.
   *
   * If we haven't collected anything, then that's because there wasn't
   * enough room, so will have collapsed back to the start of the collection.
   */
  blow_set_ptr(br, bgp_packet_write_rr_orf_part_length(p_collection, p_end)) ;

  /* If we are done, then we set the true defer/
   *
   */
  if (done)
    {
      if (!rr->defer)
        store_b(p_when, BGP_ORF_WTR_IMMEDIATE) ;
    }
  else
    {
      if (next_index == rr->next_index)
        {
          /* Something has gone wrong if nothing has been processed:
           *
           *   a) have been called again after having reported "done" (so there
           *      are no more entries to deal with.
           *
           *   b) have been asked to output an "unknown" ORF entry which is too
           *      long for a BGP message !!
           */
          if (entry == NULL)
            zlog_err("%s called %s() after said was done",
                                                       prun->name, __func__) ;
          else if (entry->unknown)
            zlog_err("%s sending REFRESH_REQ with impossible length (%d) ORF",
                                 prun->name, entry->body.orf_unknown.length) ;
          else
            zlog_err("%s failed to put even one ORF entry", prun->name) ;

          done = true ;
        } ;
    } ;

  rr->next_index = next_index ;
  return done ;
} ;

/*==============================================================================
 *
 */


/*------------------------------------------------------------------------------
 * Send route refresh message to the peer.
 *
 * Although the ORF stuff will handle arbitrary AFI/SAFI, we only send stuff
 * from known ones.
 *
 * This prepares a new bgp_route_refresh object, queues it for the peer and
 * then prods the I/O stuff.
 */
extern void
bgp_route_refresh_send (bgp_prib prib, byte orf_type,
                                             byte when_to_refresh, bool remove)
{
  bgp_route_refresh rr ;
  bool orf_refresh ;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (prib == NULL)
    return ;

  rr = bgp_route_refresh_new(prib->i_afi, prib->i_safi,
                                        (orf_type == BGP_ORF_T_PFX) ? 100 : 0) ;
  rr->defer = (when_to_refresh == BGP_ORF_WTR_DEFER);

  orf_refresh = false  ;

  if (orf_type == BGP_ORF_T_PFX)
    {
      prefix_list   plist ;

      plist = prib->plist[FILTER_IN] ;

      if (remove || (plist != NULL))
        {
          orf_refresh = true ;
          if (remove)
            {
              bgp_orf_add_remove_all(rr, BGP_ORF_T_PFX);
              prib->orf_pfx_sent = false ;

              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s sending REFRESH_REQ to remove ORF (%s)"
                            " for afi/safi: %u/%u", prib->prun->name,
                                           rr->defer ? "defer" : "immediate",
                                                        rr->i_afi, rr->i_safi) ;
            }
          else
            {
              orf_prefix_value_t orfpv;
              vector_index_t i;

              for (i = 0; prefix_bgp_orf_get(&orfpv, plist, i); ++i)
                {
                  bgp_orf_entry orfpe ;

                  orfpe = bgp_orf_add(rr, BGP_ORF_T_PFX, 0,
                                                     orfpv.type == PREFIX_DENY);
                  orfpe->body.orfpv = orfpv;
                } ;

              prib->orf_pfx_sent = true ;

              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s sending REFRESH_REQ with pfxlist ORF "
                            "(%s) for afi/safi: %u/%u", prib->prun->name,
                                            rr->defer ? "defer" : "immediate",
                                                        rr->i_afi, rr->i_safi);
            } ;
        } ;
    } ;

  if (BGP_DEBUG (normal, NORMAL))
    {
      if (!orf_refresh)
        zlog_debug("%s sending REFRESH_REQ for afi/safi: %u/%u",
                                    prib->prun->name, rr->i_afi, rr->i_safi) ;
    } ;

  /* Append to queue for the peer and prompt the I/O side of things.
   */
  dsl_append(prib->prun->rr_pending, rr, next) ;

  bgp_session_kick_write(prib->prun) ;
} ;

/*==============================================================================
 * Incoming message handling -- processing the session->rn_read ring-buffer.
 *
 * The ring-buffer contains the bodies of messages:
 *
 *   * BGP_MT_UPDATE
 *
 *   * BGP_MT_ROUTE_REFRESH
 *   * BGP_MT_ROUTE_REFRESH_pre
 */
static void bgp_packet_read_update(bgp_prun prun, sucker sr) ;
static void bgp_packet_read_rr(bgp_prun peer, sucker sr) ;

static void bpd_packet_update_nlri (bgp_prun prun, attr_set attr,
                                                  bgp_nlri nlri, bool refused) ;
static bgp_route_refresh bgp_packet_parse_rr(bgp_prun prun, sucker sr) ;

/*------------------------------------------------------------------------------
 * Process the ring buffer until it is empty.
 *
 * This is driven by prompt messages in the Routing Engine message queue.
 *
 * Each time this is called will attempt to empty the read_rb ring-buffer.
 */
extern void
bgp_packet_read_stuff(bgp_prun prun, ring_buffer rb)
{
  ptr_t       p_seg ;

  p_seg = rb_get_first(rb, true /* set_waiting */) ;
  while (p_seg != NULL)
    {
      sucker_t  sr[1] ;

      switch (rb_set_sucker(sr, rb))
        {
          case bgp_rbm_in_update:
            bgp_packet_read_update(prun, sr) ;
            break ;

          case bgp_rbm_in_rr:
          case bgp_rbm_in_rr_pre:
            bgp_packet_read_rr(prun, sr) ;
            break ;

          default:
            qassert(false) ;
        } ;

      p_seg = rb_get_step_first(rb, true /* set_waiting */) ;
    } ;

  if (rb_put_prompt(rb, 10000))
    bgp_session_kick_be_write(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Parse BGP Update packet and make attribute object.
 */
static void
bgp_packet_read_update(bgp_prun prun, sucker sr)
{
  bgp_size_t attribute_len;


  byte* attr_p ;
  bgp_attr_parsing_t args[1] ;
  bool      refused ;
  bgp_prib  prib ;

  /* Status must be Established.
   */
  if (prun->state != bgp_pEstablished)
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
                prun->name, map_direct(bgp_peer_status_map, prun->state).str);

      bgp_peer_down_error (prun, BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC) ;

      return ;
    } ;

  /* Set initial values in args:
   *
   *   * prun               -- X      -- set below
   *   * sort               -- X      -- set below
   *   * as4                -- X      -- set below
   *
   *   * seen               -- zeros  -- nothing seen, yet
   *
   *   * attrs              -- X      -- set below
   *
   *   * type               -- X       )
   *   * flags              -- X       ) set and used for individual
   *   * length             -- X       ) attribute parsing
   *   * start_p            -- X       )
   *   * end_p              -- X       )
   *   * ret                -- X       )
   *
   *   * aret               -- BGP_ATTR_PARSE_OK  -- so far, so good
   *
   *   * notify_code        -- X       )
   *   * notify_subcode     -- X       ) set and used if get
   *   * notify_data_len    -- 0       ) BGP_ATTR_PARSE_CRITICAL
   *   * notify_data        -- NULL    )
   *   * notify_attr_type   -- X       )
   *
   *   * asp                -- NULL   -- no AS_PATH, yet
   *   * as4p               -- NULL   -- no AS4_PATH, yet
   *
   *   * as4_aggregator_as  -- 0      -- no AS4_AGGREGATOR, yet
   *   * as4_aggregator_ip  -- 0      -- no AS4_AGGREGATOR, yet
   *
   *   * update             -- zeros  -- update.length      == 0 <=> no NLRI
   *                                     update.next_hop.type == nh_none
   *                                                             <=> no NEXTHOP
   *   * withdraw           -- zeros  -- withdraw.length    == 0 <=> no NLRI
   *   * mp_update          -- zeros  -- mp_update.length   == 0 <=> no NLRI
   *   * mp_withdraw        -- zeros  -- mp_withdraw.length == 0 <=> no NLRI
   *
   *   * unknown            -- NULL   -- no unknown attributes, yet
   *
   *   * mp_eor             -- false  -- no MP End-of-RIB
   */
  memset (args, 0, sizeof (args)) ;

  confirm(BGP_ATTR_PARSE_OK == 0) ;

  args->prun = prun ;

  args->sort = prun->sort ;
  args->as4  = prun->session->args->can_as4 ;

  bgp_attr_pair_load_new(args->attrs) ;

  /* Get and check length of Withdrawn Routes part, and step past.
   *
   * Get and check the length of Attributes part, and step past.
   *
   * Get (Update) NLRI part, and step past.
   */
  args->withdraw.length = suck_w(sr);
  args->withdraw.pnt    = suck_step(sr, args->withdraw.length) ;

  if (!suck_overrun_check(sr))
    {
      zlog_err ("%s [Error] Update packet error"
                " (packet unfeasible length overflow %u)",
                prun->name, args->withdraw.length);

      args->notify_code    = BGP_NOMC_UPDATE ;
      args->notify_subcode = BGP_NOMS_U_MAL_ATTR ;

      qassert(args->notify_data_len == 0) ;

      goto exit_bgp_update_critical ;
    }

  attribute_len = suck_w(sr) ;
  attr_p        = suck_step(sr, attribute_len) ;

  if (!suck_overrun_check(sr))
    {
      zlog_warn ("%s [Error] Packet Error"
                   " (update packet attribute length overflow %u)",
                   prun->name, attribute_len);

      args->notify_code    = BGP_NOMC_UPDATE ;
      args->notify_subcode = BGP_NOMS_U_MAL_ATTR ;

      qassert(args->notify_data_len == 0) ;

      goto exit_bgp_update_critical ;
    } ;

  args->update.length = suck_left(sr);
  args->update.pnt    = suck_ptr(sr) ;

  /* Check that any Withdraw stuff is well formed.
   */
  if (args->withdraw.length > 0)
    {
      args->withdraw.qafx      = qafx_ipv4_unicast ;
      args->withdraw.in.i_afi  = iAFI_IP ;
      args->withdraw.in.i_safi = iSAFI_Unicast ;

      if (!bgp_nlri_sanity_check (prun, &args->withdraw))
        {
          zlog_info ("%s withdraw NLRI fails sanity check", prun->name) ;

          args->notify_code    = BGP_NOMC_UPDATE ;
          args->notify_subcode = BGP_NOMS_U_NETWORK ;

          qassert(args->notify_data_len == 0) ;

          goto exit_bgp_update_critical ;
        } ;

      if (BGP_DEBUG (packet, PACKET_RECV))
        zlog_debug ("%s [Update:RECV] Unfeasible NLRI received", prun->name);
    } ;

  /* Check that any NLRI stuff is well formed.
   */
  if (args->update.length != 0)
    {
      args->update.qafx      = qafx_ipv4_unicast ;
      args->update.in.i_afi  = iAFI_IP;
      args->update.in.i_safi = iSAFI_Unicast ;

      if (!bgp_nlri_sanity_check (prun, &args->update))
        {
          zlog_info ("%s update NLRI fails sanity check", prun->name) ;

          args->notify_code    = BGP_NOMC_UPDATE ;
          args->notify_subcode = BGP_NOMS_U_NETWORK ;

          qassert(args->notify_data_len == 0) ;

          goto exit_bgp_update_critical ;
       } ;
    } ;

  /* Parse attributes if any.
   *
   * Note that by the time we get here, we have verified that the overall
   * structure of the packet is OK, and that any IPv4 Withdraw/Update NLRI
   * are also valid.  So, all is well so far.
   *
   * Certain attribute parsing errors should not be considered bad enough
   * to reset the session for, most particularly any partial/optional
   * attributes that have 'tunnelled' over speakers that don't understand
   * them. Instead we withdraw only the prefix concerned.
   *
   * Complicates the flow a little though..
   */
  qassert(args->aret == BGP_ATTR_PARSE_OK) ;

  if (attribute_len != 0)
    bgp_attr_parse (args, attr_p, attribute_len) ;

  /* Now we check for the "mandatory" attributes -- if we have one, other or
   * both update.length and mp_update.length.
   */
  if ((args->update.length != 0) || (args->mp_update.length != 0))
    bgp_attr_check(args) ;

  /* Dealing with any parsing issue and logging the attributes.
   */
  refused = false ;             /* assume all is well   */

  if ((args->aret != BGP_ATTR_PARSE_OK) || BGP_DEBUG (update, UPDATE_IN))
    {
      qstring qs ;
      int lvl ;

      if (args->aret == BGP_ATTR_PARSE_OK)
        {
          /* Debug logging only
           */
          lvl = LOG_DEBUG ;
        }
      else if (args->aret & BGP_ATTR_PARSE_CRITICAL)
        {
          /* Log as an ERROR
           */
          lvl = LOG_ERR ;

          zlog (prun->log, lvl,
            "%s rcvd UPDATE with fatal errors in attr(s)!!"
                                                      " Dropping session",
                                                               prun->name) ;
        }
      else if (args->aret & BGP_ATTR_PARSE_SERIOUS)
        {
          /* Log as an ERROR
           */
          lvl = LOG_ERR ;

          zlog (prun->log, lvl,
            "%s rcvd UPDATE with errors in attr(s)!!"
                                                  " Withdrawing route(s)",
                                                               prun->name) ;

          refused = true ;              /* not so good  */
        }
      else if (args->aret & BGP_ATTR_PARSE_IGNORE)
        {
          /* Log as a WARNING.  Treat as OK from now on.
           */
          lvl = LOG_WARNING ;

          zlog (prun->log, lvl,
            "%s rcvd UPDATE with errors in trivial attr(s)!!"
                                            " Ignoring those attributes.",
                                                               prun->name) ;
          args->aret = BGP_ATTR_PARSE_OK ;
        }
      else if (args->aret & BGP_ATTR_PARSE_RECOVERED)
        {
          /* Log as DEBUG.  Treat as OK from now on.
           */
          lvl = LOG_DEBUG ;

          zlog (prun->log, lvl,
            "%s rcvd UPDATE with recoverable errors in attr(s)!!"
                                            " Recovered those attributes.",
                                                               prun->name) ;
          args->aret = BGP_ATTR_PARSE_OK ;
        }
      else
        {
          /* This is bad...  unrecognised BGP_ATTR_PARSE_XXX value.
           *
           */
          lvl = LOG_CRIT ;

          zlog (prun->log, lvl,
            "[BUG] %s rcvd UPDATE: attribute parser return code=%u!!"
                                                      " Dropping session",
                                                     prun->name, args->aret) ;

          args->aret = BGP_ATTR_PARSE_CRITICAL ;        /* crunch       */

          args->notify_code     = BGP_NOMC_CEASE ;
          args->notify_subcode  = BGP_NOMS_UNSPECIFIC ;
          args->notify_data_len = 0 ;
        } ;

      /* Log attributes at the required level.
       */
      qs = bgp_dump_attr (prun, args->attrs->working,
          args->update.next_hop.type != nh_none    ? &args->update.next_hop
                                                   : NULL,
          args->mp_update.next_hop.type != nh_none ? &args->mp_update.next_hop
                                                   : NULL) ;
      if (qs != NULL)
        {
          zlog (prun->log, lvl, "%s rcvd UPDATE w/ attr: %s",
                                                prun->name, qs_string(qs)) ;
          qs_free(qs) ;
        } ;

      /* Stop now if have a critical error.
       */
      if (args->aret & BGP_ATTR_PARSE_CRITICAL)
         goto exit_bgp_update_critical ;
    } ;

  qassert( ((args->aret == BGP_ATTR_PARSE_OK)      && !refused) ||
           ((args->aret == BGP_ATTR_PARSE_SERIOUS) &&  refused) ) ;

  /* Now we process whatever NLRI we have and we are configured for.
   *
   * Note that at this stage we have whatever the UPDATE message contained,
   * notwithstanding which AFI/SAFI the session is actually negotiated for.
   * Completely unknown AFI/SAFI arrive here as qafx_other.
   *
   * TODO we have to worry about activated..., because we need values in the
   *      prib...  should we worry about negotiated ??
   */
  prib = prun->prib[qafx_ipv4_unicast] ;

  if (prib != NULL)
    {
      if (args->withdraw.length != 0)
        bpd_packet_update_nlri(prun, NULL, &args->withdraw, false) ;

      if (args->update.length != 0)
        {
          /* Now if we are going to use the attributes, it is time to store
           * them (complete with the relevant next hop), otherwise,
           * "treat-as-withdraw"
           *
           * We store the attribute set at this point because:
           *
           *   * as we parse each nlri we run filters and route-maps etc, and
           *     for each one need to start with the set of attributes as
           *     received.
           *
           *   * also, for soft-reconfig will want a stored version of the
           *     incoming attributes in any case.
           *
           *   * finally, this also works if we have some MP NLRI as well as
           *     the IPv4 Unicast -- which starts with this original set of
           *     attributes, but sets its own next-hop.
           */
          attr_set  set ;

          bgp_attr_pair_set_next_hop(args->attrs, args->update.next_hop.type,
                                                     &args->update.next_hop.ip) ;
          set = bgp_attr_pair_store(args->attrs) ;

          bpd_packet_update_nlri(prun, set, &args->update, refused) ;
        }
      else if ((args->withdraw.length == 0) && (attribute_len == 0))
        {
          /* End-of-RIB received
           */
          prib->eor_received = true ;

          /* NSF delete stale route
           */
          if (prib->nsf_mode)
            bgp_clear_stale_route (prun, qafx_ipv4_unicast);

          if (BGP_DEBUG (normal, NORMAL))
            zlog (prun->log, LOG_DEBUG,
                     "rcvd End-of-RIB for IPv4 Unicast from %s", prun->name) ;
        } ;
    } ;

  if (args->mp_withdraw.length != 0)
    {
      prib = prun->prib[args->mp_withdraw.qafx] ;
      if (prib != NULL)
        bpd_packet_update_nlri(prun, NULL, &args->mp_withdraw, false);
    } ;

  if (args->mp_update.length != 0)
    {
      prib = prun->prib[args->mp_update.qafx] ;
      if (prib != NULL)
        {
          /* Now if we are going to use the attributes, it is time to store
           * them (complete with the relevant next hop), otherwise,
           * "treat-as-withdraw"
           */
          attr_set  set ;

          bgp_attr_pair_set_next_hop(args->attrs, nh_none, NULL) ;

          if (args->mp_update.next_hop.type != nh_ipv6_2)
            {
              bgp_attr_pair_set_next_hop(args->attrs,
                                                args->mp_update.next_hop.type,
                                                 &args->mp_update.next_hop.ip) ;
            }
          else
            {
              bgp_attr_pair_set_next_hop(args->attrs, nh_ipv6_1,
                              &args->mp_update.next_hop.ip.v6[in6_global]) ;
              bgp_attr_pair_set_next_hop(args->attrs, nh_ipv6_2,
                              &args->mp_update.next_hop.ip.v6[in6_link_local]) ;
            } ;

          set = bgp_attr_pair_store(args->attrs) ;
          bpd_packet_update_nlri (prun, set, &args->mp_update, refused) ;
        } ;
    } ;

  if (args->mp_eor)
    {
      qassert((args->mp_withdraw.length | args->mp_update.length |
               args->withdraw.length    | args->update.length    ) == 0) ;

      prib = prun->prib[args->mp_withdraw.qafx] ;
      if (prib != NULL)
        {
          /* End-of-RIB received
           */
          if (!qafx_is_mpls_vpn(args->mp_withdraw.qafx))
            {
              prib->eor_received = true ;
              if (prib->nsf_mode)
                bgp_clear_stale_route (prun, args->mp_withdraw.qafx);
            } ;

          if (BGP_DEBUG (normal, NORMAL))
            zlog (prun->log, LOG_DEBUG, "rcvd End-of-RIB for %s/%s from %s",
           map_direct(bgp_afi_name_map, get_qAFI(args->mp_withdraw.qafx)).str,
           map_direct(bgp_safi_name_map, get_qSAFI(args->mp_withdraw.qafx)).str,
                                                                 prun->name) ;
        } ;
    } ;

  /* Everything is done.
   *
   * We are finished with the attribute pair, and anything left in the
   * args can now be discarded.
   */
 exit_bgp_update_receive:
  bgp_attr_pair_unload(args->attrs) ;

  if (args->asp != NULL)
    args->asp = as_path_free(args->asp) ;

  if (args->as4p != NULL)
    args->as4p = as_path_free(args->as4p) ;

  if (args->unknown != NULL)
    args->unknown = attr_unknown_free(args->unknown) ;

  return ;

  /* We have a Critical error on our hands -- issue NOTIFICATION and bring
   * down the curtain on the current session.
   */
 exit_bgp_update_critical:
   bgp_peer_down_error_with_data(prun, args->notify_code,
                                       args->notify_subcode,
                                       args->notify_data,
                                       args->notify_data_len) ;
  goto exit_bgp_update_receive ;
} ;

/*------------------------------------------------------------------------------
 * .
 *
 * NB: where there are attributes, the caller has a lock on them, and is
 *     responsible for that lock.
 *
 * NB: the NLRI will have already been sanity checked, but we make sure that
 *     we do not send any badly formed NLRI into the RIB -- so there is some
 *     (small) duplication of effort here.
 */
static void
bpd_packet_update_nlri(bgp_prun prun, attr_set attr, bgp_nlri nlri,
                                                                  bool refused)
{
  bgp_prib     prib ;
  const byte*  pnt ;
  const byte*  limit ;
  const byte*  prd ;
  sa_family_t  family ;
  prefix_t     pfx ;
  bool         mpls ;
  ulen         plen_max ;
  iroute_state_t parcel[1] ;

  qassert(!(refused && (attr == NULL))) ;       /* cannot refuse withdraw ! */

  /* Check peer status and address family.
   */
  if (prun->state != bgp_pEstablished)
    return ;

  mpls = false ;
  switch (nlri->qafx)
    {
      case qafx_ipv4_mpls_vpn:
        mpls = true ;
        fall_through ;

      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        family   = AF_INET ;
        plen_max = IPV4_MAX_PREFIXLEN ;
        break ;

#if HAVE_IPV6
      case qafx_ipv6_mpls_vpn:
        mpls = true ;
        fall_through ;

      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        family   = AF_INET6 ;
        plen_max = IPV6_MAX_PREFIXLEN ;
        break ;
#endif

      default:
        return ;
  } ;

  prib = prun->prib[nlri->qafx] ;
  if (prib == NULL)
    return ;

  /* Prepare the iroute_state_t -- apart from tags, does not change between
   * prefixes.
   *
   * Zeroizing sets:
   *
   *   * attr                   -- NULL     -- set below, if required
   *   * tags                   -- mpls_tags_null
   *
   *   * flags                  -- 0        -- sets RINFO_REFUSED if required
   *                                        -- sets RINFO_WITHDRAWN if required
   *
   *   * qafx                   -- X        -- set below
   *   * route_type             -- X        -- set below
   *
   * We start by zeroizing because may, well, later copy the entire
   * iroute_state_t
   */
  memset(parcel, 0, sizeof(iroute_state_t)) ;

  if (attr == NULL)
    parcel->flags     = RINFO_WITHDRAWN ;
  else
    {
      parcel->attr    = attr ;
      if (refused)
        parcel->flags = RINFO_REFUSED ;
    } ;
  parcel->qafx        = nlri->qafx ;

  if (bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) != 0)
    parcel->route_type = bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) ;

  /* Crunch through the NLRI
   *
   * Note that we make sure we start with a completely zeroized pfx.
   */
  pnt   = nlri->pnt;
  limit = pnt + nlri->length;

  prefix_default(&pfx, family) ;
  prd = NULL ;                          /* assume not MPLS      */

  while (1)
    {
      prefix_id_entry  pie ;
      const byte* pp ;
      usize       psize ;
      ulen        plen ;

      if (pnt == limit)
        return ;                        /* done                 */

      pp    = pnt ;
      plen  = *pp++ ;                   /* step past length     */
      psize = PSIZE (plen) ;

      pnt += 1 + psize ;                /* past length and body */
      if (pnt > limit)
        break ;                 /* Already checked.  Paranoia.  */

      /* Worry about Route Distinguisher and Tag, if required.
       *
       * Note that we have stepped 'pnt' already, so continue skips to next
       * prefix.
       */
      if (mpls)
        {
          if (psize < (8 + 3))
            break ;             /* Already checked.  Paranoia.  */

          /* Check for valid Route Distinguisher
           *
           * Log, but otherwise ignore unknown types.
           */
          prd = pp ;
          if (!mpls_rd_known_type(prd))
            {
              plog_err (prun->log,
                 "%s [Error] Update packet error: "
                                    "unknown RD type %u for %s NLRI",
                                             prun->name, mpls_rd_raw_type(pp),
                                                    get_qafx_name(nlri->qafx)) ;
              continue ;
            } ;

          /* Check for valid Tag Stack, and get it's value to parcel.
           *
           * Has already checked that the given tag stack is well formed, but
           * may have more than one entry.
           *
           * Quagga can only cope with single Tag... which is believed to
           * be the only possible/reasonable case.
           *
           * Log, but otherwise ignore more than one tag.
           */
          parcel->tags = mpls_tags_decode(pp + 8, 3) ;

          if (parcel->tags >= mpls_tags_bad)
            {
              plog_err (prun->log,
                 "%s [Error] Update packet error: "
                                    "more than one label for %s NLRI",
                                   prun->name, get_qafx_name(nlri->qafx)) ;
              continue ;
            } ;

          /* Step past the MPLS stuff.
           */
          pp   +=  8 + 3 ;
          plen -= (8 + 3) * 8 ;
        } ;

      /* Set and then check prefix.
       *
       * NB: have stepped past the prefix, so can 'continue' if want to ignore
       *     the current prefix.
       */
      if (plen > plen_max)
        break ;                 /* checked already -- paranoia  */

      prefix_body_from_nlri(&pfx, pp, plen) ;

      switch (nlri->qafx)
        {
          case qafx_ipv4_unicast:
            if (IN_CLASSD (ntohl (pfx.u.prefix4.s_addr)))
              {
               /* From draft-ietf-idr-bgp4-22, Section 6.3:
                * If a BGP router receives an UPDATE message with a
                * semantically incorrect NLRI field, in which a prefix is
                * semantically incorrect (eg. an unexpected multicast IP
                * address), it should ignore the prefix.
                */
                zlog (prun->log, LOG_ERR,
                      "IPv4 unicast NLRI is multicast address %s",
                                           siptoa (family, &pfx.u.prefix).str) ;
                continue ;
              } ;

            break ;

          case qafx_ipv4_multicast:
            /* XXX ??? checks on IPv4 multicast NLRI ??
             */
            break ;

          case qafx_ipv4_mpls_vpn:
            /* XXX ??? checks on IPv4 MPLS VPN NLRI ??
             */
            break ;

#if HAVE_IPV6
          case qafx_ipv6_unicast:
            if (IN6_IS_ADDR_LINKLOCAL (&pfx.u.prefix6))
              {
                zlog (prun->log, LOG_WARNING,
                      "IPv6 link-local NLRI received %s ignore this NLRI",
                                             siptoa (family, &pfx.u.prefix).str) ;
                continue;
              } ;
            break ;

          case qafx_ipv6_multicast:
            /* XXX ??? checks on IPv6 multicast NLRI ??
             */
            break ;

          case qafx_ipv6_mpls_vpn:
            /* XXX ??? checks on IPv6 MPLS VPN NLRI ??
             */
            break ;
#endif

          default:
            return ;
        } ;

      /* We are ready to update the adj-in !
       *
       * Map the prefix and any RD to its prefix_id_entry.  This locks the
       * prefix_id_entry, pro tem.
       */
      pie = prefix_id_find_entry(&pfx, prd) ;     /* locks the entry      */

      bgp_adj_in_update_prefix(prib, pie, parcel) ;

      prefix_id_entry_dec_ref(pie) ;
    } ;

  /* Arrives here only if and only if finds that the given bgp_nlri are
   * broken -- that is either: a prefix length is invalid for the address
   * family, or the sum of the prefix lengths overruns the length of the
   * bgp_nlri.
   *
   * This should not happen, because the bgp_nlri are set after sanity checking
   * those things !
   *
   * TODO suitable logging
   */



  return ;
} ;

/*------------------------------------------------------------------------------
 * Process incoming route refresh
 *
 * Note that at this stage we have no interest in whether was RFC or not !
 */
static void
bgp_packet_read_rr(bgp_prun prun, sucker sr)
{
  bgp_route_refresh rr ;
  qafx_t qafx ;
  bgp_prib     prib ;

  /* Parse the message into a new bgp_route_refresh object -- if can.
   *
   * Establish which address family is affected, if any.
   */
  rr = bgp_packet_parse_rr(prun, sr) ;
  if (rr == NULL)
    return ;

  qafx = qafx_from_i(rr->i_afi, rr->i_safi) ;
  prib = prun->prib[qafx] ;

  if (prib == NULL)
    return ;

  /* Deal with the ORF, if any.
   */
  if (bgp_orf_get_count(rr) > 0)
    {
      vector_index_t i ;
      bgp_orf_name name ;

      prefix_bgp_orf_name_set(name, prun->su_name, qafx) ;

      for (i = 0; i < bgp_orf_get_count(rr) ; ++i)
        {
          bgp_orf_entry orfe ;

          orfe = vector_slot(rr->entries, i);

          if (orfe->unknown)
            continue ;          /* ignore unknown       */

          if (orfe->orf_type == BGP_ORF_T_PFX)
            {
              cmd_ret_t ret ;

              if (orfe->remove_all)
                {
                  if (BGP_DEBUG (normal, NORMAL))
                    zlog_debug ("%s rcvd Remove-All pfxlist ORF request",
                                                                 prun->name) ;
                  prefix_bgp_orf_remove_all (name);
                  break;
                }

              qassert(orfe->deny ==
                                (orfe->body.orfpv.type == PREFIX_DENY)) ;
              ret = prefix_bgp_orf_set (name, get_qAFI(qafx),
                                             &orfe->body.orfpv, !orfe->remove) ;

              if (ret != CMD_SUCCESS)
                {
                  if (BGP_DEBUG (normal, NORMAL))
                    zlog_debug ("%s Received misformatted prefixlist ORF."
                                           "Remove All pfxlist", prun->name) ;
                  prefix_bgp_orf_remove_all (name);
                  break;
                }

              prib->orf_plist = prefix_list_lookup (qAFI_ORF_PREFIX, name);
            } ;
        } ;

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s rcvd Refresh %s ORF request", prun->name,
                                            rr->defer ? "Defer" : "Immediate") ;
      if (rr->defer)
        return;
    }

  /* If we were deferring sending the RIB to the peer, then we stop doing
   * so, now.
   */
  prib->orf_pfx_wait = false ;

  /* Perform route refreshment to the peer
   */
  bgp_announce_family(prun, qafx, 10);
} ;

/*==============================================================================
 * BGP ROUTE-REFRESH message parsing
 */
static bool bgp_packet_orf_recv(bgp_route_refresh rr,
                                    sa_family_t paf, sucker sr, bgp_prun prun) ;

/*------------------------------------------------------------------------------
 * Parse BGP ROUTE-REFRESH message
 *
 * This may contain ORF stuff !
 *
 * Returns:  NULL <=> OK  -- *p_rr set to the bgp_route_refresh object
 *           otherwise = bgp_notify for suitable error message
 *                        -- *p_rr set to NULL
 *
 * NB: if the connection is not fsEstablished, then will not parse
 */
static bgp_route_refresh
bgp_packet_parse_rr(bgp_prun prun, sucker sr)
{
  bgp_route_refresh rr ;
  ptr_t        p ;
  int          left ;
  iAFI_SAFI_t  mp[1] ;
  qafx_bit_t   qb ;
  bool         ok ;

  /* Start with AFI, reserved, SAFI
   */
  p = suck_step(sr, BGP_RRM_BODY_MIN_L) ;

  left = suck_left(sr) ;
  if (left < 0)
    {
      /* This should not happen -- because is checked for in the BGP Engine.
       *
       * But we don't want to proceed with rubbish !
       */
      zlog_err ("%s Route Refresh message body too short at %u bytes",
                                      prun->name, BGP_RRM_BODY_MIN_L + left) ;

      bgp_peer_down_error (prun, BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
      return NULL ;
    } ;

  confirm(BGP_RRM_BODY_MIN_L == 4) ;
  confirm((BGP_RRM_AFI       == 0) && (sizeof(BGP_RRM_AFI_T)  == 2)) ;
  confirm((BGP_RRM_RES       == 2) && (sizeof(BGP_RRM_RES_T)  == 1)) ;
  confirm((BGP_RRM_SAFI      == 3) && (sizeof(BGP_RRM_SAFI_T) == 1)) ;

  mp->i_afi  = load_ns(&p[BGP_RRM_AFI]) ;
  mp->i_safi = load_b( &p[BGP_RRM_SAFI]) ;

  qb = qafx_bit_from_i(mp->i_afi, mp->i_safi) ;

  if ((qb & prun->af_running) == qafx_empty_set)
    {
      /* This should not happen -- because is checked for in the BGP Engine.
       *
       * But we don't want to proceed with rubbish !
       */
      zlog_err ("%s Route Refresh message with unexpected afi/safi %u/%u",
                                          prun->name, mp->i_afi, mp->i_safi) ;

      bgp_peer_down_error (prun, BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
      return NULL ;
    } ;

  rr = bgp_route_refresh_new(mp->i_afi, mp->i_safi, (left == 0) ? 0 : 100) ;

  /* If there are any ORF entries, time to suck them up now.
   */
  ok = true ;

  if ((left > 0) && ok)
    {
      uint8_t when_to_refresh ;
      bool    defer ;

      when_to_refresh = suck_b(sr) ;

      switch (when_to_refresh)
        {
          case BGP_ORF_WTR_IMMEDIATE:
            defer = false ;
            break ;

          case BGP_ORF_WTR_DEFER:
            defer = true ;
            break ;

          default:
            plog_warn(prun->log,
               "%s ORF route refresh invalid 'when' value %d (AFI/SAFI %u/%u)",
                         prun->name, when_to_refresh, rr->i_afi, rr->i_safi) ;
            defer = false ;
            ok    = false ;
            break ;
        } ;

      if (ok)
        {
          sa_family_t paf ;

          paf = get_qafx_sa_family(qafx_from_i(mp->i_afi, mp->i_safi)) ;

          bgp_route_refresh_set_orf_defer(rr, defer) ;

          /* After the when to refresh, expect 1 or more ORFs           */
          do
            {
              ok = bgp_packet_orf_recv(rr, paf, sr, prun) ;
              left = suck_left(sr) ;
            } while ((left > 0) && ok) ;
        } ;
    } ;

  if ((left < 0) && !ok)
    {
      rr = bgp_route_refresh_free(rr) ;
      bgp_peer_down_error (prun, BGP_NOMC_CEASE, BGP_NOMS_UNSPECIFIC) ;
    } ;

  return rr ;
} ;

/*------------------------------------------------------------------------------
 * Process ORF Type and following ORF Entries.
 *
 * Expects there to be at least one ORF entry -- that is, the length of the
 * ORF Entries may not be 0.
 *
 * Returns:  true  <=> OK
 *           false  => invalid or malformed
 */
static bool
bgp_packet_orf_recv(bgp_route_refresh rr,
                                      sa_family_t paf, sucker sr, bgp_prun prun)
{
  bgp_session_args_c args ;
  sucker_t   ssr[1] ;
  int        left ;
  uint8_t    orf_type ;
  bgp_size_t orf_len ;
  bool       can ;

  /* Suck up the ORF type and the length of the entries that follow
   */
  left = suck_left(sr) - BGP_ORF_MIN_L ;
  if (left >= 0)
    {
      orf_type  = suck_b(sr) ;
      orf_len   = suck_w(sr) ;
    }
  else
    {
      orf_type  = 0 ;   /* ensure initialised   */
      orf_len   = 0 ;
    } ;

  /* The length may not be zero and may not exceed what there is left
   */
  if ((orf_len == 0) || (left < orf_len))
    {
      plog_warn(prun->log,
                  "%s ORF route refresh length error: %d when %d left"
                                       " (AFI/SAFI %d/%d, type %d length %d)",
        prun->name, orf_len, left, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
      return false ;
    } ;

  if (BGP_DEBUG (normal, NORMAL))
    plog_debug (prun->log, "%s rcvd ORF type %d length %d",
                                              prun->name, orf_type, orf_len) ;

  /* Sex the ORF type -- accept only if negotiated it
   *
   * We assume that if both are negotiated, that we need only process the
   * RFC Type.
   *
   * Note that for the negotiated can_orf_pfx, ORF_RM is set if we have
   * received *either* Type, but ORF_RM_pre is set only if we only received
   * the pre-RFC type.
   */
  args = prun->session->args ;
  switch (orf_type)
    {
      case BGP_ORF_T_PFX:
        can = (args->can_orf_pfx.af[rr->qafx] & (ORF_RM | ORF_RM_pre))
                                             ==  ORF_RM ;
        break ;

      case BGP_ORF_T_PFX_pre:
        can = (args->can_orf_pfx.af[rr->qafx] & (ORF_RM | ORF_RM_pre))
                                             == (ORF_RM | ORF_RM_pre);
        break ;

      default:
        can = false ;
        break ;
    } ;

  /* Suck up the ORF entries.  NB: orf_len != 0
   */
  suck_sub_init(ssr, sr, orf_len) ;

  if (!can)
    bgp_orf_add_unknown(rr, orf_type, orf_len, suck_step(ssr, orf_len)) ;
  else
    {
      /* We only actually know about BGP_ORF_T_PFX and BGP_ORF_T_PFX_pre
       *
       * We store the ORF as BGP_ORF_T_PFX (the RFC version), and somewhere
       * deep in the output code we look after outputting stuff in pre-RFC
       * form, if that is required.
       */
      while (suck_left(ssr) > 0)
        {
          bool remove_all, remove ;
          uint8_t common ;

          remove_all = false ;
          remove     = false ;
          common = suck_b(ssr) ;
          switch (common & BGP_ORF_EA_MASK)
            {
              case BGP_ORF_EA_ADD:
                break ;

              case BGP_ORF_EA_REMOVE:
                remove = true ;
                break ;

              case BGP_ORF_EA_RM_ALL:
                remove_all = true ;
                break ;

              default:
                plog_warn(prun->log,
                            "%s ORF route refresh invalid common byte: %u"
                                        " (AFI/SAFI %d/%d, type %d length %d)",
              prun->name, common, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
                return false ;
            } ;

          if (remove_all)
            bgp_orf_add_remove_all(rr, BGP_ORF_T_PFX) ;
          else
            {
              bgp_orf_entry    orfe ;
              orf_prefix_value orfpv ;
              bool    deny ;
              int left ;

              deny = (common & BGP_ORF_EA_DENY) ;

              orfe = bgp_orf_add(rr, BGP_ORF_T_PFX, remove, deny) ;
              orfpv = &orfe->body.orfpv ;

              /* Need the minimum Prefix ORF entry, less the common byte.
               */
              left = suck_left(sr) - (BGP_ORF_E_P_MIN_L - BGP_ORF_E_COM_L) ;
              if (left >= 0)
                {
                  uint8_t plen ;
                  uint8_t blen ;

                  memset(orfpv, 0, sizeof(orf_prefix_value_t)) ;

                  orfpv->seq   = suck_l(sr) ;
                  orfpv->type  = deny ? PREFIX_DENY : PREFIX_PERMIT ;
                  orfpv->ge    = suck_b(sr) ;       /* aka min      */
                  orfpv->le    = suck_b(sr) ;       /* aka max      */
                  plen         = suck_b(sr) ;

                  blen = (plen + 7) / 8 ;
                  if ((left -= blen) >= 0)
                    {
                      orfpv->pfx.family    = paf ;
                      orfpv->pfx.prefixlen = plen ;
                      if (blen != 0)
                        {
                          if (blen <= prefix_byte_len(&orfpv->pfx))
                            memcpy(&orfpv->pfx.u.prefix, suck_step(sr, blen),
                                                                         blen) ;
                          else
                            left = -1 ;
                        } ;
                    } ;
                } ;

              if (left < 0)
                {
                  plog_info (prun->log,
                              "%s ORF route refresh invalid Prefix ORF entry"
                                       " (AFI/SAFI %d/%d, type %d length %d)",
                       prun->name, rr->i_afi, rr->i_safi, orf_type, orf_len) ;
                  return false ;
                } ;
            } ;

        } ;
    } ;

  return suck_check_complete(ssr) ;
} ;

/*==============================================================================
 * Dynamic capabilities seems to have died a death... was not fully
 * supported in any case.
 */
#if 0
/* Send capability message to the peer. */

/* xTODO: require BGP Engine support for Dynamic Capability messages.    */

extern void
bgp_capability_send (bgp_peer peer, qafx_t qafx, int capability_code,
                                                                     int action)
{
  struct stream *s;
  uint   length;

  s = peer->work;
  stream_reset (s);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MT_CAPABILITY);

  /* Encode MP_EXT capability. */
  if (capability_code == BGP_CAN_MP_EXT)
    {
      stream_putc (s, action);
      stream_putc (s, BGP_CAN_MP_EXT);
      stream_putc (s, BGP_CAP_MPE_L);
      stream_putw (s, get_iAFI(qafx));
      stream_putc (s, 0);
      stream_putc (s, get_iSAFI(qafx));

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s sending CAPABILITY has %s MP_EXT CAP for afi/safi: %d/%d",
                 prun->name, action == CAPABILITY_ACTION_SET ?
                   "Advertising" : "Removing", get_iAFI(qafx), get_iSAFI(qafx));
    }

  /* Set packet size.
   *
   * Impossible to overflow the BGP Message buffer
   */
  length = bgp_packet_set_size (s);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
                                       prun->name, BGP_MT_CAPABILITY, length);

  /* Add packet to the peer.
   */
  bgp_write(peer, s);
}

/* xTODO there is a lot of recent activity eg commit 1212dc1961... to do with
 * AFI/SAFI stuff...  Need to fully catch up !!
 *
 * This version -- modified to return a qafx_t...
 *
 * Returns:  qafx_xxxx  if is known AFI/SAFI
 *           qafx_other if is unknown or undefined
 *
 * Issues a log error if is undefined
 * Issues a log debug if is unknown
 */
static qafx_t
bgp_afi_safi_valid_indices (iAFI_t i_afi, iSAFI_t i_safi)
{
#if 0           /* xTODO BGP_SAFI_VPNV4 and BGP_SAFI_VPNV6 ????  */
  /* VPNvX are AFI specific */
  if ((afi == AFI_IP6 && *safi == BGP_SAFI_VPNV4)
      || (afi == AFI_IP && *safi == BGP_SAFI_VPNV6))
    {
      zlog_warn ("Invalid afi/safi combination (%u/%u)", afi, *safi);
      return 0;
    }
#endif

  qafx_t  qafx ;

  qafx = qafx_from_i(i_afi, i_safi) ;

  if (qafx == qafx_undef)
    {
      zlog_err("undefined iAFI/iSAFI (%u/%u)", i_afi, i_safi) ;
      return qafx_other ;
    } ;

  if (qafx == qafx_other)
    zlog_debug ("unknown iAFI/iSAFI (%u/%u)", i_afi, i_safi) ;

  return qafx ;
} ;

/*==============================================================================
 * Dynamic Capability Message handling.
 */
static int
bgp_capability_msg_parse (bgp_peer peer, u_char *pnt, bgp_size_t length)
{
  u_char *end;
  struct capability_mp_data mpc;
  struct capability_header *hdr;
  u_char action;

  end = pnt + length;

  while (pnt < end)
    {
      /* We need at least action, capability code and capability length.
       */
      if (pnt + 3 > end)
        {
          zlog_info ("%s Capability length error", prun->name);
          /* xTODO: Is this the right notification ??           */
          bgp_peer_down_error (peer, BGP_NOMC_CEASE, 0);
          return -1;
        }
      action = *pnt;
      hdr = (struct capability_header *)(pnt + 1);

      /* Action value check.
       */
      if ( (action != CAPABILITY_ACTION_SET) &&
           (action != CAPABILITY_ACTION_UNSET) )
        {
          zlog_info ("%s Capability Action Value error %d",
                     prun->name, action);
          /* xTODO: Is this the right notification ??           */
          bgp_peer_down_error (peer, BGP_NOMC_CEASE, 0);
          return -1;
        }

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s CAPABILITY has action: %d, code: %u, length %u",
                                 prun->name, action, hdr->code, hdr->length);

      /* Capability length check. */
      if ((pnt + hdr->length + 3) > end)
        {
          zlog_info ("%s Capability length error", prun->name);
          /* xTODO: Is this the right notification ??           */
          bgp_peer_down_error (peer, BGP_NOMC_CEASE, 0);
          return -1;
        }

      /* Fetch structure from the byte stream. */
      memcpy (&mpc, pnt + 3, sizeof (struct capability_mp_data));

      pnt += hdr->length + 3;

      /* We know MP Capability Code.
       */
      if (hdr->code == BGP_CAN_MP_EXT)
        {
          iAFI_t  i_afi;
          iSAFI_t i_safi;
          qafx_t qafx ;

          i_afi  = ntohs (mpc.i_afi);
          i_safi = mpc.i_safi;

          qafx = bgp_afi_safi_valid_indices (mpc.i_afi, mpc.i_safi) ;

          if (qafx == qafx_other)
            {
              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s Dynamic Capability MP_EXT afi/safi invalid "
                            "(%u/%u)", prun->name, i_afi, i_safi);
              continue;
            }

          /* Ignore capability when override-capability is set.
           */
          if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
            continue;

          /* Address family check.  */
          if (BGP_DEBUG (normal, NORMAL))
            zlog_debug ("%s CAPABILITY has %s MP_EXT CAP for afi/safi: %u/%u",
                       prun->name,
                       (action == CAPABILITY_ACTION_SET) ? "Advertising"
                                                         : "Removing",
                       i_afi , i_safi);

          if (action == CAPABILITY_ACTION_SET)
            {
              peer->af_rcv |= qafx_bit(qafx) ;
              if (peer_family_is_active(peer, qafx))
                {
                  peer->af_use |= qafx_bit(qafx) ;
                  bgp_announce_family (peer, qafx);
                }
            }
          else
            {
              peer->af_rcv &= ~qafx_bit(qafx) ;
              peer->af_use &= ~qafx_bit(qafx) ;

              if (peer->af_use != qafx_empty_set)
                bgp_clear_routes (peer, qafx, false);
              else
                {
                  /* xTODO: only used for unit tests.  Test will need fixing
                   */
#if 0
                BGP_EVENT_ADD (peer, BGP_Stop);
#endif
                } ;
            } ;
        }
      else
        {
          zlog_warn ("%s unrecognized capability code: %u - ignored",
                     prun->name, hdr->code);
        } ;
    }
  return 0;
}

/* Dynamic Capability is received.
 *
 * This is exported for unit-test purposes
 */
extern int bgp_capability_receive(bgp_peer , bgp_size_t) ;

int
bgp_capability_receive (bgp_peer peer, bgp_size_t size)
{
  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s rcv CAPABILITY", prun->name);

  /* If peer does not have the capability, send notification.
   */
  if (! CHECK_FLAG (peer->caps_rcv, PEER_CAP_DYNAMIC | PEER_CAP_DYNAMIC_dep))
    {
      u_char *pnt;

      plog_err (peer->log, "%s [Error] BGP dynamic capability is not enabled",
                                                                 prun->name) ;

      pnt = stream_get_data(peer->ibuf) + BGP_MH_TYPE ;
      bgp_peer_down_error_with_data(peer, BGP_NOMC_HEADER, BGP_NOMS_H_BAD_TYPE,
                                                                       pnt, 1) ;
      return -1;
    }

  /* Status must be Established.
   */
  if (peer->state != bgp_pEstablished)
    {
      plog_err (peer->log,
                "%s [Error] Dynamic capability packet received under status %s",
              prun->name, map_direct(bgp_peer_status_map, peer->state).str) ;
      bgp_peer_down_error (peer, BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC) ;

      return -1;
    }

  /* Parse packet.
   */
  return bgp_capability_msg_parse (peer, stream_get_pnt (peer->ibuf), size);
}

#endif
