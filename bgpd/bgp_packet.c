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

#include "thread.h"
#include "stream.h"
#include "network.h"
#include "prefix.h"
#include "prefix_id.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "linklist.h"

#include "bgpd/bgpd.h"

#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_adj_out.h"

//#include "bgpd/bgp_table.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
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

static stream bgp_write_packet (bgp_peer peer) ;
static stream bgp_update_packet (peer_rib prib, route_out_parcel parcel) ;
static stream bgp_withdraw_packet (peer_rib prib, route_out_parcel parcel) ;
static stream bgp_update_packet_eor (peer_rib prib, route_out_parcel parcel) ;

/*------------------------------------------------------------------------------
 * Write packets to the peer -- subject to the XON flow control.
 *
 * Takes an optional stream argument, if not NULL then must be peer->work,
 * in which there is a message to be sent.
 *
 * Then processes the peer->sync structure to generate further updates.
 *
 * TODO: work out how bgp_routeadv_timer fits into this.
 */
extern void
bgp_write (bgp_peer peer, struct stream* s)
{
  /* If we are given a message, send that first and no matter what
   */
  if (s != NULL)
    if (bgp_packet_check_size(s, peer->su_remote) > 0)
      stream_fifo_push(peer->obuf_fifo, stream_dup(s)) ;

  /* While we are XON, queue pending updates (while there are any to go)
   */
  while (bgp_session_is_XON(peer))
    {
      s = bgp_write_packet(peer);           /* uses peer->work          */
      if (s == NULL)
        break;

      if (bgp_packet_check_size(s, peer->su_remote) > 0)
        {
          /* Append to fifo
           */
          stream_fifo_push (peer->obuf_fifo, stream_dup(s)) ;

          /* Count down flow control, send fifo if hits BGP_XON_KICK
           */
          if (bgp_session_dec_flow_count(peer))
            bgp_session_update_send(peer->session, peer->obuf_fifo) ;
        } ;
    } ;

  /* In any case, send what's in the FIFO
   */
  if (stream_fifo_head(peer->obuf_fifo) != NULL)
    bgp_session_update_send(peer->session, peer->obuf_fifo) ;
} ;

/*------------------------------------------------------------------------------
 * Get next update message to be written.
 *
 * Generates complete BGP message in the peer->work stream structure.
 *
 * Returns: peer->work -- if have something to be written.
 *          NULL       -- otherwise
 */
static stream
bgp_write_packet (bgp_peer peer)
{
  qafx_t       qafx ;
  peer_rib     prib ;
  route_out_parcel_t parcel_s ;
  route_out_parcel   parcel ;

  /* Deal with any and all withdrawn prefixes first
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      prib = peer->prib[qafx] ;

      if ((prib == NULL) || (true))
        continue ;

      /* If we get a parcel, then we have at least one prefix to withdraw,
       * so will always generate a message.
       */
      parcel = bgp_adj_out_next_withdraw(prib, &parcel_s) ;

      if (parcel != NULL)
        return bgp_withdraw_packet(prib, parcel) ;
    } ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      prib = peer->prib[qafx] ;

      if ((prib == NULL) || (true))
        continue ;

      parcel = bgp_adj_out_first_announce(prib, &parcel_s) ;

      while (parcel != NULL)
        {
          stream  s ;

          if (parcel->action == ra_out_eor)
            s = bgp_update_packet_eor(prib, parcel) ;
          else
            s = bgp_update_packet(prib, parcel) ;

          if (s != NULL)
            return s ;

          parcel = bgp_adj_out_next_announce(prib, &parcel_s) ;
        } ;
    } ;

  return NULL;
}

/*------------------------------------------------------------------------------
 * Construct an update from the given route_out_parcel.
 *
 * Generates complete BGP message in the peer->work stream structure.
 *
 * Returns: peer->work -- if have something to be written.
 *          NULL       -- otherwise
 *
 * NB: if the attributes overflow the BGP message, suppresses the update and
 *     issues a withdraw for the affected prefixes if required.
 *
 *     In this case, if none of the affected prefixes needs to be withdrawn
 *     (ie, this is the initial announce for all of them) then no message
 *     is generated.
 */
static stream
bgp_update_packet (peer_rib prib, route_out_parcel parcel)
{
  stream    s;
  ulen      attr_lp ;
  ulen      attr_len ;
  qstring   updates ;
  uint      count ;
  prefix_id_entry pie ;
  attr_set  attr_sent ;

  qassert( (parcel->action == ra_out_initial) ||
           (parcel->action == ra_out_update) ) ;
  qassert(parcel->qafx   == prib->qafx) ;
  qassert(parcel->attr   != NULL) ;

  s = prib->peer->work;
  stream_reset (s);

  pie = prefix_id_get_entry(parcel->pfx_id) ;

  if (BGP_DEBUG (update, UPDATE_OUT))
    updates = qs_new(100) ;
  else
    updates = NULL ;

  /* Generate the message, including one prefix.
   */
  bgp_packet_set_marker (s, BGP_MT_UPDATE);
  stream_putw (s, 0);   /* No AFI_IP/SAFI_UNICAST withdrawn     */

  attr_lp = stream_get_endp (s);
  qassert(attr_lp == (BGP_MSG_HEAD_L + 2)) ;

  stream_putw (s, 0);   /* Attributes length                    */

  attr_len = bgp_packet_attribute (s, prib, parcel->attr, pie->pfx,
                                                                  parcel->tag) ;
  stream_putw_at (s, attr_lp, attr_len) ;

  if (prib->qafx == qafx_ipv4_unicast)
    stream_put_prefix (s, pie->pfx);

  attr_sent = bgp_attr_lock(parcel->attr) ;

  bgp_adj_out_done_announce(prib, parcel) ;
  count = 1 ;

  /* If the attributes with at least one prefix have fitted, then all is well,
   * and for AFI_IP/SAFI_UNICAST we can tack on other prefixes which share the
   * current attributes.
   *
   * Otherwise, we have a problem, and we issue a route withdraw, instead.
   *
   * NB: we allocate BGP_STREAM_SIZE, which is larger than BGP_MSG_MAX_L,
   *     so that if the overflow is marginal, we can tell what it was.
   */
  if (bgp_packet_check_size(s, prib->peer->su_remote) > 0)
    {
      /* Eat the prefix we have already included in the message.
       *
       * Then for AFI_IP/SAFI_UNICAST, eat as many further prefixes as we can
       * fit into the message.
       */
      if (parcel->action == ra_out_initial)
        prib->scount += 1 ;

      if (prib->qafx == qafx_ipv4_unicast)
        {
          qassert(!stream_has_overflowed(s)) ;

          while (1)
            {
              ulen   len_was ;

              parcel = bgp_adj_out_next_announce(prib, parcel) ;
              if ((parcel == NULL) || (parcel->attr != attr_sent))
                break ;

              pie = prefix_id_get_entry(parcel->pfx_id) ;

              len_was = stream_get_len(s) ;
              stream_put_prefix (s, pie->pfx) ;

              if (stream_has_written_beyond(s, BGP_MSG_MAX_L))
                {
                  stream_set_endp(s, len_was) ;
                  stream_clear_overflow(s) ;
                  break ;
                } ;

              if (parcel->action == ra_out_initial)
                prib->scount += 1 ;

              bgp_adj_out_done_announce(prib, parcel) ;
              count += 1 ;
            } ;
        } ;

      /* Report the update if required.
       */
      if (updates != NULL)
        {
          qstring qs ;
          attr_next_hop_t* next_hop, * mp_next_hop ;

          next_hop = mp_next_hop = NULL ;
          if (prib->qafx == qafx_ipv4_unicast)
            next_hop    = &attr_sent->next_hop ;
          else
            mp_next_hop = &attr_sent->next_hop ;

          qs = bgp_dump_attr(prib->peer, attr_sent, next_hop, mp_next_hop) ;

          zlog (prib->peer->log, LOG_DEBUG, "%s send %u UPDATE(S) %s/%s:%s%s",
                      prib->peer->host, count,
                      map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                      map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                            qs_string(qs), qs_string(updates)) ;
          qs_free(qs) ;
          qs_free(updates) ;
        } ;

      bgp_attr_unlock(attr_sent) ;
    }
  else
    {
      /* Turn advertisement into withdraw of prefixes for which we are
       * completely unable to generate an update message.
       *
       * At this point, we have attempted to place just one NLRI in the output
       * message -- the one for the bgp_adv we came in on.
       *
       * NB: the result looks as though the prefixes *have* been advertised.
       *
       *     This avoids trying to send the same set of attributes again...
       *
       *     ...but is not a complete solution, yet.   TODO
       */
      uint withdrawn ;

      withdrawn = 0 ;

      if (updates == NULL)
        updates = qs_new(100) ;

      stream_set_endp(s, attr_lp) ;     /* as you was   */
      stream_clear_overflow(s) ;

      qassert(attr_lp == (BGP_MSG_HEAD_L + 2)) ;

      if (prib->qafx == qafx_ipv4_unicast)
        {
          /* Fill in withdrawn AFI_IP/SAFI_UNICAST
           *
           * We are guaranteed to be able to fit at least one withdraw !
           * Cope with running out of room in the message, though.
           */
          ulen  start ;

          qassert(!stream_has_overflowed(s)) ;

          start = attr_lp ;     /* start of withdrawn pnt              */

          while(1)
            {
              if (parcel->action == ra_out_update)
                {
                  stream_put_prefix (s, pie->pfx);

                  if (stream_has_written_beyond(s, BGP_MSG_MAX_L - 2))
                    {
                      stream_set_endp(s, attr_lp) ; /* back one     */
                      stream_clear_overflow(s) ;
                      break ;
                    } ;

                  withdrawn += 1 ;
                } ;

              attr_lp = stream_get_endp(s) ;

              bgp_adj_out_done_announce(prib, parcel) ;
              count += 1 ;

              parcel = bgp_adj_out_next_announce(prib, parcel) ;
              if ((parcel == NULL) || (parcel->attr != attr_sent))
                break ;

              pie = prefix_id_get_entry(parcel->pfx_id) ;
            } ;

          stream_putw_at(s, start - 2, attr_lp - start) ;
          stream_putw(s, 0) ;           /* no attributes        */
        }
      else
        {
          if (parcel->action == ra_out_update)
            {
              stream_putw (s, 0);       /* Attributes length    */

              attr_len = bgp_unreach_attribute (s, pie->pfx, prib->qafx) ;

              stream_putw_at (s, attr_lp, attr_len);
              withdrawn += 1 ;
            } ;

          bgp_adj_out_done_announce(prib, parcel) ;
          count += 1 ;
        } ;

      /* Now log the error
       */
      zlog_err("%s FORCED %u/%u WITHDRAW(S) %s/%s:%s",
                       prib->peer->host, withdrawn, count,
                       map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                       map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                                           qs_string(updates)) ;
      qs_free(updates) ;

      /* If we have no actual withdraws, exit now
       */
      bgp_attr_unlock(attr_sent) ;

      if (withdrawn == 0)
        return NULL ;

      prib->scount -= withdrawn ;
    } ;

  /* The message is complete -- and kept to size, above.
   */
  bgp_packet_set_size (s) ;

  return s ;
} ;

/*------------------------------------------------------------------------------
 * Construct a withdraw update starting with the given parcel, and then eating
 * as much as possible of the prib's withdraw queue.
 *
 * Generates complete BGP message in the peer->work stream structure.
 *
 * Returns: peer->work -- if have something to be written.
 *
 * NB: the given parcel will be a withdraw, so always creates a message
 */
static stream
bgp_withdraw_packet (peer_rib prib, route_out_parcel parcel)
{
  stream  s;
  uint    withdrawn ;
  qstring updates ;
  ulen    len_p, len_ap, limit, end_p ;

  if (BGP_DEBUG (update, UPDATE_OUT))
    updates = qs_new(100) ;
  else
    updates = NULL ;

  s = prib->peer->work;
  stream_reset (s);

  bgp_packet_set_marker (s, BGP_MT_UPDATE);
  stream_putw (s, 0) ;          /* Withdraw length      */

  if (prib->qafx == qafx_ipv4_unicast)
    {
      len_p  = stream_get_endp(s) ;
      len_ap = 0 ;
      limit  = BGP_MSG_MAX_L - 2 ;
    }
  else
    {
      stream_putw(s, 0) ;       /* Attributes length    */

      len_p  = stream_get_endp(s) ;

      stream_putc(s, BGP_ATF_OPTIONAL | BGP_ATF_EXTENDED) ;
      stream_putc(s, BGP_ATT_MP_UNREACH_NLRI) ;
      stream_putw(s, 0) ;

      len_ap = stream_get_endp(s) ;
      limit  = BGP_MSG_MAX_L ;

      stream_putw (s, get_iAFI(prib->qafx));
      stream_putc (s, get_iSAFI(prib->qafx));
    } ;

  withdrawn = 0 ;
  end_p = stream_get_endp(s) ;

  do
    {
      prefix_id_entry pie ;

      qassert(parcel->action  == ra_out_withdraw) ;
      qassert(parcel->attr    == NULL) ;
      qassert(parcel->qafx    == prib->qafx) ;

      pie = prefix_id_get_entry(parcel->pfx_id) ;

      bgp_packet_withdraw_prefix(s, pie->pfx, prib->qafx) ;

      if (stream_has_written_beyond(s, limit))
        {
          stream_set_endp(s, end_p) ;       /* as you was   */
          stream_clear_overflow(s) ;
          break ;
        } ;

      end_p = stream_get_endp(s) ;

      withdrawn += 1 ;

      if (updates != NULL)
        {
          qs_append_str(updates, " ") ;
          qs_append_str(updates, spfxtoa(pie->pfx).str) ;
        } ;

      /* Have dispatched a withdraw, so can now discard the bgp_adj_out, and
       * with it the scheduled advertisement.
       */
      parcel = bgp_adj_out_done_withdraw(prib, parcel) ;
    }
  while (parcel != NULL) ;

  prib->scount -= withdrawn ;

  /* For ipv4_unicast: set Withdrawn Routes Length
   *                   then set Total Path Attributes Length == 0
   *
   *        otherwise: set Total Path Attributes Length
   *                   then set length of the MP_UNREACH attribute
   */
  stream_putw_at(s, len_p - 2, end_p - len_p) ;

  if (prib->qafx == qafx_ipv4_unicast)
    stream_putw(s, 0) ;         /* no attributes        */
  else
    stream_putw_at(s, len_ap - 2, end_p - len_ap) ;

  /* Debug logging as required
   */
  if (updates != NULL)
    {
      zlog (prib->peer->log, LOG_DEBUG, "%s send %u WITHDRAW(S) %s/%s:%s",
                 prib->peer->host, withdrawn,
                 map_direct(bgp_afi_name_map, get_iAFI(prib->qafx)).str,
                 map_direct(bgp_safi_name_map, get_iSAFI(prib->qafx)).str,
                                                           qs_string(updates)) ;
      qs_free(updates) ;
    } ;

  /* Kept within maximum message length, above.
   */
  bgp_packet_set_size (s);
  return s ;
}

/*------------------------------------------------------------------------------
 * Construct an End-of-RIB update message for given AFI/SAFI.
 *
 * Generates complete BGP message in the peer->work stream structure.
 *
 * Returns: peer->work -- if have something to be written.
 *          NULL       -- otherwise
 */
static stream
bgp_update_packet_eor (peer_rib prib, route_out_parcel parcel)
{
  stream s ;

  bgp_adj_out_done_announce(prib, parcel) ;

  if (DISABLE_BGP_ANNOUNCE)
    return NULL;

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("send End-of-RIB for %s to %s", get_qafx_name(prib->qafx),
                                                             prib->peer->host) ;

  s = prib->peer->work;
  stream_reset (s);

  /* Make BGP update packet.
   */
  bgp_packet_set_marker (s, BGP_MT_UPDATE);

  /* Unfeasible Routes Length
   */
  stream_putw (s, 0);

  if (prib->qafx == qafx_ipv4_unicast)
    {
      /* Total Path Attribute Length
       */
      stream_putw (s, 0);
    }
  else
    {
      /* Total Path Attribute Length
       */
      stream_putw (s, 6);
      stream_putc (s, BGP_ATF_OPTIONAL);
      stream_putc (s, BGP_ATT_MP_UNREACH_NLRI);
      stream_putc (s, 3);
      stream_putw (s, get_iAFI(prib->qafx));
      stream_putc (s, get_iSAFI(prib->qafx));
    }

  /* Cannot exceed maximum message size !
   */
  bgp_packet_set_size (s);
  return s ;
}

/*------------------------------------------------------------------------------
 * Construct an update for the default route, place it in the obuf queue
 * and kick write.
 *
 * Note that this jumps all queues -- because the default route generated is
 * special.  Also, this is called (a) when a table is about to be announced, so
 * this will be the first route sent and (b) when the configuration option
 * is set, so the ordering wrt other routes and routeadv timer is moot.
 *
 * Note that this may also trigger the output of pending withdraws and updates.
 * Tant pis.
 *
 * Note also that it is assumed that (a) the attributes are essentially
 * trivial, and (b) that they are 99.9% likely to be unique.
 *
 * Uses peer->work stream structure, but copies result to new stream, which is
 * pushed onto the obuf queue.
 */
extern void
bgp_default_update_send (bgp_peer peer, prefix p, attr_set attr, qafx_t qafx,
                                                                  bgp_peer from)
{
  stream  s;
  uint    pos;
  bgp_size_t total_attr_len;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  /* Logging the attribute.
   */
  if (BGP_DEBUG (update, UPDATE_OUT))
    {
      qstring qs ;
      attr_next_hop_t* next_hop, * mp_next_hop ;

      next_hop = mp_next_hop = NULL ;
      if (qafx == qafx_ipv4_unicast)
        next_hop    = &attr->next_hop ;
      else
        mp_next_hop = &attr->next_hop ;

      qs = bgp_dump_attr(peer, attr, next_hop, mp_next_hop) ;

      if (qs != NULL)
        {
          zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s %s",
                                   peer->host, spfxtoa(p).str, qs_string(qs)) ;
          qs_free(qs) ;
        } ;
    }

  s = peer->work ;
  stream_reset (s);

  /* Make BGP update packet and set empty withdrawn NLRI
   */
  bgp_packet_set_marker (s, BGP_MT_UPDATE);
  stream_putw (s, 0);

  /* Construct attribute -- including NLRI for not AFI_IP/SAFI_UNICAST
   */
  pos = stream_get_endp (s);
  stream_putw (s, 0);

  total_attr_len = bgp_packet_attribute (s, peer->prib[qafx], attr, p, 0);
  stream_putw_at (s, pos, total_attr_len);

  /* NLRI for AFI_IP/SAFI_UNICAST.
   */
  if (qafx == qafx_ipv4_unicast)
    stream_put_prefix (s, p);

  /* Set size -- note that it is essentially impossible that the message has
   *             overflowed, but if it has there is nothing we can do about it
   *             other than suppress and treat as error (the default action).
   */
  bgp_packet_set_size (s);

  /* Add packet to the peer.
   */
  bgp_write(peer, s);
}

/*------------------------------------------------------------------------------
 * Construct a withdraw update for the default route, place it in the obuf
 * queue and kick write.
 *
 * Note that this jumps even the withdraw queue.  This is called when the
 * configuration option is unset, so the ordering wrt other routes and
 * routeadv timer is moot.  If there were other withdraws pending, they could
 * be merged in -- but that seems like a lot of work for little benefit.
 *
 * Note that this may also trigger the output of pending withdraws and updates.
 * Tant pis.
 *
 * Uses peer->work stream structure, but copies result to new stream, which is
 * pushed onto the obuf queue.
 */
extern void
bgp_default_withdraw_send (bgp_peer peer, prefix p, qafx_t qafx)
{
  stream s;
  uint   pos;
  uint   cp;
  bgp_size_t unfeasible_len;
  bgp_size_t total_attr_len;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  total_attr_len = 0;
  pos = 0;

  if (BGP_DEBUG (update, UPDATE_OUT))
    zlog (peer->log, LOG_DEBUG, "%s send UPDATE %s -- unreachable",
                                                   peer->host, spfxtoa(p).str);

  s = peer->work ;
  stream_reset (s);

  /* Make BGP update packet. */
  bgp_packet_set_marker (s, BGP_MT_UPDATE);

  /* Unfeasible Routes Length. */;
  cp = stream_get_endp (s);
  stream_putw (s, 0);

  /* Withdrawn Routes. */
  if (qafx == qafx_ipv4_unicast)
    {
      stream_put_prefix (s, p);

      unfeasible_len = stream_get_endp (s) - cp - 2;

      /* Set unfeasible len.  */
      stream_putw_at (s, cp, unfeasible_len);

      /* Set total path attribute length. */
      stream_putw (s, 0);
    }
  else
    {
      pos = stream_get_endp (s);
      stream_putw (s, 0);
      total_attr_len = bgp_unreach_attribute (s, p, qafx);

      /* Set total path attribute length. */
      stream_putw_at (s, pos, total_attr_len);
    }

  /* Impossible to overflow the BGP Message !
   */
  bgp_packet_set_size (s);

  /* Add packet to the peer.
   */
  bgp_write(peer, s);
}

/*------------------------------------------------------------------------------
 * Send route refresh message to the peer.
 *
 * Although the ORF stuff will handle arbitrary AFI/SAFI, we only send stuff
 * from known ones.
 */
extern void
bgp_route_refresh_send (peer_rib prib, byte orf_type,
                                             byte when_to_refresh, bool remove)
{
  bgp_route_refresh rr ;
  bool orf_refresh ;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  if (prib == NULL)
    return ;

  rr = bgp_route_refresh_new(get_iAFI(prib->qafx), get_iSAFI(prib->qafx), 1) ;
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
              prib->af_status &= ~PEER_STATUS_ORF_PREFIX_SENT ;

              bgp_orf_add_remove_all(rr, BGP_ORF_T_PFX);
              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s sending REFRESH_REQ to remove ORF (%s)"
                            " for afi/safi: %u/%u", prib->peer->host,
                                           rr->defer ? "defer" : "immediate",
                                                            rr->afi, rr->safi) ;
            }
          else
            {
              orf_prefix_value_t orfpv;
              vector_index_t i;

              prib->af_status |= PEER_STATUS_ORF_PREFIX_SENT ;

              for (i = 0; prefix_bgp_orf_get(&orfpv, plist, i); ++i)
                {
                  bgp_orf_entry orfpe ;

                  orfpe = bgp_orf_add(rr, BGP_ORF_T_PFX, 0,
                                                     orfpv.type == PREFIX_DENY);
                  orfpe->body.orfpv = orfpv;
                } ;

              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s sending REFRESH_REQ with pfxlist ORF "
                            "(%s) for afi/safi: %u/%u", prib->peer->host,
                                            rr->defer ? "defer" : "immediate",
                                                            rr->afi, rr->safi);
            } ;
        } ;
    } ;

  if (BGP_DEBUG (normal, NORMAL))
    {
      if (! orf_refresh)
        zlog_debug ("%s sending REFRESH_REQ for afi/safi: %u/%u",
                                           prib->peer->host, rr->afi, rr->safi);
    } ;

  bgp_session_route_refresh_send(prib->peer->session, rr);
} ;

/* Send capability message to the peer. */

/* TODO: require BGP Engine support for Dynamic Capability messages.    */

extern void
bgp_capability_send (struct peer *peer, qafx_t qafx, int capability_code,
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
                   peer->host, action == CAPABILITY_ACTION_SET ?
                   "Advertising" : "Removing", get_iAFI(qafx), get_iSAFI(qafx));
    }

  /* Set packet size.
   *
   * Impossible to overflow the BGP Message buffer
   */
  length = bgp_packet_set_size (s);

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s send message type %d, length (incl. header) %d",
                                         peer->host, BGP_MT_CAPABILITY, length);

  /* Add packet to the peer.
   */
  bgp_write(peer, s);
}











/*==============================================================================
 * Incoming UPDATE message handling
 */
static void bpd_update_receive_nlri (bgp_peer peer, route_in_action_t action,
                                                 attr_set attr, bgp_nlri nlri) ;

/*------------------------------------------------------------------------------
 * Parse BGP Update packet and make attribute object.
 */
extern void
bgp_update_receive(bgp_peer peer, bgp_size_t size)
{
  bgp_size_t attribute_len;
  byte* attr_p ;
  bgp_attr_parser_args_t args[1] ;
  route_in_action_t action ;
  peer_rib  prib ;

  /* Status must be Established.
   */
  if (peer->state != bgp_pEstablished)
    {
      zlog_err ("%s [FSM] Update packet received under status %s",
                peer->host, map_direct(bgp_peer_status_map, peer->state).str);

      bgp_peer_down_error (peer, BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC) ;

      return ;
    } ;

  /* Set initial values in args:
   *
   *   * peer               -- X      -- set below
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

  args->peer = peer ;

  args->sort = peer->sort ;
  args->as4  = per->caps_use & PEER_CAP_AS4 ;

  bgp_attr_pair_load_new(args->attrs) ;

  /* Get and check length of Withdrawn Routes part, and step past.
   *
   * Get and check the length of Attributes part, and step past.
   *
   * Get (Update) NLRI part, and step past.
   */
  args->withdraw.length = stream_getw (peer->ibuf);
  args->withdraw.pnt    = stream_get_pnt (peer->ibuf) ;

  stream_forward_getp(peer->ibuf, args->withdraw.length) ;
  if (stream_has_overrun(peer->ibuf))
    {
      zlog_err ("%s [Error] Update packet error"
                " (packet unfeasible length overflow %u)",
                peer->host, args->withdraw.length);

      args->notify_code    = BGP_NOMC_UPDATE ;
      args->notify_subcode = BGP_NOMS_U_MAL_ATTR ;

      qassert(args->notify_data_len == 0) ;

      goto exit_bgp_update_critical ;
    }

  attribute_len = stream_getw (peer->ibuf);
  attr_p        = stream_get_pnt(peer->ibuf) ;

  stream_forward_getp(peer->ibuf, attribute_len) ;
  if (stream_has_overrun(peer->ibuf))
    {
      zlog_warn ("%s [Error] Packet Error"
                   " (update packet attribute length overflow %u)",
                   peer->host, attribute_len);

      args->notify_code    = BGP_NOMC_UPDATE ;
      args->notify_subcode = BGP_NOMS_U_MAL_ATTR ;

      qassert(args->notify_data_len == 0) ;

      goto exit_bgp_update_critical ;
    } ;

  args->update.length = stream_get_read_left(peer->ibuf);
  args->update.pnt    = stream_get_pnt (peer->ibuf) ;

  stream_forward_getp(peer->ibuf, args->update.length) ;

  /* Check that any Withdraw stuff is well formed.
   */
  if (args->withdraw.length > 0)
    {
      args->withdraw.qafx    = qafx_ipv4_unicast ;
      args->withdraw.in.afi  = iAFI_IP ;
      args->withdraw.in.safi = iSAFI_Unicast ;

      if (!bgp_nlri_sanity_check (peer, &args->withdraw))
        {
          zlog_info ("%s withdraw NLRI fails sanity check", peer->host) ;

          args->notify_code    = BGP_NOMC_UPDATE ;
          args->notify_subcode = BGP_NOMS_U_NETWORK ;

          qassert(args->notify_data_len == 0) ;

          goto exit_bgp_update_critical ;
        } ;

      if (BGP_DEBUG (packet, PACKET_RECV))
        zlog_debug ("%s [Update:RECV] Unfeasible NLRI received", peer->host);
    } ;

  /* Check that any NLRI stuff is well formed.
   */
  if (args->update.length != 0)
    {
      args->update.qafx    = qafx_ipv4_unicast ;
      args->update.in.afi  = iAFI_IP;
      args->update.in.safi = iSAFI_Unicast ;

      if (!bgp_nlri_sanity_check (peer, &args->update))
        {
          zlog_info ("%s update NLRI fails sanity check", peer->host) ;

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
  action = ra_in_update ;       /* assume all is well   */

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

          zlog (peer->log, lvl,
            "%s rcvd UPDATE with fatal errors in attr(s)!!"
                                                      " Dropping session",
                                                               peer->host) ;
        }
      else if (args->aret & BGP_ATTR_PARSE_SERIOUS)
        {
          /* Log as an ERROR
           */
          lvl = LOG_ERR ;

          zlog (peer->log, lvl,
            "%s rcvd UPDATE with errors in attr(s)!!"
                                                  " Withdrawing route(s)",
                                                               peer->host) ;

          action = ra_in_treat_as_withdraw ;    /* not so good  */
        }
      else if (args->aret & BGP_ATTR_PARSE_IGNORE)
        {
          /* Log as a WARNING.  Treat as OK from now on.
           */
          lvl = LOG_WARNING ;

          zlog (peer->log, lvl,
            "%s rcvd UPDATE with errors in trivial attr(s)!!"
                                            " Ignoring those attributes.",
                                                               peer->host) ;
          args->aret = BGP_ATTR_PARSE_OK ;
        }
      else if (args->aret & BGP_ATTR_PARSE_RECOVERED)
        {
          /* Log as DEBUG.  Treat as OK from now on.
           */
          lvl = LOG_DEBUG ;

          zlog (peer->log, lvl,
            "%s rcvd UPDATE with recoverable errors in attr(s)!!"
                                            " Recovered those attributes.",
                                                               peer->host) ;
          args->aret = BGP_ATTR_PARSE_OK ;
        }
      else
        {
          /* This is bad...  unrecognised BGP_ATTR_PARSE_XXX value.
           *
           */
          lvl = LOG_CRIT ;

          zlog (peer->log, lvl,
            "[BUG] %s rcvd UPDATE: attribute parser return code=%u!!"
                                                      " Dropping session",
                                                       peer->host, args->aret) ;

          args->aret = BGP_ATTR_PARSE_CRITICAL ;        /* crunch       */

          args->notify_code     = BGP_NOMC_CEASE ;
          args->notify_subcode  = BGP_NOMS_UNSPECIFIC ;
          args->notify_data_len = 0 ;
        } ;

      /* Log attributes at the required level.
       */
      qs = bgp_dump_attr (peer, args->attrs->working,
          args->update.next_hop.type != nh_none    ? &args->update.next_hop
                                                   : NULL,
          args->mp_update.next_hop.type != nh_none ? &args->mp_update.next_hop
                                                   : NULL) ;
      if (qs != NULL)
        {
          zlog (peer->log, lvl, "%s rcvd UPDATE w/ attr: %s",
                                                peer->host, qs_string(qs)) ;
          qs_free(qs) ;
        } ;

      /* Stop now if have a critical error.
       */
      if (args->aret & BGP_ATTR_PARSE_CRITICAL)
         goto exit_bgp_update_critical ;
    } ;

  qassert( (args->aret == BGP_ATTR_PARSE_OK) ||
           (args->aret == BGP_ATTR_PARSE_SERIOUS) ) ;

  /* Now we process whatever NLRI we have and we are configured for.
   *
   * Note that at this stage we have whatever the UPDATE message contained,
   * notwithstanding which AFI/SAFI the session is actually negotiated for.
   * Completely unknown AFI/SAFI arrive here as qafx_other.
   *
   * TODO we have to worry about activated..., because we need values in the
   *      prib...  should we worry about negotiated ??
   */
  prib = peer_family_prib(peer, qafx_ipv4_unicast) ;

  if (prib != NULL)
    {
      if (args->withdraw.length != 0)
        bpd_update_receive_nlri(peer, ra_in_withdraw, NULL, &args->withdraw) ;

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

          bpd_update_receive_nlri(peer, action, set, &args->update) ;
        }
      else if ((args->withdraw.length == 0) && (attribute_len == 0))
        {
          /* End-of-RIB received
           */
          prib->af_status |= PEER_STATUS_EOR_RECEIVED ;

          /* NSF delete stale route
           */
          if (prib->nsf)
            bgp_clear_stale_route (peer, qafx_ipv4_unicast);

          if (BGP_DEBUG (normal, NORMAL))
            zlog (peer->log, LOG_DEBUG,
                       "rcvd End-of-RIB for IPv4 Unicast from %s", peer->host) ;
        } ;
    } ;

  if (args->mp_withdraw.length != 0)
    {
      prib = peer_family_prib(peer, args->mp_withdraw.qafx) ;
      if (prib != NULL)
        bpd_update_receive_nlri(peer, ra_in_withdraw, NULL, &args->mp_withdraw);
    } ;

  if (args->mp_update.length != 0)
    {
      prib = peer_family_prib(peer, args->mp_update.qafx) ;
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
          bpd_update_receive_nlri (peer, action, set, &args->mp_update) ;
        } ;
    } ;

  if (args->mp_eor)
    {
      qassert((args->mp_withdraw.length | args->mp_update.length |
               args->withdraw.length    | args->update.length    ) == 0) ;

      prib = peer_family_prib(peer, args->mp_withdraw.qafx) ;
      if (prib != NULL)
        {
          /* End-of-RIB received
           */
          if (!qafx_is_mpls_vpn(args->mp_withdraw.qafx))
            {
              prib->af_status |= PEER_STATUS_EOR_RECEIVED ;
              if (prib->nsf)
                bgp_clear_stale_route (peer, args->mp_withdraw.qafx);
            } ;

          if (BGP_DEBUG (normal, NORMAL))
            zlog (peer->log, LOG_DEBUG, "rcvd End-of-RIB for %s/%s from %s",
           map_direct(bgp_afi_name_map, get_qAFI(args->mp_withdraw.qafx)).str,
           map_direct(bgp_safi_name_map, get_qSAFI(args->mp_withdraw.qafx)).str,
                                                                   peer->host) ;
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
   bgp_peer_down_error_with_data(peer, args->notify_code,
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
bpd_update_receive_nlri(bgp_peer peer, route_in_action_t action, attr_set attr,
                                                                  bgp_nlri nlri)
{
  const byte*  pnt ;
  const byte*  limit ;
  const byte*  prd ;
  sa_family_t  family ;
  prefix_t     p ;
  bool         mpls ;
  ulen         plen_max ;
  route_in_parcel_t parcel[1] ;

  if (qdebug)
    {
      switch (action)
        {
          case ra_in_withdraw:
            assert(attr == NULL) ;
            break ;

          case ra_in_update:
          case ra_in_treat_as_withdraw:
            assert(attr != NULL) ;
            break ;

          default:
            assert(false) ;
        } ;
    } ;

  /* Check peer status and address family.
   */
  if (peer->state != bgp_pEstablished)
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

  /* Prepare the route_in_parcel -- things which do not change between prefixes.
   */
  memset(parcel, 0, sizeof(route_in_parcel_t)) ;

  parcel->attr    = attr ;
  parcel->qafx    = nlri->qafx ;
  parcel->action  = action ;

  if (bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) != 0)
    parcel->route_type = bgp_route_type(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL) ;

  /* Crunch through the NLRI
   */
  pnt   = nlri->pnt;
  limit = pnt + nlri->length;

  prefix_default(&p, family) ;
  prd = NULL ;                          /* assume not MPLS      */

  while (1)
    {
      prefix_id_entry  pie ;
      const byte* pp ;
      usize       psize ;
      ulen        plen ;
      bool        ok ;

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
              plog_err (peer->log,
                 "%s [Error] Update packet error: "
                                    "unknown RD type %u for %s NLRI",
                                             peer->host, mpls_rd_raw_type(pp),
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
          parcel->tag = mpls_tags_decode(pp + 8, 3) ;

          if (parcel->tag >= mpls_tags_bad)
            {
              plog_err (peer->log,
                 "%s [Error] Update packet error: "
                                    "more than one label for %s NLRI",
                                   peer->host, get_qafx_name(nlri->qafx)) ;
              continue ;
            } ;

          /* Step past the MPLS stuff.
           */
          pp   +=  8 + 3 ;
          plen -= (8 + 3) * 8 ;
        } ;

      /* Check address.
       *
       * NB: have stepped past the prefix, so can 'continue' if want to ignore
       *     the current prefix.
       */
      if (plen > plen_max)
        break ;                 /* checked already -- paranoia  */

      switch (nlri->qafx)
        {
          case qafx_ipv4_unicast:
            if (IN_CLASSD (ntohl (p.u.prefix4.s_addr)))
              {
               /* From draft-ietf-idr-bgp4-22, Section 6.3:
                * If a BGP router receives an UPDATE message with a
                * semantically incorrect NLRI field, in which a prefix is
                * semantically incorrect (eg. an unexpected multicast IP
                * address), it should ignore the prefix.
                */
                zlog (peer->log, LOG_ERR,
                      "IPv4 unicast NLRI is multicast address %s",
                                             siptoa (family, &p.u.prefix).str) ;
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
            if (IN6_IS_ADDR_LINKLOCAL (&p.u.prefix6))
              {
                zlog (peer->log, LOG_WARNING,
                      "IPv6 link-local NLRI received %s ignore this NLRI",
                                             siptoa (family, &p.u.prefix).str) ;
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

      /* We are ready to update the RIB !
       *
       * Map the prefix and any RD to its prefix_id_entry.  This locks the
       * prefix_id_entry, pro tem.
       */
      pie = prefix_id_find_entry(&p, prd) ;     /* locks the entry      */

      parcel->pfx_id = prefix_id_get_id(pie) ;

      ok = bgp_update_from_peer(peer, parcel, false /* not refresh */) ;

      prefix_id_entry_dec_ref(pie) ;

      /* Address family configuration mismatch or maximum-prefix count overflow.
       */
      if (!ok)
        return ;
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
 */
void
bgp_route_refresh_recv(bgp_peer peer, bgp_route_refresh rr)
{
  qafx_t qafx ;
  vector_index_t i, e;
  bgp_orf_name name ;
  peer_rib     prib ;
  int ret;

  qafx = qafx_from_i(rr->afi, rr->safi) ;
  prib = peer_family_prib(peer, qafx) ;

  if (prib == NULL)
    return ;

  prefix_bgp_orf_name_set(name, &peer->su_name, qafx) ;

  if ((e = bgp_orf_get_count(rr)) > 0)
    {
      for (i = 0; i < e; ++i)
        {
          bgp_orf_entry orfe ;

          orfe = vector_slot(rr->entries, i);

          if (orfe->unknown)
            continue ;          /* ignore unknown       */

          if (orfe->orf_type == BGP_ORF_T_PFX)
            {
              if (orfe->remove_all)
                {
                  if (BGP_DEBUG (normal, NORMAL))
                    zlog_debug ("%s rcvd Remove-All pfxlist ORF request",
                        peer->host);
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
                        "Remove All pfxlist", peer->host);
                  prefix_bgp_orf_remove_all (name);
                  break;
                }

              prib->orf_plist = prefix_list_lookup (qAFI_ORF_PREFIX, name);
            }
        }

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s rcvd Refresh %s ORF request", peer->host,
                    rr->defer ? "Defer" : "Immediate");
      if (rr->defer)
        return;
    }

  /* If we were deferring sending the RIB to the peer, then we stop doing
   * so, now.
   */
  UNSET_FLAG (prib->af_status, PEER_STATUS_ORF_WAIT_REFRESH) ;

  /* Perform route refreshment to the peer
   */
  bgp_announce_family (peer, qafx);
}

/* TODO there is a lot of recent activity eg commit 1212dc1961... to do with
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
#if 0           /* TODO BGP_SAFI_VPNV4 and BGP_SAFI_VPNV6 ????  */
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
bgp_capability_msg_parse (struct peer *peer, u_char *pnt, bgp_size_t length)
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
          zlog_info ("%s Capability length error", peer->host);
          /* TODO: Is this the right notification ??           */
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
                     peer->host, action);
          /* TODO: Is this the right notification ??           */
          bgp_peer_down_error (peer, BGP_NOMC_CEASE, 0);
          return -1;
        }

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("%s CAPABILITY has action: %d, code: %u, length %u",
                                   peer->host, action, hdr->code, hdr->length);

      /* Capability length check. */
      if ((pnt + hdr->length + 3) > end)
        {
          zlog_info ("%s Capability length error", peer->host);
          /* TODO: Is this the right notification ??           */
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

          i_afi  = ntohs (mpc.afi);
          i_safi = mpc.safi;

          qafx = bgp_afi_safi_valid_indices (mpc.afi, mpc.safi) ;

          if (qafx == qafx_other)
            {
              if (BGP_DEBUG (normal, NORMAL))
                zlog_debug ("%s Dynamic Capability MP_EXT afi/safi invalid "
                            "(%u/%u)", peer->host, i_afi, i_safi);
              continue;
            }

          /* Ignore capability when override-capability is set.
           */
          if (CHECK_FLAG (peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY))
            continue;

          /* Address family check.  */
          if (BGP_DEBUG (normal, NORMAL))
            zlog_debug ("%s CAPABILITY has %s MP_EXT CAP for afi/safi: %u/%u",
                       peer->host,
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

              if (peer->af_use != qafx_set_empty)
                bgp_clear_routes (peer, qafx, false);
              else
                {
                  /* TODO: only used for unit tests.  Test will need fixing
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
                     peer->host, hdr->code);
        } ;
    }
  return 0;
}

/* Dynamic Capability is received.
 *
 * This is exported for unit-test purposes
 */
extern int bgp_capability_receive(struct peer*, bgp_size_t) ;

int
bgp_capability_receive (struct peer *peer, bgp_size_t size)
{
  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s rcv CAPABILITY", peer->host);

  /* If peer does not have the capability, send notification.
   */
  if (! CHECK_FLAG (peer->caps_rcv, PEER_CAP_DYNAMIC | PEER_CAP_DYNAMIC_dep))
    {
      u_char *pnt;

      plog_err (peer->log, "%s [Error] BGP dynamic capability is not enabled",
                                                                   peer->host) ;

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
                peer->host, map_direct(bgp_peer_status_map, peer->state).str) ;
      bgp_peer_down_error (peer, BGP_NOMC_FSM, BGP_NOMS_UNSPECIFIC) ;

      return -1;
    }

  /* Parse packet.
   */
  return bgp_capability_msg_parse (peer, stream_get_pnt (peer->ibuf), size);
}
