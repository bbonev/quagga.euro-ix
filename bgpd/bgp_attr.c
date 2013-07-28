/* BGP attributes management routines.
   Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro

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

#include "linklist.h"
#include "prefix_id.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "stream.h"
#include "log.h"

#include "bgp.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_names.h"
#include "bgpd/bgp_mplsvpn.h"

/*==============================================================================
 * Parsing of Attributes Section of UPDATE Message
 */
static const byte* bgp_attr_origin(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_aspath(bgp_attr_parser_args restrict args,
                                           const byte* attr_p, as_path* p_asp) ;
static const byte* bgp_attr_nexthop(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_med(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_local_pref(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_atomic(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_aggregator(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_as4_aggregator(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_community(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_originator_id(bgp_attr_parser_args args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_cluster_list(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_mp_reach_parse(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_mp_unreach_parse(bgp_attr_parser_args restrict args,
                                       const byte* attr_p,
                                       const byte* start_p, const byte* end_p) ;
static const byte* bgp_attr_ecommunities(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_unknown(bgp_attr_parser_args restrict args,
                                                           const byte* attr_p) ;

static bgp_attr_parse_ret_t bgp_attr_munge_as4_aggr(
                                           bgp_attr_parser_args restrict args) ;
static bgp_attr_parse_ret_t bgp_attr_munge_as4_path(
                                           bgp_attr_parser_args restrict args) ;
static void bgp_attr_as_path_set_if_ok(bgp_attr_parser_args restrict args) ;

static void bgp_attr_malformed(bgp_attr_parser_args restrict args,
                                       byte subcode, bgp_attr_parse_ret_t ret) ;

/*------------------------------------------------------------------------------
 * Read attribute of update packet.
 *
 * This function is called from bgp_update() in bgpd.c.
 *
 * NB: expects the args structure to be initialised, ready to process the
 *     attributes, including inter alia:
 *
 *   * peer               -- the peer
 *   * sort               -- it's sort
 *   * as4                -- it's NEW_BGP speaker state
 *
 *   * seen               -- zeros  -- nothing seen, yet
 *
 *   * attrs              -- per bgp_attr_pair_load_new()
 *
 *   * aret               -- state so far: probably BGP_ATTR_PARSE_OK
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
 *   * withdraw           -- zeros  -- withdraw.length    == 0 >=> no NLRI
 *   * mp_update          -- zeros  -- mp_update.length   == 0 <=> no NLRI
 *   * mp_withdraw        -- zeros  -- mp_withdraw.length == 0 >=> no NLRI
 *
 *   * unknown            -- NULL   -- no unknown attributes, yet
 *
 *   * mp_eor             -- false  -- no MP End-of-RIB
 *
 * NB: for the detection of MP End-of-RIB it is *essential* that update.length
 *     and withdraw.length reflect the presence/absence of either or both.
 *
 * Returns: BGP_ATTR_PARSE_OK       -- all well
 *
 *          BGP_ATTR_PARSE_IGNORE   -- OK, ignoring one or more bad, but
 *                                     trivial, attributes
 *
 *          BGP_ATTR_PARSE_SERIOUS  -- not good, but keep going, treating
 *                                     all prefixes as being withdrawn.
 *
 *          BGP_ATTR_PARSE_CRITICAL -- not good at all: session must be dropped
 *
 * NB: expects caller to tidy up the args, in particular to deal with the:
 *
 *      attrs     -- this function adds stuff to the working set of the
 *                   attribute pair -- it does not store the result.
 *
 *      asp       -- intermediate AS_PATH, if any remains
 *      asp4      -- intermediate AS4_PATH, if any remains
 *      unknown   -- intermediate unknown attributes
 */
extern void
bgp_attr_parse (bgp_attr_parser_args restrict args, const byte* start_p,
                                                                  uint attr_len)
{
  uint  attr_have ;
  const byte*  attr_p ;
  const byte*  end_p ;

  /* Grind our way through the attribute TLVs.
   *
   * We have: start_p = start of all attributes
   *          end_p   = end of all attributes
   *          attr_p  = working pointer as each attribute is processed
   *
   *          args->start_p = start of the current attribute
   *          args->end_p   = end of the current attribute
   */
  attr_p = start_p ;
  end_p  = start_p + attr_len ;

  while ((attr_have = end_p - attr_p) > 0)
    {
      ulen header_length ;
      byte flags ;

      /* Remember the start of the attribute -- used in bgp_attr_malformed()
       * and other error handling.
       */
      args->start_p = attr_p ;

      /* Fetch attribute flag, type and length -- look out for overflow.
       *
       * Note that stream_getx() return zero if overrun the end.
       *
       * "The lower-order four bits of the Attribute Flags octet are
       * unused.  They MUST be zero when sent and MUST be ignored when
       * received."  RFC4271, 4.3, "Path Attributes:"
       *
       * NB: for the time being, if we find a fragment which is too small for
       *     the attribute red tape, or we find a length which overruns the
       *     end of the attributes, we treat this as a CRITICAL error.  TODO ***
       */
      flags = attr_p[0] ;
      args->flags = flags & ~BGP_ATF_ZERO ;     /* discard LS bits      */

      if (flags & BGP_ATF_EXTENDED)
        header_length = 4 ;
      else
        header_length = 3 ;

      if (attr_have < header_length)
        {
          args->type   = (attr_have > 1) ? attr_p[1] : BGP_ATT_UNDEFINED ;
          args->length = (attr_have > 2) ? attr_p[2] : 0 ;

          zlog (args->peer->log, LOG_ERR,
                "%s: broken BGP attribute [0x%x %u %u] have just %u octets for"
                                                            " attribute header",
                 args->peer->host, flags, args->type, args->length, attr_have) ;

          bgp_attr_malformed(args, BGP_NOMS_U_A_LENGTH,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
          return ;
        } ;

      args->type  = attr_p[1] ;

      if (header_length == 4)
        args->length = load_ns(&attr_p[2]) ;
      else
        args->length = attr_p[2] ;

      attr_p += header_length ;

      if (attr_have < (header_length + args->length))
        {
          zlog (args->peer->log, LOG_ERR,
                "%s: broken BGP attribute [0x%x %u %u] have just %u octets for"
                                                              " attribute body",
                      args->peer->host, flags, args->type, args->length,
                                                  (attr_have - header_length)) ;

          bgp_attr_malformed(args, BGP_NOMS_U_A_LENGTH,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
          return ;
        } ;

      /* Parse according to type
       */
      args->end_p = attr_p + args->length ;
      args->ret   = BGP_ATTR_PARSE_OK ;

      switch (args->type)
        {
          case BGP_ATT_UNDEFINED:
            break ;

          case BGP_ATT_RESERVED:
            break ;

          case BGP_ATT_ORIGIN:
            attr_p = bgp_attr_origin (args, attr_p);
            break;

          case BGP_ATT_AS_PATH:
            attr_p = bgp_attr_aspath (args, attr_p, &args->asp) ;
            break;

          case BGP_ATT_AS4_PATH:
            attr_p = bgp_attr_aspath (args, attr_p, &args->as4p) ;
            break;

          case BGP_ATT_NEXT_HOP:
            attr_p = bgp_attr_nexthop (args, attr_p);
            break;

          case BGP_ATT_MED:
            attr_p = bgp_attr_med (args, attr_p);
            break;

          case BGP_ATT_LOCAL_PREF:
            attr_p = bgp_attr_local_pref (args, attr_p);
            break;

          case BGP_ATT_ATOMIC_AGGREGATE:
            attr_p = bgp_attr_atomic (args, attr_p);
            break;

          case BGP_ATT_AGGREGATOR:
            attr_p = bgp_attr_aggregator (args, attr_p);
            break;

          case BGP_ATT_AS4_AGGREGATOR:
            attr_p = bgp_attr_as4_aggregator (args, attr_p);
            break;

          case BGP_ATT_COMMUNITIES:
            attr_p = bgp_attr_community (args, attr_p);
            break;

          case BGP_ATT_ORIGINATOR_ID:
            attr_p = bgp_attr_originator_id (args, attr_p);
            break;

          case BGP_ATT_CLUSTER_LIST:
            attr_p = bgp_attr_cluster_list (args, attr_p);
            break;

          case BGP_ATT_MP_REACH_NLRI:
            attr_p = bgp_attr_mp_reach_parse (args, attr_p);
            break;

          case BGP_ATT_MP_UNREACH_NLRI:
            attr_p = bgp_attr_mp_unreach_parse (args, attr_p, start_p, end_p);
            break;

          case BGP_ATT_ECOMMUNITIES:
            attr_p = bgp_attr_ecommunities (args, attr_p);
            break;

          default:
            attr_p = bgp_attr_unknown (args, attr_p);
            break;
        } ;

      /* If all is well, check that the individual attribute parser has
       * reached the expected end.
       *
       * If all is still OK, continue parsing straight away.
       */
      if (args->ret == BGP_ATTR_PARSE_OK)
        {
          if (attr_p == args->end_p)
            continue ;

          /* This is actually an internal error -- at some point has failed to
           * read everything that was expected (underrun) or have tried to
           * read more than is available (overrun) !
           */
          zlog (args->peer->log, LOG_CRIT,
                   "%s: BGP attribute %s, parser error: %srun %u bytes (BUG)",
                args->peer->host, map_direct(bgp_attr_name_map, args->type).str,
                           attr_p > args->end_p ? "over" : "under",
                                                                 args->length) ;

          args->notify_code     = BGP_NOMC_CEASE ;
          args->notify_subcode  = BGP_NOMS_UNSPECIFIC ;
          args->notify_data_len = 0 ;

          args->ret |= BGP_ATTR_PARSE_CRITICAL ;
        } ;

      /* Make sure the overall result is up to date, and step to the next
       * attribute on the basis of the length of the previous.
       *
       * Decide what should do *now* with the return code, if anything
       */
      args->aret |= args->ret ;

      if (args->aret & BGP_ATTR_PARSE_CRITICAL)
        return ;
    } ;

  qassert(attr_p == (start_p + attr_len)) ;

  /* Now need to deal with the AS_PATH, AS4_PATH, AS_AGGREGATOR and
   * AS4_AGGREGATOR.
   *
   * If is a NEW_BGP speaker, then will already have dealt with AS4_PATH and
   * AS4_AGGREGATOR
   *
   * If is an OLD_BGP speaker then need to process any AS4_AGGREGATOR first,
   * see bgp_attr_munge_as4_aggr().  Then we process any AS4_PATH and AS_PATH
   * together.
   */
  if (!(args->as4))
    {
      bgp_attr_parse_ret_t ret ;

      /* NB: must deal with AS4_AGGREGATOR first, in case that returns
       *     BGP_ATTR_PARSE_IGNORE -- which means ignore it *and* and AS4_PATH.
       *
       *     In this case BGP_ATTR_PARSE_IGNORE does not signal an *error*,
       *     so we do not set "ignored" on the strength of it.
       */
      ret = bgp_attr_munge_as4_aggr (args) ;

      if (ret == BGP_ATTR_PARSE_OK)
        args->aret |= bgp_attr_munge_as4_path(args) ;
      else
        qassert(ret == BGP_ATTR_PARSE_IGNORE) ;
    } ;

  /* Finally do the checks on the aspath we did not do yet because we waited
   * for a potentially synthesized aspath, and if all is well, set the AS Path
   * in the attributes.
   */
  if (args->asp != NULL)
    bgp_attr_as_path_set_if_ok(args);

  /* Have completed the parsing of the attributes.
   *
   * Finally, deal with the unknown attributes.  Here discards all but the
   * valid Optional Transitive, and sets Partial on those.
   */
  if (args->unknown != NULL)
    {
      if (attr_unknown_transitive(args->unknown))
        bgp_attr_pair_set_transitive(args->attrs, args->unknown) ;
      else
        attr_unknown_free(args->unknown) ;

      args->unknown = NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Mandatory attribute check -- given that reachable NLRI is present
 *
 * Require:  ORIGIN
 *           AS_PATH
 *           NEXT_HOP    -- if have IPv4 NLRI at the message level
 *           LOCAL_PREF  -- if peer is iBGP
 */
extern void
bgp_attr_check (bgp_attr_parser_args restrict args)
{
  attr_set  working ;
  qstring   missing ;
  uint8_t   type ;

  missing = NULL ;
  working = args->attrs->working ;

  /* Check for missing stuff in roughly ascending order of significance.
   */
  if (working->origin > BGP_ATT_ORG_MAX)
    {
      missing = qs_append_str(missing, " origin") ;
      type = BGP_ATT_ORIGIN ;
    } ;
  confirm(BGP_ATT_ORG_MIN == 0) ;

  if ((args->sort == BGP_PEER_IBGP) && !(working->have & atb_local_pref))
    {
      missing = qs_append_str(missing, " local_pref") ;
      type = BGP_ATT_LOCAL_PREF ;
    } ;

  if ((args->update.length != 0) && (args->update.next_hop.type != nh_ipv4))
    {
      missing = qs_append_str(missing, " next_hop") ;
      type = BGP_ATT_NEXT_HOP ;
    } ;

  if (working->asp == NULL)
    {
      missing = qs_append_str(missing, " as_path") ;
      type = BGP_ATT_AS_PATH ;
    } ;

  if (missing == NULL)
    return ;

  zlog (args->peer->log, LOG_ERR, "%s Missing well-known attribute(s)%s.",
                                         args->peer->host, qs_string(missing)) ;

  args->type = type ;

  bgp_attr_malformed (args, BGP_NOMS_U_MISSING, BGP_ATTR_PARSE_SERIOUS) ;
} ;

/*------------------------------------------------------------------------------
 * Make attributes for outgoing BGP Message.
 */
extern bgp_size_t
bgp_packet_attribute (stream s, peer_rib prib, attr_set attr, prefix p,
                                                              mpls_tags_t tags)
{
  bgp_peer  peer ;
  size_t cp ;
  bool send_as4_path ;
  bool send_as4_aggregator ;
  bool as4 ;
  as_path_out_t asp_out[1] ;
  bgp_peer_sort_t sort ;
  uint sizep, tp, tl ;

  peer = prib->peer ;
  qassert(peer->type == PEER_TYPE_REAL) ;

  send_as4_path       = false ;
  send_as4_aggregator = false ;
  as4  = peer->caps_use & PEER_CAP_AS4 ;
  sort = peer->sort ;

  /* Remember current pointer
   */
  cp = stream_get_endp (s);

  /* Origin attribute.
   */
  stream_putc (s, BGP_ATF_TRANSITIVE);
  stream_putc (s, BGP_ATT_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);

  /* AS path attribute.
   */
  asp_out->seg = BGP_AS_SEG_NULL ;      /* prepend nothing      */

  switch (sort)
    {
      case BGP_PEER_EBGP:
        /* For an eBGP session, generally want to prepend the local_as,
         * removing any confed stuff.
         *
         * But in some cases we send the as_path exactly as is:
         *
         *   * for RS Client we send as-is, even if it is empty (!)
         *
         *   * if PEER_AFF_AS_PATH_UNCHANGED we send as is, unless is
         *     completely empty
         *
         * If change_local_as is set, then that will be the local_as and we
         * need to insert the bgp->ebgp_as (ie the true local-as) just after
         * the (fake) local_as -- except where they are equal.
         */
        if (prib->af_flags & PEER_AFF_RSERVER_CLIENT)
          break ;

        if (prib->af_flags & PEER_AFF_AS_PATH_UNCHANGED)
          if (!as_path_is_empty(attr->asp))
            break ;

        asp_out->seg = BGP_AS_SEQUENCE ;
        asp_out->prepend_count  = 1 ;
        asp_out->prepend_asn[0] = peer->local_as ;

        if (peer->change_local_as != BGP_ASN_NULL)
          {
            qassert(peer->change_local_as == peer->local_as) ;

            if (peer->bgp->ebgp_as != peer->local_as)
              {
                asp_out->prepend_count  = 2 ;
                asp_out->prepend_asn[1] = peer->bgp->ebgp_as ;
              } ;
          } ;

        break ;

      case BGP_PEER_CBGP:
        /* A Confed Member in a different Member-AS, so we need to do the
         * AS_CONFED_SEQUENCE thing
         */
        asp_out->seg    = BGP_AS_CONFED_SEQUENCE ;
        asp_out->prepend_count  = 1 ;
        asp_out->prepend_asn[0] = peer->local_as ;

        break ;

      case BGP_PEER_UNSPECIFIED:
      default:
        qassert(false) ;
        fall_through ;

      case BGP_PEER_IBGP:
        /* Send AS_PATH as is.
         */
        break ;
    } ;

  send_as4_path = as_path_out_prepare(asp_out, attr->asp, as4) ;

  if (asp_out->len[0] > 0)
    stream_put(s, asp_out->part[0], asp_out->len[0]) ;
  if (asp_out->len[1] > 0)
    stream_put(s, asp_out->part[1], asp_out->len[1]) ;

  /* Nexthop attribute.
   */
  if ((prib->qafx == qafx_ipv4_unicast) && (attr->next_hop.type == nh_ipv4))
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_NEXT_HOP);
      stream_putc (s, 4);
      stream_put_ipv4 (s, attr->next_hop.ip.v4) ;
    } ;

  /* MED attribute. */
  if (attr->have & atb_med)
    {
      stream_putc (s, BGP_ATF_OPTIONAL);
      stream_putc (s, BGP_ATT_MED);
      stream_putc (s, 4);
      stream_putl (s, attr->med);
    }

  /* Local preference.
   */
  if ((sort == BGP_PEER_IBGP) || (sort == BGP_PEER_CBGP))
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

  /* Atomic aggregate.
   */
  if (attr->have & atb_atomic_aggregate)
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_ATOMIC_AGGREGATE);
      stream_putc (s, 0);
    }

  /* Aggregator.
   */
  if (attr->aggregator_as != BGP_ASN_NULL)
    {
      /* Common to BGP_ATT_AGGREGATOR, regardless of ASN size
       *
       * XXX BUG -- need to set BGP_ATF_PARTIAL if not originating this !!
       */
      stream_putc (s, BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_AGGREGATOR);

      if (as4)
        {
          /* AS4 capable peer */
          stream_putc (s, 8);
          stream_putl (s, attr->aggregator_as);
        }
      else
        {
          /* 2-byte AS peer */
          stream_putc (s, 6);

          /* Is ASN representable in 2-bytes? Or must AS_TRANS be used?
           */
          if ( attr->aggregator_as > 65535 )
            {
              stream_putw (s, BGP_ASN_TRANS);

              /* we have to send AS4_AGGREGATOR, too.
               * we'll do that later in order to send attributes in ascending
               * order.
               */
              send_as4_aggregator = true ;
            }
          else
            stream_putw (s, attr->aggregator_as);
        }
      stream_put_ipv4 (s, attr->aggregator_ip);
    }

  /* Community attribute.
   */
  if ( (attr->community != NULL) &&
                      (prib->af_flags & PEER_AFF_SEND_COMMUNITY) )
    {
      byte * p ;
      ulen len ;

      p = attr_community_out_prepare(attr->community, &len) ;

      stream_put (s, p, len) ;
    } ;

  /* Route Reflection.
   *
   * Note that by the time we get to here, if the incoming and the outgoing
   * session is iBGP, we MUST be a Route Reflector and this is a route that
   * we are reflecting.
   */
  if (attr->have & atb_reflected)
    {
      attr_cluster_out_t clust_out[1] ;

      /* Put the BGP_ATT_ORIGINATOR_ID,
       */
      stream_putc (s, BGP_ATF_OPTIONAL);
      stream_putc (s, BGP_ATT_ORIGINATOR_ID);
      stream_putc (s, 4);
      stream_put_ipv4 (s, attr->originator_id ) ;

      /* Prepare and put the cluster list, prepending either the (explicit)
       * cluster_id or the (implicit) router_id.
       */
      clust_out->cluster_id = peer->bgp->cluster_id ;

      attr_cluster_out_prepare(clust_out, attr->cluster) ;

      if (clust_out->len[0] > 0)
        stream_put(s, clust_out->part[0], clust_out->len[0]) ;
      if (clust_out->len[1] > 0)
        stream_put(s, clust_out->part[1], clust_out->len[1]) ;
    } ;

  /* MP_REACH_NLRI, as required.
   */
  switch (prib->qafx)
    {
      case qafx_ipv4_unicast:
        qassert(p->family == AF_INET) ;
        qassert(p->rd_id == prefix_rd_id_null) ;
        break ;

      case qafx_ipv4_multicast:
        qassert(p->family == AF_INET) ;
        qassert(p->rd_id == prefix_rd_id_null) ;

        stream_putc (s, BGP_ATF_OPTIONAL);
        stream_putc (s, BGP_ATT_MP_REACH_NLRI);
        sizep = stream_get_endp (s);
        stream_putc (s, 0);             /* Marker: Attribute Length.    */
        stream_putw (s, iAFI_IP);
        stream_putc (s, iSAFI_Multicast);

        stream_putc (s, 4) ;            /* next hop length              */
        stream_put_ipv4 (s, attr->next_hop.ip.v4) ;

        stream_putc (s, 0);             /* SNPA                         */

        stream_put_prefix (s, p);

        stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
        break ;

      case qafx_ipv4_mpls_vpn:
        qassert(p->family == AF_INET) ;
        qassert(p->rd_id != prefix_rd_id_null) ;

        stream_putc (s, BGP_ATF_OPTIONAL);
        stream_putc (s, BGP_ATT_MP_REACH_NLRI);
        sizep = stream_get_endp (s);
        stream_putc (s, 0);             /* Attribute Length, TBA.       */
        stream_putw (s, iAFI_IP);
        stream_putc (s, iSAFI_MPLS_VPN);

        stream_putc (s, 12) ;           /* next hop length              */
        stream_putl (s, 0) ;            /* first 4 bytes of 0 RD        */
        stream_putl (s, 0) ;            /* second 4 bytes of same       */
        stream_put_ipv4 (s, attr->next_hop.ip.v4) ;

        stream_putc (s, 0);             /* SNPA                         */

        tp = stream_get_endp (s) ;
        stream_putc (s, 0);             /* prefix length place-holder   */

        tl = mpls_tags_to_stream(s, tags) ;
        stream_put (s, prefix_rd_id_get_val(p->rd_id), 8);
        stream_put (s, &p->u.prefix, PSIZE (p->prefixlen));

        stream_putc_at (s, tp, p->prefixlen + ((tl + 8) * 8)) ;

        stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
        break ;

#ifdef HAVE_IPV6
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        stream_putc (s, BGP_ATF_OPTIONAL);
        stream_putc (s, BGP_ATT_MP_REACH_NLRI);
        sizep = stream_get_endp (s);
        stream_putc (s, 0);
        stream_putw (s, iAFI_IP6);
        stream_putc (s, get_iSAFI(prib->qafx)) ;

        switch (attr->next_hop.type)
          {
            case nh_ipv6_1:             /* "global" address only        */
              stream_putc(s, 16) ;

              stream_put(s, &attr->next_hop.ip.v6[0].addr, 16) ;
              break ;

            case nh_ipv6_2:             /* "global" and link-local addresses */
              stream_putc(s, 32) ;

              stream_put(s, &attr->next_hop.ip.v6, 32) ;
              break ;

            default:
              stream_putc(s, 0) ;
              break ;
          } ;

        stream_putc (s, 0);               /* SNPA */

        stream_put_prefix (s, p);

        stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);

        break ;
#endif /* HAVE_IPV6 */

      default:
        break ;
    } ;

  /* Extended Communities attribute.
   *
   * Send only the transitive community if this is not iBGP and not Confed.
   */
  if ((attr->ecommunity != NULL) &&
                                (prib->af_flags & PEER_AFF_SEND_EXT_COMMUNITY))
    {
      bool trans_only ;
      byte *p ;
      ulen len ;

      trans_only = (sort != BGP_PEER_IBGP) && (sort != BGP_PEER_CBGP) ;

      p = attr_ecommunity_out_prepare(attr->ecommunity, trans_only, &len) ;
      stream_put (s, p, len) ;          /* len may be zero      */
    } ;

  if (send_as4_path)
    {
      /* If the peer is NOT As4 capable, AND there are ASN > 65535 in path
       * THEN give out AS4_PATH
       *
       * If was an eBGP AS_PATH, then we just want the AS4 version of that.
       *
       * Otherwise, treat as an eBGP AS_PATH, but with no prepending.
       *
       * Treating as eBGP AS_PATH has the effect of stripping any and all
       * confed stuff.
       */
      if (asp_out->seg != BGP_AS_SEQUENCE)
        {
          asp_out->seg   = BGP_AS_SEQUENCE ;
          asp_out->prepend_count = 0 ;
        } ;

      as_path_out_prepare(asp_out, attr->asp, true /* want AS4 ASN */) ;

      if (asp_out->len[0] > 0)
        stream_put(s, asp_out->part[0], asp_out->len[0]) ;
      if (asp_out->len[1] > 0)
        stream_put(s, asp_out->part[1], asp_out->len[1]) ;
    } ;

  /* AS4_AGGREGATOR, if required.
   */
  if (send_as4_aggregator)
    {
      stream_putc (s, BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_AS4_AGGREGATOR);
      stream_putc (s, 8);
      stream_putl (s, attr->aggregator_as) ;
      stream_put_ipv4 (s, attr->aggregator_ip) ;
    }

  /* Unknown Optional, Transitive Attributes, if any.
   */
  if (attr->transitive != NULL)
    {
      byte *p ;
      ulen len ;

      p = attr_unknown_out_prepare(attr->transitive, &len) ;
      stream_put (s, p, len) ;
    } ;

  /* Return total size of attribute.
   */
  return stream_get_endp (s) - cp;
}

/*------------------------------------------------------------------------------
 * Construct an MP_UNREACH_NLRI attribute for the given prefix
 */
extern bgp_size_t
bgp_unreach_attribute (stream s, prefix p, qafx_t qafx)
{
  uint cp;
  uint attrlen_pnt;
  bgp_size_t size;
  iSAFI_t i_safi ;

  cp = stream_get_endp (s);

  stream_putc (s, BGP_ATF_OPTIONAL);
  stream_putc (s, BGP_ATT_MP_UNREACH_NLRI);

  attrlen_pnt = stream_get_endp (s);
  stream_putc (s, 0);           /* Length of this attribute. */

  stream_putw (s, get_iAFI(qafx)) ;
  i_safi = get_iSAFI(qafx) ;
  stream_putc (s, i_safi) ;

  if (get_qSAFI(qafx) == qSAFI_MPLS_VPN)
    {
      qassert(p->rd_id != prefix_rd_id_null) ;
      bgp_packet_withdraw_vpn_prefix (s, p) ;
    }
  else
    {
      qassert(p->rd_id == prefix_rd_id_null) ;
      stream_put_prefix (s, p);
    } ;

  /* Set MP attribute length. */
  size = stream_get_endp (s) - attrlen_pnt - 1;
  stream_putc_at (s, attrlen_pnt, size);

  return stream_get_endp (s) - cp;
}

/*------------------------------------------------------------------------------
 * Put a withdraw prefix to the given stream.
 *
 * If this is an MPLS_VPN, then insert an empty label and the Route
 * Distinguisher between the prefix length and the address.
 */
extern void
bgp_packet_withdraw_prefix (stream s, prefix_c p, qafx_t qafx)
{
  if (!qafx_is_mpls_vpn(qafx))
    {
      qassert(p->rd_id == prefix_rd_id_null) ;
      stream_put_prefix (s, p);
    }
  else
    {
      qassert(p->rd_id != prefix_rd_id_null) ;

      stream_putc (s, p->prefixlen + ((3 + 8) * 8));
      stream_put (s, "\x00\x00\x01", 3);
      stream_put (s, prefix_rd_id_get_val(p->rd_id), 8);
      stream_put (s, &p->u.prefix, PSIZE (p->prefixlen));
    } ;
}

/*------------------------------------------------------------------------------
 * Make attribute for bgp_dump.
 */
extern void
bgp_dump_routes_attr (struct stream* s, attr_set attr, prefix p)
{
  uint cp, len ;

  as_path_out_t asp_out[1] ;

  /* Remember current pointer and insert placeholder for the length
   */
  cp = stream_get_endp (s);

  stream_putw (s, 0);

  /* Origin attribute.
   */
  stream_putc (s, BGP_ATF_TRANSITIVE);
  stream_putc (s, BGP_ATT_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);

  /* AS Path attribute
   *
   * Puts in AS4 form, the entire AS_PATH, as is.
   */
  asp_out->seg = BGP_AS_SEG_NULL ;      /* prepend nothing      */

  as_path_out_prepare(asp_out, attr->asp, true /* in AS4 form */) ;

  if (asp_out->len[0] > 0)
    stream_put(s, asp_out->part[0], asp_out->len[0]) ;
  if (asp_out->len[1] > 0)
    stream_put(s, asp_out->part[1], asp_out->len[1]) ;

  /* Nexthop attribute.
   *
   * If it's an IPv6 prefix, don't dump the IPv4 nexthop to save space
   */
  if((p != NULL)
#ifdef HAVE_IPV6
     && (p->family != AF_INET6)
#endif /* HAVE_IPV6 */
     )
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_NEXT_HOP);
      stream_putc (s, 4);
      stream_put_ipv4 (s, attr->next_hop.ip.v4);
    }

  /* MED attribute.
   */
  if (attr->have & atb_med)
    {
      stream_putc (s, BGP_ATF_OPTIONAL);
      stream_putc (s, BGP_ATT_MED);
      stream_putc (s, 4);
      stream_putl (s, attr->med);
    }

  /* Local preference.
   */
  if (attr->have & atb_local_pref)
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

  /* Atomic aggregate. */
  if (attr->have & atb_atomic_aggregate)
    {
      stream_putc (s, BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_ATOMIC_AGGREGATE);
      stream_putc (s, 0);
    }

  /* Aggregator -- in AS4 form
   */
  if (attr->aggregator_as != BGP_ASN_NULL)
    {
      stream_putc (s, BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE);
      stream_putc (s, BGP_ATT_AGGREGATOR);
      stream_putc (s, 8);
      stream_putl (s, attr->aggregator_as);
      stream_put_ipv4 (s, attr->aggregator_ip) ;
    }

  /* Community attribute.
   */
  if (attr->community != NULL)
    {
      byte * p ;
      ulen len ;

      p = attr_community_out_prepare(attr->community, &len) ;

      stream_put (s, p, len) ;
    } ;

#ifdef HAVE_IPV6
  /* Add a MP_NLRI attribute to dump the IPv6 next hop
   */
  if ((p != NULL) && (p->family == AF_INET6))
    {
      if ( (attr->next_hop.type == nh_ipv6_1) ||
           (attr->next_hop.type == nh_ipv6_2) )
        {
          uint sizep ;

          stream_putc (s, BGP_ATF_OPTIONAL);
          stream_putc (s, BGP_ATT_MP_REACH_NLRI);
          sizep = stream_get_endp (s);
          stream_putc (s, 0);           /* Marker: Attribute length.    */
          stream_putw (s, AFI_IP6) ;
          stream_putc (s, SAFI_UNICAST) ;

          switch (attr->next_hop.type)
            {
              case nh_ipv6_1:           /* "global" address only        */
                stream_putc(s, 16) ;

                stream_put(s, &attr->next_hop.ip.v6[0].addr, 16) ;
                break ;

              case nh_ipv6_2:           /* "global" and link-local      */
                stream_putc(s, 32) ;

                stream_put(s, &attr->next_hop.ip.v6, 32) ;
                break ;

              default:
                assert(false) ;
            } ;

          stream_putc (s, 0);               /* SNPA */
          stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
        } ;
    } ;
#endif /* HAVE_IPV6 */

  /* Return total size of attribute. */
  len = stream_get_endp (s) - cp - 2;
  stream_putw_at (s, cp, len);
}

/*==============================================================================
 * Common stuff for attribute parsing and error handling
 */

/* Flag check table for known attributes
 *
 * For each known attribute: mask = flags we care about
 *                           req  = state required for those flags
 */
#define BGP_ATTR_FLAGS_WELL_KNOWN \
  .mask = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,\
  .req  =                0 | BGP_ATF_TRANSITIVE |               0

#define BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS \
  .mask = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE | BGP_ATF_PARTIAL,\
  .req  = BGP_ATF_OPTIONAL |                  0 |               0

#define BGP_ATTR_FLAGS_OPTIONAL_TRANS \
  .mask = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE |               0,\
  .req  = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE |               0

typedef const struct
{
  uint8_t mask ;
  uint8_t req ;
} attr_flags_check_t ;

static const attr_flags_check_t attr_flags_check_array[BGP_ATT_MAX] =
{
  [0                         ] = { 0                                 },

  [BGP_ATT_ORIGIN            ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
  [BGP_ATT_AS_PATH           ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
  [BGP_ATT_NEXT_HOP          ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
  [BGP_ATT_MED               ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_LOCAL_PREF        ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
  [BGP_ATT_ATOMIC_AGGREGATE  ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
  [BGP_ATT_AGGREGATOR        ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },

  [BGP_ATT_COMMUNITIES       ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },
  [BGP_ATT_ORIGINATOR_ID     ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_CLUSTER_LIST      ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_MP_REACH_NLRI     ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_MP_UNREACH_NLRI   ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_ECOMMUNITIES      ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },
  [BGP_ATT_AS4_PATH          ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },
  [BGP_ATT_AS4_AGGREGATOR    ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },

  [BGP_ATT_DPA               ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },
  [BGP_ATT_ADVERTISER        ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_RCID_PATH         ] = { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS },
  [BGP_ATT_AS_PATHLIMIT      ] = { BGP_ATTR_FLAGS_OPTIONAL_TRANS     },
} ;

static const attr_flags_check_t attr_flags_check_known =
                                         { BGP_ATTR_FLAGS_WELL_KNOWN } ;
static const attr_flags_check_t attr_flags_check_trans =
                                         { BGP_ATTR_FLAGS_OPTIONAL_TRANS } ;
static const attr_flags_check_t attr_flags_check_non_trans =
                                         { BGP_ATTR_FLAGS_OPTIONAL_NON_TRANS } ;

/*------------------------------------------------------------------------------
 * Common code for parsing issues.
 *
 */
static const struct message attr_flag_str[] =
{
  { BGP_ATF_OPTIONAL,   "Optional"        },
  { BGP_ATF_TRANSITIVE, "Transitive"      },
  { BGP_ATF_PARTIAL,    "Partial"         },
  { BGP_ATF_EXTENDED,   "Extended Length" },
};
static const size_t attr_flag_str_max =
  sizeof (attr_flag_str) / sizeof (attr_flag_str[0]);


inline static bool bgp_attr_flags_check(
                   bgp_attr_parser_args restrict args)           Always_Inline ;
inline static bool bgp_attr_seen_flags_check(
                   bgp_attr_parser_args restrict args)           Always_Inline ;
inline static bool bgp_attr_seen_flags_length_check(
                   bgp_attr_parser_args restrict args, uint len) Always_Inline ;






/*------------------------------------------------------------------------------
 * Implement draft-idr-error-handling
 *
 * Is passed a provisional return code.  That may be upgraded so that the
 * result is one of:
 *
 *   * BGP_ATTR_PARSE_IGNORE if the attribute can safely be ignored.
 *
 *   * BGP_ATTR_PARSE_SERIOUS if should "treat-as-withdraw" if possible.
 *
 *   * BGP_ATTR_PARSE_CRITICAL if must notify and close the session.
 *
 * If this is the first serious or critical error, set up the notification
 * details as required.
 *
 * If there has been a serious error, and we now have a critical error, it
 * is assumed that the critical error is (most likely) a consequential
 * error -- so the notification reports the first error.
 *
 * This function is not responsible for any logging.  The caller is expected
 * to log all errors in some suitable form.
 *
 * NB: sets args->ret and updates args->aret.
 */
static void
bgp_attr_malformed (bgp_attr_parser_args restrict args, byte subcode,
                                                       bgp_attr_parse_ret_t ret)
{
  switch (args->type)
    {
      /* where an optional attribute is inconsequential, e.g. it does not
       * affect route selection, and can be safely ignored then any such
       * attributes which are malformed should just be ignored and the
       * route processed as normal.
       */
      case BGP_ATT_AS4_AGGREGATOR:
      case BGP_ATT_AGGREGATOR:
      case BGP_ATT_ATOMIC_AGGREGATE:
        if (ret == BGP_ATTR_PARSE_OK)
          ret = BGP_ATTR_PARSE_IGNORE ;
        break ;

      /* Errors in core attributes, particularly ones which may influence route
       * selection, are serious and will either "treat-as-withdraw" or
       * cause a session reset.
       *
       * Some of these are, technically, Optional Transitive, so it is
       * theoretically possible that they mean nothing to the sender, so
       * could be ignored -- that possibility is discounted.
       */
      case BGP_ATT_ORIGIN:
      case BGP_ATT_AS_PATH:
      case BGP_ATT_NEXT_HOP:
      case BGP_ATT_MED:
      case BGP_ATT_LOCAL_PREF:
      case BGP_ATT_COMMUNITIES:         /* Optional, Transitive */
      case BGP_ATT_ORIGINATOR_ID:
      case BGP_ATT_CLUSTER_LIST:
      case BGP_ATT_ECOMMUNITIES:        /* Optional, Transitive */
      case BGP_ATT_AS4_PATH:            /* Optional, Transitive */
        if (ret != BGP_ATTR_PARSE_CRITICAL)
          ret = BGP_ATTR_PARSE_SERIOUS ;
        break ;

      /* Errors in some attributes cannot even be "treat-as-withdraw", and will
       * cause a session reset.
       */
      case BGP_ATT_MP_REACH_NLRI:
      case BGP_ATT_MP_UNREACH_NLRI:
        ret = BGP_ATTR_PARSE_CRITICAL ;
        break ;

      /* Unknown attributes can only fail flags-wise.
       */
      default:
        if (ret != BGP_ATTR_PARSE_CRITICAL)
          ret = BGP_ATTR_PARSE_SERIOUS ;
        break ;
    } ;

  /* Set up notification, if required.
   *
   * Note that this points into whatever buffer the attributes are currently
   * in -- same like all other attribute processing.
   */
  if ( (ret & (BGP_ATTR_PARSE_SERIOUS | BGP_ATTR_PARSE_CRITICAL)) &&
       ((args->aret & (BGP_ATTR_PARSE_SERIOUS | BGP_ATTR_PARSE_CRITICAL)) ==0) )
    {
      args->notify_code    = BGP_NOMC_UPDATE ;
      args->notify_subcode = subcode ;

      switch(subcode)
        {
          case BGP_NOMS_U_MAL_ATTR:
          case BGP_NOMS_U_MAL_AS_PATH:
          case BGP_NOMS_U_AS_LOOP:
          case BGP_NOMS_U_NETWORK:
          default:
            args->notify_data     = NULL ;
            args->notify_data_len = 0 ; /* send nothing                 */
            break ;

          case BGP_NOMS_U_MISSING:
            args->notify_attr_type = args->type ;

            args->notify_data     = &args->notify_attr_type ;
            args->notify_data_len = 1 ; /* send just the missing type   */
            break ;

          case BGP_NOMS_U_UNKNOWN:
          case BGP_NOMS_U_A_FLAGS:
          case BGP_NOMS_U_A_LENGTH:
          case BGP_NOMS_U_ORIGIN:
          case BGP_NOMS_U_NEXT_HOP:
          case BGP_NOMS_U_OPTIONAL:
            args->notify_data     = args->start_p ;
            args->notify_data_len = args->end_p - args->start_p ;
                                        /* send complete attribute      */
            if (qdebug)
              {
                if (args->start_p[0] & BGP_ATF_EXTENDED)
                  qassert(args->notify_data_len ==
                                       ((uint)load_ns(&args->start_p[2]) + 4)) ;
                else
                  qassert(args->notify_data_len ==
                                                 ((uint)args->start_p[2] + 3)) ;
              } ;
            break ;
        } ;
    } ;

  /* Update the overall result.
   */
  args->ret  |= ret ;
  args->aret |= ret ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on the basis it is a repeat.
 *
 * Issues a logging message and treats as BGP_NOMS_U_MAL_ATTR
 *
 * Updates args->ret and args->aret.
 *
 * NB: all length errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_seen_malformed (bgp_attr_parser_args restrict args)
{
  bgp_attr_malformed(args, BGP_NOMS_U_MAL_ATTR, BGP_ATTR_PARSE_SERIOUS) ;

  zlog (args->peer->log, LOG_WARNING,
            "%s: error BGP attribute type %s appears twice in a message",
              args->peer->host, map_direct(bgp_attr_name_map, args->type).str) ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on basis of its length
 *
 * Issues a logging message and treats as BGP_NOMS_U_A_LENGTH
 *
 * Updates args->ret and args->aret.
 *
 * NB: all length errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_length_malformed (bgp_attr_parser_args restrict args,
                                                              ulen len_required)
{
  bgp_attr_malformed(args, BGP_NOMS_U_A_LENGTH, BGP_ATTR_PARSE_SERIOUS) ;

  zlog (args->peer->log, LOG_ERR, "%s attribute length is %u -- should be %u",
                                map_direct(bgp_attr_name_map, args->type).str,
                                                   args->length, len_required) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on basis of the flags being invalid
 *
 * Issues a logging message and treats as BGP_NOMS_U_A_FLAGS
 *
 * Updates args->ret and args->aret.
 *
 * NB: all flags errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_flags_malformed(bgp_attr_parser_args restrict args,
                                                      attr_flags_check_t* check)
{
  uint8_t diff ;
  bool seen ;
  uint i ;

  bgp_attr_malformed(args, BGP_NOMS_U_A_FLAGS, BGP_ATTR_PARSE_SERIOUS) ;

  qassert((args->flags & 0x0F) == 0) ;
  qassert(check->mask != 0) ;

  diff = (args->flags ^ check->req) & check->mask ;

  seen = false ;
  for (i = 0; i < attr_flag_str_max ; i++)
    {
      uint8_t bit ;

      bit = attr_flag_str[i].key ;

      if (diff & bit)
        {
          zlog (args->peer->log, LOG_ERR,
                   "%s attribute must%s be flagged as \"%s\"",
                   map_direct(bgp_attr_name_map, args->type).str,
                   (check->req & bit) ? "" : " not", attr_flag_str[i].str) ;
          seen = true ;
        } ;
    } ;

  qassert (seen) ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Common check for attribute flags
 *
 * NB: for known attributes *only*
 */
inline static bool
bgp_attr_flags_check(bgp_attr_parser_args restrict args)
{
  const attr_flags_check_t* check ;

  qassert(args->type < BGP_ATT_MAX) ;

  check = &attr_flags_check_array[args->type] ;
  if ((args->flags & check->mask) == check->req)
    return true ;
  else
    return bgp_attr_flags_malformed(args, check) ;
} ;

/*------------------------------------------------------------------------------
 * Common check for whether given attribute has been seen already
 *
 * Returns:  true <=> first time the attribute has been seen
 */
inline static bool
bgp_attr_seen_check(bgp_attr_parser_args restrict args)
{
  if (bm_test_set(&args->seen, args->type))
    return bgp_attr_seen_malformed(args) ;
  else
    return true ;
} ;

/*------------------------------------------------------------------------------
 * Common check for known attributes of variable length
 *
 *   * checks and sets the args->seen bit
 *
 *   * checks that the flags are valid
 *
 * Returns:  true <=> all the above checks have passed
 *
 */
inline static bool
bgp_attr_seen_flags_check(bgp_attr_parser_args restrict args)
{
  if (bgp_attr_seen_check(args))
    return bgp_attr_flags_check(args) ;

  bgp_attr_flags_check(args) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Common check for known attributes of fixed length
 *
 *   * checks and sets the args->seen bit
 *
 *   * checks that the flags are valid
 *
 *   * checks that the length is exactly as given
 *
 * Returns:  true <=> all the above checks have passed
 *
 */
inline static bool
bgp_attr_seen_flags_length_check(bgp_attr_parser_args restrict args, uint len)
{
  bool ok ;

  ok = bgp_attr_seen_flags_check(args) ;

  if (args->length == len)
    return ok ;
  else
    return bgp_attr_length_malformed(args, len) ;
} ;





/*------------------------------------------------------------------------------
 * NLRI "syntax" check -- run through the given encode NLRI and check.
 *
 *   * qafx_ipv4_unicast    ) each prefix must be 0..32 bits long.
 *   * qafx_ipv4_multicast  )
 *
 *   * qafx_ipv4_mpls       ) each prefix must have:
 *
 *                              8 byte Route Distinguisher -- value unchecked
 *                              one or more 3 byte tag     -- last with BoS
 *                              0..32 bits of IPv4.
 *
 *   * qafx_ipv6_unicast    ) each prefix must be 0..128 bits long.
 *   * qafx_ipv6_multicast  )
 *
 *   * qafx_ipv6_mpls       ) each prefix must have:
 *
 *                              8 byte Route Distinguisher -- value unchecked
 *                              one or more 3 byte tag     -- last with BoS
 *                              0..128 bits of IPv6.
 *
 *   * everything else        no check on the prefix
 *
 * The sum of all the prefix lengths must exactly match the toatl nlri.
 *
 * Note that we do not concern ourselves with the value of any prefix, or
 * Route Distinguisher or tag(s).
 *
 * Returns:  true <=> passes sanity check
 */
extern bool
bgp_nlri_sanity_check (bgp_peer peer, bgp_nlri nlri)
{
  const byte*  pnt ;
  uint         offset, length ;
  byte         prefix_len_max, prefix_ip_len_max, prefix_len;
  bool         mpls ;

  mpls = false ;

  switch (nlri->qafx)
    {
      case qafx_ipv4_mpls_vpn:
        mpls = true ;
        fall_through ;

      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        prefix_ip_len_max =  32 ;
        break ;

      case qafx_ipv6_mpls_vpn:
        mpls = true ;
        fall_through ;

      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        prefix_ip_len_max = 128 ;
        break ;

      default:
        prefix_ip_len_max = 255 ;               /* it's a byte, guys    */
        break ;
    } ;

  prefix_len_max = prefix_ip_len_max ;          /* if not MPLS          */

  /* RFC4271 6.3 The NLRI field in the UPDATE message is checked for
   * syntactic validity.  If the field is syntactically incorrect,
   * then the Error Subcode is set to Invalid Network Field.
   */
  pnt    = nlri->pnt ;
  length = nlri->length ;
  offset = 0 ;
  while (offset < length)
    {
      prefix_len = pnt[offset] ;

      /* Worry about Route Distinguisher and Tag, if required.
       */
      if (mpls)
        {
          if (length < (offset + PSIZE(prefix_len) + 1))
            {
              /* If the total NLRI length is broken, suppress the checking
               * of the Route Distinguisher, Tag and the Prefix Length.
               */
              prefix_len_max = prefix_len ;
            }
          else
            {
              /* The nominal prefix_len is within the current NLRI, so we
               * can check the Route Distinguisher, Tag and the Prefix Length.
               *
               * Quagga can only cope with single Tag... which is believed to
               * be the only possible/reasonable case.  Here, however, we allow
               * tag stack and require last tag to be marked BoS.
               */
              uint tl ;

              if (prefix_len < (64 + 24))
                {
                  plog_err (peer->log,
                     "%s [Error] Update packet error: "
                                      "prefix nlri_len %u < %u for %s NLRI",
                                 peer->host, prefix_len, 64 + 24,
                                                get_qafx_name(nlri->qafx)) ;
                  return false ;
                } ;

              tl = mpls_tags_scan(&pnt[8 + 1], (prefix_len - 64) / 8) ;

              if (tl == 0)
                {
                  plog_err (peer->log,
                     "%s [Error] Update packet error: "
                                        "invalid label(s) for %s NLRI",
                                       peer->host, get_qafx_name(nlri->qafx)) ;
                  return false ;
                } ;

              prefix_len_max = 64 + (tl * 8) + prefix_ip_len_max ;
            } ;
        } ;

      /* Prefix length check.
       */
      if (prefix_len > prefix_len_max)
        {
          plog_err (peer->log,
                    "%s [Error] Update packet error: prefix nlri_len %u > %u "
                                                                  "for %s NLRI",
                                      peer->host, prefix_len, prefix_len_max,
                                                    get_qafx_name(nlri->qafx)) ;
          return false ;
        }

      /* Step and check remains within total nlri_len.
       */
      offset += PSIZE(prefix_len) + 1 ;
    } ;

  if (offset == length)
    return true ;

  plog_err (peer->log,
                   "%s [Error] Update packet error: prefix nlri_len %u overruns"
                                                       " total size of %s NLRI",
                            peer->host, prefix_len, get_qafx_name(nlri->qafx)) ;
  return false ;
} ;

/*==============================================================================
 * Individual Attribute Parsing
 *
 * NB: because the entire value section of the attribute set is used when
 *     hashing and looking up, it is *essential* that the value of each
 *     attribute remains all-zeros until it is accepted and set along with
 *     the atb_xxx flag.
 *
 *     To put this another way, even if (for example) the atb_origin flag is
 *     not set, the origin value field still part of the value of the
 *     attribute set, and must be zero.
 */

/*------------------------------------------------------------------------------
 * Get origin attribute of the update message.
 */
static const byte*
bgp_attr_origin (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  uint origin ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 1))
    return attr_p ;

  /* Fetch origin attribute.
   *
   * If the ORIGIN attribute has an undefined value, then the Error Subcode is
   * set to Invalid Origin Attribute.  The Data field contains the unrecognized
   * attribute (type, length and value).
   */
  origin = *attr_p++ ;

  confirm(BGP_ATT_ORG_MIN == 0) ;

  if (origin > BGP_ATT_ORG_MAX)
    {
      zlog (args->peer->log, LOG_ERR, "Origin attribute value %u is invalid",
                                                                       origin) ;
      bgp_attr_malformed(args, BGP_NOMS_U_ORIGIN, 0) ;
    }
  else
    {
      /* Set origin attribute.
       */
      bgp_attr_pair_set_origin(args->attrs, origin) ;
    } ;

  return attr_p ;
} ;

/*------------------------------------------------------------------------------
 * Parse AS path information -- parses AS_PATH or AS4_PATH.
 *
 * Does NOT set the working attribute set's as_path, but returns the parsed
 * path for further processing -- ie merging AS_PATH and AS4_PATH etc.
 *
 * Returns: if valid: BGP_ATTR_PARSE_PROCEED   XXX ..................................
 *
 *                    and sets *p_asp = address of struct aspath in the hash of
 *                    known aspaths, with reference count incremented.
 *
 *              else: whatever bgp_attr_malformed() decides.
 *
 * NB: empty AS path (length == 0) is valid.  The returned struct aspath will
 *     have segments == NULL and str == zero length string (unique).
 *
 * NB: an AS4 speaker should not be sending an AS4_PATH, and we will (later)
 *     ignore the attribute.  We capture it here so that it can be seen in
 *     any logging/debug stuff.
 */
static const byte*
bgp_attr_aspath (bgp_attr_parser_args restrict args, const byte* attr_p,
                                                                 as_path* p_asp)
{
  as_path asp ;
  bool as4 ;

  qassert( (args->type == BGP_ATT_AS_PATH)
        || (args->type == BGP_ATT_AS4_PATH) ) ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Parse the AS_PATH/AS4_PATH body.
   *
   * For AS_PATH  peer with AS4 => 4Byte ASN otherwise 2Byte ASN
   *     AS4_PATH 4Byte ASN
   */
  as4 = args->as4 || (args->type == BGP_ATT_AS4_PATH) ;

  asp = as_path_parse (attr_p, args->length, as4) ;

  attr_p += args->length ;

  if (asp != NULL)
    {
      /* AS4_PATH MUST NOT be carried in an UPDATE message between NEW_BGP
       * speakers; any such MUST be discarded (draft-ietf-idr-rfc4894bis-07).
       *
       * AS_CONFED_SEQUENCE and AS_CONFED_SET... MUST NOT be included in an
       * AS4_PATH.
       */
      if (args->type == BGP_ATT_AS4_PATH)
        {
          if (args->as4)
            {
              if (BGP_DEBUG(as4, AS4))
                zlog_debug ("[AS4] %s sent AS4_PATH "
                             "despite being an AS4 speaker", args->peer->host) ;
              args->ret |= BGP_ATTR_PARSE_IGNORE ;
            } ;

          if (as_path_confed_path_length(asp) != 0)
            {
              /* One or more confed segments in the path -> invalid
               */
              zlog (args->peer->log, LOG_ERR, "Malformed %s from %s, "
                                                 " contains Confed segment(s)",
                                 map_direct(bgp_attr_name_map, args->type).str,
                                                      args->peer->host);
              bgp_attr_malformed (args, BGP_NOMS_U_MAL_AS_PATH , 0) ;
            } ;
        } ;
    }
  else
    {
      zlog (args->peer->log, LOG_ERR, "Malformed %s from %s, length is %u",
                                 map_direct(bgp_attr_name_map, args->type).str,
                                               args->peer->host, args->length);
      bgp_attr_malformed (args, BGP_NOMS_U_MAL_AS_PATH , 0) ;
    } ;

  /* Return the as_path if all is well, otherwise discard.
   */
  if ((args->ret && BGP_ATTR_PARSE_FAILED) == 0)
    *p_asp = asp ;
  else
    as_path_free(asp) ;

  return attr_p ;
} ;

/*------------------------------------------------------------------------------
 * Nexthop attribute.
 */
static const byte*
bgp_attr_nexthop (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  in_addr_t nexthop_n, nexthop_h ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 4))
    return attr_p ;

  /* According to section 6.3 of RFC4271, syntactically incorrect NEXT_HOP
   * attribute must result in a NOTIFICATION message.
   *
   * At the same time, semantically incorrect NEXT_HOP is more likely to be
   * just logged locally (this is implemented somewhere else).
   *
   * The UPDATE message is ignored in any of these cases.
   */
  nexthop_n = load_l(attr_p) ;          /* NB: stays in Network Order   */

  nexthop_h = ntohl(nexthop_n) ;
  if (IPV4_NET0 (nexthop_h) || IPV4_NET127 (nexthop_h)
                            || IPV4_CLASS_DE (nexthop_h))
    {
      zlog (args->peer->log, LOG_ERR, "Martian nexthop %s",
                                       siptoa(AF_INET, &nexthop_n).str);
      bgp_attr_malformed (args, BGP_NOMS_U_NEXT_HOP, 0) ;
    }
  else
    {
      args->update.next_hop.type  = nh_ipv4 ;
      args->update.next_hop.ip.v4 = nexthop_n ;
    } ;

  return attr_p + 4 ;
}

/*------------------------------------------------------------------------------
 * MED attribute.
 */
static const byte*
bgp_attr_med (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 4))
    return attr_p ;

  /* Get the MED and set in working attributes
   */
  bgp_attr_pair_set_med(args->attrs, load_nl(attr_p)) ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Local preference attribute.
 */
static const byte*
bgp_attr_local_pref (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 4))
    return attr_p ;

  /* If it is contained in an UPDATE message that is received from an external
   * peer, then this attribute MUST be ignored by the receiving speaker.
   */
  if (args->sort != BGP_PEER_EBGP)
    {
      /* Get the Local Pref and set in working attributes
       */
      bgp_attr_pair_set_local_pref(args->attrs, load_nl(attr_p)) ;
    }
  else
    {
      /* We ignore any local pref received from an eBGP peer (RFC 4271, 5.1.5)
       */
      args->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Atomic Aggregate Attribute.
 */
static const byte*
bgp_attr_atomic (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   *
   * If OK, set the flag which is alk we need to know.
   */
  if (bgp_attr_seen_flags_length_check(args, 0))
    bgp_attr_pair_set_atomic_aggregate(args->attrs, true) ;

  return attr_p ;
}

/*------------------------------------------------------------------------------
 * Aggregator attribute
 */
static const byte*
bgp_attr_aggregator (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   *
   * NEW_BGP peer will send 4 Byte AS, peer without will send 2 Byte
   */
  if (!bgp_attr_seen_flags_length_check(args, args->as4 ? 4 + 4 : 4 + 2))
    return attr_p ;

  if (args->as4)
    {
      args->aggregator_as = load_nl(attr_p) ;
      attr_p += 4 ;
    }
  else
    {
      args->aggregator_as = load_ns(attr_p) ;
      attr_p += 2 ;
    } ;

  args->aggregator_ip = load_l(attr_p) ;
                                /* NB: stays in Network Order   */

  confirm(BGP_ASN_NULL == 0) ;

  if (args->aggregator_as != BGP_ASN_NULL)
    {
      bgp_attr_pair_set_aggregator(args->attrs, args->aggregator_as,
                                                args->aggregator_ip) ;
    }
  else
    {
      zlog (args->peer->log, LOG_ERR, "Invalid ASN (0) in AGGREGATOR") ;
      bgp_attr_malformed (args, BGP_NOMS_U_OPTIONAL, 0) ;
    } ;

  return attr_p + 4 ;
}

/*------------------------------------------------------------------------------
 * New Aggregator attribute
 *
 * NB: an AS4 speaker should not be sending an AS4_AGGREGATOR, and we will
 *     (later) ignore the attribute.  We capture it here so that it can be seen
 *     in any logging/debug stuff.
 */
static const byte*
bgp_attr_as4_aggregator (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 8))
    return attr_p ;

  /* Get and set the as4_aggregator_as/_ip, storing in the args.
   *
   * Those are processed against the AS_AGGREGATOR values, when all
   * attributes have been processed.
   */
  args->as4_aggregator_as  = load_nl(attr_p) ;
  args->as4_aggregator_ip  = load_l(attr_p + 4) ;
                                        /* NB: stays in Network Order   */

  confirm(BGP_ASN_NULL == 0) ;

  if (args->as4_aggregator_as == BGP_ASN_NULL)
    {
      zlog (args->peer->log, LOG_ERR, "Invalid ASN (0) in AGGREGATOR") ;
      bgp_attr_malformed (args, BGP_NOMS_U_OPTIONAL, 0) ;
    } ;

  /* draft-ietf-idr-rfc4893bis-07:
   *
   *   "... AS4_PATH and AS4_AGGREGATOR MUST NOT be carried in an UPDATE
   *    message between NEW BGP speakers.  ... MUST discard ... and
   *    continue processing the UPDATE message.
   */
  if (args->as4)
    {
      if (BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s sent AS4_AGGREGATOR despite being an"
                                              " AS4 speaker", args->peer->host);
      args->ret |= BGP_ATTR_PARSE_IGNORE ; // XXX ...............................
    } ;

  return attr_p + 8 ;
} ;

/*------------------------------------------------------------------------------
 * Communities attribute.
 */
static const byte*
bgp_attr_community (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  attr_community comm ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Length must be a multiple of 4 -- zero length is acceptable
   *                                   (RFC1997 is silent in the matter).
   *
   * Note that a zero length Communities attribute is indistinguishable from
   * an absent one -- except for the "seen" state.
   */
  if ((args->length % 4) != 0)
    {
      zlog (args->peer->log, LOG_ERR, "Malformed COMMUNITIES (length is %u)",
                                                                 args->length) ;
      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  /* Construct and set the communities sub-attribute
   *
   * NB: at this stage we accept whatever the attribute contains.  If one or
   *     more community is invalid, that is a matter for a higher authority.
   */
  comm = attr_community_set (attr_p, args->length / 4) ;

  bgp_attr_pair_set_community(args->attrs, comm) ;

  return attr_p + args->length ;
} ;

/*------------------------------------------------------------------------------
 * Originator ID attribute -- Route Reflector
 */
static const byte*
bgp_attr_originator_id (bgp_attr_parser_args args, const byte* attr_p)
{
  in_addr_t  id ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(args, 4))
    return attr_p ;

  /* If iBGP, get and set the Originator ID in the cluster sub-attribute,
   * creating it if required.
   *
   * Ignore otherwise -- including cBGP.
   *
   * ORIGINATOR_ID is optional non-transitive.  RFC4456 says that it "will
   * be created by an RR in reflecting a route" and "will carry the BGP
   * Identifier of the originator of the route in the Local AS".  So,
   * reflecting means:
   *
   *   a) from RR Client to other iBGP and to other RR Clients
   *
   *      An RR Client may itself be a RR, in which case it will send an
   *      ORIGINATOR_ID.
   *
   *      A simple RR Client should not be sending an ORIGINATOR_ID, but we
   *      cannot tell if it does.
   *
   *   b) from another iBGP to RR Client
   *
   *      Another iBGP may also be a RR, in which case it will send an
   *      ORIGINATOR_ID.
   *
   *      Another simple iBGP should not be sending an ORIGINATOR_ID, but we
   *      cannot tell if it does.
   *
   * The two cases are the same, so we end up accepting ORIGINATOR_ID from any
   * iBGP peer.
   */
  if (args->sort == BGP_PEER_IBGP)
    {
      id = load_l(attr_p) ;     /* NB: stays in Network Order   */
      bgp_attr_pair_set_originator_id(args->attrs, id) ;
    }
  else
    {
      args->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Cluster list attribute -- Route Reflector
 */
static const byte*
bgp_attr_cluster_list (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  attr_cluster clust ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Length must be a multiple of 4 -- zero length is acceptable.
   */
  if (args->length % 4)
    {
      zlog (args->peer->log, LOG_ERR, "Bad cluster list length %u",
                                                                  args->length);
      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  /* If iBGP, get and set the Cluster List in the cluster sub-attribute,
   * creating it if required.
   *
   * Ignore otherwise -- including cBGP.
   *
   * CLUSTER_LIST is optional non-transitive.  See ORIGINATOR_ID for more
   * discussion of the handling.
   */
  if (args->sort == BGP_PEER_IBGP)
    {
      clust = attr_cluster_set(attr_p, args->length / 4) ;
      bgp_attr_pair_set_cluster(args->attrs, clust) ;
    }
  else
    {
      args->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + args->length ;
} ;

/*------------------------------------------------------------------------------
 * Multiprotocol reachability information parse.
 */
static const byte*
bgp_attr_mp_reach_parse (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  bgp_nlri  nlri ;
  byte      reserved ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Need a minimum of 5 bytes, for AFI, SAFI, nexthop_len and reserved octet.
   */
  if (args->length < (2 + 1 + 1 + 1))
    {
      zlog (args->peer->log, LOG_ERR,
                        "%s attribute length is %u -- should be at least 5",
                    map_direct(bgp_attr_name_map, BGP_ATT_MP_REACH_NLRI).str,
                                                                 args->length) ;
      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  /* Load AFI, SAFI and Next Hop Length and check that we have enough for the
   * all that plus the reserved octet.
   */
  nlri = &args->mp_update ;

  nlri->in.afi          = load_ns(attr_p) ;
  nlri->in.safi         = attr_p[2] ;
  nlri->next_hop_length = attr_p[3] ;

  if (args->length < (2 + 1 + 1 + nlri->next_hop_length + 1))
    {
      zlog_info ("%s: %s, MP nexthop length %u + reserved byte"
                                                   " overruns end of attribute",
                 __func__, args->peer->host, nlri->next_hop_length);

      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  attr_p  += (2 + 1 + 1) ;      /* step past red-tape   */

  /* Nexthop extraction -- if length is recognised.
   */
  switch (nlri->next_hop_length)
    {
      case 4:
        nlri->next_hop.ip.v4 = load_l(attr_p) ;
        nlri->next_hop.type  = nh_ipv4 ;
        break;

      /* RFC4364 -- BGP/MPLS IP VPNs -- "VPN-IPv4"
       *
       * 4.3.2 ...address encoded as a VPN-IPv4 address with an RD of 0.
       *
       * We step straight past the RD, without checking it.
       */
      case 12:
        memcpy(nlri->next_hop_rd[0], attr_p, 8) ;

        nlri->next_hop.ip.v4 = load_l(attr_p + 8) ;
        nlri->next_hop.type  = nh_ipv4 ;
        break ;

#ifdef HAVE_IPV6
      /* RFC2545 -- the "global" in this context means "not-link-local",
       *            and can be "site-local" -- though the RFC does have a big
       *            caveat on the use of "site-local".
       */
      case 16:
        memcpy(&nlri->next_hop.ip.v6[in6_global], attr_p, 16) ;
        nlri->next_hop.type = nh_ipv6_1 ;
        break;

      /* RFC4659 -- BGP/MPLS IP VPN Extension for IPv6 VPN -- "VPN-IPv6"
       *
       * 3.2.1.1 BGP Speaker Requesting IPv6 Transport
       *
       *    * 24 bytes:  8 byte RD == 0, 16 bytes "global" IPv6
       *
       *    * 48 bytes:  see below
       */
      case 24:
        memcpy(nlri->next_hop_rd[0], attr_p, 8) ;

        memcpy(&nlri->next_hop.ip.v6[in6_global], attr_p + 8, 16) ;
        nlri->next_hop.type = nh_ipv6_1 ;
        break;

      /* RFC2545 -- but check for 2nd address really being link-local is
       *            not specified by the RFC.
       */
      case 32:
        memcpy(&nlri->next_hop.ip.v6, attr_p, 32) ;
        nlri->next_hop.type = nh_ipv6_2 ;

        confirm((in6_global == 0) && (in6_link_local == 1)) ;

        break;

      /* RFC4659 -- BGP/MPLS IP VPN Extension for IPv6 VPN -- "VPN-IPv6"
       *
       * 3.2.1.1 BGP Speaker Requesting IPv6 Transport
       *
       *    * 48 bytes:  8 byte RD == 0, 16 bytes "global" IPv6
       *                 8 byte RD == 0, 16 bytes "link-local" IPv6
       */
      case 48:
        memcpy(nlri->next_hop_rd[0], attr_p +  0, 8) ;
        memcpy(nlri->next_hop_rd[1], attr_p + 24, 8) ;

        memcpy(&nlri->next_hop.ip.v6[in6_global],     attr_p +  8, 16) ;
        memcpy(&nlri->next_hop.ip.v6[in6_link_local], attr_p + 32, 16) ;

        nlri->next_hop.type = nh_ipv6_2 ;
        break ;
#endif /* HAVE_IPV6 */

      default:
        zlog_info ("%s: (%s) unknown multiprotocol next hop length: %u",
                            __func__, args->peer->host, nlri->next_hop_length) ;

        bgp_attr_malformed (args, BGP_NOMS_U_OPTIONAL, 0) ;
        return attr_p ;
    } ;

#ifdef HAVE_IPV6
  /* Check link-local is link local.
   */
  if ((nlri->next_hop.type == nh_ipv6_2) &&
         ! IN6_IS_ADDR_LINKLOCAL(
                          &nlri->next_hop.ip.v6[in6_link_local].addr))
    {
      if (BGP_DEBUG (update, UPDATE_IN))
        zlog_debug ("%s got two nexthop %s %s "
                               "but second one is not a link-local nexthop",
                   args->peer->host,
                   siptoa(AF_INET6,
                         &nlri->next_hop.ip.v6[in6_global].addr).str,
                   siptoa(AF_INET6,
                         &nlri->next_hop.ip.v6[in6_link_local].addr).str) ;

      nlri->next_hop.type = nh_ipv6_1 ;     /* discard link-local   */
    }
#endif /* HAVE_IPV6 */

  /* Step past the next_hop, pick up and step past the reserved octet
   *
   * Check the reserved octet value
   */
  reserved = attr_p[nlri->next_hop_length] ;
  attr_p  += nlri->next_hop_length + 1 ;

  if (reserved != 0)
    zlog_warn("%s sent non-zero value, %u, for defunct SNPA-length field"
                                         " in MP_REACH_NLRI for AFI/SAFI %u/%u",
                     args->peer->host, reserved, nlri->in.afi, nlri->in.safi) ;

  /* Worry about whether we recognise the AFI/SAFI pair.
   *
   * The far end really should not be sending stuff that we don't recognise,
   * since we only announce a capability for stuff we do !
   *
   * Should not really be sending stuff that we are not enabled for, and so
   * have not announced a capability for.  TODO ********************************
   *
   * It's not 100% clear whether can/should check the nexthop type against the
   * AFI/SAFI.  TODO ***********************************************************
   */
  nlri->qafx = qafx_from_i(nlri->in.afi, nlri->in.safi) ;

  switch (nlri->qafx)
    {
      case qafx_undef:
        zlog_warn("%s sent undefined AFI/SAFI %u/%u MP_REACH_NLRI",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;

        args->ret |= BGP_ATTR_PARSE_IGNORE ;

        nlri->qafx = qafx_other ;       /* treat as "other" from now on */
        break ;

      case qafx_other:
      default:
        zlog_warn("%s sent unknown AFI/SAFI %u/%u MP_REACH_NLRI",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;

        args->ret |= BGP_ATTR_PARSE_IGNORE ;
        break ;

      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
      case qafx_ipv4_mpls_vpn:
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
      case qafx_ipv6_mpls_vpn:
        break ;
    } ;

  /* What is left of the attribute is the NLRI.
   *
   * RFC 4760 says (section 5, NLRI Encoding) that the NLRI "...is encoded as
   * one or more 2-tuples..." which indicates that zero length NLRI would
   * be wrong -- except, of course, for End-of-RIB !!
   *
   * Accepting zero bytes of NLRI does not appear to do harm.  But we whine
   * about it in the logging.
   */
  nlri->pnt    = attr_p ;
  nlri->length = args->length - (2 + 1 + 1 + nlri->next_hop_length + 1) ;

  if (nlri->length == 0)
    {
      if (args->ret == BGP_ATTR_PARSE_OK)
        zlog_warn("%s sent zero length NLRI in MP_REACH_NLRI"
         " for AFI/SAFI %u/%u", args->peer->host, nlri->in.afi, nlri->in.safi) ;
    }
  else
    {
      /* If the NLRI are not valid drops the session
       */
      if (!bgp_nlri_sanity_check (args->peer, nlri))
        {
          zlog_info ("%s %s NLRI in MP_REACH_NLRI fails sanity check",
                                 args->peer->host, get_qafx_name(nlri->qafx)) ;

          bgp_attr_malformed (args, BGP_NOMS_U_OPTIONAL,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
        } ;
    } ;

  return attr_p + nlri->length ;
} ;

/*------------------------------------------------------------------------------
 * Multiprotocol unreachable parse
 *
 * Sets mp_eor iff all is well, and attribute is empty and there are no
 * Withdraw/Update NLRI.  Takes the start and end of all attributes in order to
 * perform this test.
 *
 * NB: expects the args->mp_withdraw structure to have been zeroized.
 */
static const byte*
bgp_attr_mp_unreach_parse (bgp_attr_parser_args restrict args,
                                         const byte* attr_p,
                                         const byte* start_p, const byte* end_p)
{
  bgp_nlri  nlri ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Check for at least enough for AFI and SAFI, and fetch same.
   */
  if (args->length < (2 + 1))
    {
      zlog (args->peer->log, LOG_ERR,
                            "%s attribute length is %u -- should be at least 3",
                    map_direct(bgp_attr_name_map, BGP_ATT_MP_UNREACH_NLRI).str,
                                                                 args->length) ;
      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  nlri = &args->mp_withdraw ;

  nlri->in.afi   = load_ns(attr_p) ;
  nlri->in.safi  = attr_p[2] ;

  /* Worry about whether we recognise the AFI/SAFI pair.
   *
   * The far end really should not be sending stuff that we don't recognise,
   * since we only announce a capability for stuff we do !
   *
   * Should not really be sending stuff that we are not enabled for, and so
   * have not announced a capability for.  TODO ********************************
   *
   * It's not 100% clear whether can/should check the nexthop type against the
   * AFI/SAFI.  TODO ***********************************************************
   */
  nlri->qafx = qafx_from_i(nlri->in.afi, nlri->in.safi) ;

  switch (nlri->qafx)
    {
      case qafx_undef:
        zlog_warn("%s sent undefined AFI/SAFI %u/%u MP_REACH_NLRI",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;

        args->ret |= BGP_ATTR_PARSE_IGNORE ;

        nlri->qafx = qafx_other ;       /* treat as "other" from now on */
        break ;

      case qafx_other:
      default:
        zlog_warn("%s sent unknown AFI/SAFI %u/%u MP_REACH_NLRI",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;

        args->ret |= BGP_ATTR_PARSE_IGNORE ;
        break ;

      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
      case qafx_ipv4_mpls_vpn:
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
      case qafx_ipv6_mpls_vpn:
        break ;
    } ;

  /* What is left of the attribute is the NLRI.
   */
  nlri->pnt    = attr_p       + (2 + 1) ;
  nlri->length = args->length - (2 + 1) ;

  qassert(!args->mp_eor) ;      /* default is no MP End-of-RIB  */

  if (nlri->length == 0)
    {
      /* We have an MP End-of-RIB iff:
       *
       *   * this is the only attribute -- the start and end of this attribute
       *                               are the start and end of all attributes
       *
       *   * there are no Withdraw or Update NLRI.
       *
       * If there are Update NLRI and this is the only attribute, then that
       * will trigger the missing mandatory attribute error, later.
       *
       * If there are withdraw NLRI and this is the only attribute, then this
       * is a bit odd.
       *
       * If this is not an End-of-RIB, then no NLRI in an MP_UNREACH_NLRI is
       * noteworthy.
       */
      if ((args->start_p == start_p) && (args->end_p == end_p))
        {
          if (args->update.length == 0)
            {
              if (args->withdraw.length == 0)
                args->mp_eor = true ;
              else
                zlog_warn("%s sent apparent End-of-RIB in MP_UNREACH_NLRI"
                       " for AFI/SAFI %u/%u BUT have Withdrawn Routes",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;
            } ;
        }
      else
        {
          if (args->ret == BGP_ATTR_PARSE_OK)
            zlog_warn("%s sent zero length NLRI in MP_UNREACH_NLRI"
                        " for AFI/SAFI %u/%u",
                                args->peer->host, nlri->in.afi, nlri->in.safi) ;
        } ;
    }
  else
    {
      if (!bgp_nlri_sanity_check (args->peer, nlri))
        {
          zlog(args->peer->log, LOG_ERR,
                 "%s %s NLRI in MP_UNREACH_NLRI fails sanity check",
                                  args->peer->host, get_qafx_name(nlri->qafx)) ;

          bgp_attr_malformed (args, BGP_NOMS_U_OPTIONAL,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
        } ;
    } ;

  return attr_p + args->length ;
} ;

/*------------------------------------------------------------------------------
 * Extended Community attribute.
 */
static const byte*
bgp_attr_ecommunities (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  attr_ecommunity ecomm ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(args))
    return attr_p ;

  /* Length must be a multiple of 8 -- zero length is acceptable
   *                                   (RFC4360 is silent on the matter).
   *
   * Note that a zero length Extended Communities attribute is
   * indistinguishable from an absent one -- except for the "seen" state.
   */
  if ((args->length % 8) != 0)
    {
      zlog (args->peer->log, LOG_ERR, "Malformed EXT COMMUNITIES (length is %u)",
                                                                 args->length) ;

      bgp_attr_malformed (args, BGP_NOMS_U_A_LENGTH, 0) ;

      return attr_p ;
    } ;

  /* Construct and set the extended communities sub-attribute
   *
   * NB: at this stage we accept whatever the attribute contains.  If one or
   *     more extended community is invalid, that is a matter for a higher
   *     authority.
   */
  ecomm = attr_ecommunity_set (attr_p, args->length / 8) ;

  bgp_attr_pair_set_ecommunity(args->attrs, ecomm) ;

  return attr_p + args->length ;
} ;

/*------------------------------------------------------------------------------
 * BGP unknown attribute treatment
 */
static const byte*
bgp_attr_unknown (bgp_attr_parser_args restrict args, const byte* attr_p)
{
  const attr_flags_check_t* check ;

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s Unknown attribute received "
                                            "(%stransitive type %u, length %u)",
                   args->peer->host,
                      (args->flags & BGP_ATF_TRANSITIVE) ? "" : "non-",
                                                      args->type, args->length);

  if (BGP_DEBUG (events, EVENTS))
    zlog (args->peer->log, LOG_DEBUG,
                          "Unknown attribute type %u length %u received",
                                                      args->type, args->length);

  /* Check for whether already seen this attribute type
   */
  bgp_attr_seen_check(args) ;

  /* Optional, Non-Transitive attributes MUST have Partial Bit == 0
   *
   * Optional, Transitive will have Partial Bit == 1, unless the attribute
   * was added by the originator *and* all ASes it has passed through
   * recognised it.
   *
   * Not-Optional attributes really should be known -- so either Quagga is
   * deficient or the other end is mistaken.  In any case, we treat this as
   * a BGP_NOMS_U_UNKNOWN.
   *
   * The significance of the Partial Bit is, frankly, a mystery.
   */
  if (args->flags & BGP_ATF_OPTIONAL)
    check = (args->flags & BGP_ATF_TRANSITIVE) ? &attr_flags_check_trans
                                               : &attr_flags_check_non_trans ;
  else
    {
      bgp_attr_malformed(args, BGP_NOMS_U_UNKNOWN, BGP_ATTR_PARSE_SERIOUS) ;
      check = &attr_flags_check_known ;
    } ;

  if ((args->flags & check->mask) != check->req)
    bgp_attr_flags_malformed(args, check) ;

  /* For the time being we simply push a pointer to the raw attribute onto
   * the vector of unknown attributes, for processing later.
   */
  args->unknown = attr_unknown_add(args->unknown, args->start_p) ;

  return attr_p + args->length ;
}

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * Process AS4_AGGREGATOR attribute -- assuming peer is NOT an AS4 speaker
 *
 * This is done once all attributes have been processed, so that we can mash
 * any AGGREGATOR and the AS4_AGGREGATOR together, if required.
 *
 * NB: this must be done *before* processing the AS4_PATH, because RFC4893
 *     says:
 *
 *       "A NEW BGP speaker should also be prepared to receive the
 *        AS4_AGGREGATOR attribute along with the AGGREGATOR attribute from an
 *        OLD BGP speaker. When both the attributes are received, if the AS
 *        number in the AGGREGATOR attribute is not AS_TRANS, then:
 *
 *          - the AS4_AGGREGATOR attribute and the AS4_PATH attribute SHALL
 *            be ignored,
 *
 *          - the AGGREGATOR attribute SHALL be taken as the information
 *            about the aggregating node, and
 *
 *          - the AS_PATH attribute SHALL be taken as the AS path
 *            information.
 *
 *        Otherwise,
 *
 *          - the AGGREGATOR attribute SHALL be ignored,
 *
 *          - the AS4_AGGREGATOR attribute SHALL be taken as the information
 *            about the aggregating node, and
 *
 *          - the AS path information would need to be constructed, as in all
 *            other cases.
 *
 *     There are two reasons for the AGGREGATOR to not be AS_TRANS:
 *
 *       1. Some AS2 speaker since the last AS4 speaker has aggregated
 *
 *          Aggregation has possibly unfortunate effects on the relationship
 *          between the AS_PATH and the AS4_PATH, so the latter is discarded.
 *
 *          In any case, it is likely that the AS2 aggregator could lose the
 *          AS4_PATH entirely in the process !
 *
 *       2. The last AS4 speaker was bonkers, and may not be trustworthy !
 *
 *     But (1) is probably the reason for this behaviour.
 *
 * Returns: BGP_ATTR_PARSE_OK     -- all is well
 *          BGP_ATTR_PARSE_IGNORE => ignore this AND any AS4_PATH
 *                                   NB: this is not, strictly, and error
 */
static bgp_attr_parse_ret_t
bgp_attr_munge_as4_aggr (bgp_attr_parser_args restrict args)
{
  qassert(!args->as4) ;

  if (args->as4_aggregator_as == BGP_ASN_NULL)
    return BGP_ATTR_PARSE_OK ;          /* Easy if no AS4_AGGREGATOR    */

  /* AGGREGATOR is Optional Transitive.
   *
   * RFC4893 says:
   *
   *   "... if the NEW speaker has to send the AGGREGATOR attribute,
   *    and if the aggregating Autonomous System's AS number is truly 4-
   *    octets, then the speaker constructs the AS4_AGGREGATOR attributes by
   *    taking the attribute length and attribute value from the AGGREGATOR
   *    attribute and placing them into the attribute length and attribute
   *    value of the AS4_AGGREGATOR attribute, and sets the AS number field
   *    in the existing AGGREGATOR attribute to the reserved AS number,
   *    AS_TRANS. Note that if the AS number is 2-octets only, then the
   *    AS4_AGGREGATOR attribute SHOULD NOT be sent."
   *
   * So, expect the AS4 speaker to generate an AS4_AGGREGATOR iff there is an
   * AGGREGATOR, and the iff the ASN involved requires it.
   *
   * Do not expect any AS in between to drop the AGGREGATOR attribute.
   *
   * As noted above the RFC also says:
   *
   *   "A NEW BGP speaker should also be prepared to receive the
   *    AS4_AGGREGATOR attribute along with the AGGREGATOR attribute..."
   *
   * It is silent on the case where an AS4_AGGREGATOR appears on its own !!
   * In this case we suppose:
   *
   *   (a) an AS4 speaker has issued an AS4_AGGREGATOR *without* sending the
   *       matching AGGREGATOR -- which is a mistake !
   *
   *       In this case, one could treat this as if the AS4 speaker had failed
   *       to use AS_TRANS in the AGGREGATOR attribute.
   *
   *   (b) an AS of either sex has dropped the AGGREGATOR , but not the
   *       AS4_AGGREGATOR.
   *
   *       An AS2 speaker may have deliberately discarded the AGGREGATOR
   *       information, but (of course) not known enough to drop the
   *       AS4 version !
   *
   * We cannot really distinguish the case of deliberately dropping the
   * AGGREGATOR (however naughty that might be) from a failure to issue
   * both AGGREGATOR and AS4_AGGREGATOR together.  BUT, if we were to resurrect
   * an AGGREGATOR from a lone AS4_AGGREGATOR, then some poor AS2 speaker
   * will find that BGP is no longer working as it did before !!!
   */
  if (args->aggregator_as == BGP_ASN_NULL)
    {
      if ( BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s BGP not AS4 capable peer"
                    " sent AS4_AGGREGATOR but no AGGREGATOR,"
                    " so ignore the AS4_AGGREGATOR", args->peer->host);

      return BGP_ATTR_PARSE_OK ;        /* Easy(-ish) if no AGGREGATOR  */
    } ;

  /* received both AGGREGATOR and AS4_AGGREGATOR.
   */
  if (args->aggregator_as != BGP_ASN_TRANS)
    {
      if ( BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s BGP not AS4 capable peer"
                    " sent AGGREGATOR %u != AS_TRANS and"
                    " AS4_AGGREGATOR, so ignore"
                    " AS4_AGGREGATOR and AS4_PATH", args->peer->host,
                                                          args->aggregator_as) ;
      return BGP_ATTR_PARSE_IGNORE ;
    } ;

  /* Finally -- set the aggregator information from the AS4_AGGREGATOR !
   */
  bgp_attr_pair_set_aggregator(args->attrs, args->as4_aggregator_as,
                                            args->as4_aggregator_ip) ;

  return BGP_ATTR_PARSE_OK ;
} ;

/*------------------------------------------------------------------------------
 * Process AS4_PATH attribute, if any -- assuming peer is NOT an AS4 speaker
 *
 * This is done once all attributes have been processed, so that we can mash
 * the AS_PATH and the AS4_PATH together, if required.
 *
 * NB: this MUST be done *after* bgp_attr_munge_as4_aggr() -- see there.
 *
 * On entry, args->asp is the AS_PATH attribute and args->as4p is the AS4_PATH.
 * When this function returns, args->asp is the effective path, after any
 * reconciliation of the two attributes.
 *
 * Returns: BGP_ATTR_PARSE_OK  -- all is well
 *
 * NB: we quietly ignore AS4_PATH if no AS_PATH -- same like AS4_AGGREGATOR.
 */
static bgp_attr_parse_ret_t
bgp_attr_munge_as4_path (bgp_attr_parser_args restrict args)
{
  as_path merged ;

  qassert(!args->as4) ;

  if (args->as4p == NULL)
    return BGP_ATTR_PARSE_OK ;          /* Easy if no AS4_PATH          */

  if (args->asp == NULL)
    {
      /* The lack of an AS_PATH is likely to become a serious issue in the
       * near future.
       *
       * In the meantime, we ignore the AS4_PATH.  If it were ever the case that
       * an AS_PATH is optional... then it would be perfectly possible for the
       * non-AS4 speaker to send the AS4_PATH.  So this is not the place to
       * decide whether the lack of AS_PATH is a problem -- but certainly we
       * can do nothing with the AS4_PATH !
       */
      if (BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s BGP not AS4 capable peer"
                    " sent AS4_PATH but no AS_PATH,"
                    " so ignore the AS4_PATH", args->peer->host);

      return BGP_ATTR_PARSE_OK ;        /* Easy(-ish) if no AS_PATH     */
    } ;

  /* need to reconcile NEW_AS_PATH and AS_PATH
   */
  merged = as_path_reconcile_as4 (args->asp, args->as4p) ;

  qassert(merged == args->asp) ;

  return BGP_ATTR_PARSE_OK ;
} ;

/*------------------------------------------------------------------------------
 * If the as path is acceptable, set it in the attribute pair.
 *
 * Performs final checks on the AS_PATH -- once have resolved any AS4_PATH
 * issues,
 *
 * If all is OK, sets args->asp as the AS Path attribute in the attribute set,
 * and clears args->asp (ownership changes when path is set).
 *
 * If path contains any confed stuff, then:
 *
 *   * reject if is an eBGP peer
 *
 *   * reject if is not all at the front of the AS_PATH.
 *
 * If is an eBGP session, and is BGP_FLAG_ENFORCE_FIRST_AS, reject the path
 * if first ASN is not peer.
 *
 * NB: if the AS_PATH is malformed, that is reported as problem with the
 *     AS_PATH attribute, even if the malformation is due to a problem
 *     with the AS4_PATH.
 *
 *     The AS_PATH is Well-Known Mandatory.  So bgp_attr_malformed() will
 *     not allow much latitude !
 *
 * Updates args->aret if AS_PATH is not acceptable
 */
static void
bgp_attr_as_path_set_if_ok(bgp_attr_parser_args restrict args)
{
  as_path asp ;

  asp = args->asp ;

  if (as_path_confed_path_length(asp) != 0)
    {
      /* Have some confed stuff, somewhere in the AS_PATH.
       */
      if (args->sort == BGP_PEER_EBGP)
        {
          zlog (args->peer->log, LOG_ERR,
                    "AS path from %s contains CONFED stuff", args->peer->host) ;

          bgp_attr_malformed (args, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;

      if (!as_path_confed_ok(asp))
        {
          zlog (args->peer->log, LOG_ERR,
                  "AS path from %s contains CONFED stuff, but not all at start",
                                                             args->peer->host) ;
          bgp_attr_malformed (args, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    }
  else
    {
      if (args->sort == BGP_PEER_CBGP)
        {
          zlog (args->peer->log, LOG_ERR,
                      "AS path from %s does not contain CONFED stuff",
                                                             args->peer->host) ;

          bgp_attr_malformed (args, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    } ;

  /* First AS check for EBGP -- NB: have already rejected any confed stuff.
   */
  if ((args->sort == BGP_PEER_EBGP)
                           && (as_path_first_simple_asn(asp) != args->peer->as))
    {
      struct bgp* bgp ;

      bgp = args->peer->bgp;

      if ((bgp != NULL) && bgp_flag_check (bgp, BGP_FLAG_ENFORCE_FIRST_AS))
        {
          zlog (args->peer->log, LOG_ERR, "%s incorrect first AS (must be %u)",
                                             args->peer->host, args->peer->as) ;

          bgp_attr_malformed(args, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    } ;

  /* The AS PATH is OK -- so now add to the attribute set.
   */
  args->asp = NULL ;                    /* Transfer to attributes       */

  bgp_attr_pair_set_as_path(args->attrs, asp) ;
} ;

/*==============================================================================
 * Test interfaces
 */
extern const byte*
tx_bgp_attr_mp_reach_parse(bgp_attr_parser_args args, const byte* attr_p)
{
  return bgp_attr_mp_reach_parse(args, attr_p) ;
} ;

extern const byte*
tx_bgp_attr_mp_unreach_parse(bgp_attr_parser_args args,
                                       const byte* attr_p,
                                       const byte* start_p, const byte* end_p)
{
  return bgp_attr_mp_unreach_parse(args, attr_p, start_p, end_p) ;
} ;

