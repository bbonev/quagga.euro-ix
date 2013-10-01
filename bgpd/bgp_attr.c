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
#include "prefix.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "log.h"

#include "bgp.h"
#include "bgpd/bgp_session.h"
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
static const byte* bgp_attr_origin(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_aspath(bgp_attr_parsing restrict prs,
                                           const byte* attr_p, as_path* p_asp) ;
static const byte* bgp_attr_nexthop(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_med(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_local_pref(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_atomic(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_aggregator(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_as4_aggregator(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_community(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_originator_id(bgp_attr_parsing prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_cluster_list(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_mp_reach_parse(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_mp_unreach_parse(bgp_attr_parsing restrict prs,
                                       const byte* attr_p,
                                       const byte* start_p, const byte* end_p) ;
static const byte* bgp_attr_ecommunities(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;
static const byte* bgp_attr_unknown(bgp_attr_parsing restrict prs,
                                                           const byte* attr_p) ;

static bgp_attr_parse_ret_t bgp_attr_munge_as4_aggr(
                                           bgp_attr_parsing restrict prs) ;
static bgp_attr_parse_ret_t bgp_attr_munge_as4_path(
                                           bgp_attr_parsing restrict prs) ;
static void bgp_attr_as_path_set_if_ok(bgp_attr_parsing restrict prs) ;

static void bgp_attr_malformed(bgp_attr_parsing restrict prs,
                                       byte subcode, bgp_attr_parse_ret_t ret) ;

/*------------------------------------------------------------------------------
 * Read attribute of update packet.
 *
 * This function is called from bgp_update() in bgpd.c.
 *
 * NB: expects the parsing structure to be initialised, ready to process the
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
 * NB: expects caller to tidy up the result, in particular to deal with the:
 *
 *      attrs     -- this function adds stuff to the working set of the
 *                   attribute pair -- it does not store the result.
 *
 *      asp       -- intermediate AS_PATH, if any remains
 *      asp4      -- intermediate AS4_PATH, if any remains
 *      unknown   -- intermediate unknown attributes
 */
extern void
bgp_attr_parse (bgp_attr_parsing restrict prs, const byte* start_p,
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
   *          prs->start_p = start of the current attribute
   *          prs->end_p   = end of the current attribute
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
      prs->start_p = attr_p ;

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
      prs->flags = flags & ~BGP_ATF_ZERO ;     /* discard LS bits      */

      if (flags & BGP_ATF_EXTENDED)
        header_length = 4 ;
      else
        header_length = 3 ;

      if (attr_have < header_length)
        {
          prs->type   = (attr_have > 1) ? attr_p[1] : BGP_ATT_UNDEFINED ;
          prs->length = (attr_have > 2) ? attr_p[2] : 0 ;

          zlog (prs->peer->log, LOG_ERR,
                "%s: broken BGP attribute [0x%x %u %u] have just %u octets for"
                                                            " attribute header",
                 prs->peer->host, flags, prs->type, prs->length, attr_have) ;

          bgp_attr_malformed(prs, BGP_NOMS_U_A_LENGTH,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
          return ;
        } ;

      prs->type  = attr_p[1] ;

      if (header_length == 4)
        prs->length = load_ns(&attr_p[2]) ;
      else
        prs->length = attr_p[2] ;

      attr_p += header_length ;

      if (attr_have < (header_length + prs->length))
        {
          zlog (prs->peer->log, LOG_ERR,
                "%s: broken BGP attribute [0x%x %u %u] have just %u octets for"
                                                              " attribute body",
                      prs->peer->host, flags, prs->type, prs->length,
                                                  (attr_have - header_length)) ;

          bgp_attr_malformed(prs, BGP_NOMS_U_A_LENGTH,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
          return ;
        } ;

      /* Parse according to type
       */
      prs->end_p = attr_p + prs->length ;
      prs->ret   = BGP_ATTR_PARSE_OK ;

      switch (prs->type)
        {
          case BGP_ATT_UNDEFINED:
            break ;

          case BGP_ATT_RESERVED:
            break ;

          case BGP_ATT_ORIGIN:
            attr_p = bgp_attr_origin (prs, attr_p);
            break;

          case BGP_ATT_AS_PATH:
            attr_p = bgp_attr_aspath (prs, attr_p, &prs->asp) ;
            break;

          case BGP_ATT_AS4_PATH:
            attr_p = bgp_attr_aspath (prs, attr_p, &prs->as4p) ;
            break;

          case BGP_ATT_NEXT_HOP:
            attr_p = bgp_attr_nexthop (prs, attr_p);
            break;

          case BGP_ATT_MED:
            attr_p = bgp_attr_med (prs, attr_p);
            break;

          case BGP_ATT_LOCAL_PREF:
            attr_p = bgp_attr_local_pref (prs, attr_p);
            break;

          case BGP_ATT_A_AGGREGATE:
            attr_p = bgp_attr_atomic (prs, attr_p);
            break;

          case BGP_ATT_AGGREGATOR:
            attr_p = bgp_attr_aggregator (prs, attr_p);
            break;

          case BGP_ATT_AS4_AGGREGATOR:
            attr_p = bgp_attr_as4_aggregator (prs, attr_p);
            break;

          case BGP_ATT_COMMUNITIES:
            attr_p = bgp_attr_community (prs, attr_p);
            break;

          case BGP_ATT_ORIGINATOR_ID:
            attr_p = bgp_attr_originator_id (prs, attr_p);
            break;

          case BGP_ATT_CLUSTER_LIST:
            attr_p = bgp_attr_cluster_list (prs, attr_p);
            break;

          case BGP_ATT_MP_REACH_NLRI:
            attr_p = bgp_attr_mp_reach_parse (prs, attr_p);
            break;

          case BGP_ATT_MP_UNREACH_NLRI:
            attr_p = bgp_attr_mp_unreach_parse (prs, attr_p, start_p, end_p);
            break;

          case BGP_ATT_ECOMMUNITIES:
            attr_p = bgp_attr_ecommunities (prs, attr_p);
            break;

          default:
            attr_p = bgp_attr_unknown (prs, attr_p);
            break;
        } ;

      /* If all is well, check that the individual attribute parser has
       * reached the expected end.
       *
       * If all is still OK, continue parsing straight away.
       */
      if (prs->ret == BGP_ATTR_PARSE_OK)
        {
          if (attr_p == prs->end_p)
            continue ;

          /* This is actually an internal error -- at some point has failed to
           * read everything that was expected (underrun) or have tried to
           * read more than is available (overrun) !
           */
          zlog (prs->peer->log, LOG_CRIT,
                   "%s: BGP attribute %s, parser error: %srun %u bytes (BUG)",
                prs->peer->host, map_direct(bgp_attr_name_map, prs->type).str,
                           attr_p > prs->end_p ? "over" : "under",
                                                                 prs->length) ;

          prs->notify_code     = BGP_NOMC_CEASE ;
          prs->notify_subcode  = BGP_NOMS_UNSPECIFIC ;
          prs->notify_data_len = 0 ;

          prs->ret |= BGP_ATTR_PARSE_CRITICAL ;
        } ;

      /* Make sure the overall result is up to date, and step to the next
       * attribute on the basis of the length of the previous.
       *
       * Decide what should do *now* with the return code, if anything
       */
      prs->aret |= prs->ret ;

      if (prs->aret & BGP_ATTR_PARSE_CRITICAL)
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
  if (!(prs->as4))
    {
      bgp_attr_parse_ret_t ret ;

      /* NB: must deal with AS4_AGGREGATOR first, in case that returns
       *     BGP_ATTR_PARSE_IGNORE -- which means ignore it *and* and AS4_PATH.
       *
       *     In this case BGP_ATTR_PARSE_IGNORE does not signal an *error*,
       *     so we do not set "ignored" on the strength of it.
       */
      ret = bgp_attr_munge_as4_aggr (prs) ;

      if (ret == BGP_ATTR_PARSE_OK)
        prs->aret |= bgp_attr_munge_as4_path(prs) ;
      else
        qassert(ret == BGP_ATTR_PARSE_IGNORE) ;
    } ;

  /* Finally do the checks on the aspath we did not do yet because we waited
   * for a potentially synthesized aspath, and if all is well, set the AS Path
   * in the attributes.
   */
  if (prs->asp != NULL)
    bgp_attr_as_path_set_if_ok(prs);

  /* Have completed the parsing of the attributes.
   *
   * Finally, deal with the unknown attributes.  Here discards all but the
   * valid Optional Transitive, and sets Partial on those.
   */
  if (prs->unknown != NULL)
    {
      if (attr_unknown_transitive(prs->unknown))
        bgp_attr_pair_set_transitive(prs->attrs, prs->unknown) ;
      else
        attr_unknown_free(prs->unknown) ;

      prs->unknown = NULL ;
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
bgp_attr_check (bgp_attr_parsing restrict prs)
{
  attr_set  working ;
  qstring   missing ;
  uint8_t   type ;

  missing = NULL ;
  working = prs->attrs->working ;

  /* Check for missing stuff in roughly ascending order of significance.
   */
  if (working->origin > BGP_ATT_ORG_MAX)
    {
      missing = qs_append_str(missing, " origin") ;
      type = BGP_ATT_ORIGIN ;
    } ;
  confirm(BGP_ATT_ORG_MIN == 0) ;

  if ((prs->sort == BGP_PEER_IBGP) && !(working->have & atb_local_pref))
    {
      missing = qs_append_str(missing, " local_pref") ;
      type = BGP_ATT_LOCAL_PREF ;
    } ;

  if ((prs->update.length != 0) && (prs->update.next_hop.type != nh_ipv4))
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

  zlog (prs->peer->log, LOG_ERR, "%s Missing well-known attribute(s)%s.",
                                         prs->peer->host, qs_string(missing)) ;

  prs->type = type ;

  bgp_attr_malformed (prs, BGP_NOMS_U_MISSING, BGP_ATTR_PARSE_SERIOUS) ;
} ;

/*------------------------------------------------------------------------------
 * Make attributes for outgoing BGP Message.
 *
 * Returns:  length of attributes -- including any overrun
 *
 * NB: assumes the blower has not (yet) overrun !
 *
 * NB: does a blow_overrun_check() (or equivalent) before returning
 */
extern ulen
bgp_packet_write_attribute(blower br, bgp_prib prib, attr_set attr)
{
  bgp_peer  peer ;
  bool as4, send_as4_path, send_as4_aggregator ;
  bgp_peer_sort_t sort ;
  ptr_t     p, start ;
  uint      len ;
  as_path_out_t asp_out[1] ;

  peer = prib->peer ;
  qassert(peer->type == PEER_TYPE_REAL) ;

  send_as4_path       = false ;
  send_as4_aggregator = false ;
  as4  = peer->session->args->can_as4 ;
  sort = peer->sort ;

  start = blow_ptr(br) ;

  /* Origin attribute.
   */
  p = blow_want(br, 3 + BGP_ATT_ORIGIN_L) ;

  p[0] = BGP_ATF_TRANSITIVE ;
  p[1] = BGP_ATT_ORIGIN ;
  p[2] = BGP_ATT_ORIGIN_L ;
  p[3] = (attr->origin <= BGP_ATT_ORG_MAX) ? attr->origin : BGP_ATT_ORG_INCOMP ;

  confirm(BGP_ATT_ORG_MIN  == 0) ;
  confirm(BGP_ATT_ORIGIN_L == 1) ;

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
        if (prib->route_server_client)
          break ;

        if (prib->as_path_unchanged && !as_path_is_empty(attr->asp))
          break ;

        asp_out->seg = BGP_AS_SEQUENCE ;
        asp_out->prepend_count  = 1 ;
        asp_out->prepend_asn[0] = peer->args.local_as ;

        if (peer->change_local_as != BGP_ASN_NULL)
          {
            qassert(peer->change_local_as == peer->args.local_as) ;

            if (peer->bgp->ebgp_as != peer->args.local_as)
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
        asp_out->prepend_asn[0] = peer->args.local_as ;

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

  blow_n_check(br, asp_out->part[0], asp_out->len[0]) ;
  blow_n_check(br, asp_out->part[1], asp_out->len[1]) ;

  /* Note... have just checked for blower overrun, the next few attributes
   *         all add up to rather less than blow_buffer_safe, so we can
   *         check for overrun once, later.
   */
  confirm( ( (3 + BGP_ATT_NEXT_HOP_L) +
             (3 + BGP_ATT_MED_L)      +
             (3 + BGP_ATT_L_PREF_L)   +
             (3 + BGP_ATT_A_AGGREGATE_L) +
             (3 + BGP_ATT_AGR_AS4_L)       ) < blow_buffer_safe) ;

  /* Nexthop attribute.
   */
  if ((prib->qafx == qafx_ipv4_unicast) && (attr->next_hop.type == nh_ipv4))
    {
      p = blow_step(br, 3 + BGP_ATT_NEXT_HOP_L) ;

      p[0] = BGP_ATF_TRANSITIVE ;
      p[1] = BGP_ATT_NEXT_HOP ;
      p[2] = BGP_ATT_NEXT_HOP_L ;
      store_l(&p[3], attr->next_hop.ip.v4) ;

      confirm(BGP_ATT_NEXT_HOP_L == 4) ;
    } ;

  /* MED attribute.
   */
  if (attr->have & atb_med)
    {
      p = blow_step(br, 3 + BGP_ATT_MED_L) ;

      p[0] = BGP_ATF_OPTIONAL ;
      p[1] = BGP_ATT_MED ;
      p[2] = BGP_ATT_MED_L ;
      store_nl(&p[3], attr->med) ;

      confirm(BGP_ATT_MED_L == 4) ;
    }

  /* Local preference.
   */
  if ((sort == BGP_PEER_IBGP) || (sort == BGP_PEER_CBGP))
    {
      p = blow_step(br, 3 + BGP_ATT_L_PREF_L) ;

      p[0] = BGP_ATF_TRANSITIVE ;
      p[1] = BGP_ATT_LOCAL_PREF ;
      p[2] = BGP_ATT_L_PREF_L ;
      store_nl(&p[3], attr->local_pref) ;

      confirm(BGP_ATT_L_PREF_L == 4) ;
    } ;

  /* Atomic aggregate.
   */
  if (attr->have & atb_atomic_aggregate)
    {
      p = blow_step(br, 3 + BGP_ATT_A_AGGREGATE_L) ;

      p[0] = BGP_ATF_TRANSITIVE ;
      p[1] = BGP_ATT_A_AGGREGATE ;
      p[2] = BGP_ATT_A_AGGREGATE_L ;

      confirm(BGP_ATT_A_AGGREGATE_L == 0) ;
    } ;

  /* Aggregator.
   */
  if (attr->aggregator_as != BGP_ASN_NULL)
    {
      /* Common to BGP_ATT_AGGREGATOR, regardless of ASN size
       *
       * XXX BUG -- need to set BGP_ATF_PARTIAL if not originating this !!
       */
      len = (as4) ? BGP_ATT_AGR_AS4_L : BGP_ATT_AGR_AS2_L ;
      p   = blow_step(br, 3 + len) ;

      p[0] = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE ;
      p[1] = BGP_ATT_AGGREGATOR ;
      p[2] = len ;

      if (as4)
        {
          /* AS4 capable peer
           */
          store_nl(&p[3], attr->aggregator_as) ;
        }
      else
        {
          /* 2-byte AS peer
           *
           * Is ASN representable in 2-bytes? Or must AS_TRANS be used?
           */
          as_t asn ;

          asn = attr->aggregator_as ;

          if (asn > 65535 )
            {
              /* we have to send AS4_AGGREGATOR, too.
               * we'll do that later in order to send attributes in ascending
               * order.
               */
              send_as4_aggregator = true ;
              asn = BGP_ASN_TRANS ;
            } ;

          store_ns(&p[3], asn) ;
        } ;

      store_l(&p[3 + len - 4], attr->aggregator_ip) ;
    } ;

  /* Quick check for overflow !!
   *
   * What we have written since the last overrun check will be less than the
   * slack -- see above.
   */
  blow_overrun_check(br) ;

  /* Community attribute.
   */
  if ( (attr->community != NULL) && prib->send_community)
    {
      p = attr_community_out_prepare(attr->community, &len) ;
      blow_n_check(br, p, len) ;
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
      p = blow_want(br, 3 + BGP_ATT_ORIG_ID_L) ;

      p[0] = BGP_ATF_OPTIONAL ;
      p[1] = BGP_ATT_ORIGINATOR_ID ;
      p[2] = BGP_ATT_ORIG_ID_L ;
      store_l(&p[3], attr->originator_id ) ;

      confirm(BGP_ATT_ORIG_ID_L == 4) ;

      /* Prepare and put the cluster list, prepending either the (explicit)
       * cluster_id or the (implicit) router_id.
       */
      clust_out->cluster_id = peer->bgp->cluster_id ;

      attr_cluster_out_prepare(clust_out, attr->cluster) ;

      blow_n_check(br, clust_out->part[0], clust_out->len[0]) ;
      blow_n_check(br, clust_out->part[1], clust_out->len[1]) ;
    } ;

  /* Extended Communities attribute.
   *
   * Send only the transitive community if this is not iBGP and not Confed.
   */
  if ((attr->ecommunity != NULL) && prib->send_ecommunity)
    {
      bool trans_only ;

      trans_only = (sort != BGP_PEER_IBGP) && (sort != BGP_PEER_CBGP) ;

      p = attr_ecommunity_out_prepare(attr->ecommunity, trans_only, &len) ;
      blow_n_check(br, p, len) ;
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

      blow_n_check(br, asp_out->part[0], asp_out->len[0]) ;
      blow_n_check(br, asp_out->part[1], asp_out->len[1]) ;
    } ;

  /* AS4_AGGREGATOR, if required.
   */
  if (send_as4_aggregator)
    {
      p = blow_want(br, 3 + BGP_ATT_AGR_AS4_L) ;

      p[0] = BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE ;
      p[1] = BGP_ATT_AS4_AGGREGATOR ;
      p[2] = BGP_ATT_AGR_AS4_L ;
      store_nl(&p[3], attr->aggregator_as) ;
      store_l (&p[7], attr->aggregator_ip) ;

      confirm(BGP_ATT_AGR_AS4_L == 8) ;
    } ;

  /* Unknown Optional, Transitive Attributes, if any.
   */
  if (attr->transitive != NULL)
    {
      p = attr_unknown_out_prepare(attr->transitive, &len) ;
      blow_n_check(br, p, len) ;
    } ;

  /* Return length of attributes -- including any overrun.
   */
  return blow_ptr_inc_overrun(br) - start ;
} ;

/*------------------------------------------------------------------------------
 * Lay down the start of an MP_REACH_NLRI attribute.
 *
 * Will happily lay down an IPv4_Unicast MP_REACH_NLRI.
 *
 * Puts:  Flags    -- BGP_ATF_OPTIONAL
 *        Type     -- BGP_ATT_MP_REACH_NLRI
 *        Length   -- 1 bytes of zero         -- NB: NOT Extended Length.
 *        AFI      -- 2 bytes
 *        SAFI     -- 1 byte
 *        Length   -- of next hop
 *        Next Hop -- 'n' bytes as required
 *        0        -- defunct "SNPA"
 *
 * Returns:  total length of attribute, whether or not overran.
 *
 * NB: the *total* length includes the 3 Flags/Type/Length bytes.
 */
extern ulen
bgp_reach_attribute(blower br, bgp_prib prib, attr_set attr)
{
  ptr_t p, s ;
  uint  len ;

  /* Start the MP_REACH_NLRI attribute -- with overrun check.
   */
  s = blow_want(br, 3 + BGP_ATT_MPR_NH_LEN) ;

  confirm(BGP_ATT_MPR_NH_LEN == 3) ;

  store_b( &s[0], BGP_ATF_OPTIONAL) ;
  store_b( &s[1], BGP_ATT_MP_REACH_NLRI) ;
  store_b( &s[2], 0) ;
  store_ns(&s[3], prib->i_afi) ;
  store_b (&s[5], prib->i_safi) ;

  /* After the first bytes of the attribute above, we will now write 'len'
   * bytes of next-hop, preceded by one byte of length and followed by one
   * byte of "SNPA" -- so, provided the next-hop length is no greater than
   * this 'len_safe', we don't need any further overrun checks.
   */
  enum { len_safe = blow_buffer_safe - (3 + BGP_ATT_MPR_NH_LEN + 1 + 1) } ;

  /* Now the next-hop, as required.
   */
  switch (prib->qafx)
    {
      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        len = 4 ;
        confirm(4 <= len_safe) ;

        p = blow_step(br, 1 + len) ;

        store_b(&p[0], len) ;
        store_l(&p[1], attr->next_hop.ip.v4) ;
        break ;

      case qafx_ipv4_mpls_vpn:
        len = 12 ;
        confirm(12 <= len_safe) ;

        p = blow_step(br, 1 + len) ;

        store_b(&p[0], len) ;
        store_l(&p[1], 0) ;             /* first 4 bytes of 0 RD        */
        store_l(&p[5], 0) ;             /* second 4 bytes of same       */
        store_l(&p[9], attr->next_hop.ip.v4) ;
        break ;

#ifdef HAVE_IPV6
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        switch (attr->next_hop.type)
          {
            case nh_ipv6_1:             /* "global" address only        */
              len = 16 ;
              break ;

            case nh_ipv6_2:             /* "global" and link-local addresses */
              len = 32 ;
              break ;

            default:
              len = 0 ;
              break ;
          } ;

        confirm(32 <= len_safe) ;

        blow_b(br, len) ;
        blow_n(br, &attr->next_hop.ip.v6, len) ;

        break ;
#endif /* HAVE_IPV6 */

      default:
        len = 0 ;
        confirm(0 <= len_safe) ;

        blow_b(br, 0) ;
        break ;
    } ;

  blow_b(br, 0) ;               /* "SNPA"               */

  qassert((blow_ptr(br) - s) == (3 + BGP_ATT_MPR_NH_LEN + 1 + len + 1)) ;

  return (3 + BGP_ATT_MPR_NH_LEN + 1 + len + 1) ;
} ;

/*------------------------------------------------------------------------------
 * Blow the given prefix and any tags using the given blower.
 *
 * NB: caller MUST check for blower overflow -- eg by blow_left() -- BEFORE
 *     calling this.
 *
 *     Caller may (well) want to check for blower overflow on return.
 *
 * Returns:  byte length of the prefix -- prefix length + prefix body
 */
extern ulen
bgp_blow_prefix(blower br, bgp_prib prib, prefix_id_t pfx_id, mpls_tags_t tags)
{
  prefix_id_entry pie ;
  prefix_raw_t pfx_raw[1] ;
  size_t       pfx_size ;
  ptr_t        p_prefixlen ;
  uint         tl ;

  confirm(sizeof(pfx_raw) <= blow_buffer_safe) ;  /* not quite coincidence */

  pie = prefix_id_get_entry(pfx_id) ;

  switch (prib->qafx)
    {
      case qafx_ipv4_unicast:
      case qafx_ipv4_multicast:
        qassert(pie->pfx->family == AF_INET) ;
        qassert(pie->pfx->rd_id == prefix_rd_id_null) ;

        return prefix_blow(br, pie->pfx) ;

      case qafx_ipv4_mpls_vpn:
        qassert(pie->pfx->family == AF_INET) ;
        qassert(pie->pfx->rd_id != prefix_rd_id_null) ;

        pfx_size = prefix_to_raw(pfx_raw, pie->pfx) ;

        p_prefixlen = blow_step(br, 1) ;        /* prefix length        */

        tl = mpls_tags_blow(br, tags) ; /* tag length in bytes          */
        blow_n_check(br, prefix_rd_id_get_val(pie->pfx->rd_id), 8) ;
        blow_n_check(br, &pfx_raw->prefix, pfx_size - 1) ;

        *p_prefixlen = ((tl + 8) * 8) + pfx_raw->prefix_len ;

        return (tl + 8 + pfx_size) ;

#ifdef HAVE_IPV6
      case qafx_ipv6_unicast:
      case qafx_ipv6_multicast:
        qassert(pie->pfx->family == AF_INET) ;
        qassert(pie->pfx->rd_id == prefix_rd_id_null) ;

        return prefix_blow(br, pie->pfx) ;
#endif /* HAVE_IPV6 */

      default:
        return 0 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Lay down the start of an MP_UNREACH_NLRI attribute.
 *
 * Will happily lay down an IPv4_Unicast MP_REACH_NLRI.
 *
 * Puts:  Flags    -- BGP_ATF_OPTIONAL
 *        Type     -- BGP_ATT_MP_UNREACH_NLRI
 *        Length   -- 1 bytes of zero         -- NB: NOT Extended Length.
 *        AFI      -- 2 bytes
 *        SAFI     -- 1 byte
 *
 * Returns:  total length of attribute, whether or not overran.
 *
 * NB: the *total* length includes the 3 Flags/Type/Length bytes.
 */
extern ulen
bgp_unreach_attribute(blower br, bgp_prib prib)
{
  ptr_t p ;

  p = blow_want(br, 3 + BGP_ATT_MPU_NLRI) ;
  confirm(BGP_ATT_MPU_NLRI == 3) ;

  store_b( &p[0], BGP_ATF_OPTIONAL) ;
  store_b( &p[1], BGP_ATT_MP_UNREACH_NLRI) ;
  store_b( &p[2], 0) ;
  store_ns(&p[3], prib->i_afi) ;
  store_b (&p[5], prib->i_safi) ;

  return 3 + BGP_ATT_MPU_NLRI ;
} ;

/*------------------------------------------------------------------------------
 * Make attribute for bgp_dump.
 *
 * Returns:  length of what has written, *including* the length word.
 */
extern ulen
bgp_dump_routes_attr (blower br, attr_set attr, prefix pfx)
{
  ptr_t  len_p, p ;
  ulen   len ;

  as_path_out_t asp_out[1] ;

  /* Remember current pointer and insert placeholder for the length
   */
  blow_overrun_check(br) ;              /* start carefully      */
  len_p = blow_step(br, 2) ;

  /* Origin attribute.
   */
  p = blow_step(br, 4) ;

  store_b (&p[0], BGP_ATF_TRANSITIVE);
  store_b (&p[1], BGP_ATT_ORIGIN);
  store_b (&p[2], 1);
  store_b (&p[3], attr->origin);

  /* AS Path attribute
   *
   * Puts in AS4 form, the entire AS_PATH, as is.
   */
  asp_out->seg = BGP_AS_SEG_NULL ;      /* prepend nothing      */

  as_path_out_prepare(asp_out, attr->asp, true /* in AS4 form */) ;
  blow_n_check(br, asp_out->part[0], asp_out->len[0]) ;
  blow_n_check(br, asp_out->part[1], asp_out->len[1]) ;

  /* Nexthop attribute.
   *
   * If it's not IPv4, don't dump the IPv4 nexthop to save space
   */
  if ((pfx != NULL) && (pfx->family == AF_INET6))
    {
      p = blow_step(br, 7) ;

      store_b (&p[0], BGP_ATF_TRANSITIVE);
      store_b (&p[1], BGP_ATT_NEXT_HOP);
      store_b (&p[2], 4);
      store_l (&p[3], attr->next_hop.ip.v4);
    } ;

  /* MED attribute.
   */
  if (attr->have & atb_med)
    {
      p = blow_step(br, 7) ;

      store_b (&p[0], BGP_ATF_OPTIONAL);
      store_b (&p[1], BGP_ATT_MED);
      store_b (&p[2], 4);
      store_nl(&p[3], attr->med);
    }

  /* Local preference.
   */
  if (attr->have & atb_local_pref)
    {
      p = blow_step(br, 7) ;

      store_b (&p[0], BGP_ATF_TRANSITIVE);
      store_b (&p[1], BGP_ATT_LOCAL_PREF);
      store_b (&p[2], 4);
      store_nl(&p[3], attr->local_pref);
    }

  /* Atomic aggregate. */
  if (attr->have & atb_atomic_aggregate)
    {
      p = blow_step(br, 3) ;

      store_b (&p[0], BGP_ATF_TRANSITIVE);
      store_b (&p[1], BGP_ATT_A_AGGREGATE);
      store_b (&p[2], 0);
    }

  /* Aggregator -- in AS4 form
   */
  if (attr->aggregator_as != BGP_ASN_NULL)
    {
      p = blow_step(br, 11) ;

      store_b (&p[0], BGP_ATF_OPTIONAL | BGP_ATF_TRANSITIVE);
      store_b (&p[1], BGP_ATT_AGGREGATOR);
      store_b (&p[2], 8);
      store_nl(&p[3], attr->aggregator_as);
      store_l (&p[7], attr->aggregator_ip) ;
    }

  blow_overrun_check(br) ;              /* treading carefully   */

  /* Community attribute.
   */
  if (attr->community != NULL)
    {
      p = attr_community_out_prepare(attr->community, &len) ;
      blow_n_check(br, p, len) ;
     } ;

#ifdef HAVE_IPV6
  /* Add a MP_NLRI attribute to dump the IPv6 next hop
   */
  if ((pfx != NULL) && (pfx->family == AF_INET6))
    {
      if ( (attr->next_hop.type == nh_ipv6_1) ||
           (attr->next_hop.type == nh_ipv6_2) )
        {
          /* Start the MP_REACH_NLRI attribute -- with overrun check.
           */
          p = blow_want(br, 3 + BGP_ATT_MPR_NH_LEN) ;

          confirm(BGP_ATT_MPR_NH_LEN == 3) ;

          store_b( &p[0], BGP_ATF_OPTIONAL) ;
          store_b( &p[1], BGP_ATT_MP_REACH_NLRI) ;
          store_ns(&p[3], iAFI_IP6) ;
          store_b (&p[5], iSAFI_Unicast) ;

          switch (attr->next_hop.type)
            {
              case nh_ipv6_1:           /* "global" address only        */
                len = 16 ;
                break ;

              case nh_ipv6_2:           /* "global" and link-local addresses */
                len = 32 ;
                break ;

              default:
                len = 0 ;
                break ;
            } ;

          blow_b(br, len) ;
          blow_n_check(br, &attr->next_hop.ip.v6, len) ;

          blow_b(br, 0) ;               /* "SNPA"               */

          store_b(&p[2], 3 + 1 + len + 1) ;
        } ;
    } ;
#endif /* HAVE_IPV6 */

  len = blow_ptr_inc_overrun(br) - len_p ;      /* total length */

  store_ns(len_p, len - 2) ;

  return len ;
} ;

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
  [BGP_ATT_A_AGGREGATE       ] = { BGP_ATTR_FLAGS_WELL_KNOWN         },
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
                   bgp_attr_parsing restrict prs)           Always_Inline ;
inline static bool bgp_attr_seen_flags_check(
                   bgp_attr_parsing restrict prs)           Always_Inline ;
inline static bool bgp_attr_seen_flags_length_check(
                   bgp_attr_parsing restrict prs, uint len) Always_Inline ;






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
 * NB: sets prs->ret and updates prs->aret.
 */
static void
bgp_attr_malformed (bgp_attr_parsing restrict prs, byte subcode,
                                                       bgp_attr_parse_ret_t ret)
{
  switch (prs->type)
    {
      /* where an optional attribute is inconsequential, e.g. it does not
       * affect route selection, and can be safely ignored then any such
       * attributes which are malformed should just be ignored and the
       * route processed as normal.
       */
      case BGP_ATT_AS4_AGGREGATOR:
      case BGP_ATT_AGGREGATOR:
      case BGP_ATT_A_AGGREGATE:
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
       ((prs->aret & (BGP_ATTR_PARSE_SERIOUS | BGP_ATTR_PARSE_CRITICAL)) ==0) )
    {
      prs->notify_code    = BGP_NOMC_UPDATE ;
      prs->notify_subcode = subcode ;

      switch(subcode)
        {
          case BGP_NOMS_U_MAL_ATTR:
          case BGP_NOMS_U_MAL_AS_PATH:
          case BGP_NOMS_U_AS_LOOP:
          case BGP_NOMS_U_NETWORK:
          default:
            prs->notify_data     = NULL ;
            prs->notify_data_len = 0 ; /* send nothing                 */
            break ;

          case BGP_NOMS_U_MISSING:
            prs->notify_attr_type = prs->type ;

            prs->notify_data     = &prs->notify_attr_type ;
            prs->notify_data_len = 1 ; /* send just the missing type   */
            break ;

          case BGP_NOMS_U_UNKNOWN:
          case BGP_NOMS_U_A_FLAGS:
          case BGP_NOMS_U_A_LENGTH:
          case BGP_NOMS_U_ORIGIN:
          case BGP_NOMS_U_NEXT_HOP:
          case BGP_NOMS_U_OPTIONAL:
            prs->notify_data     = prs->start_p ;
            prs->notify_data_len = prs->end_p - prs->start_p ;
                                        /* send complete attribute      */
            if (qdebug)
              {
                if (prs->start_p[0] & BGP_ATF_EXTENDED)
                  qassert(prs->notify_data_len ==
                                       ((uint)load_ns(&prs->start_p[2]) + 4)) ;
                else
                  qassert(prs->notify_data_len ==
                                                 ((uint)prs->start_p[2] + 3)) ;
              } ;
            break ;
        } ;
    } ;

  /* Update the overall result.
   */
  prs->ret  |= ret ;
  prs->aret |= ret ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on the basis it is a repeat.
 *
 * Issues a logging message and treats as BGP_NOMS_U_MAL_ATTR
 *
 * Updates prs->ret and prs->aret.
 *
 * NB: all length errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_seen_malformed (bgp_attr_parsing restrict prs)
{
  bgp_attr_malformed(prs, BGP_NOMS_U_MAL_ATTR, BGP_ATTR_PARSE_SERIOUS) ;

  zlog (prs->peer->log, LOG_WARNING,
            "%s: error BGP attribute type %s appears twice in a message",
              prs->peer->host, map_direct(bgp_attr_name_map, prs->type).str) ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on basis of its length
 *
 * Issues a logging message and treats as BGP_NOMS_U_A_LENGTH
 *
 * Updates prs->ret and prs->aret.
 *
 * NB: all length errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_length_malformed (bgp_attr_parsing restrict prs,
                                                              ulen len_required)
{
  bgp_attr_malformed(prs, BGP_NOMS_U_A_LENGTH, BGP_ATTR_PARSE_SERIOUS) ;

  zlog (prs->peer->log, LOG_ERR, "%s attribute length is %u -- should be %u",
                                map_direct(bgp_attr_name_map, prs->type).str,
                                                   prs->length, len_required) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Reject attribute on basis of the flags being invalid
 *
 * Issues a logging message and treats as BGP_NOMS_U_A_FLAGS
 *
 * Updates prs->ret and prs->aret.
 *
 * NB: all flags errors are treated as BGP_ATTR_PARSE_SERIOUS, at least.
 *
 * Returns:  false
 */
static bool
bgp_attr_flags_malformed(bgp_attr_parsing restrict prs,
                                                      attr_flags_check_t* check)
{
  uint8_t diff ;
  bool seen ;
  uint i ;

  bgp_attr_malformed(prs, BGP_NOMS_U_A_FLAGS, BGP_ATTR_PARSE_SERIOUS) ;

  qassert((prs->flags & 0x0F) == 0) ;
  qassert(check->mask != 0) ;

  diff = (prs->flags ^ check->req) & check->mask ;

  seen = false ;
  for (i = 0; i < attr_flag_str_max ; i++)
    {
      uint8_t bit ;

      bit = attr_flag_str[i].key ;

      if (diff & bit)
        {
          zlog (prs->peer->log, LOG_ERR,
                   "%s attribute must%s be flagged as \"%s\"",
                   map_direct(bgp_attr_name_map, prs->type).str,
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
bgp_attr_flags_check(bgp_attr_parsing restrict prs)
{
  const attr_flags_check_t* check ;

  qassert(prs->type < BGP_ATT_MAX) ;

  check = &attr_flags_check_array[prs->type] ;
  if ((prs->flags & check->mask) == check->req)
    return true ;
  else
    return bgp_attr_flags_malformed(prs, check) ;
} ;

/*------------------------------------------------------------------------------
 * Common check for whether given attribute has been seen already
 *
 * Returns:  true <=> first time the attribute has been seen
 */
inline static bool
bgp_attr_seen_check(bgp_attr_parsing restrict prs)
{
  if (bm_test_set(&prs->seen, prs->type))
    return bgp_attr_seen_malformed(prs) ;
  else
    return true ;
} ;

/*------------------------------------------------------------------------------
 * Common check for known attributes of variable length
 *
 *   * checks and sets the prs->seen bit
 *
 *   * checks that the flags are valid
 *
 * Returns:  true <=> all the above checks have passed
 *
 */
inline static bool
bgp_attr_seen_flags_check(bgp_attr_parsing restrict prs)
{
  if (bgp_attr_seen_check(prs))
    return bgp_attr_flags_check(prs) ;

  bgp_attr_flags_check(prs) ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Common check for known attributes of fixed length
 *
 *   * checks and sets the prs->seen bit
 *
 *   * checks that the flags are valid
 *
 *   * checks that the length is exactly as given
 *
 * Returns:  true <=> all the above checks have passed
 *
 */
inline static bool
bgp_attr_seen_flags_length_check(bgp_attr_parsing restrict prs, uint len)
{
  bool ok ;

  ok = bgp_attr_seen_flags_check(prs) ;

  if (prs->length == len)
    return ok ;
  else
    return bgp_attr_length_malformed(prs, len) ;
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
bgp_attr_origin (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  uint origin ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 1))
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
      zlog (prs->peer->log, LOG_ERR, "Origin attribute value %u is invalid",
                                                                       origin) ;
      bgp_attr_malformed(prs, BGP_NOMS_U_ORIGIN, 0) ;
    }
  else
    {
      /* Set origin attribute.
       */
      bgp_attr_pair_set_origin(prs->attrs, origin) ;
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
bgp_attr_aspath (bgp_attr_parsing restrict prs, const byte* attr_p,
                                                                 as_path* p_asp)
{
  as_path asp ;
  bool as4 ;

  qassert( (prs->type == BGP_ATT_AS_PATH)
        || (prs->type == BGP_ATT_AS4_PATH) ) ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Parse the AS_PATH/AS4_PATH body.
   *
   * For AS_PATH  peer with AS4 => 4Byte ASN otherwise 2Byte ASN
   *     AS4_PATH 4Byte ASN
   */
  as4 = prs->as4 || (prs->type == BGP_ATT_AS4_PATH) ;

  asp = as_path_parse (attr_p, prs->length, as4) ;

  attr_p += prs->length ;

  if (asp != NULL)
    {
      /* AS4_PATH MUST NOT be carried in an UPDATE message between NEW_BGP
       * speakers; any such MUST be discarded (draft-ietf-idr-rfc4894bis-07).
       *
       * AS_CONFED_SEQUENCE and AS_CONFED_SET... MUST NOT be included in an
       * AS4_PATH.
       */
      if (prs->type == BGP_ATT_AS4_PATH)
        {
          if (prs->as4)
            {
              if (BGP_DEBUG(as4, AS4))
                zlog_debug ("[AS4] %s sent AS4_PATH "
                             "despite being an AS4 speaker", prs->peer->host) ;
              prs->ret |= BGP_ATTR_PARSE_IGNORE ;
            } ;

          if (as_path_confed_path_length(asp) != 0)
            {
              /* One or more confed segments in the path -> invalid
               */
              zlog (prs->peer->log, LOG_ERR, "Malformed %s from %s, "
                                                 " contains Confed segment(s)",
                                 map_direct(bgp_attr_name_map, prs->type).str,
                                                      prs->peer->host);
              bgp_attr_malformed (prs, BGP_NOMS_U_MAL_AS_PATH , 0) ;
            } ;
        } ;
    }
  else
    {
      zlog (prs->peer->log, LOG_ERR, "Malformed %s from %s, length is %u",
                                 map_direct(bgp_attr_name_map, prs->type).str,
                                               prs->peer->host, prs->length);
      bgp_attr_malformed (prs, BGP_NOMS_U_MAL_AS_PATH , 0) ;
    } ;

  /* Return the as_path if all is well, otherwise discard.
   */
  if ((prs->ret && BGP_ATTR_PARSE_FAILED) == 0)
    *p_asp = asp ;
  else
    as_path_free(asp) ;

  return attr_p ;
} ;

/*------------------------------------------------------------------------------
 * Nexthop attribute.
 */
static const byte*
bgp_attr_nexthop (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  in_addr_t nexthop_n, nexthop_h ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 4))
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
      zlog (prs->peer->log, LOG_ERR, "Martian nexthop %s",
                                       siptoa(AF_INET, &nexthop_n).str);
      bgp_attr_malformed (prs, BGP_NOMS_U_NEXT_HOP, 0) ;
    }
  else
    {
      prs->update.next_hop.type  = nh_ipv4 ;
      prs->update.next_hop.ip.v4 = nexthop_n ;
    } ;

  return attr_p + 4 ;
}

/*------------------------------------------------------------------------------
 * MED attribute.
 */
static const byte*
bgp_attr_med (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 4))
    return attr_p ;

  /* Get the MED and set in working attributes
   */
  bgp_attr_pair_set_med(prs->attrs, load_nl(attr_p)) ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Local preference attribute.
 */
static const byte*
bgp_attr_local_pref (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 4))
    return attr_p ;

  /* If it is contained in an UPDATE message that is received from an external
   * peer, then this attribute MUST be ignored by the receiving speaker.
   */
  if (prs->sort != BGP_PEER_EBGP)
    {
      /* Get the Local Pref and set in working attributes
       */
      bgp_attr_pair_set_local_pref(prs->attrs, load_nl(attr_p)) ;
    }
  else
    {
      /* We ignore any local pref received from an eBGP peer (RFC 4271, 5.1.5)
       */
      prs->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Atomic Aggregate Attribute.
 */
static const byte*
bgp_attr_atomic (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   *
   * If OK, set the flag which is alk we need to know.
   */
  if (bgp_attr_seen_flags_length_check(prs, 0))
    bgp_attr_pair_set_atomic_aggregate(prs->attrs, true) ;

  return attr_p ;
}

/*------------------------------------------------------------------------------
 * Aggregator attribute
 */
static const byte*
bgp_attr_aggregator (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   *
   * NEW_BGP peer will send 4 Byte AS, peer without will send 2 Byte
   */
  if (!bgp_attr_seen_flags_length_check(prs, prs->as4 ? 4 + 4 : 4 + 2))
    return attr_p ;

  if (prs->as4)
    {
      prs->aggregator_as = load_nl(attr_p) ;
      attr_p += 4 ;
    }
  else
    {
      prs->aggregator_as = load_ns(attr_p) ;
      attr_p += 2 ;
    } ;

  prs->aggregator_ip = load_l(attr_p) ;
                                /* NB: stays in Network Order   */

  confirm(BGP_ASN_NULL == 0) ;

  if (prs->aggregator_as != BGP_ASN_NULL)
    {
      bgp_attr_pair_set_aggregator(prs->attrs, prs->aggregator_as,
                                                prs->aggregator_ip) ;
    }
  else
    {
      zlog (prs->peer->log, LOG_ERR, "Invalid ASN (0) in AGGREGATOR") ;
      bgp_attr_malformed (prs, BGP_NOMS_U_OPTIONAL, 0) ;
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
bgp_attr_as4_aggregator (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 8))
    return attr_p ;

  /* Get and set the as4_aggregator_as/_ip, storing in the prs.
   *
   * Those are processed against the AS_AGGREGATOR values, when all
   * attributes have been processed.
   */
  prs->as4_aggregator_as  = load_nl(attr_p) ;
  prs->as4_aggregator_ip  = load_l(attr_p + 4) ;
                                        /* NB: stays in Network Order   */

  confirm(BGP_ASN_NULL == 0) ;

  if (prs->as4_aggregator_as == BGP_ASN_NULL)
    {
      zlog (prs->peer->log, LOG_ERR, "Invalid ASN (0) in AGGREGATOR") ;
      bgp_attr_malformed (prs, BGP_NOMS_U_OPTIONAL, 0) ;
    } ;

  /* draft-ietf-idr-rfc4893bis-07:
   *
   *   "... AS4_PATH and AS4_AGGREGATOR MUST NOT be carried in an UPDATE
   *    message between NEW BGP speakers.  ... MUST discard ... and
   *    continue processing the UPDATE message.
   */
  if (prs->as4)
    {
      if (BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s sent AS4_AGGREGATOR despite being an"
                                              " AS4 speaker", prs->peer->host);
      prs->ret |= BGP_ATTR_PARSE_IGNORE ; // XXX ...............................
    } ;

  return attr_p + 8 ;
} ;

/*------------------------------------------------------------------------------
 * Communities attribute.
 */
static const byte*
bgp_attr_community (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  attr_community comm ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Length must be a multiple of 4 -- zero length is acceptable
   *                                   (RFC1997 is silent in the matter).
   *
   * Note that a zero length Communities attribute is indistinguishable from
   * an absent one -- except for the "seen" state.
   */
  if ((prs->length % 4) != 0)
    {
      zlog (prs->peer->log, LOG_ERR, "Malformed COMMUNITIES (length is %u)",
                                                                 prs->length) ;
      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  /* Construct and set the communities sub-attribute
   *
   * NB: at this stage we accept whatever the attribute contains.  If one or
   *     more community is invalid, that is a matter for a higher authority.
   */
  comm = attr_community_set (attr_p, prs->length / 4) ;

  bgp_attr_pair_set_community(prs->attrs, comm) ;

  return attr_p + prs->length ;
} ;

/*------------------------------------------------------------------------------
 * Originator ID attribute -- Route Reflector
 */
static const byte*
bgp_attr_originator_id (bgp_attr_parsing prs, const byte* attr_p)
{
  in_addr_t  id ;

  /* Check for: seen already, valid flags, and exact length
   */
  if (!bgp_attr_seen_flags_length_check(prs, 4))
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
  if (prs->sort == BGP_PEER_IBGP)
    {
      id = load_l(attr_p) ;     /* NB: stays in Network Order   */
      bgp_attr_pair_set_originator_id(prs->attrs, id) ;
    }
  else
    {
      prs->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + 4 ;
} ;

/*------------------------------------------------------------------------------
 * Cluster list attribute -- Route Reflector
 */
static const byte*
bgp_attr_cluster_list (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  attr_cluster clust ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Length must be a multiple of 4 -- zero length is acceptable.
   */
  if (prs->length % 4)
    {
      zlog (prs->peer->log, LOG_ERR, "Bad cluster list length %u",
                                                                  prs->length);
      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;
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
  if (prs->sort == BGP_PEER_IBGP)
    {
      clust = attr_cluster_set(attr_p, prs->length / 4) ;
      bgp_attr_pair_set_cluster(prs->attrs, clust) ;
    }
  else
    {
      prs->ret |= BGP_ATTR_PARSE_IGNORE ;
    } ;

  return attr_p + prs->length ;
} ;

/*------------------------------------------------------------------------------
 * Multiprotocol reachability information parse.
 */
static const byte*
bgp_attr_mp_reach_parse (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  bgp_nlri  nlri ;
  byte      reserved ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Need a minimum of 5 bytes, for AFI, SAFI, nexthop_len and reserved octet.
   */
  if (prs->length < (2 + 1 + 1 + 1))
    {
      zlog (prs->peer->log, LOG_ERR,
                        "%s attribute length is %u -- should be at least 5",
                    map_direct(bgp_attr_name_map, BGP_ATT_MP_REACH_NLRI).str,
                                                                 prs->length) ;
      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  /* Load AFI, SAFI and Next Hop Length and check that we have enough for the
   * all that plus the reserved octet.
   */
  nlri = &prs->mp_update ;

  nlri->in.i_afi        = load_ns(attr_p) ;
  nlri->in.i_safi       = attr_p[2] ;
  nlri->next_hop_length = attr_p[3] ;

  if (prs->length < (2 + 1 + 1 + nlri->next_hop_length + 1))
    {
      zlog_info ("%s: %s, MP nexthop length %u + reserved byte"
                                                   " overruns end of attribute",
                 __func__, prs->peer->host, nlri->next_hop_length);

      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;
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
                            __func__, prs->peer->host, nlri->next_hop_length) ;

        bgp_attr_malformed (prs, BGP_NOMS_U_OPTIONAL, 0) ;
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
                   prs->peer->host,
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
                   prs->peer->host, reserved, nlri->in.i_afi, nlri->in.i_safi) ;

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
  nlri->qafx = qafx_from_i(nlri->in.i_afi, nlri->in.i_safi) ;

  switch (nlri->qafx)
    {
      case qafx_undef:
        zlog_warn("%s sent undefined AFI/SAFI %u/%u MP_REACH_NLRI",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;

        prs->ret |= BGP_ATTR_PARSE_IGNORE ;

        nlri->qafx = qafx_other ;       /* treat as "other" from now on */
        break ;

      case qafx_other:
      default:
        zlog_warn("%s sent unknown AFI/SAFI %u/%u MP_REACH_NLRI",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;

        prs->ret |= BGP_ATTR_PARSE_IGNORE ;
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
  nlri->length = prs->length - (2 + 1 + 1 + nlri->next_hop_length + 1) ;

  if (nlri->length == 0)
    {
      if (prs->ret == BGP_ATTR_PARSE_OK)
        zlog_warn("%s sent zero length NLRI in MP_REACH_NLRI"
      " for AFI/SAFI %u/%u", prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;
    }
  else
    {
      /* If the NLRI are not valid drops the session
       */
      if (!bgp_nlri_sanity_check (prs->peer, nlri))
        {
          zlog_info ("%s %s NLRI in MP_REACH_NLRI fails sanity check",
                                 prs->peer->host, get_qafx_name(nlri->qafx)) ;

          bgp_attr_malformed (prs, BGP_NOMS_U_OPTIONAL,
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
 * NB: expects the prs->mp_withdraw structure to have been zeroized.
 */
static const byte*
bgp_attr_mp_unreach_parse (bgp_attr_parsing restrict prs,
                                         const byte* attr_p,
                                         const byte* start_p, const byte* end_p)
{
  bgp_nlri  nlri ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Check for at least enough for AFI and SAFI, and fetch same.
   */
  if (prs->length < (2 + 1))
    {
      zlog (prs->peer->log, LOG_ERR,
                            "%s attribute length is %u -- should be at least 3",
                    map_direct(bgp_attr_name_map, BGP_ATT_MP_UNREACH_NLRI).str,
                                                                 prs->length) ;
      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;
      return attr_p ;
    } ;

  nlri = &prs->mp_withdraw ;

  nlri->in.i_afi  = load_ns(attr_p) ;
  nlri->in.i_safi = attr_p[2] ;

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
  nlri->qafx = qafx_from_i(nlri->in.i_afi, nlri->in.i_safi) ;

  switch (nlri->qafx)
    {
      case qafx_undef:
        zlog_warn("%s sent undefined AFI/SAFI %u/%u MP_REACH_NLRI",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;

        prs->ret |= BGP_ATTR_PARSE_IGNORE ;

        nlri->qafx = qafx_other ;       /* treat as "other" from now on */
        break ;

      case qafx_other:
      default:
        zlog_warn("%s sent unknown AFI/SAFI %u/%u MP_REACH_NLRI",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;

        prs->ret |= BGP_ATTR_PARSE_IGNORE ;
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
  nlri->pnt    = attr_p      + (2 + 1) ;
  nlri->length = prs->length - (2 + 1) ;

  qassert(!prs->mp_eor) ;      /* default is no MP End-of-RIB  */

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
      if ((prs->start_p == start_p) && (prs->end_p == end_p))
        {
          if (prs->update.length == 0)
            {
              if (prs->withdraw.length == 0)
                prs->mp_eor = true ;
              else
                zlog_warn("%s sent apparent End-of-RIB in MP_UNREACH_NLRI"
                       " for AFI/SAFI %u/%u BUT have Withdrawn Routes",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;
            } ;
        }
      else
        {
          if (prs->ret == BGP_ATTR_PARSE_OK)
            zlog_warn("%s sent zero length NLRI in MP_UNREACH_NLRI"
                        " for AFI/SAFI %u/%u",
                             prs->peer->host, nlri->in.i_afi, nlri->in.i_safi) ;
        } ;
    }
  else
    {
      if (!bgp_nlri_sanity_check (prs->peer, nlri))
        {
          zlog(prs->peer->log, LOG_ERR,
                 "%s %s NLRI in MP_UNREACH_NLRI fails sanity check",
                                  prs->peer->host, get_qafx_name(nlri->qafx)) ;

          bgp_attr_malformed (prs, BGP_NOMS_U_OPTIONAL,
                                                      BGP_ATTR_PARSE_CRITICAL) ;
        } ;
    } ;

  return attr_p + prs->length ;
} ;

/*------------------------------------------------------------------------------
 * Extended Community attribute.
 */
static const byte*
bgp_attr_ecommunities (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  attr_ecommunity ecomm ;

  /* Check for: seen already and valid flags
   */
  if (!bgp_attr_seen_flags_check(prs))
    return attr_p ;

  /* Length must be a multiple of 8 -- zero length is acceptable
   *                                   (RFC4360 is silent on the matter).
   *
   * Note that a zero length Extended Communities attribute is
   * indistinguishable from an absent one -- except for the "seen" state.
   */
  if ((prs->length % 8) != 0)
    {
      zlog (prs->peer->log, LOG_ERR, "Malformed EXT COMMUNITIES (length is %u)",
                                                                 prs->length) ;

      bgp_attr_malformed (prs, BGP_NOMS_U_A_LENGTH, 0) ;

      return attr_p ;
    } ;

  /* Construct and set the extended communities sub-attribute
   *
   * NB: at this stage we accept whatever the attribute contains.  If one or
   *     more extended community is invalid, that is a matter for a higher
   *     authority.
   */
  ecomm = attr_ecommunity_set (attr_p, prs->length / 8) ;

  bgp_attr_pair_set_ecommunity(prs->attrs, ecomm) ;

  return attr_p + prs->length ;
} ;

/*------------------------------------------------------------------------------
 * BGP unknown attribute treatment
 */
static const byte*
bgp_attr_unknown (bgp_attr_parsing restrict prs, const byte* attr_p)
{
  const attr_flags_check_t* check ;

  if (BGP_DEBUG (normal, NORMAL))
    zlog_debug ("%s Unknown attribute received "
                                            "(%stransitive type %u, length %u)",
                   prs->peer->host,
                      (prs->flags & BGP_ATF_TRANSITIVE) ? "" : "non-",
                                                      prs->type, prs->length);

  if (BGP_DEBUG (events, EVENTS))
    zlog (prs->peer->log, LOG_DEBUG,
                          "Unknown attribute type %u length %u received",
                                                      prs->type, prs->length);

  /* Check for whether already seen this attribute type
   */
  bgp_attr_seen_check(prs) ;

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
  if (prs->flags & BGP_ATF_OPTIONAL)
    check = (prs->flags & BGP_ATF_TRANSITIVE) ? &attr_flags_check_trans
                                               : &attr_flags_check_non_trans ;
  else
    {
      bgp_attr_malformed(prs, BGP_NOMS_U_UNKNOWN, BGP_ATTR_PARSE_SERIOUS) ;
      check = &attr_flags_check_known ;
    } ;

  if ((prs->flags & check->mask) != check->req)
    bgp_attr_flags_malformed(prs, check) ;

  /* For the time being we simply push a pointer to the raw attribute onto
   * the vector of unknown attributes, for processing later.
   */
  prs->unknown = attr_unknown_add(prs->unknown, prs->start_p) ;

  return attr_p + prs->length ;
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
bgp_attr_munge_as4_aggr (bgp_attr_parsing restrict prs)
{
  qassert(!prs->as4) ;

  if (prs->as4_aggregator_as == BGP_ASN_NULL)
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
  if (prs->aggregator_as == BGP_ASN_NULL)
    {
      if ( BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s BGP not AS4 capable peer"
                    " sent AS4_AGGREGATOR but no AGGREGATOR,"
                    " so ignore the AS4_AGGREGATOR", prs->peer->host);

      return BGP_ATTR_PARSE_OK ;        /* Easy(-ish) if no AGGREGATOR  */
    } ;

  /* received both AGGREGATOR and AS4_AGGREGATOR.
   */
  if (prs->aggregator_as != BGP_ASN_TRANS)
    {
      if ( BGP_DEBUG(as4, AS4))
        zlog_debug ("[AS4] %s BGP not AS4 capable peer"
                    " sent AGGREGATOR %u != AS_TRANS and"
                    " AS4_AGGREGATOR, so ignore"
                    " AS4_AGGREGATOR and AS4_PATH", prs->peer->host,
                                                          prs->aggregator_as) ;
      return BGP_ATTR_PARSE_IGNORE ;
    } ;

  /* Finally -- set the aggregator information from the AS4_AGGREGATOR !
   */
  bgp_attr_pair_set_aggregator(prs->attrs, prs->as4_aggregator_as,
                                            prs->as4_aggregator_ip) ;

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
 * On entry, prs->asp is the AS_PATH attribute and prs->as4p is the AS4_PATH.
 * When this function returns, prs->asp is the effective path, after any
 * reconciliation of the two attributes.
 *
 * Returns: BGP_ATTR_PARSE_OK  -- all is well
 *
 * NB: we quietly ignore AS4_PATH if no AS_PATH -- same like AS4_AGGREGATOR.
 */
static bgp_attr_parse_ret_t
bgp_attr_munge_as4_path (bgp_attr_parsing restrict prs)
{
  as_path merged ;

  qassert(!prs->as4) ;

  if (prs->as4p == NULL)
    return BGP_ATTR_PARSE_OK ;          /* Easy if no AS4_PATH          */

  if (prs->asp == NULL)
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
                    " so ignore the AS4_PATH", prs->peer->host);

      return BGP_ATTR_PARSE_OK ;        /* Easy(-ish) if no AS_PATH     */
    } ;

  /* need to reconcile NEW_AS_PATH and AS_PATH
   */
  merged = as_path_reconcile_as4 (prs->asp, prs->as4p) ;

  qassert(merged == prs->asp) ;

  return BGP_ATTR_PARSE_OK ;
} ;

/*------------------------------------------------------------------------------
 * If the as path is acceptable, set it in the attribute pair.
 *
 * Performs final checks on the AS_PATH -- once have resolved any AS4_PATH
 * issues,
 *
 * If all is OK, sets prs->asp as the AS Path attribute in the attribute set,
 * and clears prs->asp (ownership changes when path is set).
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
 * Updates prs->aret if AS_PATH is not acceptable
 */
static void
bgp_attr_as_path_set_if_ok(bgp_attr_parsing restrict prs)
{
  as_path asp ;

  asp = prs->asp ;

  if (as_path_confed_path_length(asp) != 0)
    {
      /* Have some confed stuff, somewhere in the AS_PATH.
       */
      if (prs->sort == BGP_PEER_EBGP)
        {
          zlog (prs->peer->log, LOG_ERR,
                    "AS path from %s contains CONFED stuff", prs->peer->host) ;

          bgp_attr_malformed (prs, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;

      if (!as_path_confed_ok(asp))
        {
          zlog (prs->peer->log, LOG_ERR,
                  "AS path from %s contains CONFED stuff, but not all at start",
                                                             prs->peer->host) ;
          bgp_attr_malformed (prs, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    }
  else
    {
      if (prs->sort == BGP_PEER_CBGP)
        {
          zlog (prs->peer->log, LOG_ERR,
                      "AS path from %s does not contain CONFED stuff",
                                                             prs->peer->host) ;

          bgp_attr_malformed (prs, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    } ;

  /* First AS check for EBGP -- NB: have already rejected any confed stuff.
   */
  if ((prs->sort == BGP_PEER_EBGP)
                && (as_path_first_simple_asn(asp) != prs->peer->args.remote_as))
    {
      bgp_inst bgp ;

      bgp = prs->peer->bgp;

      if ((bgp != NULL) && bgp_flag_check (bgp, BGP_FLAG_ENFORCE_FIRST_AS))
        {
          zlog (prs->peer->log, LOG_ERR,
                                  "%s incorrect first AS in path (must be %u)",
                                   prs->peer->host, prs->peer->args.remote_as) ;

          bgp_attr_malformed(prs, BGP_NOMS_U_MAL_AS_PATH, 0) ;
          return ;
        } ;
    } ;

  /* The AS PATH is OK -- so now add to the attribute set.
   */
  prs->asp = NULL ;                    /* Transfer to attributes       */

  bgp_attr_pair_set_as_path(prs->attrs, asp) ;
} ;

/*==============================================================================
 * Test interfaces
 */
extern const byte*
tx_bgp_attr_mp_reach_parse(bgp_attr_parsing prs, const byte* attr_p)
{
  return bgp_attr_mp_reach_parse(prs, attr_p) ;
} ;

extern const byte*
tx_bgp_attr_mp_unreach_parse(bgp_attr_parsing prs,
                                       const byte* attr_p,
                                       const byte* start_p, const byte* end_p)
{
  return bgp_attr_mp_unreach_parse(prs, attr_p, start_p, end_p) ;
} ;

