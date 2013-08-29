/* MPLS-VPN
   Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>

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

#include "command.h"
#include "log.h"
#include "memory.h"
#include "ring_buffer.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"

/*==============================================================================
 * Decoding, encoding etc mpls_tags_t values.
 */

/*------------------------------------------------------------------------------
 * Scan tag stack to find length in bytes -- stops on first BoS !
 *
 * Returns:  3, 6, 9 ...   length of tag stack in bytes.
 *           0 <=> did not find BoS in the given bytes.
 */
extern uint
mpls_tags_scan(const byte* pnt, uint len)
{
  uint l ;

  l = 0 ;
  while (1)
    {
      l += 3 ;

      if (l > len)
        return 0 ;

      if (pnt[l - 1] & MPLS_LABEL_BOS)
        return l ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * From tag stack -- in Network Order -- extract opaque mpls_tags_t
 *
 * Only supports a single entry stack.
 *
 * Returns:  mpls_tags_t value -- 24 bits, with BoS and the "unspecified" bits
 *           mpls_tags_overflow => valid tag stack, but too long
 *           mpls_tags_invalid  => invalid tag stack
 */
extern mpls_tags_t
mpls_tags_decode(const byte* pnt, uint len)
{
  uint l ;

  /* Deal with simple case of valid single entry stack.
   */
  if ((len == 3) && (pnt[2] & MPLS_LABEL_BOS))
    return ((mpls_tags_t) pnt[0] << 16) +
           ((mpls_tags_t) pnt[1] <<  8) +
           ((mpls_tags_t) pnt[2] ) ;

  /* Return mpls_tags_invalid if:  (a) length is not 3, 6, 9, ...
   *                               (b) find BoS not at the end
   *                               (c) fail to find BoS at the end
   *
   * Otherwise, return mpls_tags_overflow
   */
  l = 3 ;
  while (l != len)
    {
      if (l > len)
        return mpls_tags_invalid ;

      if (pnt[l - 1] & MPLS_LABEL_BOS)
        return mpls_tags_invalid ;

      l += 3 ;
    } ;

  if (!(pnt[len - 1] & MPLS_LABEL_BOS))
    return mpls_tags_invalid ;

  return mpls_tags_overflow ;
} ;


/*------------------------------------------------------------------------------
 * Convert string to mpls_tags_t
 *
 * Expects string to give 20-bit value of the tag, which is stored as an
 * mpls_tags_t.
 *
 * Only supports a single entry stack.
 */
extern mpls_tags_t
str2tag (const char *str)
{
  uint      t ;
  strtox_t  tox ;

  t = strtoul_xr(str, &tox, &str, 0, MPLS_LABEL_LAST) ;

  if ((tox != strtox_ok) || (*str != '\0'))
    return mpls_tags_invalid ;  /* number or terminator no good */

  return (t << 4) | MPLS_LABEL_BOS ;
}

/*------------------------------------------------------------------------------
 * Write given tag stack to given address, using up to len bytes.
 *
 * Only supports a single entry stack -- so whatever the mpls_tags_t value is,
 * puts 3 bytes and sets BoS on the last one.
 *
 * Returns:  number of bytes written
 */
extern uint
mpls_tags_encode(byte* pnt, uint len, mpls_tags_t tags)
{
  if (len < 3)
    return 0 ;

  qassert(mpls_tags_null == (uint)MPLS_LABEL_NULL_IPV4) ;

  pnt[0] = (tags >> 16) & 0xFF ;
  pnt[1] = (tags >>  8) & 0xFF ;
  pnt[2] = (tags | MPLS_LABEL_BOS) & 0xFF ;

  return 3 ;
} ;

/*------------------------------------------------------------------------------
 * Write given tag stack to stream.
 *
 * Only supports a single entry stack -- so whatever the mpls_tags_t value is,
 * puts 3 bytes and sets BoS on the last one.
 *
 * Returns:  number of bytes written
 */
extern uint
mpls_tags_blow(blower br, mpls_tags_t tags)
{
  return mpls_tags_encode(blow_step(br, 3), 3, tags) ;
} ;

/*------------------------------------------------------------------------------
 * Number of bytes required to encode the given tag stack.
 *
 * Only supports a single entry stack -- so whatever the mpls_tags_t value is,
 * currently returns 3.
 *
 * Returns:  number of bytes required
 */
extern uint
mpls_tags_length(mpls_tags_t tags)
{
  return 3 ;
} ;

/*------------------------------------------------------------------------------
 * From 3 bytes of tag -- in Network Order -- extract 20 bit Label Value, in
 *                                                                   Host Order
 */
extern mpls_label_t
mpls_label_decode (const byte* pnt)
{
  return ((mpls_label_t) pnt[0] << 12) +
         ((mpls_label_t) pnt[1] <<  4) +
         ((mpls_label_t)(pnt[2] & 0xf0) >> 4);
} ;

/*------------------------------------------------------------------------------
 * Get the ith tag stack entry as a 20 bit Label Value (in Host Order)
 *
 * The 0th entry is the top-most label.  If there are 'n' labels in the stack,
 * the 'n-1'th entry is the BoS.
 *
 * Only supports a single entry stack -- so currently any i > 0 gives overflow
 * (unless the tag stack is invalid).
 *
 * Returns:  mpls_label_t value -- 20 bits
 *           mpls_label_overflow => requested i exceeds depth of stack
 *                                  or stack itself is in overflow.
 *           mpls_label_invalid  => invalid tag stack
 */
extern mpls_label_t
mpls_tags_label(mpls_tags_t tags, uint i)
{
  if (tags == mpls_tags_invalid)
    return mpls_label_invalid ;

  if ((tags == mpls_tags_overflow) || (i != 0))
    return mpls_label_overflow ;

  return tags >> 4 ;
} ;

/*==============================================================================
 * Decoding, encoding etc Route Distinguisher values.
 */

/*------------------------------------------------------------------------------
 * Get type of Route Distinguisher direct from raw form
 */
extern rd_type_t
mpls_rd_raw_type (const byte* pnt)
{
  return load_ns(pnt) ;
}

/*------------------------------------------------------------------------------
 * Is given raw Route Distinguisher of a known form ?
 */
extern bool
mpls_rd_known_type(const byte* pnt)
{
  switch (mpls_rd_raw_type (pnt))
    {
      case RD_TYPE_AS:
      case RD_TYPE_IP:
        return true ;

      default:
        return false ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Decode Route Distinguisher from raw form to given mpls_rd
 */
extern bool
mpls_rd_decode(mpls_rd rd, const byte* pnt)
{
  bool known ;

  known = true ;                /* assume all is well   */

  switch (rd->type = mpls_rd_raw_type (pnt))
    {
      case RD_TYPE_AS:
        rd->u.as.asn  = load_ns(&pnt[2]) ;
        rd->u.as.val  = load_nl(&pnt[4]) ;

        break ;

      case RD_TYPE_IP:
        rd->u.ip.addr = load_l(&pnt[2]) ;       /* Network Order        */
        rd->u.ip.val  = load_ns(&pnt[6]) ;

        break ;

      default:
        known = false ;

        memcpy(rd->u.unknown.b, &pnt[2], 6) ;
        break ;
    } ;

  return known ;
} ;

/*------------------------------------------------------------------------------
 * Convert string to Route Distinguisher
 *
 * String is:  99:99999     RD_TYPE_AS
 *        or:  A.B.C.D:99   RD_TYPE_IP
 */
extern bool
str2prefix_rd (prefix_rd prd, const char* str)
{
  byte* s ;

  s = prd->val ;
  memset(s, 0, prefix_rd_len) ;

  /* If there are no '.', then this is 99:9999 -- RD_TYPE_AS
   */
  if (strchr(str, '.') == NULL)
    {
      strtox_t tox ;
      uint16_t asn ;
      uint32_t rest ;

      asn = strtoul_xr(str, &tox, &str, 0, UINT16_MAX) ;

      if ((tox != strtox_ok) || (*str != ':'))
        return false ;                  /* number or terminator no good */

      rest = strtoul_xr(str + 1, &tox, &str, 0, UINT32_MAX) ;

      if ((tox != strtox_ok) || (*str != '\0'))
        return false ;                  /* number or terminator no good */

      store_ns(&s[0], RD_TYPE_AS) ;
      store_ns(&s[2], asn) ;
      store_nl(&s[4], rest) ;
    }
  else
    {
      in_addr_t ipv4 ;
      strtox_t  tox ;
      uint16_t  rest ;

      if (!str2ipv4 (&ipv4, str, &str))
        return false ;                  /* IPv4 address no good         */

      if (*str != ':')
        return false ;                  /* invalid separator            */

      rest = strtoul_xr(str + 1, &tox, &str, 0, UINT16_MAX) ;

      if ((tox != strtox_ok) || (*str != '\0'))
        return false ;                  /* number or terminator no good */

      store_ns(&s[0], RD_TYPE_IP) ;
      store_l(&s[2], ipv4) ;            /* already in Network Order     */
      store_ns(&s[6], rest) ;
    }

  return true ;
}

/*------------------------------------------------------------------------------
 * Convert string to Route Distinguisher -- issue error message if no good.
 */
extern bool
str2prefix_rd_vty (vty vty, prefix_rd prd, const char *str)
{
  if (str2prefix_rd (prd, str))
    return true ;

  vty_out (vty, "%% Malformed Route Distinguisher\n") ;
  return false ;
} ;

/*------------------------------------------------------------------------------
 * Construct Route Distinguisher String.
 */
extern str_rdtoa_t
srdtoa(prefix_rd_c prd)
{
  str_rdtoa_t QFB_QFS(pfa, qfs) ;
  mpls_rd_t rd[1] ;

  mpls_rd_decode(rd, prd->val);

  switch (rd->type)
    {
      case RD_TYPE_AS:
        qfs_put_unsigned(qfs, rd->u.as.asn, pf_int_dec, 0, 0) ;
        qfs_put_ch(qfs, ':') ;
        qfs_put_unsigned(qfs, rd->u.as.val, pf_int_dec, 0, 0) ;
        break ;

      case RD_TYPE_IP:
        qfs_put_ip_address(qfs, &rd->u.ip.addr, pf_ipv4, 0) ;
        qfs_put_ch(qfs, ':') ;
        qfs_put_unsigned(qfs, rd->u.ip.val, pf_int_dec, 0, 0) ;
        break ;

      default:
        qfs_put_str(qfs, "0x") ;
        qfs_put_n_hex(qfs, prd->val, 8, pf_uc) ;
        break ;
    } ;

  qfs_term(qfs) ;
  return pfa;
} ;

/*------------------------------------------------------------------------------
 * Construct Tag Stack String.
 *
 * Only supports a single entry stack -- so whatever the mpls_tags_t value is,
 * that is it.
 */
extern str_tgtoa_t
stgtoa(mpls_tags_t tags)
{
  str_tgtoa_t QFB_QFS(pfa, qfs) ;

  qfs_put_str(qfs, "0x") ;
  qfs_put_unsigned(qfs, tags, pf_hex_X | pf_zeros, 6, 0) ;

  qfs_term(qfs) ;
  return pfa;
} ;

/*==============================================================================
 * MPLS CLI stuff.
 */

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_set_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:nn_or_IP-address:nn tag WORD",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "BGP tag\n"
       "tag value\n")
{
  return bgp_static_unset_vpnv4 (vty, argv[0], argv[1], argv[2]);
}

static int
show_adj_route_vpn (vty vty, const char* peer_str, const char* rd_str)
{
  bgp_peer       peer ;
  prefix_rd_t    prd_s ;
  prefix_rd      prd ;
  bgp_inst       bgp ;
  vector         rv ;
  vector_index_t i ;
  bool header ;
  const char* v4_header = "   Network          Next Hop            "
                                                 "Metric LocPrf Weight Path\n" ;
  prefix_rd_id_t rd_id ;

  peer = peer_lookup_vty (vty, NULL, peer_str, qafx_ipv4_mpls_vpn) ;
  if (peer == NULL)
    return CMD_WARNING;

  if (rd_str == NULL)
    prd = NULL ;
  else
    {
      prd = &prd_s ;

      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING;
    } ;


  /* TODO -- this is broken... should be walking the peer's adj_out !
   */
#if 1
  bgp = peer->bgp ;
#else
  /* This is the previous code... which doesn't seem to make a lot of sense,
   * since this is supposed to be showing the routes advertised to a given
   * peer.
   */
  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif

  rv = bgp_rib_extract(bgp->rib[qafx_ipv4_mpls_vpn], prd) ;

  header = false ;
  rd_id  = prefix_rd_id_null ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;
      prefix       pfx ;

      rn = vector_get_item(rv, i) ;
      ri = svs_head(&rn->iroute_bases[0], rn->avail) ;

      if (ri == NULL)
        continue ;

      if (!header)
        {
          vty_out (vty, "BGP table version is 0, local router ID is %s\n",
                                         siptoa(AF_INET, &bgp->router_id).str);
          vty_out (vty, "Status codes: s suppressed, d damped, h history, "
                                            "* valid, > best, i - internal\n");
          vty_out (vty, "Origin codes: i - IGP, e - EGP, "
                                                         "? - incomplete\n\n") ;
          vty_out (vty, v4_header);
          header = true ;
        } ;

      pfx = prefix_id_get_prefix(rn->pfx_id) ;

      if (pfx->rd_id != rd_id)
        {
          mpls_rd_t rd[1] ;

          rd_id = pfx->rd_id ;

          /* Decode RD type.
           */
          mpls_rd_decode(rd, prefix_rd_id_get_val(rd_id)->val);

          vty_out (vty, "Route Distinguisher: ");

          switch (rd->type)
            {
              case RD_TYPE_AS:
                vty_out (vty, "%u:%d", rd->u.as.asn, rd->u.as.val) ;
                break ;

              case RD_TYPE_IP:
                vty_out (vty, "%s:%d", sipv4toa(rd->u.ip.addr).str,
                                                       rd->u.ip.val) ;
                break ;

              default:
                vty_out (vty, "%d:??", rd->type) ;
                break ;
            } ;

          vty_out (vty, "\n") ;
        } ;

      do
        {
          route_vty_out_tmp (vty, pfx, ri->iroutes[0].attr, ri->current.qafx);

          ri = svs_next(ri->iroutes[0].list, rn->avail) ;
        }
      while (ri != NULL) ;
    } ;
  return CMD_SUCCESS;
}

enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact
};

static int
bgp_show_mpls_vpn (vty vty, const char* rd_str, enum bgp_show_type type,
                                                void* output_arg, bool tags)
{
  bgp_inst       bgp ;
  vector         rv ;
  vector_index_t i ;
  bool header ;
  prefix_rd_t    prd_s ;
  prefix_rd      prd ;
  prefix_rd_id_t rd_id ;

  const char* v4_header =
      "   Network          Next Hop            Metric LocPrf Weight Path\n" ;
  const char* v4_header_tag =
      "   Network          Next Hop      In tag/Out tag\n";

  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (rd_str == NULL)
    prd = NULL ;
  else
    {
      prd = &prd_s ;

      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING;
    } ;

  rv = bgp_rib_extract(bgp->rib[qafx_ipv4_mpls_vpn], prd) ;

  header = false ;
  rd_id  = prefix_rd_id_null ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;

      rn = vector_get_item(rv, i) ;
      ri = svs_head(&rn->iroute_bases[0], rn->avail) ;

      while (ri != NULL)
        {
          prefix  pfx ;

          if (type == bgp_show_type_neighbor)
            {
              sockunion su ;

              su = &ri->prib->peer->session->cops->su_remote ;

              if (!sockunion_same(su, (sockunion)output_arg))
                continue;
            } ;

          if (!header)
            {
              if (tags)
                vty_out (vty, v4_header_tag);
              else
                {
                  vty_out (vty, "BGP table version is 0, "
                                                      "local router ID is %s\n",
                                          siptoa(AF_INET, &bgp->router_id).str);
                  vty_out (vty, "Status codes: s suppressed, d damped, "
                                  "h history, * valid, > best, i - internal\n");
                  vty_out (vty, "Origin codes: i - IGP, e - EGP, "
                                                          "? - incomplete\n\n");
                  vty_out (vty, v4_header);
                } ;

              header = true;
            }

          pfx = prefix_id_get_prefix(rn->pfx_id) ;

          if (pfx->rd_id != rd_id)
            {
              mpls_rd_t rd[1] ;

              rd_id = pfx->rd_id ;

              /* Decode RD type.
               */
              mpls_rd_decode(rd, prefix_rd_id_get_val(rd_id)->val);

              vty_out (vty, "Route Distinguisher: ");

              switch (rd->type)
                {
                  case RD_TYPE_AS:
                    vty_out (vty, "%u:%d", rd->u.as.asn, rd->u.as.val) ;
                    break ;

                  case RD_TYPE_IP:
                    vty_out (vty, "%s:%d", sipv4toa(rd->u.ip.addr).str,
                                                           rd->u.ip.val) ;
                    break ;

                  default:
                    vty_out (vty, "%d:??", rd->type) ;
                    break ;
                } ;

              vty_out (vty, "\n") ;
            } ;

          if (tags)
            route_vty_out_tag (vty, pfx, ri, true);
          else
            route_vty_out (vty, pfx, ri, true);

          ri = svs_next(ri->iroutes[0].list, rn->avail) ;
        } ;
    } ;

  return CMD_SUCCESS;
}

static int
bgp_show_mpls_vpn_neighbor (vty vty, const char* rd_str,
                                               const char* peer_str, bool tags)
{
  bgp_peer peer;

  peer = peer_lookup_vty (vty, NULL, peer_str, qafx_ipv4_mpls_vpn) ;
  if (peer == NULL)
    return CMD_WARNING;

  return bgp_show_mpls_vpn (vty, rd_str, bgp_show_type_neighbor, peer->su_name,
                                                                         tags) ;
} ;

DEFUN (show_ip_bgp_vpnv4_all,
       show_ip_bgp_vpnv4_all_cmd,
       "show ip bgp vpnv4 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL, false);
}

DEFUN (show_ip_bgp_vpnv4_rd,
       show_ip_bgp_vpnv4_rd_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
  return bgp_show_mpls_vpn (vty, argv[0], bgp_show_type_normal, NULL, 0);
}

DEFUN (show_ip_bgp_vpnv4_all_tags,
       show_ip_bgp_vpnv4_all_tags_cmd,
       "show ip bgp vpnv4 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL,  1);
}

DEFUN (show_ip_bgp_vpnv4_rd_tags,
       show_ip_bgp_vpnv4_rd_tags_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, argv[0], bgp_show_type_normal, NULL, 1);
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_routes,
       show_ip_bgp_vpnv4_all_neighbor_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_mpls_vpn_neighbor (vty, NULL, argv[0], false) ;
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_routes,
       show_ip_bgp_vpnv4_rd_neighbor_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_mpls_vpn_neighbor (vty, argv[0], argv[1], false) ;
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return show_adj_route_vpn (vty, argv[0], NULL);
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors "
                                                    "A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return show_adj_route_vpn (vty, argv[1], argv[0]);
}

CMD_INSTALL_TABLE(static, bgp_mplsvpn_cmd_table, BGPD) =
{
  { BGP_VPNV4_NODE,  &vpnv4_network_cmd                                 },
  { BGP_VPNV4_NODE,  &no_vpnv4_network_cmd                              },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_cmd                          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_tags_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_tags_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbor_routes_cmd         },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_cmd                          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_tags_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_tags_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbor_routes_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd },

  CMD_INSTALL_END
} ;

void
bgp_mplsvpn_cmd_init (void)
{
  cmd_install_table(bgp_mplsvpn_cmd_table) ;
}

void
bgp_mplsvpn_init (void)
{
}
