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

#include "misc.h"

#include "bgpd/bgp_mplsvpn.h"

#include "vty.h"
#include "log.h"
#include "ring_buffer.h"
#include "qfstring.h"

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

void
bgp_mplsvpn_init (void)
{
}
