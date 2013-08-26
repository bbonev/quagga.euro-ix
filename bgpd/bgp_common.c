/* BGP Common -- header
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

#include "bgpd/bgp_common.h"
#include "lib/zassert.h"

/*==============================================================================
 * Conversion qafx_bit_t -> qafx_t.
 *
 * If no bits are set, returns qafx_undef.
 *
 * If more than one bit is set, returns the lowest number qafx.
 *
 * NB: this is not built for speed.
 *
 * NB: it is a mistake to convert a value > qafx_bits_max (FATAL unless NDEBUG)
 */
extern qafx_t
qafx_num(qafx_bit_t bit)
{
  qafx_t num ;
  dassert(bit <= qafx_bits_max) ;

  if (bit == 0)
    return qafx_undef ;

  num = 0 ;

  while ((bit & 0xF) == 0)
    {
      num  += 4 ;
      bit >>= 4 ;
    }

  while ((bit & 1) == 0)
    {
      num  += 1;
      bit >>= 1 ;
    } ;

  return num ;
} ;

/*==============================================================================
 * Conversion tables for qafx_t => qAFI and qSAFI
 *                   and qafx_t => iAFI and iSAFI
 *                   and qafx_t => pAF
 */

const qAFI_t  qAFI_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = qAFI_IPv4,
    [qafx_ipv4_multicast]   = qAFI_IPv4,
    [qafx_ipv4_mpls_vpn]    = qAFI_IPv4,
    [qafx_ipv6_unicast]     = qAFI_IPv6,
    [qafx_ipv6_multicast]   = qAFI_IPv6,
    [qafx_ipv6_mpls_vpn]    = qAFI_IPv6,
    [qafx_other]            = qAFI_undef
  } ;
CONFIRM(qAFI_undef == 0) ;      /* not known -> qAFI_undef      */

const qSAFI_t qSAFI_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = qSAFI_Unicast,
    [qafx_ipv4_multicast]   = qSAFI_Multicast,
    [qafx_ipv4_mpls_vpn]    = qSAFI_MPLS_VPN,
    [qafx_ipv6_unicast]     = qSAFI_Unicast,
    [qafx_ipv6_multicast]   = qSAFI_Multicast,
    [qafx_ipv6_mpls_vpn]    = qSAFI_MPLS_VPN,
    [qafx_other]            = qSAFI_undef
  } ;
CONFIRM(qSAFI_undef == 0) ;     /* not known -> qSAFI_undef     */

const iAFI_t  iAFI_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = iAFI_IPv4,
    [qafx_ipv4_multicast]   = iAFI_IPv4,
    [qafx_ipv4_mpls_vpn]    = iAFI_IPv4,
    [qafx_ipv6_unicast]     = iAFI_IPv6,
    [qafx_ipv6_multicast]   = iAFI_IPv6,
    [qafx_ipv6_mpls_vpn]    = iAFI_IPv6,
    [qafx_other]            = iAFI_Reserved
  } ;
CONFIRM(iAFI_Reserved == 0) ;   /* not known -> iAFI_Reserved   */

const iSAFI_t iSAFI_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = iSAFI_Unicast,
    [qafx_ipv4_multicast]   = iSAFI_Multicast,
    [qafx_ipv4_mpls_vpn]    = iSAFI_MPLS_VPN,
    [qafx_ipv6_unicast]     = iSAFI_Unicast,
    [qafx_ipv6_multicast]   = iSAFI_Multicast,
    [qafx_ipv6_mpls_vpn]    = iSAFI_MPLS_VPN,
    [qafx_other]            = iSAFI_Reserved,
  } ;
CONFIRM(iSAFI_Reserved == 0) ;  /* not known -> iSAFI_Reserved  */

const sa_family_t sa_family_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = AF_INET,
    [qafx_ipv4_multicast]   = AF_INET,
    [qafx_ipv4_mpls_vpn]    = AF_INET,
    [qafx_ipv6_unicast]     = AF_INET6,
    [qafx_ipv6_multicast]   = AF_INET6,
    [qafx_ipv6_mpls_vpn]    = AF_INET6,
    [qafx_other]            = AF_UNSPEC,
  } ;
CONFIRM(AF_UNSPEC == 0) ;       /* not known -> AF_UNSPEC       */

/*==============================================================================
 * Conversion tables for qafx_t => string
 */
const char* qafx_name_map[qafx_count] =
  {
    [qafx_ipv4_unicast]     = "IPv4 Unicast",
    [qafx_ipv4_multicast]   = "IPv4 Multicast",
    [qafx_ipv4_mpls_vpn]    = "IPv4 MPLS VPN",
    [qafx_ipv6_unicast]     = "IPv6 Unicast",
    [qafx_ipv6_multicast]   = "IPv6 Multicast",
    [qafx_ipv6_mpls_vpn]    = "IPv6 MPLS VPN",
    [qafx_other]            = "??qafx_other??"
  } ;
CONFIRM(qAFI_undef == 0) ;      /* not known -> qAFI_undef      */

/*==============================================================================
 * Convert iAFI/iSAFI => qafx_t  -- tolerates unknown/reserved
 *     and qAFI/qSAFI => qafx_t  -- tolerates undef, but not unknown
 */

/*------------------------------------------------------------------------------
 * iAFI/iSAFI => qafx_t   unknowns => qafx_other
 *                        reserved => qafx_undef
 */
extern qafx_t
qafx_from_i(iAFI_t i_afi, iSAFI_t i_safi)
{
  switch (i_afi)
  {
    case iAFI_Reserved:
      return qafx_undef ;               /* no matter what the iSAFI is  */

    case iAFI_IP:
      switch(i_safi)
        {
          case iSAFI_Reserved:
            return qafx_undef ;         /* no matter what the iAFI is   */
          case iSAFI_Unicast:
            return qafx_ipv4_unicast ;
          case iSAFI_Multicast:
            return qafx_ipv4_multicast ;
          case iSAFI_MPLS_VPN:
            return qafx_ipv4_mpls_vpn ;
          default:
            break ;
        } ;
        break ;

    case iAFI_IP6:
      switch(i_safi)
        {
          case iSAFI_Reserved:
            return qafx_undef ;         /* no matter what the iAFI is   */
          case iSAFI_Unicast:
            return qafx_ipv6_unicast ;
          case iSAFI_Multicast:
            return qafx_ipv6_multicast ;
          case iSAFI_MPLS_VPN:
            return qafx_ipv6_mpls_vpn ;
          default:
            break ;
        } ;
        break ;

    default:
      switch(i_safi)
        {
          case iSAFI_Reserved:
            return qafx_undef ;         /* no matter what the iAFI is   */
          default:
            break ;
        } ;
      break ;
  } ;

  return qafx_other ;
} ;

/*------------------------------------------------------------------------------
 * qAFI/qSAFI => qafx_t
 *
 * NB: qAFI_undef       with any qSAFI_xxx => qafx_undef
 *     qSAFI_undef      with any qAFI_xxx  => qafx_undef
 *     qSAFI_Reserved_3 with any qAFI_xxx  => qafx_undef
 *
 *     any unrecognised qAFI/qSAFI combinations => qafx_other
 */
extern qafx_t
qafx_from_q(qAFI_t q_afi, qSAFI_t q_safi)
{
  switch (q_afi)
    {
      case qAFI_undef:
        if ((q_safi >= qSAFI_min) && (q_safi <= qSAFI_max))
          return qafx_undef ;           /* for all valid qSAFI  */
      break ;

    case qAFI_IP:
      switch(q_safi)
        {
          case qSAFI_undef:
            return qafx_undef ;
          case qSAFI_Unicast:
            return qafx_ipv4_unicast ;
          case qSAFI_Multicast:
            return qafx_ipv4_multicast ;
          case qSAFI_MPLS_VPN:
            return qafx_ipv4_mpls_vpn ;
          default:
            break ;
        } ;
        break ;

    case qAFI_IP6:
      switch(q_safi)
        {
          case qSAFI_undef:
            return qafx_undef ;
          case qSAFI_Unicast:
            return qafx_ipv6_unicast ;
          case qSAFI_Multicast:
            return qafx_ipv6_multicast ;
          case qSAFI_MPLS_VPN:
            return qafx_ipv6_mpls_vpn ;
          default:
            break ;
        } ;
        break ;

    default:
      break ;
  } ;

  return qafx_other ;
} ;

/*==============================================================================
 * Convert iAFI/iSAFI => qafx_bit_t  -- tolerates unknown/reserved
 *     and qAFI/qSAFI => qafx_bit_t  -- tolerates undef, but not unknown
 */

/*------------------------------------------------------------------------------
 * iAFI/iSAFI => qafx_bit_t   unknowns => 0
 *                            reserved => 0
 */
extern qafx_bit_t
qafx_bit_from_i(iAFI_t i_afi, iSAFI_t i_safi)
{
  qafx_t  qn ;

  qn = qafx_from_i(i_afi, i_safi) ;

  if ((qn != qafx_undef) && (qn != qafx_other))
    return qafx_bit(qn) ;
  else
    return 0 ;
} ;

/*------------------------------------------------------------------------------
 * qAFI/qSAFI => qafx_bit_t
 *
 * NB: qAFI_undef   with any qSAFI_xxx => 0
 *     qSAFI_undef  with any qAFI_xxx  => 0
 *     qSAFI_Unused qith any qAFI_xxx  => 0
 *
 * NB: any unrecognised qAFI/qSAFI combinations => FATAL error
 */
extern qafx_bit_t
qafx_bit_from_q(qAFI_t q_afi, qSAFI_t q_safi)
{
  qafx_t  qn ;

  qn = qafx_from_q(q_afi, q_safi) ;

  if ((qn != qafx_undef) && (qn != qafx_other))
    return qafx_bit(qn) ;
  else
    return 0 ;
} ;
