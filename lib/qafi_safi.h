/* Quagga AFI/SAFI
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002 Kunihiro Ishiguro
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _QUAGGA_AFI_SAFI_H
#define _QUAGGA_AFI_SAFI_H

#include "misc.h"
#include "name_map.h"
#include "zassert.h"

/*==============================================================================
 * Generic AFI and SAFI types.
 */
typedef uint16_t afi_t;
typedef uint8_t  safi_t;

/*==============================================================================
 * iAFI and iSAFI
 *
 * These are the standard IANA registered AFI and SAFI values.
 */

typedef enum iAFI  iAFI_t ;

enum iAFI
{
  iAFI_Reserved    = 0,         /* No meaning defined by IANA   */

  iAFI_IP          = 1,         /* IP (IP version 4)            */
  iAFI_IP6         = 2,         /* IP6 (IP version 6)           */

  iAFI_IPv4        = iAFI_IP,   /* locally AKA                  */
  iAFI_IPv6        = iAFI_IP6   /* locally AKA                  */
} ;


typedef enum iSAFI iSAFI_t ;

enum iSAFI
{
  iSAFI_Reserved   =   0,       /* No meaning defined by IANA   */

  iSAFI_Unicast    =   1,       /* unicast forwarding           */
  iSAFI_Multicast  =   2,       /* multicast forwarding         */

  iSAFI_Reserved_3 =   3,       /* Reserved by IANA             */

  iSAFI_MPLS_VPN   = 128        /* MPLS-labeled VPN address     */
} ;

/*==============================================================================
 * qAFI and qSAFI
 *
 * These are the AFI and SAFI values that Quagga uses internally.
 *
 * They are almost the same as the IANA numbers, but different where that
 * is required to produce a dense set.
 */

typedef enum qAFI  qAFI_t ;

enum qAFI
{
  qAFI_min         = 0,         /* minimum valid qAFI           */
  qAFI_undef       = 0,         /* undefined AFI                */

  qAFI_first       = 1,         /* first real qAFI              */

  qAFI_IP          = 1,
  qAFI_IP6         = 2,

  qAFI_last        = 2,         /* last real qAFI               */

  qAFI_max         = 2,         /* maximum valid qAFI           */
  qAFI_count,                   /* number of distinct qAFI      */

  qAFI_IPv4        = qAFI_IP,
  qAFI_IPv6        = qAFI_IP6,
  qAFI_ipv4        = qAFI_IP,
  qAFI_ipv6        = qAFI_IP6,
} ;

typedef enum qSAFI qSAFI_t ;

enum qSAFI
{
  qSAFI_min        =   0,       /* minimum valid qSAFI          */
  qSAFI_undef      =   0,       /* undefined SAFI               */

  qSAFI_first      =   1,       /* first real qSAFI             */

  qSAFI_Unicast    =   1,
  qSAFI_Multicast  =   2,
  qSAFI_MPLS_VPN   =   3,

  qSAFI_last       =   3,       /* last real qSAFI              */

  qSAFI_max        =   3,       /* maximum valid qSAFI          */
  qSAFI_count                   /* number of distinct qSAFI     */
} ;

/*==============================================================================
 * iAFI_SAFI and qAFI_SAFI structures
 */
typedef struct iAFI_SAFI  iAFI_SAFI_t ;
typedef struct iAFI_SAFI* iAFI_SAFI ;
typedef const struct iAFI_SAFI* iAFI_SAFI_c ;

struct iAFI_SAFI
{
  iAFI_t   i_afi ;
  iSAFI_t  i_safi ;
} ;

typedef struct qAFI_SAFI  qAFI_SAFI_t ;
typedef struct qAFI_SAFI* qAFI_SAFI ;
typedef const struct qAFI_SAFI* qAFI_SAFI_c ;

struct qAFI_SAFI
{
  qAFI_t   q_afi ;
  qSAFI_t  q_safi ;
} ;

/*==============================================================================
 * Quagga AFI/SAFI values -- original macro definitions
 */

/* Address family numbers from RFC1700. */
#define AFI_RESERVED              0
#define AFI_IP                    1
#define AFI_IP6                   2
#define AFI_MAX                   3

CONFIRM( (AFI_IP  == qAFI_IP)
      && (AFI_IP  == iAFI_IP) ) ;
CONFIRM( (AFI_IP6 == qAFI_IP6)
      && (AFI_IP6 == iAFI_IP6) ) ;
CONFIRM(AFI_MAX == qAFI_count) ;

/* Subsequent Address Family Identifier. */
#define SAFI_UNICAST              1
#define SAFI_MULTICAST            2
#define SAFI_MPLS_VPN             3
#define SAFI_MAX                  4

CONFIRM(SAFI_UNICAST        == iSAFI_Unicast) ;
CONFIRM(SAFI_MULTICAST      == iSAFI_Multicast) ;
CONFIRM(SAFI_MPLS_VPN       == qSAFI_MPLS_VPN) ;

/*==============================================================================
 * IPv6 Address Extensions
 *
 * It is handy to be able to handle IPv6 addresses as pairs of uint64_t or
 * uint32_t -- so here is an union, overlaying struct in6_addr, which allows
 * that.
 *
 * Note that the in6_addr_t is defined whether or not HAVE_IPV6.
 *
 * Also, for IPv6 a pair of "global" and "link-local" addresses is a useful
 * addition.
 */
#include "zebra.h"              /* Need IPv6 stuff      */

/* Convenience name for the base struct in_addr and struct in6_addr
 */
typedef struct in_addr  in_addr_s ;
#if HAVE_IPV6
typedef struct in6_addr in6_addr_s ;
#endif

/* For when struct in6_addr does not have these elements
 */
union in6_addr_u
{
#if HAVE_IPV6
  in6_addr_s  addr ;
#endif
  uint64_t    n64[2] ;          /* Network Order        */
  uint32_t    n32[4] ;
  uint8_t     b[16] ;
};

typedef union in6_addr_u in6_addr_t ;

#if HAVE_IPV6
CONFIRM(sizeof(in6_addr_t) == sizeof(in6_addr_s)) ;
#endif

enum in6_addr_type
{
  in6_global     = 0,           /* For next-hop         */
  in6_link_local = 1,
} ;

/*------------------------------------------------------------------------------
 * To carry an IPv4 or an IPv6 address -- where have external means to
 * distinguish the two.
 */
typedef union ip_union  ip_union_t ;
typedef union ip_union* ip_union ;

union ip_union
{
  in_addr_t   ipv4 ;
  in6_addr_t  ipv6 ;
};

/*------------------------------------------------------------------------------
 * Address pair -- any of:
 *
 *   * address + mask       -- both in Network Order
 *
 *   * address + wild-card  -- both in Network Order
 *
 *   * address start + end  -- both in Host Order
 *
 *     Components of the address range are in HOST ORDER, so that address
 *     ranges can be compared most readily.
 *
 *     IPv6 addresses are held as pairs of uint64_t, where the [0] value is
 *     the MS of the pair.  (So on a Big-Endian machine the entire address is
 *     in network order, but on a Little-Endian machine each half is in
 *     host order, but the two halves are in network order !
 */
typedef in_addr_t   in_addr_pair_t[2] ;
typedef in6_addr_t  in6_addr_pair_t[2] ;

typedef union ip_union_pair  ip_union_pair_t ;
typedef union ip_union_pair* ip_union_pair ;
typedef const union ip_union_pair* ip_union_pair_c ;

union ip_union_pair
{
  in_addr_pair_t  ipv4 ;
  in6_addr_pair_t ipv6 ;
} ;

/*==============================================================================
 * Functions
 */
Inline sa_family_t afi2family (qAFI_t qafi);
Inline qAFI_t family2afi (sa_family_t family);

extern name_str_t afitoa_lc(afi_t) ;
extern name_str_t afitoa_uc(afi_t) ;

/*------------------------------------------------------------------------------
 * Convert qAFI_xxx to sa_family_t (AF_INET, AF_INET6, ...)
 *
 * Maps qAFI_undef and unknown values to AF_UNSPEC
 */
enum sa_family
{
  sa_family_ipv4  = AF_INET,
#if HAVE_IPV6
  sa_family_ipv6  = AF_INET6,
#endif
  sa_family_count,
} ;

#if HAVE_IPV6
CONFIRM(AF_INET6 > AF_INET) ;
#endif

extern const sa_family_t qAFI_to_family_map[qAFI_count] ;

Inline sa_family_t
afi2family (qAFI_t qafi)
{
  if ((uint)qafi < (uint)qAFI_count)
    return qAFI_to_family_map[qafi] ;
  else
    return AF_UNSPEC ;
} ;

/*------------------------------------------------------------------------------
 * Convert sa_family_t (AF_INET, AF_INET6, ...) to qAFI_xxx
 *
 * Maps AF_UNSPEC and unknown values to qAFI_undef.
 */
extern const qAFI_t qAFI_from_family_map[sa_family_count] ;

Inline qAFI_t
family2afi(sa_family_t family)
{
  if ((uint)family < (uint)sa_family_count)
    return qAFI_from_family_map[family] ;
  else
    return qAFI_undef ;
} ;

#endif /* _QUAGGA_AFI_SAFI_H */
