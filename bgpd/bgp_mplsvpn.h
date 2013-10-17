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

#ifndef _QUAGGA_BGP_MPLSVPN_H
#define _QUAGGA_BGP_MPLSVPN_H

#include "misc.h"
#include "qstring.h"
#include "prefix_id.h"
#include "vty.h"
#include "ring_buffer.h"

#include "bgpd/bgp_common.h"

/*------------------------------------------------------------------------------
 * Route Distinguishers.
 *
 * The raw route distinguisher is an 8 byte object, in Network-Order.  The
 * prefix_rd_t contains a raw route distinguisher.
 *
 * Here we have the known types of Route Distinguisher and a structure to hold
 * same.
 */
typedef struct mpls_rd  mpls_rd_t ;
typedef struct mpls_rd* mpls_rd ;

enum rd_type
  {
    RD_TYPE_AS  = 0,
    RD_TYPE_IP  = 1,
  } ;

typedef enum rd_type rd_type_t ;

struct mpls_rd
{
  rd_type_t     type ;

  union
    {
      struct
        {
          as_t     asn ;
          uint32_t val ;
        } as ;

      struct
        {
          in_addr_t addr ;
          uint16_t  val ;
        } ip ;

      struct
        {
          byte     b[6] ;
        } unknown ;
    } u ;
};

/*------------------------------------------------------------------------------
 * A single MPLS Label, as a simple 20-bit integer -- 0x00000..0xFFFFF
 */
typedef uint32_t mpls_label_t ;

enum
{
  mpls_label_bad      = UINT32_MAX - 1, /* value >= to this is bad      */

  mpls_label_invalid  = UINT32_MAX - 1,
  mpls_label_overflow = UINT32_MAX,
} ;

CONFIRM(mpls_label_invalid  > (uint)MPLS_LABEL_LAST) ;
CONFIRM(mpls_label_overflow > (uint)MPLS_LABEL_LAST) ;

/*------------------------------------------------------------------------------
 * Opaque value representing an MPLS Tag Stack.
 *
 * Convenient to have an mpls_tags_t for simple comparison of tag values, for
 * equality at least.
 *
 * At present, Quagga allows only one level of tag stack -- so the "opaque"
 * value is the 24 bit RFC3017 label, in Host Order, complete with BoS bit.
 *
 * Since the BoS bit is not zero, we can use zero as a null, "no tag" value.
 */
typedef uint32_t mpls_tags_t ;

enum
{
  mpls_tags_null     = 0,               /* no tag                       */

  mpls_tags_bad      = UINT32_MAX - 1,  /* value >= to this is bad      */

  mpls_tags_invalid  = UINT32_MAX - 1,
  mpls_tags_overflow = UINT32_MAX,
} ;

/*------------------------------------------------------------------------------
 * Fixed length string structure for Route Distinguisher in string form and
 * for tag stack, ditto.
 */
QFB_T(40) str_rdtoa_t ;
QFB_T( 9) str_tgtoa_t ;         /* 1 tag deep ! */

/*------------------------------------------------------------------------------
 *
 */
extern uint mpls_tags_scan(const byte* pnt, uint len) ;
extern mpls_tags_t mpls_tags_decode(const byte* pnt, uint len) ;
extern mpls_tags_t str2tag (const char* str) ;
extern uint mpls_tags_encode(byte* pnt, uint len, mpls_tags_t tags) ;
extern uint mpls_tags_blow(blower br, mpls_tags_t tags) ;
extern uint mpls_tags_length(mpls_tags_t tags) ;

extern mpls_label_t mpls_label_decode (const byte* pnt) ;
extern mpls_label_t mpls_tags_label(mpls_tags_t tags, uint i) ;

extern rd_type_t mpls_rd_raw_type (const byte* pnt) ;
extern bool mpls_rd_known_type(const byte* pnt) ;
extern bool mpls_rd_decode(mpls_rd rd, const byte* pnt) ;

extern void bgp_mplsvpn_init (void);

extern bool str2prefix_rd (prefix_rd prd, const char* str);
extern bool str2prefix_rd_vty (vty vty, prefix_rd prd, const char* str);
extern str_rdtoa_t srdtoa(prefix_rd_c prd) ;
extern str_tgtoa_t stgtoa(mpls_tags_t tags) ;

#endif /* _QUAGGA_BGP_MPLSVPN_H */
