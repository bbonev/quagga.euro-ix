/* BGP attributes.
   Copyright (C) 1996, 97, 98 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_ATTR_H
#define _QUAGGA_BGP_ATTR_H

#include "misc.h"
#include "bitmap.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_attr_store.h"

#include "stream.h"

enum
{
  BGP_MED_MIN = 0,
  BGP_MED_MAX = UINT32_MAX,
} ;

/*
 *
 */
typedef enum
{
  BGP_ATTR_PARSE_OK    = 0,

  BGP_ATTR_PARSE_RECOVERED  = BIT(0),

  BGP_ATTR_PARSE_IGNORE     = BIT(1),
  BGP_ATTR_PARSE_SERIOUS    = BIT(2),
  BGP_ATTR_PARSE_CRITICAL   = BIT(3),

  BGP_ATTR_PARSE_FAILED     = (BGP_ATTR_PARSE_IGNORE |
                               BGP_ATTR_PARSE_SERIOUS |
                               BGP_ATTR_PARSE_CRITICAL),
} bgp_attr_parse_ret_t;

/*
 *
 *
 */
typedef struct bgp_nlri  bgp_nlri_t ;
typedef struct bgp_nlri* bgp_nlri ;

struct bgp_nlri
{
  /* The AFI/SAFI is stored exactly as received, and as the qafx for that.
   *
   * If the AFI/SAFI is not recognised, then qafx will be qafx_other.  If the
   * AFI/SAFI is invalid, then qafx will be qafx_undef.
   */
  iAFI_SAFI_t   in ;            /* incoming Internet AFI/SAFI   */

  qafx_t        qafx ;

  /* The next hop associated with reachable NLRI
   *
   * For completeness, on reading will capture any RD and actual length
   * of the next hop.  Where there is an RD it will (should) be zero, and that
   * is not included in the next_hop value.
   */
  attr_next_hop_t       next_hop ;

  byte         next_hop_length ;
  byte         next_hop_rd[2][8] ;

  /* The pnt pointer points into the incoming packet data stream.
   *
   * Nothing else is valid if the length == 0.
   */
  const byte*  pnt ;
  uint         length ;         /* of entire NLRI in bytes      */
} ;

/* The attribute parser structure carries the current state of the parsing
 * of a set of attributes and delivers the result.
 */
typedef struct bgp_attr_parser_args  bgp_attr_parser_args_t ;
typedef struct bgp_attr_parser_args* bgp_attr_parser_args ;

struct bgp_attr_parser_args
{
  /* Context in which parsing proceeds.
   */
  bgp_peer        peer ;

  bgp_peer_sort_t sort ;
  bool            as4 ;         /* NEW_BGP speaker              */

  /* Properties of the current attribute being processed
   */
  uint8_t    type ;
  uint8_t    flags ;

  bgp_size_t length ;           /* data length                  */

  const byte* start_p ;         /* start of *raw* attribute     */
  const byte* end_p ;           /* end of *raw* attribute       */

  bgp_attr_parse_ret_t ret ;

  /* Overall result
   *
   * Accumulates the return value, and keeps the first notification, in case
   * cannot "treat-as-withdraw".
   */
  bgp_attr_parse_ret_t aret ;

  bool        mp_eor ;

  byte        notify_code ;
  byte        notify_subcode ;
  uint        notify_data_len ;
  const byte* notify_data ;

  byte        notify_attr_type ;        /* for BGP_NOMS_U_MISSING       */

  /* Intermediate results
   */
  as_path    asp ;
  as_path    as4p ;

  as_t       aggregator_as ;            /* 0 => not seen                */
  in_addr_t  aggregator_ip ;

  as_t       as4_aggregator_as ;        /* 0 => not seen                */
  in_addr_t  as4_aggregator_ip ;

  bgp_nlri_t update ;
  bgp_nlri_t withdraw ;

  bgp_nlri_t mp_update ;
  bgp_nlri_t mp_withdraw ;

  attr_unknown unknown ;

  /* Bitmap for all attributes seen and attribute pair for construction
   * and use of the attribute set.
   */
  bitmap_s(BGP_ATT_COUNT) seen ;

  attr_pair_t  attrs[1] ;       /* embedded                     */
}  ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_attr_parse (bgp_attr_parser_args restrict args,
                                           const byte* start_p, uint attr_len) ;
extern void bgp_attr_check (bgp_attr_parser_args restrict args) ;

extern bgp_size_t bgp_packet_attribute(stream s, peer_rib prib,
                                    attr_set attr, prefix p, mpls_tags_t tags) ;
extern bgp_size_t bgp_unreach_attribute (stream s, prefix p, qafx_t qafx);

extern void bgp_packet_withdraw_prefix(stream s, prefix_c p, qafx_t qafx) ;

extern void bgp_dump_routes_attr (struct stream* s, attr_set attr, prefix p) ;

/*------------------------------------------------------------------------------
 * Unit test interfaces
 */
extern const byte* tx_bgp_attr_mp_reach_parse(bgp_attr_parser_args args,
                                                           const byte* attr_p) ;
extern const byte* tx_bgp_attr_mp_unreach_parse(bgp_attr_parser_args args,
                                       const byte* attr_p,
                                       const byte* start_p, const byte* end_p) ;

#endif /* _QUAGGA_BGP_ATTR_H */
