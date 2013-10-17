/* BGP Routemap -- Header.
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman (substantially rewritten)
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
#ifndef _QUAGGA_BGP_ROUTEMAP_H
#define _QUAGGA_BGP_ROUTEMAP_H

#include "bgpd/bgp_attr_store.h"

/*------------------------------------------------------------------------------
 * For Route-Map operations we pass a small package of information, including
 * a pointer to an attr_pair.
 *
 */
enum bgp_rmap_type
  {
    BGP_RMAP_TYPE_NONE         = 0,

    BGP_RMAP_TYPE_IN           = BIT( 0), /* neighbor route-map in       */
    BGP_RMAP_TYPE_OUT          = BIT( 1), /* neighbor route-map out      */
    BGP_RMAP_TYPE_NETWORK      = BIT( 2), /* network route-map           */
    BGP_RMAP_TYPE_REDISTRIBUTE = BIT( 3), /* redistribute route-map      */
    BGP_RMAP_TYPE_DEFAULT      = BIT( 4), /* default-originate route-map */

    BGP_RMAP_TYPE_RS_IN        = BIT( 5), /* neighbor route-map rs-in    */
    BGP_RMAP_TYPE_IMPORT       = BIT( 6), /* neighbor route-map import   */
    BGP_RMAP_TYPE_EXPORT       = BIT( 7), /* neighbor route-map export   */
  } ;
typedef enum bgp_rmap_type bgp_rmap_type_t ;

typedef struct bgp_route_map  bgp_route_map_t ;
typedef struct bgp_route_map* bgp_route_map ;

struct bgp_route_map
{
  attr_pair     attrs ;

  bgp_peer      peer ;
  bgp_prun      prun ;

  qafx_t        qafx ;

  bgp_rmap_type_t rmap_type;
};

/*==============================================================================
 * Prototypes
 */
extern void bgp_route_map_cmd_init (void);
extern void bgp_route_map_init (void);

#endif /* _QUAGGA_BGP_ROUTEMAP_H */
