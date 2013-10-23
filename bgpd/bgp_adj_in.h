/* Peer-RIB Adj-In handling -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_ADJ_IN_H
#define _QUAGGA_BGP_ADJ_IN_H

#include "lib/misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_attr_store.h"

#include "lib/list_util.h"
#include "lib/prefix_id.h"

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_adj_in_init(bgp_prib prib) ;
extern void bgp_adj_in_reset(bgp_prib prib) ;

extern route_info bgp_route_info_new(bgp_prib prib, prefix_id_entry pie) ;
extern route_info bgp_route_info_extend(route_info ri) ;

extern route_info bgp_route_info_free(route_info ri, bool remove) ;


extern void bgp_adj_in_update_prefix(bgp_prib prib, prefix_id_entry pie,
                                        iroute_state parcel, mpls_tags_t tags) ;

extern route_info bgp_route_select_lc(bgp_rib_node rn, bgp_lc_id_t lc) ;


extern void bgp_adj_in_discard(bgp_prib prib) ;
extern void bgp_adj_in_set_stale(bgp_prib prib) ;
extern void bgp_adj_in_discard_stale(bgp_prib prib) ;
extern void bgp_adj_in_refresh(bgp_prib prib) ;


#endif /* _QUAGGA_BGP_ADJ_IN_H */
