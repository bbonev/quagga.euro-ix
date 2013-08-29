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
#include "lib/list_util.h"
#include "lib/prefix_id.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_attr_store.h"

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_adj_in_init(peer_rib prib) ;
extern void bgp_adj_in_reset(peer_rib prib) ;

extern route_info bgp_route_info_new(peer_rib prib, prefix_id_entry pie) ;
extern route_info bgp_route_info_extend(route_info ri) ;

extern route_info bgp_route_info_free(route_info ri, bool ream) ;


extern void bgp_adj_in_update(peer_rib prib, prefix_id_entry pie,
                                                          iroute_state parcel) ;



extern void bgp_adj_in_discard(peer_rib prib) ;
extern void bgp_adj_in_set_stale(peer_rib prib) ;
extern void bgp_adj_in_discard_stale(peer_rib prib) ;
extern void bgp_adj_in_refresh(peer_rib prib) ;
extern void bgp_adj_in_rs_enable(peer_rib prib) ;
extern void bgp_adj_in_rs_disable(peer_rib prib) ;


#endif /* _QUAGGA_BGP_ADJ_IN_H */
