/* BGP Peer Command Support -- Header
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Restructured: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_PEER_VTY_H
#define _QUAGGA_BGP_PEER_VTY_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"

#include "filter.h"
#include "plist.h"

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_config_write_peer (vty vty, bgp_inst bgp,
                                                   bgp_peer peer, qafx_t qafx) ;

extern void peer_distribute_update (access_list alist) ;
extern void peer_prefix_list_update (prefix_list plist) ;
extern void peer_aslist_update (void) ;

extern void peer_rsclient_unset(bgp_peer peer, qafx_t qafx, bool keep_export) ;

extern bgp_ret_t peer_ebgp_multihop_set (bgp_peer peer, ttl_t);
extern bgp_ret_t peer_ebgp_multihop_unset (bgp_peer peer);

extern bgp_ret_t peer_description_set (bgp_peer peer, const char* desc);
extern bgp_ret_t peer_description_unset (bgp_peer peer);

extern bgp_ret_t peer_update_source_if_set (bgp_peer peer, const char* ifname);
extern bgp_ret_t peer_update_source_addr_set (bgp_peer peer, sockunion su);
extern bgp_ret_t peer_update_source_unset (bgp_peer peer);

extern bgp_ret_t peer_default_originate_set (bgp_peer peer, qafx_t qafx,
                                                        const char* rmap_name) ;
extern bgp_ret_t peer_default_originate_unset (bgp_peer peer, qafx_t qafx);

extern bgp_ret_t peer_port_set (bgp_peer peer, uint16_t port);
extern bgp_ret_t peer_port_unset (bgp_peer peer);

extern bgp_ret_t peer_weight_set (bgp_peer peer, uint weight);
extern bgp_ret_t peer_weight_unset (bgp_peer peer);

extern bgp_ret_t peer_timers_set (bgp_peer peer, uint keepalive,
                                                 uint holdtime) ;
extern bgp_ret_t peer_timers_unset (bgp_peer peer);

extern bgp_ret_t peer_timers_connect_set (bgp_peer peer, uint connect);
extern bgp_ret_t peer_timers_connect_unset (bgp_peer peer);

extern bgp_ret_t peer_advertise_interval_set (bgp_peer, uint32_t);
extern bgp_ret_t peer_advertise_interval_unset (bgp_peer);

extern bgp_ret_t peer_interface_set (bgp_peer peer, const char* ifname);
extern bgp_ret_t peer_interface_unset (bgp_peer peer);

extern bgp_ret_t peer_distribute_set (bgp_peer peer, qafx_t qafx, int direct,
                                                             const char* name) ;
extern bgp_ret_t peer_distribute_unset (bgp_peer peer, qafx_t qafx, int direct);

extern bgp_ret_t peer_allowas_in_set (bgp_peer peer, qafx_t qafx, uint allow) ;
extern bgp_ret_t peer_allowas_in_unset (bgp_peer peer, qafx_t qafx) ;

extern bgp_ret_t peer_local_as_set (bgp_peer peer, as_t asn, bool no_prepend) ;
extern bgp_ret_t peer_local_as_unset (bgp_peer peer);

extern bgp_ret_t peer_prefix_list_set (bgp_peer peer, qafx_t qafx, int direct,
                                                             const char* name) ;
extern bgp_ret_t peer_prefix_list_unset (bgp_peer peer, qafx_t qafx,
                                                                   int direct) ;

extern bgp_ret_t peer_aslist_set (bgp_peer peer, qafx_t qafx, int direct,
                                                             const char* name) ;
extern bgp_ret_t peer_aslist_unset (bgp_peer peer, qafx_t qafx, int direct);

extern bgp_ret_t peer_route_map_set (bgp_peer peer, qafx_t qafx, int direct,
                                                             const char* name) ;
extern bgp_ret_t peer_route_map_unset (bgp_peer peer, qafx_t qafx, int direct) ;

extern bgp_ret_t peer_unsuppress_map_set (bgp_peer peer, qafx_t qafx,
                                                             const char* name) ;
extern bgp_ret_t peer_unsuppress_map_unset (bgp_peer peer, qafx_t qafx) ;

extern bgp_ret_t peer_password_set (bgp_peer peer, const char* password) ;
extern bgp_ret_t peer_password_unset (bgp_peer peer) ;

extern bgp_ret_t peer_maximum_prefix_set (bgp_peer peer, qafx_t qafx,
                 uint32_t max, byte thresh_pc, bool warning, uint16_t restart) ;
extern bgp_ret_t peer_maximum_prefix_unset (bgp_peer peer, qafx_t qafx);

extern bgp_ret_t peer_ttl_security_hops_set (bgp_peer peer, ttl_t ttl);
extern bgp_ret_t peer_ttl_security_hops_unset (bgp_peer peer);

#endif /* _QUAGGA_BGP_PEER_VTY */
