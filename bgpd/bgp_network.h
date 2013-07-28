/* BGP network related header
 * Copyright (c) 1997 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_NETWORK_H
#define _QUAGGA_BGP_NETWORK_H

#include "bgpd/bgp_common.h"

#include "sockunion.h"

extern uint bgp_listeners_init(const char* addresses, const char* port_str) ;
extern void bgp_listeners_finish(void) ;

extern bool bgp_listen_set(bgp_connection_options_c cops) ;
extern void bgp_listen_set_password(bgp_connection_options_c cops) ;
extern void bgp_listen_unset(bgp_connection_options_c cops) ;

extern void bgp_connect(bgp_connection connection) ;
extern void bgp_accept_open(bgp_connection connection) ;


extern void bgp_not_prepared_to_accept(bgp_connection connection) ;
extern void bgp_set_new_ttl(bgp_connection connection, int ttl, bool gtsm) ;

#endif /* _QUAGGA_BGP_NETWORK_H */
