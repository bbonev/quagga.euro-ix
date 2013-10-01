/* BGP packet management header.
   Copyright (C) 1999 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_PACKET_H
#define _QUAGGA_BGP_PACKET_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route_refresh.h"

/* Packet send and receive function prototypes.
 */
extern void bgp_packet_write_stuff(bgp_peer peer, ring_buffer rb) ;

extern void bgp_route_refresh_send (bgp_prib prib, byte orf_type,
                                            byte when_to_refresh, bool remove) ;


extern void bgp_packet_read_stuff(bgp_peer peer, ring_buffer rb) ;




extern bool bgp_nlri_sanity_check(bgp_peer peer, bgp_nlri nlri) ;

#endif /* _QUAGGA_BGP_PACKET_H */
