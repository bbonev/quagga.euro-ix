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

#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route_refresh.h"

#define BGP_NLRI_LENGTH       1U
#define BGP_TOTAL_ATTR_LEN    2U
#define BGP_UNFEASIBLE_LEN    2U
#define BGP_WRITE_PACKET_MAX 10U

/* When to refresh */
#define REFRESH_IMMEDIATE 1
#define REFRESH_DEFER     2

/* ORF Common part flag */
#define ORF_COMMON_PART_ADD        0x00
/* TODO: BUG REPORT... ORF_COMMON_PART_REMOVE should be 0x40 !          */
#define ORF_COMMON_PART_REMOVE     0x80
/* TODO: BUG REPORT... ORF_COMMON_PART_REMOVE_ALL should be 0x80 !      */
#define ORF_COMMON_PART_REMOVE_ALL 0xC0
#define ORF_COMMON_PART_PERMIT     0x00
#define ORF_COMMON_PART_DENY       0x20

/* Packet send and receive function prototypes.
 */
extern void bgp_write (bgp_peer peer, struct stream*);

extern void bgp_route_refresh_send (peer_rib prib, byte orf_type,
                                            byte when_to_refresh, bool remove) ;
extern void bgp_capability_send (bgp_peer peer, qafx_t, int, int);
extern void bgp_default_update_send (bgp_peer peer, prefix p, attr_set attr,
                                                   qafx_t qafx, bgp_peer from) ;
extern void bgp_default_withdraw_send (bgp_peer peer, prefix p, qafx_t qafx);

extern int bgp_capability_receive (bgp_peer peer, bgp_size_t);

extern void bgp_update_receive(bgp_peer peer, bgp_size_t size) ;

extern void bgp_route_refresh_recv(bgp_peer peer, bgp_route_refresh rr) ;

extern bool bgp_nlri_sanity_check(bgp_peer peer, bgp_nlri nlri) ;

#endif /* _QUAGGA_BGP_PACKET_H */
