/* BGP Peer Index -- header
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_PEER_INDEX_H
#define _QUAGGA_BGP_PEER_INDEX_H

#include "bgpd/bgp_common.h"

#include "lib/sockunion.h"

/*==============================================================================
 * The Peer Index maps:
 *
 *   * IP address (name of peer)
 *   * peer_id    (ordinal of peer)
 *
 * To the bgp_peer_index_entry, which in turn points to:
 *
 *   * the peer structure
 *
 *   * its session structure.
 *
 * When a peer is created it is "registered", so a Peer Index Entry is created
 * with it, which adds the peer to the peer index by its IP address and gives
 * the peer an id.  At any time at most one peer can be registered for a given
 * IP address.
 *
 * When a peer is deleted, the Peer Index Entry is removed from the IP address
 * index -- so the IP address no longer has a peer or a session associated with
 * it.
 */
typedef enum bgp_peer_id bgp_peer_id_t ;
enum bgp_peer_id
{
  bgp_peer_id_null      = 0,     /* no peer can have id == 0     */

  bgp_peer_id_first     = 1,
  bgp_peer_id_max       = UINT_MAX,
} ;

/*------------------------------------------------------------------------------
 * Canonical name of peer, derived from sockunion.
 *
 * For IPv4: 4xhhhhhhhh         -- ie  32 bits as  8 hex digits, lower-case
 *     IPv6: 6xhhh....hhh       -- ie 128 bits as 32 hex digits, upper-case
 *
 * This is a step towards separating the name of peer from its address, by
 * converting the address to a string in a canonical form suitable for sorting.
 */
typedef struct bgp_peer_su_cname bgp_peer_su_cname_t ;

struct bgp_peer_su_cname
{
  char str[40] ;                /* plenty big enough    */
} ;

/*==============================================================================
 * Functions
 */
extern void bgp_peer_index_init(void) ;
extern void bgp_peer_index_init_r(void) ;
extern void bgp_peer_index_finish(void) ;

extern bgp_peer_su_cname_t bgp_peer_su_cname(sockunion su) ;

extern bgp_peer_id_t bgp_peer_index_register(bgp_peer peer, chs_c cname) ;
extern void bgp_peer_index_deregister(bgp_peer peer) ;

extern bgp_peer bgp_peer_index_peer_lookup(chs_c cname) ;
extern bgp_prun bgp_peer_index_prun_lookup(chs_c cname) ;
extern bgp_session bgp_peer_index_session_lookup(chs_c cname) ;

#endif /* _QUAGGA_BGP_PEER_INDEX_H */

