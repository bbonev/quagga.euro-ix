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
#include "bgpd/bgp_connection.h"

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
typedef       struct bgp_peer_index_entry  bgp_peer_index_entry_t ;
typedef const struct bgp_peer_index_entry* bgp_peer_index_entry_c ;

typedef uint bgp_peer_id_t ;

enum { bgp_peer_id_null = 0 } ; /* no peer can have id == 0     */

/*==============================================================================
 * Functions
 */
extern void bgp_peer_index_init(void* parent) ;
extern void bgp_peer_index_init_r(void) ;
extern void bgp_peer_index_finish(void) ;
extern void bgp_peer_index_register(bgp_peer peer, bgp_session session) ;
extern void bgp_peer_index_deregister(bgp_peer peer) ;

extern bgp_session bgp_peer_index_seek_session(sockunion su) ;

#endif /* _QUAGGA_BGP_PEER_INDEX_H */

