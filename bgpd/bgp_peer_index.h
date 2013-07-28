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
 * To the bgp_peer_index_entry.
 *
 * When a peer is created it is "registered", so a Peer Index Entry is created
 * with it, which adds the peer to the peer index by its IP address and gives
 * the peer an id.  At any time at most one peer can be registered for a given
 * IP address.
 *
 * When a peer is deleted, the Peer Index Entry is removed from the IP address
 * index -- so the IP address no longer has a peer associated with it.
 * However, the Peer Index Entry may still be in use by the BGP Engine, so
 * until that is done with the Index Entry it cannot be deleted.  Further,
 * the Index Entry is not actually freed -- along with the id -- until the
 * peer structure is finally deleted.
 *
 * The bgp_peer_index entry contains enough to allow connections to be accepted
 * (or not) completely asynchronously with both the Routeing and the BGP
 * Engines, so:
 *
 *   * particularly for a passive peer, connections can be accepted in between
 *     sessions -- so if a session drops and the peer opens up a connection
 *     before the session is re-enabled, that connection will be accepted and
 *     held.
 *
 *   * when session is Established, is supposed to wait for an OPEN
 *     before rejecting the connection.  (Since we do not support
 *     CollisionDetectEstablishedState.)  Though if Graceful Restart is
 *     set, the session will drop as soon as the new connection is accepted.
 *
 * The bgp_peer_index_entry also keeps track of the password setting for the
 * peer.  So this has a life beyond the session.  Indeed, a
 *
 * When a BGP session is enabled, it will check to see if an accepted
 * connection is pending, and adopt it if it is.
 */
#if 0
typedef enum bgp_peer_index_entry_state bgp_peer_index_entry_state_t ;

enum bgp_peer_index_entry_state
{
  pie_inactive      = 0,

  pie_registered    = BIT(0),
  pie_listening     = BIT(1),
  pie_in_session    = BIT(2),

  pie_msg_in_flight = BIT(4),
} ;
#endif

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
extern void bgp_peer_index_deregister_peer(bgp_peer peer) ;
extern void bgp_peer_index_deregister_session(bgp_session session) ;

extern bgp_session bgp_peer_index_seek_session(sockunion su) ;

#endif /* _QUAGGA_BGP_PEER_INDEX_H */

