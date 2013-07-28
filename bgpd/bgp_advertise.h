/* BGP advertisement and adjacency
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_ADVERTISE_H
#define _QUAGGA_BGP_ADVERTISE_H

#include "lib/misc.h"
#include "lib/list_util.h"
#include "lib/prefix_id.h"

#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_rib.h"

/*------------------------------------------------------------------------------
 * BGP Advertise Attributes.
 *
 * To support the gathering of updates for the same set of attributes together,
 * there is a vhash table, by attribute "id", which contains a pointer to
 * the attributes in question and a list of bgp_adv objects for those
 * attributes.
 *
 * The hash is the peer->adv_attr_hash[].
 */
#if 0

typedef struct bgp_adv_attr  bgp_adv_attr_t ;

struct bgp_adv_attr
{
  /* Red Tape for the hash
   */
  vhash_node_t  vhash ;

  /* The attributes in question.
   *
   * NB: this pointer "owns" a lock on the stored attribute set.
   *
   *     Pointers to the bgp_adv_attr own a lock on the vhash node.  They do
   *     not have their own lock on the attributes.
   *
   * NB: the attributes here are the attributes *after* any 'out' route-map.
   */
  attr_set attr ;

  /* Base of list of bgp_adv objects which share these attributes.
   */
  route_parcel_base_t abase ;
};

CONFIRM(offsetof(bgp_adv_attr_t, vhash) == 0) ; /* see vhash.h  */

#endif

#if 0
struct bgp_adv
{
  bgp_adv_type_t  type ;        /* update/withdraw                      */

  qafx_t          qafx ;        /* for completeness                     */

  /* List of advertisements for the peer -- peer->sync[]->update/withdraw
   */
  struct dl_list_pair(bgp_adv) fifo ;

  /* If this is an Update advertisement, then 'aa' points at the bgp_adv_attr
   * structure, and the bgp_adv object lives on the bgp_adv_attr list of
   * advertisements using those attributes.
   *
   * So, for update advertisements:   aa->attr are the outgoing attributes.
   *
   *     for withdraw advertisements: aa is NULL.
   */
  bgp_adv_attr  aa ;
  struct dl_list_pair(bgp_adv) alist ;

  /* The related bgp_adj_out object points at bgp_adv while there is an
   * advertisement pending.  Essentially the bgp_adv is an extension of the
   * adj_out for the duration of the advertisement process.
   *
   * This points back to that bgp_adj_out.
   *
   * The main purpose of this pointer is:
   *
   *   * so that the bgp_adj_out->attr_sent can be updated once an update
   *     has been sent, or to remove it once a withdraw has been.
   *
   *     TODO ... I believe the bgp_adj_out is discarded.............................
   *
   *   *
   */
  bgp_adj_out  ao ;

  /* The route that is being announced -- this points at the currently
   * selected bgp_info item on the relevant rn->info list.
   *
   * The ri contains the attributes for the route before any 'out' route-map
   * for the destination.
   */
  bgp_info     ri ;
};

/*------------------------------------------------------------------------------
 * BGP adjacency out.
 *
 * For each route, this contains the state of the route as advertised, or in
 * the process of being advertised, to a given peer.
 */
typedef struct bgp_adj_out  bgp_adj_out_t ;

struct bgp_adj_out
{
  /* Lives on the bgp_node->adj_out list
   */
  bgp_node      rn ;
  struct dl_list_pair(bgp_adj_out) adj ;

  /* Lives on the list of routes sent to this peer.
   */
  bgp_peer      peer;
  struct dl_list_pair(bgp_adj_out) route ;

  /* Advertisement information -- while update is scheduled.
   */
  bgp_adv       adv;

  /* The attributes last sent to this peer.
   *
   * NB: this field is updated when an UPDATE message is sent, so reflects
   *     what we last said to the peer.  If we have never sent anything, or
   *     the last thing we sent was a withdraw, then this is NULL.
   *
   *     While there is an advertisement pending (ie adv is not NULL), this is
   *     NOT the attributes last selected for the peer.
   *
   * NB: if an UPDATE fails because the attributes will not fit into a valid
   *     BGP Message (!), then although the prefix has been withdrawn, it still
   *     appears as if the (broken) attributes have been sent -- which they
   *     have, to the extent possible.
   */
  attr_set      attr_sent ;
};


/*------------------------------------------------------------------------------
 * BGP adjacency in.
 *
 * For each route, this contains the state of the route as received, from a
 * a given peer.
 */
typedef struct bgp_adj_in  bgp_adj_in_t ;

struct bgp_adj_in
{
  /* Linked list pointer
   */
  bgp_node      rn ;
  struct dl_list_pair(bgp_adj_in) adj ;

  /* Peer received from
   */
  bgp_peer      peer;
  struct dl_list_pair(bgp_adj_in) route ;

  /* Received attributes and (for RS Clients) the attributes after rs-in.
   */
  attr_set    attr ;
  attr_set    rs_in ;
};

#if 0
/* BGP adjacency linked list.  */
#define BGP_INFO_ADD(N,A,TYPE)                        \
  do {                                                \
    (A)->adj_prev = NULL;                             \
    (A)->adj_next = (N)->TYPE;                        \
    if ((N)->TYPE)                                    \
      (N)->TYPE->adj_prev = (A);                      \
    (N)->TYPE = (A);                                  \
  } while (0)

#define BGP_INFO_DEL(N,A,TYPE)                        \
  do {                                                \
    if ((A)->adj_next)                                \
      (A)->adj_next->adj_prev = (A)->adj_prev;        \
    if ((A)->adj_prev)                                \
      (A)->adj_prev->adj_next = (A)->adj_next;        \
    else                                              \
      (N)->TYPE = (A)->adj_next;                      \
  } while (0)

#define BGP_ADJ_IN_ADD(N,A)    BGP_INFO_ADD(N,A,adj_in)
#define BGP_ADJ_IN_DEL(N,A)    BGP_INFO_DEL(N,A,adj_in)
#define BGP_ADJ_OUT_ADD(N,A)   BGP_INFO_ADD(N,A,adj_out)
#define BGP_ADJ_OUT_DEL(N,A)   BGP_INFO_DEL(N,A,adj_out)

#endif


/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_adj_out_update (bgp_peer peer, prefix_id_entry pie,
                               attr_set attr, qafx_t qafx, mpls_tag_val_t tag) ;

extern void bgp_adj_out_withdraw (bgp_node rn, bgp_peer peer) ;
extern void bgp_adj_out_delete (bgp_adj_out ao) ;
extern bool bgp_adj_out_lookup (bgp_peer peer, bgp_node rn) ;

extern void bgp_adj_in_set (bgp_node rn, bgp_peer peer, attr_set attr) ;
extern void bgp_adj_rs_in_set (bgp_node rn, bgp_peer peer, attr_set attr,
                                                               attr_set rs_in) ;
extern void bgp_adj_in_unset (bgp_node rn, bgp_peer peer);
extern void bgp_adj_rs_in_unset (bgp_node rn, bgp_peer peer) ;
extern void bgp_adj_in_remove (bgp_node rn, bgp_adj_in ai);

extern bgp_adv bgp_adv_next_by_attr(bgp_adv adv) ;
extern bgp_adv bgp_adv_delete(bgp_adv adv) ;

extern void bgp_sync_init (struct peer *);
extern void bgp_sync_delete (struct peer *);

#endif
#endif /* _QUAGGA_BGP_ADVERTISE_H */
