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

/* BGP advertise FIFOs.
 */
typedef struct bgp_advertise* bgp_advertise ;

struct bgp_advertise_fifo_base dl_base_pair(bgp_advertise) ;

/* BGP advertise attribute.  */
struct bgp_advertise_attr
{
  /* Attribute pointer to be announced.
   *
   * NB: each item on the fifo below owns its own lock on the attr, so the
   *     bgp_advertise_attr does *not* own a lock.
   */
  struct attr *attr;

  /* List of bgp_advertise_attr which share the attributes.
   *
   * When this list becomes empty, the bgp_advertise_attr object is removed
   * from the sync->hash and destroyed.
   */
  struct bgp_advertise_fifo_base base ;
};

struct bgp_advertise
{
  /* FIFO for advertisement.
   *
   * Will be on the peer's update fifo for updates and withdraw fifo for
   * withdraws.
   */
  struct dl_list_pair(bgp_advertise) fifo ;

  /* Link list for same attribute advertisements.
   */
  struct dl_list_pair(bgp_advertise) baa_list ;

  /* Prefix information
   */
  struct bgp_node *rn;

  /* The adj-out this is an advertisement for.
   */
  struct bgp_adj_out *adj;

  /* Advertisement attribute.
   *
   * NB: withdraw <=> NULL   -- when a bgp_advertise object is annulled,
   *                            is removed from the withdraw fifo if this
   *                            is NULL, otherwise from the update fifo !
   *
   * Note that the attr are those after the 'out' filtering, so may not be
   * the same as the attr in the bgp_info.
   */
  struct bgp_advertise_attr *baa;

  /* BGP info.
   *
   * NB: withdraw <=> NULL
   */
  struct bgp_info *binfo;
};

/* BGP adjacency out.  */
struct bgp_adj_out
{
  /* Linked list pointer.       */
  struct bgp_node*   rn ;
  struct dl_list_pair(struct bgp_adj_out*) rn_list ;

  /* Advertised peer.           */
  struct peer *peer;
  struct dl_list_pair(struct bgp_adj_out*) peer_list ;

  /* Advertised attribute.      */
  struct attr *attr;

  /* Advertisement information. */
  struct bgp_advertise *adv;
};

/* BGP adjacency in. */
struct bgp_adj_in
{
  /* Linked list pointer.       */
  struct bgp_node*   rn ;
  struct dl_list_pair(struct bgp_adj_in*) rn_list ;

  /* Received peer.             */
  struct peer *peer;
  struct dl_list_pair(struct bgp_adj_in*) peer_list ;

  /* Received attribute.        */
  struct attr *attr;

  /* Received Tag, if any       */
  uchar tag[3];
};

/* BGP advertisement list.  */
struct bgp_synchronize
{
  struct bgp_advertise_fifo_base update;
  struct bgp_advertise_fifo_base withdraw;
#if 0
  struct bgp_advertise_fifo_base withdraw_low;
#endif

  struct hash *hash ;
};

Inline bgp_advertise
bgp_advertise_fifo_head(struct bgp_advertise_fifo_base* base)
{
  return ddl_head(*base) ;
} ;

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

/* Prototypes.  */
extern void bgp_adj_out_set (struct bgp_node *, struct peer *, struct prefix *,
                      struct attr *, afi_t, safi_t, struct bgp_info *);
extern void bgp_adj_out_unset (struct bgp_node *, struct peer *, struct prefix *,
                        afi_t, safi_t);
extern void bgp_adj_out_remove (struct bgp_adj_out *, afi_t, safi_t);
extern bool bgp_adj_out_lookup (struct peer *, struct prefix *, afi_t, safi_t,
                        struct bgp_node *);

extern void bgp_adj_in_set (struct bgp_node *, struct peer *, struct attr *,
                                                                  const uchar*);
extern void bgp_adj_in_unset (struct bgp_node *, struct peer *);
extern void bgp_adj_in_remove (struct bgp_adj_in *adj_in, afi_t afi,
                                                                   safi_t safi);

extern struct bgp_advertise* bgp_advertise_unset(struct bgp_advertise * adv,
                                  struct bgp_synchronize* sync, bool free_adv) ;
extern struct bgp_advertise* bgp_advertise_redux(struct bgp_advertise * adv,
                                                 struct bgp_synchronize* sync) ;

extern void bgp_sync_init (struct peer *);
extern void bgp_sync_start(struct peer *peer) ;
extern void bgp_sync_delete (struct peer *);

extern void bgp_advertise_finish(void) ;

#endif /* _QUAGGA_BGP_ADVERTISE_H */
