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

/* BGP advertise FIFO.  */
typedef struct bgp_advertise* bgp_advertise ;

typedef struct bgp_advertise_fifo_base* bgp_advertise_fifo_base ;

struct bgp_advertise_fifo
{
  bgp_advertise_fifo_base base ;
  bgp_advertise next;
  bgp_advertise prev;
};

struct bgp_advertise_fifo_base
{
  bgp_advertise head;
  bgp_advertise tail;
};

/* BGP advertise attribute.  */
struct bgp_advertise_attr
{
  /* Head of advertisement pointer. */
  struct bgp_advertise_fifo_base base ;

  /* Reference counter.  */
  attr_refcnt_t refcnt;

  /* Attribute pointer to be announced.  */
  struct attr *attr;
};

struct bgp_advertise
{
  /* FIFO for advertisement.  */
  struct bgp_advertise_fifo fifo;

  /* Link list for same attribute advertise.  */
  bgp_advertise adv_next;
  bgp_advertise adv_prev;

  /* Prefix information.  */
  struct bgp_node *rn;

  /* Reference pointer.  */
  struct bgp_adj_out *adj;

  /* Advertisement attribute.  */
  struct bgp_advertise_attr *baa;

  /* BGP info.  */
  struct bgp_info *binfo;
};

/* BGP adjacency out.  */
struct bgp_adj_out
{
  /* Linked list pointer.       */
  struct bgp_node*   rn ;
  struct bgp_adj_out *adj_next;
  struct bgp_adj_out *adj_prev;

  /* Advertised peer.           */
  struct peer *peer;
  struct bgp_adj_out* route_next ;
  struct bgp_adj_out* route_prev ;

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
  struct bgp_adj_in *adj_next;
  struct bgp_adj_in *adj_prev;

  /* Received peer.             */
  struct peer *peer;
  struct bgp_adj_in* route_next ;
  struct bgp_adj_in* route_prev ;

  /* Received attribute.        */
  struct attr *attr;
};

/* BGP advertisement list.  */
struct bgp_synchronize
{
  struct bgp_advertise_fifo_base update;
  struct bgp_advertise_fifo_base withdraw;
  struct bgp_advertise_fifo_base withdraw_low;
};

/* bgp_advertise_fifo handling
 *
 * Rules: base->head == NULL => empty
 *        base->tail -- only valid if base->head != NULL
 *
 *        adv->fifo.base == NULL => not on fifo
 *
 *        adv->fifo.next == NULL => last   (if fifo.base != NULL)
 *        adv->fifo.prev == NULL => first  (if fifo.base != NULL)
 */
Inline void
bgp_advertise_fifo_init(bgp_advertise_fifo_base base)
{
  base->head = NULL ;
} ;

Inline bgp_advertise
bgp_advertise_fifo_head(bgp_advertise_fifo_base base)
{
  return base->head ;
} ;

Inline void
bgp_advertise_fifo_add(bgp_advertise_fifo_base base, bgp_advertise adv)
{
  adv->fifo.next = NULL ;
  adv->fifo.base = base ;

  if (base->head == NULL)
    {
      adv->fifo.prev  = NULL ;
      base->head      = adv ;
    }
  else
    {
      adv->fifo.prev  = base->tail ;
      base->tail->fifo.next = adv ;
    } ;

  base->tail = adv ;
} ;

Inline void
bgp_advertise_fifo_del(bgp_advertise adv)
{
  bgp_advertise_fifo_base base = adv->fifo.base ;

  if (base != NULL)
    {
      if (adv->fifo.next == NULL)
        base->tail = adv->fifo.prev ;
      else
        adv->fifo.next->fifo.prev = adv->fifo.prev ;

      if (adv->fifo.prev == NULL)
        base->head = adv->fifo.next ;
      else
        adv->fifo.prev->fifo.next = adv->fifo.next ;

      adv->fifo.base = NULL ;
    } ;
 } ;

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

/* Prototypes.  */
extern void bgp_adj_out_set (struct bgp_node *, struct peer *, struct prefix *,
                      struct attr *, afi_t, safi_t, struct bgp_info *);
extern void bgp_adj_out_unset (struct bgp_node *, struct peer *, struct prefix *,
                        afi_t, safi_t);
extern void bgp_adj_out_remove (struct bgp_node *, struct bgp_adj_out *,
                         struct peer *, afi_t, safi_t);
extern int bgp_adj_out_lookup (struct peer *, struct prefix *, afi_t, safi_t,
                        struct bgp_node *);

extern void bgp_adj_in_set (struct bgp_node *, struct peer *, struct attr *);
extern void bgp_adj_in_unset (struct bgp_node *, struct peer *);
extern void bgp_adj_in_remove (struct bgp_node *, struct bgp_adj_in *);

extern struct bgp_advertise* bgp_advertise_unset(struct bgp_advertise * adv,
                     struct peer *peer, afi_t afi, safi_t safi, bool free_adv) ;
extern struct bgp_advertise* bgp_advertise_redux(struct bgp_advertise * adv,
                                    struct peer *peer, afi_t afi, safi_t safi) ;

extern void bgp_sync_init (struct peer *);
extern void bgp_sync_delete (struct peer *);

#endif /* _QUAGGA_BGP_ADVERTISE_H */
