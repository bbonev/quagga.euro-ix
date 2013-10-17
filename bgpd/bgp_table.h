/* BGP routing table
   Copyright (C) 1998, 2001 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_TABLE_H
#define _QUAGGA_BGP_TABLE_H

#include "bgpd/bgp_common.h"

#include "prefix.h"

/* The bgp_node is the entry in a prefix table, which contains the information
 * for a number of notional tables:
 *
 *   * RIB    -- all available routes for the prefix
 *
 *               In an ordinary table,
 *
 */
typedef struct bgp_node  bgp_node_t ;

struct bgp_node
{
  prefix_t      p ;

  bgp_table     table;

  bgp_node      parent;
  bgp_node      link[2];
#define l_left   link[0]
#define l_right  link[1]

  void*         info;

#if 0
  bgp_adj_out   adj_out;
  bgp_adj_in    adj_in;
#endif

  bgp_node      prn;

  uint          lock;

  byte          qafx ;
  bool          on_wq ;

  bgp_node      wq_next ;
};

typedef enum
{
  BGP_TABLE_MAIN,
  BGP_TABLE_RSCLIENT,
} bgp_table_type_t;

typedef struct bgp_table  bgp_table_t ;

struct bgp_table
{
  bgp_table_type_t type;

  qafx_t qafx ;

  uint lock;

  /* The owner of this 'bgp_table' structure. */
  bgp_peer  owner;

  bgp_node  top;

  unsigned long count;
};

extern bgp_table bgp_table_init (qafx_t qafx);
extern void bgp_table_lock (struct bgp_table *);
extern void bgp_table_unlock (struct bgp_table *);
extern bgp_table bgp_table_finish (bgp_table);
extern void bgp_unlock_node (struct bgp_node *node);
extern bgp_node bgp_table_top (const struct bgp_table *const);
extern bgp_node bgp_route_next (struct bgp_node *);
extern bgp_node bgp_route_next_until (struct bgp_node *, struct bgp_node *);
extern bgp_node bgp_node_get (bgp_table table, prefix_c p);
extern bgp_node bgp_node_lookup (bgp_table, prefix_c);
extern bgp_node bgp_node_lookup_parent (bgp_table table, prefix_c p) ;
extern bgp_node bgp_lock_node (struct bgp_node *node);
extern bgp_node bgp_node_match (const struct bgp_table *, prefix_c);
extern bgp_node bgp_node_match_ipv4 (const struct bgp_table *,
                                          struct in_addr *);
#ifdef HAVE_IPV6
extern struct bgp_node *bgp_node_match_ipv6 (const struct bgp_table *,
                                          struct in6_addr *);
#endif /* HAVE_IPV6 */
extern unsigned long bgp_table_count (const struct bgp_table *const);

/*------------------------------------------------------------------------------
 *
 */
inline static bgp_table
bgp_table_get(bgp_table* p_table, qafx_t qafx)
{
  bgp_table table ;

  table = *p_table ;

  if (table != NULL)
    return table ;

  return *p_table = bgp_table_init (qafx) ;
} ;

#endif /* _QUAGGA_BGP_TABLE_H */
