/* BGP nexthop scan
   Copyright (C) 2000 Kunihiro Ishiguro

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

#ifndef _QUAGGA_BGP_NEXTHOP_H
#define _QUAGGA_BGP_NEXTHOP_H

#include "misc.h"
#include "if.h"
#include "sockunion.h"
#include "bgp_attr_store.h"

/*==============================================================================
 * Work in progress... new next-hop stuff
 */

typedef enum next_hop_state next_hop_state_t ;

enum next_hop_state
{
  nhs_unknown       = 0,

  nhs_valid,
  nhs_invalid,

  nhs_reachable,
  nhs_unreachable,

} ;

extern next_hop_state_t bgp_next_hop_in_valid(attr_set_c attr) ;
extern next_hop_state_t bgp_next_hop_in_reachable(attr_set_c attr) ;










/*==============================================================================
 * To be displaced Next-Hop Stuff
 */

#define BGP_SCAN_INTERVAL_DEFAULT   60
#define BGP_IMPORT_INTERVAL_DEFAULT 15

/* BGP nexthop cache value structure. */
struct bgp_nexthop_cache
{
  /* This nexthop exists in IGP. */
  bool  valid;

  /* Nexthop is changed. */
  bool  changed;

  /* Nexthop is changed. */
  bool  metricchanged;

  /* IGP route's metric. */
  uint32_t metric;

  /* Nexthop number and nexthop linked list.*/
  byte  nexthop_num;
  struct nexthop *nexthop;
};

extern void bgp_scan_cmd_init (void);
extern void bgp_scan_init (void);
extern void bgp_scan_finish (void);
extern bool bgp_nexthop_lookup (qAFI_t q_afi, bgp_peer peer, route_info ri,
                                                                  bool*, bool*);
extern void bgp_connected_add (struct connected *c);
extern void bgp_connected_delete (struct connected *c);
extern int bgp_multiaccess_check_v4 (in_addr_t ip, sockunion su);
extern int bgp_config_write_scan_time (struct vty *);
extern bool bgp_nexthop_onlink (qAFI_t q_afi, attr_next_hop next_hop);
extern bool bgp_nexthop_self (in_addr_t ip);

#endif /* _QUAGGA_BGP_NEXTHOP_H */
