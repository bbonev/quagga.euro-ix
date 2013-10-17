/* BGP static routes -- header
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 *
 * Recast: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#ifndef _QUAGGA_BGP_ROUTE_STATIC_H
#define _QUAGGA_BGP_ROUTE_STATIC_H

#include "bgpd/bgp_common.h"

#include "prefix.h"
#include "vty.h"

/*------------------------------------------------------------------------------
 * BGP static route configuration.
 */
typedef struct bgp_static bgp_static_t ;

struct bgp_static
{
  /* Backdoor configuration.                            */
  bool backdoor;

  /* Import check status.                               */
  bool  valid;

  /* IGP metric.                                        */
  uint32_t igpmetric;

  /* IGP nexthop.                                       */
  struct in_addr igpnexthop;

  /* Atomic set reference count (ie cause of pathlimit) */
  uint32_t atomic;

  /* BGP redistribute route-map.                        */
  struct
  {
    char *name;
    struct route_map *map;
  } rmap;

  /* MPLS label.                                        */
  byte  tag[3];
};

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_static_cmd_init (void) ;

extern void bgp_static_delete (bgp_inst bgp);
extern void bgp_static_update (bgp_inst bgp, prefix pfx,
                                             struct bgp_static *, qafx_t qafx);
extern void bgp_static_withdraw (bgp_inst bgp, prefix pfx, qafx_t qafx);

#endif /* _QUAGGA_BGP_ROUTE_STATIC_H */
