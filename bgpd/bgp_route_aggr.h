/* BGP route aggregation -- header
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

#ifndef _QUAGGA_BGP_ROUTE_AGGR_H
#define _QUAGGA_BGP_ROUTE_AGGR_H

#include "bgpd/bgp_common.h"

#include "prefix.h"

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern void bgp_aggregate_cmd_init (void) ;

extern void bgp_aggregate_increment (bgp_run, prefix, void*, qafx_t qafx);
extern void bgp_aggregate_decrement (bgp_run, prefix, void*, qafx_t qafx);

#endif /* _QUAGGA_BGP_ROUTE_AGGR_H */
