/* BGP Peer Groups -- header
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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
#ifndef _QUAGGA_BGP_PEER_GROUP_H
#define _QUAGGA_BGP_PEER_GROUP_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_config.h"

#include "lib/vty.h"
#include "lib/list_util.h"

/*==============================================================================
 *
 */

#if 0
/*------------------------------------------------------------------------------
 * BGP peer-group support.
 */
typedef struct bgp_peer_group bgp_peer_group_t ;

struct bgp_peer_group
{
  char*     name;

  bgp_inst  bgp;                /* Does not own a lock          */

  bgp_pconfig_t c ;             /* the actual configuration     */
};
#endif

/*==============================================================================
 *
 */
#if 0

extern bgp_peer_group peer_group_lookup (bgp_inst bgp, const char* name);
extern bgp_peer_group peer_group_get (bgp_inst bgp, const char* name);
extern bgp_ret_t peer_group_delete (bgp_peer_group group) ;
extern int peer_group_cmp (bgp_peer_group g1, bgp_peer_group g2) ;

extern bgp_ret_t peer_group_bind (bgp_inst bgp, sockunion su,
                               bgp_peer_group group, qafx_t qafx, as_t* p_asn) ;
extern bgp_ret_t peer_group_unbind (bgp_peer peer, bgp_peer_group group,
                                                                  qafx_t qafx) ;
#endif

#endif /* _QUAGGA_BGP_PEER_GROUP_H */

