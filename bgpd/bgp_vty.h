/* BGP VTY interface.
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
#ifndef _QUAGGA_BGP_VTY_H
#define _QUAGGA_BGP_VTY_H

#include "bgpd/bgp_common.h"

#include "command.h"

/*==============================================================================
 * Here we have vty stuff which is common to the configuration and run-time.
 *
 * NB: including this does *not* pull in configuration or run-time structures.
 */
#define CMD_AS_RANGE "<1-4294967294>"

extern void bgp_vty_init (void) ;

extern cmd_ret_t bgp_vty_return (vty vty, bgp_ret_t ret) ;

extern qafx_t bgp_node_qafx (vty vty) ;
extern qafx_t bgp_node_qafx_explicit(vty vty) ;
extern qAFI_t bgp_node_afi (vty vty) ;
extern qSAFI_t bgp_node_safi (vty vty) ;

extern bgp_inst bgp_node_inst(vty vty) ;
extern bgp_inst bgp_inst_lookup_vty(vty vty, chs_c name, as_t as) ;

extern bgp_peer bgp_peer_or_group_lookup_vty(vty vty, chs_c p_str) ;
extern bgp_peer bgp_peer_lookup_vty(vty vty, chs_c p_str) ;
extern bgp_peer bgp_group_lookup_vty(vty vty, chs_c p_str) ;

extern bgp_run bgp_run_lookup_vty(vty vty, chs_c v_str) ;

extern bgp_prun prun_lookup_view_vty(vty vty, chs_c v_str, chs_c p_str) ;
extern bgp_prun prun_lookup_view_qafx_vty(vty vty, chs_c v_str, chs_c p_str,
                                                                  qafx_t qafx) ;

#endif /* _QUAGGA_BGP_VTY_H */
