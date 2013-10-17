/* BGP Configuration Handling -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#ifndef _QUAGGA_BGP_CONFIG_H
#define _QUAGGA_BGP_CONFIG_H

#include "bgpd/bgp_common.h"

#include "list_util.h"
#include "sockunion.h"
#include "name_index.h"

/*------------------------------------------------------------------------------
 * The nature of a setting change
 */
typedef enum bgp_setting_change bgp_sc_t ;
enum bgp_setting_change
{
  bsc_unset   = BIT(0),
  bsc_off     = bsc_unset,

  bsc_set     = BIT(1),

  bsc_set_on  = bsc_set,
  bsc_set_off = bsc_off | bsc_set,
};

/*==============================================================================
 *
 */
extern name_index bgp_config_name_index ;

/*==============================================================================
 * Functions
 */
extern void bgp_config_new_prepare(void) ;


extern bgp_ret_t bgp_config_inst_changed(void) ;



#if 0

extern uint bgp_config_peer_changed(bgp_peer peer, qafx_t qafx, uint setting) ;

extern void bgp_config_part_prepare(bgp_config_pending_part_t type,
                                                                   void* part) ;
extern uint bgp_config_part_changed(bgp_config_pending_part_t type,
                                        void* part, qafx_t qafx, uint setting) ;

#endif

extern bgp_prun bgp_config_prun(bgp_pconfig pc) ;



extern bgp_bconfig bgp_config_inst_prepare(bgp_inst bgp) ;
extern bgp_baf_config bgp_config_inst_af_prepare(bgp_inst bgp, qafx_t qafx) ;

extern bgp_pconfig bgp_config_peer_prepare(bgp_peer peer) ;
extern bgp_paf_config bgp_config_peer_af_prepare(bgp_peer peer, qafx_t qafx) ;

#endif /* _QUAGGA_BGP_CONFIG_H */

