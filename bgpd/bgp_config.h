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

/*------------------------------------------------------------------------------
 * The nature of a running change
 */
typedef enum bgp_run_delta bgp_run_delta_t ;
enum bgp_run_delta
{
  brd_null              = 0,                    /* no delta     */

  /* brd_resume       -- after compilation and application of deltas, the
   *                     object in question should be resumed.
   *
   *                     This is used for RIBs in particular, where they are
   *                     resumed if there is at least one peer running.
   */
  brd_resume        = BIT(0),

  /* brd_refresh_in   -- the inbound filtering has changed, such that all
   *                     routes from the neighbor must be refreshed, and
   *                     any changes propagated.
   */
  brd_refresh_in    = BIT(1),

  /* brd_refresh_out  -- the outbound filtering has changed, such that all
   *                     routes to the neighbor must be refreshed, and
   *                     any changes propagated.
   */
  brd_refresh_out   = BIT(2),

  /* brd_reselect     -- selection criteria have changed, such that all routes
   *                     should be re-selected.
   *
   *                     This is a RIB level delta, where all the others are
   *                     peer level ones.
   *
   *                     This has no effect on individual peers, except that
   *                     refresh_out is redundant.
   */
  brd_reselect      = BIT(3),

  /* brd_renew        -- the connection options and/or the session arguments
   *                     have changed, so the BGP Engine should take note.
   *
   *                     BUT: delta does not justify dropping an established
   *                          session.
   *
   *                          delta may/or may not justify dropping a
   *                          connection which is in the process of trying to
   *                          establish itself.
   */
  brd_renew         = BIT(4),

  /* brd_route_refresh -- need to send a route-refresh request, perhaps to
   *                      update orf prefix filtering.
   */
  brd_route_refresh = BIT(5),

  /* brd_restart      -- drop the existing session (if any) and start a new
   *                     one.
   *
   *                     TODO  graceful ????
   */
  brd_restart       = BIT(6),

  /* brd_shutdown     -- drop the existing session (if any) and when all is
   *                     quiet, delete the running state for the peer.
   */
  brd_shutdown      = BIT(7),
} ;

/*==============================================================================
 * Functions
 */
extern void bgp_config_new_prepare(void) ;

extern bgp_bconfig bgp_config_inst_prepare(bgp_inst bgp) ;
extern bgp_baf_config bgp_config_inst_af_prepare(bgp_inst bgp, qafx_t qafx) ;

extern bgp_pconfig bgp_config_peer_prepare(bgp_peer peer) ;
extern bgp_paf_config bgp_config_peer_af_prepare(bgp_peer peer, qafx_t qafx) ;






extern bgp_assembly bgp_assemble(bgp_inst bgp) ;
extern void bgp_compile(bgp_inst bgp, bgp_assembly assembly) ;


extern bgp_ret_t bgp_config_inst_changed(void) ;

extern bgp_prun bgp_config_prun(bgp_pconfig pc) ;


#endif /* _QUAGGA_BGP_CONFIG_H */

