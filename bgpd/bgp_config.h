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
  brd_null          = 0,

  /* brd_continue     -- for prun: not a new prun and not to
   *
   *                     for prib:
   */
  brd_continue      = BIT(0),

  /* brd_refresh_in   -- for prun: N/A, but if a prun param change requires all
   *                               pribs to brd_refresh_in, that will be
   *                               inherited from the prun by all pribs.
   *
   *                     for prib: the inbound filtering has changed, such that
   *                               all routes from the neighbor must be
   *                               refreshed, and any changes propagated.
   */
  brd_refresh_in    = BIT(1),

  /* brd_refresh_out  -- for prun: N/A, but if a prun param change requires all
   *                               pribs to brd_refresh_out, that will be
   *                               inherited from the prun by all pribs.
   *
   *                     for prib: the outbound filtering has changed, such
   *                               that all routes to the neighbor must be
   *                               refreshed, and any changes propagated.
   */
  brd_refresh_out   = BIT(2),

  /* brd_reselect     -- for prun: selection criteria have changed, such that
   *                               all routes should be re-selected.
   *
   *                     for prib: N/A, except that suppresses brd_refresh_out,
   *                               so is inherited from the prun for that
   *                               purpose.
   */
  brd_reselect      = BIT(3),

  /* brd_renew        -- for prun: the connection options and/or the session
   *                               arguments have changed, so the BGP Engine
   *                               should take note.
   *
   *                               NB: the changes do not justify dropping an
   *                                   established session.
   *
   *                                   the changes may/or may not justify
   *                                   dropping a connection which is in the
   *                                   process of trying to establish itself.
   *
   *                               This will be ignored if the prun has to be
   *                               restarted (or shutdown or deleted !)
   *
   *                      for prib: N/A.
   */
  brd_renew         = BIT(4),

  /* brd_route_refresh -- for prib: need to send a route-refresh request,
   *                                perhaps to update orf prefix filtering.
   *
   *                                This will be ignored if the prun has to be
   *                                restarted (or shutdown or deleted !)
   */
  brd_route_refresh = BIT(5),

  /* brd_restart      -- for prun: stop the existing session (if any) and stop
   *                               all pribs.
   *
   *                               When all is quiet, delete any pribs marked
   *                               to be deleted.  Start any pribs which are
   *                               not (then) marked as brd_continue.  Then
   *                               restart other remaining pribs and set the
   *                               session going again.
   *
   *                     for prib: brd_restart without brd_continue <=> new
   *                               prib.
   *
   *                     TODO  graceful ????
   */
  brd_restart       = BIT(6),

  /* brd_shutdown     -- for prun: stop the existing session (if any) and stop
   *                               all pribs.  When all is quiet leave the
   *                               prun and all configured pribs, but delete
   *                               the session (if any).
   *
   *                     for prib: drop the adj-in/adj-out, leaving configured
   *                               but inactive.
   */
  brd_shutdown      = BIT(7),

  /* brd_delete       -- for prun: no longer configured.
   *
   *                     for prib: no longer configured.
   */
  brd_delete        = BIT(8),
} ;

/*==============================================================================
 * Functions
 */
extern void bgp_config_new_prepare(void) ;

extern bgp_bconfig bgp_config_inst_prepare(bgp_inst bgp) ;
extern bgp_baf_config bgp_config_inst_af_prepare(bgp_inst bgp, qafx_t qafx) ;

extern bgp_pconfig bgp_config_peer_prepare(bgp_peer peer) ;
extern bgp_paf_config bgp_config_peer_af_prepare(bgp_peer peer, qafx_t qafx) ;

extern void bgp_config_queue(bgp_peer peer) ;





extern bgp_assembly bgp_assemble(bgp_inst bgp) ;
extern void bgp_compile(bgp_inst bgp, bgp_assembly assembly) ;


extern bgp_ret_t bgp_config_inst_changed(void) ;

extern bgp_prun bgp_config_prun(bgp_pconfig pc) ;




#endif /* _QUAGGA_BGP_CONFIG_H */

