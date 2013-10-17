/* BGP Running Instances -- header.
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

#ifndef _QUAGGA_BGP_RUN_H
#define _QUAGGA_BGP_RUN_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_notification.h"

#include "thread.h"
#include "plist.h"
#include "qtime.h"
#include "privs.h"
#include "ihash.h"
#include "sockunion.h"
#include "workqueue.h"
#include "list_util.h"

/*------------------------------------------------------------------------------
 * BGP running instance structure.
 */
typedef struct bgp_run  bgp_run_t ;
struct bgp_run
{
  /* The brun has a parent instance.  The running code does not care.
   *
   * The brun is hung off the bgp_env -- so all running instances can be found.
   *
   * The view name is a copy of the value in the instance, and *cannot* change
   * while it and the brun are in existence.
   */
  bgp_inst      parent_inst ;

  struct dl_list_pair(bgp_run) brun_list ;

  chs_c         view_name ;

  /* Route-Contexts by name, if any and the view's rcontext, ditto.
   */
  vhash_table   rc_name_index ;
  bgp_rcontext  rc_view ;

  /* Reference count to allow bgp_peer_delete to finish after bgp_delete
   */
  uint  lock;

  /* Self and peers
   */
  bgp_prun      prun_self ;

  struct dl_base_pair(bgp_prun) pruns ;

  /* BGP router identifier.
   */
  in_addr_t     router_id_r;

  /* BGP route reflector cluster ID.
   */
  in_addr_t     cluster_id_r ;

  /* BGP AS and confederation information.
   *
   * The 'my_as' is a copy of that in the bgp_inst and *cannot* change !
   *
   * The ebgp_as is:  bgp->my_as, unless bgp->confed_id is set, when it is that.
   *
   * So bgp->ebgp_as is the effective as for eBGP sessions (NB: that *excludes*
   * sessions to Confederation peers in different Member ASes).
   *
   * check_confed_id is set iff:  confed_id != BGP_ASN_NULL
   *                         and: confed_id != bgp->my_as
   *
   * check_confed_id_all is set iff: confed_id not in confed_peers.
   *
   * What check_confed_id means is that for iBGP and for cBGP, we can check
   * that the AS-PATH on incoming routes does NOT contain the confed_id.
   *
   * NB: the confed_id *may* be the same as the bgp->my_as.
   *
   * NB: the confed_peers *will* exclude the bgp->my_as, but not necessarily the
   *     confed_id !
   */
  as_t    my_as ;
  as_t    ebgp_as ;

  as_t    confed_id_r ;         /* BGP_ASN_NULL <=> no CONFED   */
  asn_set confed_peers_r ;

  bool    check_confed_id_r ;
  bool    check_confed_id_all_r ;

  /* BGP flags.
   */
  bool    do_graceful_restart ;         /* BGP_FLAG_GRACEFUL_RESTART      */
  bool    do_prefer_current_selection ; /* ! BGP_FLAG_COMPARE_ROUTER_ID   */
  bool    do_enforce_first_as ;         /* BGP_FLAG_ENFORCE_FIRST_AS      */
  bool    do_import_check ;             /* BGP_FLAG_IMPORT_CHECK          */
  bool    do_log_neighbor_changes ;     /* BGP_FLAG_LOG_NEIGHBOR_CHANGES  */

  bool    no_client_to_client ;         /* BGP_FLAG_NO_CLIENT_TO_CLIENT   */
  bool    no_fast_ext_failover ;        /* BGP_FLAG_NO_FAST_EXT_FAILOVER  */

  /* BGP routing information bases -- one per AFI/SAFI.
   */
  bgp_rib rib[qafx_count] ;
  bool    real_rib ;           /* true <=> install routes      */

  /* BGP redistribute
   */
  bool     redist_r[AFI_MAX][ZEBRA_ROUTE_MAX];
  bool     redist_metric_set_r[AFI_MAX][ZEBRA_ROUTE_MAX];
  uint32_t redist_metric_r[AFI_MAX][ZEBRA_ROUTE_MAX];

  struct
  {
    char *name;
    struct route_map *map;
  } rmap_r[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* Running arguments
   */
  bgp_args_t    args_r ;
} ;

/*------------------------------------------------------------------------------
 * For many purposes BGP requires a CLOCK_MONOTONIC type time, in seconds.
 */
Inline time_t
bgp_clock(void)
{
  return qt_get_mono_secs() ;
}

/*------------------------------------------------------------------------------
 * For some purposes BGP requires a Wall Clock version of a time returned by
 * bgp_clock() above.
 *
 * This is calculated from the current Wall Clock, the current bgp_clock and
 * the bgp_clock time of some moment in the past.
 *
 * The fundamental problem is that the Wall Clock *may* (just may) be altered
 * by the operator or automatically, if the system clock is wrong.  So there
 * are, potentially, two versions of a past moment:
 *
 *   1) according to the Wall Clock at the time.
 *
 *   2) according to the Wall Clock now.
 *
 * There doesn't seem to be a good way of selecting between these if they are
 * different... Here we take (2), which (a) doesn't require us to fetch and
 * store both bgp_clock() and Wall Clock times every time we record the time
 * of some event, and (b) assumes that if the Wall Clock has been adjusted,
 * it was wrong before.  This can still cause confusion, because the Wall
 * Clock time calculated now may differ from any logged Wall Clock times !!
 */
Inline time_t
bgp_wall_clock(time_t mono)
{
  return time(NULL) - (bgp_clock() - mono) ;
} ;

/*------------------------------------------------------------------------------
 * Prototypes.
 */
extern bgp_run bgp_run_lookup(chs_c view_name) ;

extern bgp_prib bgp_run_get_pribs(bgp_run brun, qafx_t qafx) ;


#endif /* _QUAGGA_BGP_RUN_H */
