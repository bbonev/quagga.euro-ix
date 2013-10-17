/* BGP Instances Configuration Operations -- header.
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

#ifndef _QUAGGA_BGPD_INST_CONFIG_H
#define _QUAGGA_BGPD_INST_CONFIG_H

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_config.h"

#include "vty.h"

/*==============================================================================
 * BGP Instances and their Configuration
 */

/*------------------------------------------------------------------------------
 * BGP instance structure.
 */
typedef struct bgp_inst bgp_inst_t ;

struct bgp_inst
{
  bgp_env       parent_env ;

  struct dl_list_pair(bgp_inst) bgp_list ;

  /* The the 'view' name is an essential part of the bgp_inst, and *cannot* be
   * changed once the bgp_inst has been created.
   */
  chs_t         name;

  /* BGP Peers and Groups.
   *
   * All the peers and groups associated with this bgp instance.  The vectors
   * are held in group-name and peer-ip order:
   *
   *   * to find a group within a view, does a vector_bsearch() in this vector.
   *
   *   * for output of configuration etc, the output is in order.
   */
  vector_t      groups[1] ;
  vector_t      peers[1] ;      /* real peers           */

  bgp_run       brun ;

  /* The configuration for this bgp_inst.
   */
  bgp_bconfig   c ;
};

/*==============================================================================
 * The BGP Instance Configuration
 *
 * The bgp instance configuration items.
 */
typedef enum bgp_bc_setting  bgp_bc_setting_t ;
enum bgp_bc_setting
{
  /* These first settings map directly to bgp_flag_t bits -- see below.
   *
   * There are some peer_flag_t bits which do not have cgs_FLAG_xxx equivalents.
   * those flags start at or after cgs_flag_count.
   */
  bcs_ALWAYS_COMPARE_MED       = 0,
  bcs_DETERMINISTIC_MED,
  bcs_MED_MISSING_AS_WORST,
  bcs_MED_CONFED,
  bcs_DEFAULT_IPV4,
  bcs_NO_CLIENT_TO_CLIENT,
  bcs_ENFORCE_FIRST_AS,
  bcs_COMPARE_ROUTER_ID,
  bcs_ASPATH_IGNORE,
  bcs_IMPORT_CHECK,
  bcs_NO_FAST_EXT_FAILOVER,
  bcs_LOG_NEIGHBOR_CHANGES,
  bcs_GRACEFUL_RESTART,
  bcs_ASPATH_CONFED,

  bcs_count_of_flags,

  /* The qafx for which we have things configured.
   */
  bcs_qafx_first        = bcs_count_of_flags,
  bcs_qafx_last         = bcs_qafx_first + (qafx_last - qafx_first),

  /* These settings are for more general values
   *
   * description does not affect the running state !
   */
  bcs_router_id,
  bcs_cluster_id,

  bcs_confed_id,
  bcs_confed_peers,

  /* The bgp_args
   */
  bcs_port,
  bcs_local_pref,
  bcs_med,
  bcs_weight,
  bcs_holdtime_secs,
  bcs_keepalive_secs,
  bcs_connect_retry_secs,
  bcs_accept_retry_secs,
  bcs_open_hold_secs,
  bcs_ibgp_mrai_secs,
  bcs_cbgp_mrai_secs,
  bcs_ebgp_mrai_secs,
  bcs_idle_hold_min_secs,
  bcs_idle_hold_max_secs,
  bcs_restart_time_secs,
  bcs_stalepath_time_secs,
  bcs_distance_ebgp,
  bcs_distance_ibgp,
  bcs_distance_local,

  bcs_count_of_settings
} ;
CONFIRM(bcs_count_of_settings <= 64) ;

typedef uint64_t bgp_bc_set_t ;
#define bcs_bit(n) BIT64(n)
#define bcs_qafx_bit(q) bcs_bit(bcs_qafx_first + (q) - qafx_first)

#if 0

typedef enum bgp_flag bgp_flag_t ;
enum bgp_flag
{
  /* The following flags have global significance -- no peer or peer-group can
   * have an individual setting.
   */
  BGP_FLAG_ALWAYS_COMPARE_MED       = BIT(bcs_ALWAYS_COMPARE_MED),
  BGP_FLAG_DETERMINISTIC_MED        = BIT(bcs_DETERMINISTIC_MED),
  BGP_FLAG_MED_MISSING_AS_WORST     = BIT(bcs_MED_MISSING_AS_WORST),
  BGP_FLAG_MED_CONFED               = BIT(bcs_MED_CONFED),
  BGP_FLAG_NO_DEFAULT_IPV4          = BIT(bcs_DEFAULT_IPV4),
  BGP_FLAG_NO_CLIENT_TO_CLIENT      = BIT(bcs_NO_CLIENT_TO_CLIENT),
  BGP_FLAG_ENFORCE_FIRST_AS         = BIT(bcs_ENFORCE_FIRST_AS),
  BGP_FLAG_COMPARE_ROUTER_ID        = BIT(bcs_COMPARE_ROUTER_ID),
  BGP_FLAG_ASPATH_IGNORE            = BIT(bcs_ASPATH_IGNORE),
  BGP_FLAG_IMPORT_CHECK             = BIT(bcs_IMPORT_CHECK),
  BGP_FLAG_NO_FAST_EXT_FAILOVER     = BIT(bcs_NO_FAST_EXT_FAILOVER),
  BGP_FLAG_LOG_NEIGHBOR_CHANGES     = BIT(bcs_LOG_NEIGHBOR_CHANGES),
  BGP_FLAG_GRACEFUL_RESTART         = BIT(bcs_GRACEFUL_RESTART),
  BGP_FLAG_ASPATH_CONFED            = BIT(bcs_ASPATH_CONFED),
} ;

#endif

/*------------------------------------------------------------------------------
 * bgp_inst_config object
 *
 * This captures all of the values which are set by configuration for a given
 * bgp instance.
 */
typedef struct bgp_bconfig bgp_bconfig_t ;

struct bgp_bconfig
{
  bgp_inst  parent_inst ;

  /* ASN and BGP router identifier.
   *
   * The ASN cannot, in fact, change once the bgp instance is created.
   */
  as_t      my_as ;

  /* BGP flags.
   */
  bgp_bc_set_t  set ;
  bgp_bc_set_t  set_on ;

  /* The route-id, as set by configuration.
   *
   * The run-time may have a setting furnished by the south-side.
   */
  in_addr_t router_id ;

  /* Confederation ID, confederation peers.
   *
   * In the running state there is also ebgp_as, which is a copy of my_as
   * unless have confed_id, when is a copy of that.
   */
  as_t      confed_id ;
  asn_set   confed_peers ;

  /* BGP route reflector ID.
   */
  in_addr_t cluster_id ;

  /* Configured arguments
   */
  bgp_args_t    args ;

  /* BGP Per AF flags and redistribution.
   */
  bgp_baf_config  afc[qafx_count] ;
} ;

Inline bool
bcs_is_set(bgp_bconfig bc, bgp_bc_setting_t bcs)
{
  return (bc->set & bcs_bit(bcs)) ;
} ;

Inline bool
bcs_is_on(bgp_bconfig bc, bgp_bc_setting_t bcs)
{
  return (bc->set & bc->set_on & bcs_bit(bcs)) ;
} ;

Inline bool
bcs_qafx_config(bgp_bconfig bc, qafx_t qafx)
{
  return (bc->set & bc->set_on & bcs_qafx_bit(bcs_qafx_bit(qafx))) ;
} ;

Inline qafx_set_t
bcs_qafxs(bgp_bconfig bc)
{
  return ((bc->set_on & bc->set) >> bcs_qafx_first) & qafx_known_bits ;

  confirm((bcs_qafx_bit(qafx_first) >> bcs_qafx_first) == qafx_first_bit) ;
}

/*==============================================================================
 * The redistribution configuration.
 */
typedef enum bgp_redist_type bgp_redist_type_t ;
enum bgp_redist_type
{
  redist_type_count  = ZEBRA_ROUTE_MAX
};

typedef struct bgp_redist_config  bgp_redist_config_t ;
typedef struct bgp_redist_config* bgp_redist_config ;

struct bgp_redist_config
{
  bool        set ;
  bool        metric_set ;
  uint32_t    metric ;
  nref_c      rmap_name ;
} ;

/*------------------------------------------------------------------------------
 * Which redist settings to change in bgp_redistribute_set()
 */
typedef enum redist_set redist_set_t ;
enum redist_set
{
  redist_set_metric    = BIT(0),
  redist_set_rmap      = BIT(1),
  redist_set_action    = BIT(2),
} ;

/*==============================================================================
 * The bgp instance afc specific configuration items.
 *
 * There is not a lot of this, so it is embedded in the bgp_
 */
typedef enum bgp_bafc_setting  bgp_bafc_setting_t ;
enum bgp_bafc_setting
{
  bafcs_DAMPING                 = 0,

  bafcs_count_of_flags,

  /* The redistribute settings cover a number of bits, dependiing on the
   * number of route types known to us.
   */
  bafcs_redist                  = bafcs_count_of_flags,

  bafcs_redist_first  = bafcs_redist,
  bafcs_redist_last   = bafcs_redist + redist_type_count - 1,

  bafcs_count_of_settings       = bafcs_count_of_flags,
};

CONFIRM(bafcs_count_of_settings <= 64) ;

typedef uint64_t bgp_bafc_set_t ;
#define bafcs_bit(n) BIT64(n)

typedef struct bgp_baf_config  bgp_baf_config_t ;

struct bgp_baf_config
{
  bgp_bconfig       parent_bconf ;
  qafx_t            qafx ;

  /* Just flags
   */
  bgp_bafc_set_t    set ;
  bgp_bafc_set_t    set_on ;

  /* BGP redistribute
   */
  bool          redist_changed ;

  bgp_redist_config_t  redist[redist_type_count] ;
};

Inline bool
bafcs_is_set(bgp_baf_config bafc, bgp_bafc_setting_t bafcs)
{
  return (bafc != NULL) ? (bafc->set & bafcs_bit(bafcs))
                        : false ;
} ;

Inline bool
bafcs_is_on(bgp_baf_config bafc, bgp_bafc_setting_t bafcs)
{
  return (bafc != NULL) ? (bafc->set & bafc->set_on & bafcs_bit(bafcs))
                        : false ;
} ;

/*==============================================================================
 * Prototypes.
 */
extern int bgp_config_write (vty vty) ;
extern bool bgp_config_write_family_header(vty vty, qafx_t qafx,
                                                              bool* p_done_af) ;

extern bgp_ret_t bgp_inst_get(bgp_inst* p_bgp, chs_c name, as_t* p_as) ;
extern bgp_ret_t bgp_inst_delete (bgp_inst bgp) ;
extern bgp_inst bgp_inst_lookup(chs_c name, as_t as) ;
extern bgp_inst bgp_inst_default (void) ;

extern bgp_ret_t bgp_flag_modify(bgp_inst bgp, bgp_bc_setting_t bcs,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_af_flag_modify (bgp_inst bgp, qafx_t qafx,
                                       bgp_bafc_setting_t bafcs, bgp_sc_t bsc) ;

extern bgp_ret_t bgp_router_id_set(bgp_inst bgp, chs_c id_str, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_cluster_id_set(bgp_inst bgp, chs_c id_str, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_confed_id_set (bgp_inst bgp, as_t confed_id, bgp_sc_t bsc);
extern bgp_ret_t bgp_confed_peer_set(bgp_inst bgp, as_t asn, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_timers_set (bgp_inst bgp, uint keepalive, uint holdtime,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_stalepath_time_set (bgp_inst bgp, uint stalepath_time_secs,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_connect_retry_time_set (bgp_inst bgp,
                                        uint connect_retry_secs, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_accept_retry_time_set (bgp_inst bgp,
                                         uint accept_retry_secs, bgp_sc_t bsc) ;
extern bgp_ret_t bgp_open_hold_time_set (bgp_inst bgp, uint openholdtime,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_mrai_set (bgp_inst bgp, uint ibgp_mrai,
                                             uint cbgp_mrai,
                                             uint ebgp_mrai, bgp_sc_t bsc) ;

extern bgp_ret_t bgp_restart_time_set (bgp_inst bgp, uint restart_time_secs,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_local_pref_set(bgp_inst bgp, uint local_pref,
                                                                 bgp_sc_t bsc) ;
extern bgp_ret_t bgp_default_med_set (bgp_inst bgp, uint med, bgp_sc_t bsc) ;

extern bgp_ret_t bgp_redistribute_set(bgp_inst bgp, qafx_t qafx,
                                  bgp_redist_type_t r_type, redist_set_t what,
                                   chs_c rmap_name, uint metric, bgp_sc_t bsc) ;

#endif /* _QUAGGA_BGPD_INST_CONFIG_H */
