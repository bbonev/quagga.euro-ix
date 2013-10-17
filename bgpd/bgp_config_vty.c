/* BGP VTY configuration interface.
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

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

#include "misc.h"

#include "command.h"
#include "vty.h"
#include "log.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_config_vty.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_inst_config.h"
#include "bgpd/bgp_peer_config.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_names.h"

//extern struct in_addr router_id_zebra;     TODO ???

/*==============================================================================
 * BGP global configuration.
 */

/*------------------------------------------------------------------------------
 * Multiple instance option
 */
DEFUN (bgp_multiple_instance_func,
       bgp_multiple_instance_cmd,
       "bgp multiple-instance",
       BGP_STR
       "Enable bgp multiple instance\n")
{
  return bgp_vty_return(vty, bgp_option_set(BGP_OPT_MULTIPLE_INSTANCE));
}

DEFUN (no_bgp_multiple_instance,
       no_bgp_multiple_instance_cmd,
       "no bgp multiple-instance",
       NO_STR
       BGP_STR
       "BGP multiple instance\n")
{
  return bgp_vty_return(vty, bgp_option_unset(BGP_OPT_MULTIPLE_INSTANCE));
}

/*------------------------------------------------------------------------------
 * Cisco style configuration option
 */
DEFUN (bgp_config_type,
       bgp_config_type_cmd,
       "bgp config-type (cisco|zebra)",
       BGP_STR
       "Configuration type\n"
       "cisco\n"
       "zebra\n")
{
  bgp_ret_t ret ;

  if (strncmp (argv[0], "c", 1) == 0)
    ret = bgp_option_set (BGP_OPT_CONFIG_CISCO);
  else
    ret = bgp_option_unset (BGP_OPT_CONFIG_CISCO);

  return bgp_vty_return(vty, ret) ;
}

DEFUN (no_bgp_config_type,
       no_bgp_config_type_cmd,
       "no bgp config-type",
       NO_STR
       BGP_STR
       "Display configuration type\n")
{
  return bgp_vty_return(vty, bgp_option_unset(BGP_OPT_CONFIG_CISCO));
}

/*------------------------------------------------------------------------------
 * Unsupported "no synchronization"
 */
DEFUN (no_synchronization,
       no_synchronization_cmd,
       "no synchronization",
       NO_STR
       "Perform IGP synchronization\n")
{
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Unsupported "no auto-summary"
 */
DEFUN (no_auto_summary,
       no_auto_summary_cmd,
       "no auto-summary",
       NO_STR
       "Enable automatic network number summarization\n")
{
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Unsupported and deprecated "neighbor version"
 */
DEFUN_DEPRECATED (neighbor_version,
                  neighbor_version_cmd,
                  NEIGHBOR_CMD "version (4|4-)",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Set the BGP version to match a neighbor\n"
                  "Neighbor's BGP version\n")
{
  return CMD_SUCCESS;
}

/*==============================================================================
 * BGP Instance configuration.
 */

/*------------------------------------------------------------------------------
 * Setting/Clearing a bgp configuration "flag"
 */
static cmd_ret_t
bgp_flag_modify_vty(vty vty, bgp_bc_setting_t bcs, bgp_sc_t bsc)
{
  bgp_inst bgp ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  return bgp_vty_return(vty, bgp_flag_modify(bgp, bcs, bsc)) ;
}

/*------------------------------------------------------------------------------
 * Setting/Clearing a bgp_config->c.flag
 */
static cmd_ret_t
bgp_af_flag_modify_vty(vty vty, qafx_t qafx, bgp_bafc_setting_t bafcs,
                                                                   bgp_sc_t bsc)
{
  bgp_inst bgp ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  return bgp_vty_return(vty, bgp_af_flag_modify(bgp, qafx, bafcs, bsc)) ;
}

/*------------------------------------------------------------------------------
 * "router bgp" commands.
 */
DEFUN_ATTR (router_bgp,
            router_bgp_cmd,
            "router bgp " CMD_AS_RANGE,
            ROUTER_STR
            BGP_STR
            AS_STR,
            CMD_ATTR_NODE + BGP_NODE)
{
  bgp_ret_t     ret;
  bgp_inst      bgp;
  as_t          as;
  chs_c         name ;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);

  name = (argc == 2) ? argv[1] : NULL ;

  ret = bgp_inst_get (&bgp, name, &as) ;
  if (ret == BGP_ERR_AS_MISMATCH)
    {
      vty_out (vty, "BGP is already running; AS is %u\n", as);
      ret = BGP_WARNING ;
    } ;

  if (ret == BGP_SUCCESS)
    {
      vty->node  = BGP_NODE ;
      vty->index = bgp ;
    } ;

  return bgp_vty_return(vty, ret) ;
}

ALIAS_ATTR (router_bgp,
            router_bgp_view_cmd,
            "router bgp " CMD_AS_RANGE " view WORD",
            ROUTER_STR
            BGP_STR
            AS_STR
            "BGP view\n"
            "view name\n",
            CMD_ATTR_NODE + BGP_NODE)

/*------------------------------------------------------------------------------
 * "no router bgp" commands.
 */
DEFUN (no_router_bgp,
       no_router_bgp_cmd,
       "no router bgp " CMD_AS_RANGE,
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR)
{
  as_t          as ;
  chs_c         name ;
  bgp_inst      bgp ;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[0], BGP_ASN_FIRST, BGP_ASN_LAST);

  name = (argc == 2) ? argv[1] : NULL ;

  bgp = bgp_inst_lookup_vty(vty, name, as) ;
  if (bgp == NULL)
    return CMD_WARNING;

  return bgp_vty_return(vty, bgp_inst_delete (bgp)) ;
}

ALIAS (no_router_bgp,
       no_router_bgp_view_cmd,
       "no router bgp " CMD_AS_RANGE " view WORD",
       NO_STR
       ROUTER_STR
       BGP_STR
       AS_STR
       "BGP view\n"
       "view name\n")

/*------------------------------------------------------------------------------
 * bgp router-id.
 */
static cmd_ret_t
do_bgp_router_id(vty vty, chs_c id_str, bgp_sc_t bsc)
{
  bgp_inst bgp ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  return bgp_vty_return(vty, bgp_router_id_set(bgp, id_str, bsc)) ;
}

DEFUN (bgp_router_id,
       bgp_router_id_cmd,
       "bgp router-id A.B.C.D",
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")
{
  return do_bgp_router_id(vty, argv[0], bsc_set_on) ;
}

DEFUN (no_bgp_router_id,
       no_bgp_router_id_cmd,
       "no bgp router-id",
       NO_STR
       BGP_STR
       "Override configured router identifier\n")
{
  /* TODO ... previously (a) rejected if not set, (b) rejected if not match !
   */
  return do_bgp_router_id(vty, (argc == 1) ? argv[0] : NULL, bsc_unset) ;
}

ALIAS (no_bgp_router_id,
       no_bgp_router_id_val_cmd,
       "no bgp router-id A.B.C.D",
       NO_STR
       BGP_STR
       "Override configured router identifier\n"
       "Manually configured router identifier\n")

/*------------------------------------------------------------------------------
 * BGP Cluster ID.
 *
 * Where the cluster-id is defined as an integer, that is handled by inet_aton()
 * as a single part address and stored in Network Order.
 */
static cmd_ret_t
do_bgp_cluster_id(vty vty, chs_c id_str, bgp_sc_t bsc)
{
  bgp_inst bgp ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  return bgp_vty_return(vty, bgp_cluster_id_set(bgp, id_str, bsc)) ;
}

DEFUN (bgp_cluster_id,
       bgp_cluster_id_cmd,
       "bgp cluster-id A.B.C.D",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")
{
  return do_bgp_cluster_id(vty, argv[0], bsc_set_on) ;
}

ALIAS (bgp_cluster_id,
       bgp_cluster_id32_cmd,
       "bgp cluster-id <1-4294967295>",
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id as 32 bit quantity\n")

DEFUN (no_bgp_cluster_id,
       no_bgp_cluster_id_cmd,
       "no bgp cluster-id",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n")
{
  return do_bgp_cluster_id(vty, (argc == 1) ? argv[0] : NULL, bsc_unset) ;
}

ALIAS (no_bgp_cluster_id,
       no_bgp_cluster_id_arg_cmd,
       "no bgp cluster-id A.B.C.D",
       NO_STR
       BGP_STR
       "Configure Route-Reflector Cluster-id\n"
       "Route-Reflector Cluster-id in IP address format\n")

/*------------------------------------------------------------------------------
 * BGP Confederation ID (ASN)
 *
 * Note that the confed_id may be the same as my_as (for one member of the
 * confederation, at least).
 */
static cmd_ret_t
do_bgp_confederation_identifier(vty vty, chs_c id_str, bgp_sc_t bsc)
{
  bgp_inst bgp ;
  as_t id;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  if (id_str != NULL)
    VTY_GET_INTEGER_RANGE ("AS", id, id_str, BGP_ASN_FIRST, BGP_ASN_LAST);
  else
    id = BGP_ASN_NULL ;

  return bgp_vty_return(vty, bgp_confed_id_set(bgp, id, bsc)) ;
}

DEFUN (bgp_confederation_identifier,
       bgp_confederation_identifier_cmd,
       "bgp confederation identifier " CMD_AS_RANGE,
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")
{
  return do_bgp_confederation_identifier(vty, argv[0], bsc_set_on) ;
}

DEFUN (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_cmd,
       "no bgp confederation identifier",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n")
{
  return do_bgp_confederation_identifier(vty, (argc == 1) ? argv[0] : NULL,
                                                                    bsc_unset) ;
}

ALIAS (no_bgp_confederation_identifier,
       no_bgp_confederation_identifier_arg_cmd,
       "no bgp confederation identifier " CMD_AS_RANGE,
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "AS number\n"
       "Set routing domain confederation AS\n")

/*------------------------------------------------------------------------------
 * Confederation peers
 */
static cmd_ret_t
do_bgp_confederation_peers(vty vty, uint n, chs_c const v[], bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  as_t      asn;
  uint      i ;
  bgp_ret_t ret ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  /* Scan the arguments for validity.
   */
  for (i = 0; i < n ; i++)
    VTY_GET_INTEGER_RANGE ("AS", asn, v[i], BGP_ASN_FIRST, BGP_ASN_LAST);

  /* Implement change
   */
  ret = BGP_SUCCESS ;

  for (i = 0; i < n ; i++)
    {
      bgp_ret_t reta ;

      VTY_GET_INTEGER_RANGE ("AS", asn, v[i], BGP_ASN_FIRST, BGP_ASN_LAST);

      reta = bgp_confed_peer_set(bgp, asn, bsc) ;

      if (ret == BGP_SUCCESS)
        ret = reta ;
    } ;

  return bgp_vty_return(vty, ret) ;
} ;

DEFUN (bgp_confederation_peers,
       bgp_confederation_peers_cmd,
       "bgp confederation peers .ASs",
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  return do_bgp_confederation_peers(vty, argc, &argv[0], bsc_set_on) ;
}

DEFUN (no_bgp_confederation_peers,
       no_bgp_confederation_peers_cmd,
       "no bgp confederation peers .ASs",
       NO_STR
       "BGP specific commands\n"
       "AS confederation parameters\n"
       "Peer ASs in BGP confederation\n"
       AS_STR)
{
  return do_bgp_confederation_peers(vty, argc, &argv[0], bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * BGP timers.
 *
 * Sets the default values for session keepalive and holdtime.  These values
 * are used where a peer does not have its own setting, or a peer is a member
 * of a group which does not have its own setting.
 *
 * NB: changing the default does not affect any existing sessions.
 */
static cmd_ret_t
do_bgp_timers(vty vty, chs_c k_str, chs_c h_str, bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  uint      keepalive, holdtime ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  if (k_str != NULL)
    VTY_GET_INTEGER_RANGE("keepalive", keepalive, k_str, 0, 65535) ;
  else
    keepalive = 0 ;

  if (h_str != NULL)
    {
      VTY_GET_INTEGER_RANGE("holdtime",  holdtime,  h_str, 0, 65535) ;
      if ((holdtime < 3) && (holdtime != 0) && (bsc == bsc_set_on))
        {
          vty_out(vty, "%% hold time must be 0 or 3 or greater\n") ;
          return CMD_WARNING;
        } ;
    }
  else
    holdtime  = 0 ;

  return bgp_vty_return(vty, bgp_timers_set (bgp, keepalive, holdtime, bsc)) ;
}

DEFUN (bgp_timers,
       bgp_timers_cmd,
       "timers bgp <0-65535> <0-65535>",
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  return do_bgp_timers(vty, argv[0], argv[1], bsc_set_on) ;
}

DEFUN (no_bgp_timers,
       no_bgp_timers_cmd,
       "no timers bgp",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n")
{
  return do_bgp_timers(vty, (argc > 0) ? argv[0] : NULL,
                            (argc > 1) ? argv[1] : NULL, bsc_unset) ;
}

ALIAS (no_bgp_timers,
       no_bgp_timers_arg_cmd,
       "no timers bgp <0-65535> <0-65535>",
       NO_STR
       "Adjust routing timers\n"
       "BGP timers\n"
       "Keepalive interval\n"
       "Holdtime\n")

/*------------------------------------------------------------------------------
 * Route Reflector client-to-client reflection.
 */
DEFUN (bgp_client_to_client_reflection,
       bgp_client_to_client_reflection_cmd,
       "bgp client-to-client reflection",
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  /* Note the reverse sense of the flag
   */
  return bgp_flag_modify_vty(vty, bcs_NO_CLIENT_TO_CLIENT, bsc_unset) ;
}

DEFUN (no_bgp_client_to_client_reflection,
       no_bgp_client_to_client_reflection_cmd,
       "no bgp client-to-client reflection",
       NO_STR
       "BGP specific commands\n"
       "Configure client to client route reflection\n"
       "reflection of routes allowed\n")
{
  /* Note the reverse sense of the flag
   */
  return bgp_flag_modify_vty(vty, bcs_NO_CLIENT_TO_CLIENT, bsc_set_on) ;
}

/*------------------------------------------------------------------------------
 * "bgp always-compare-med" configuration.
 */
DEFUN (bgp_always_compare_med,
       bgp_always_compare_med_cmd,
       "bgp always-compare-med",
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  return bgp_flag_modify_vty(vty, bcs_ALWAYS_COMPARE_MED, bsc_set_on) ;
}

DEFUN (no_bgp_always_compare_med,
       no_bgp_always_compare_med_cmd,
       "no bgp always-compare-med",
       NO_STR
       "BGP specific commands\n"
       "Allow comparing MED from different neighbors\n")
{
  return bgp_flag_modify_vty(vty, bcs_ALWAYS_COMPARE_MED, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp deterministic-med" configuration.
 */
DEFUN (bgp_deterministic_med,
       bgp_deterministic_med_cmd,
       "bgp deterministic-med",
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  return bgp_flag_modify_vty(vty, bcs_DETERMINISTIC_MED, bsc_set_on) ;
}

DEFUN (no_bgp_deterministic_med,
       no_bgp_deterministic_med_cmd,
       "no bgp deterministic-med",
       NO_STR
       "BGP specific commands\n"
       "Pick the best-MED path among paths advertised from the neighboring AS\n")
{
  return bgp_flag_modify_vty(vty, bcs_DETERMINISTIC_MED, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp graceful-restart" configuration.
 */
DEFUN (bgp_graceful_restart,
       bgp_graceful_restart_cmd,
       "bgp graceful-restart",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  return bgp_flag_modify_vty(vty, bcs_GRACEFUL_RESTART, bsc_set_on) ;
}

DEFUN (no_bgp_graceful_restart,
       no_bgp_graceful_restart_cmd,
       "no bgp graceful-restart",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n")
{
  return bgp_flag_modify_vty(vty, bcs_GRACEFUL_RESTART, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * bgp graceful-restart stalepath-time
 */
static cmd_ret_t
do_bgp_graceful_restart_stalepath_time(vty vty, chs_c st_str, bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  uint      stale_time ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  if (st_str != NULL)
    VTY_GET_INTEGER_RANGE("stalepath-time", stale_time, st_str, 1, 3600) ;
  else
    stale_time = 0 ;

  return bgp_vty_return(vty, bgp_stalepath_time_set(bgp, stale_time, bsc)) ;
}

DEFUN (bgp_graceful_restart_stalepath_time,
       bgp_graceful_restart_stalepath_time_cmd,
       "bgp graceful-restart stalepath-time <1-3600>",
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")
{
  return do_bgp_graceful_restart_stalepath_time(vty, argv[0], bsc_set_on) ;
}

DEFUN (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_cmd,
       "no bgp graceful-restart stalepath-time",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n")
{
  return do_bgp_graceful_restart_stalepath_time(vty,
                                       (argc > 0) ? argv[0] : NULL, bsc_unset) ;
}

ALIAS (no_bgp_graceful_restart_stalepath_time,
       no_bgp_graceful_restart_stalepath_time_val_cmd,
       "no bgp graceful-restart stalepath-time <1-3600>",
       NO_STR
       "BGP specific commands\n"
       "Graceful restart capability parameters\n"
       "Set the max time to hold onto restarting peer's stale paths\n"
       "Delay value (seconds)\n")

/*------------------------------------------------------------------------------
 * "bgp fast-external-failover" configuration.
 */
DEFUN (bgp_fast_external_failover,
       bgp_fast_external_failover_cmd,
       "bgp fast-external-failover",
       BGP_STR
       "Immediately reset session if a link to a directly"
                                         " connected external peer goes down\n")
{
  return bgp_flag_modify_vty(vty, bcs_NO_FAST_EXT_FAILOVER, bsc_set_on) ;
}

DEFUN (no_bgp_fast_external_failover,
       no_bgp_fast_external_failover_cmd,
       "no bgp fast-external-failover",
       NO_STR
       BGP_STR
       "Immediately reset session if a link to a directly"
                                         " connected external peer goes down\n")
{
  return bgp_flag_modify_vty(vty, bcs_NO_FAST_EXT_FAILOVER, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp enforce-first-as" configuration.
 */
DEFUN (bgp_enforce_first_as,
       bgp_enforce_first_as_cmd,
       "bgp enforce-first-as",
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  return bgp_flag_modify_vty(vty, bcs_ENFORCE_FIRST_AS, bsc_set_on) ;
}

DEFUN (no_bgp_enforce_first_as,
       no_bgp_enforce_first_as_cmd,
       "no bgp enforce-first-as",
       NO_STR
       BGP_STR
       "Enforce the first AS for EBGP routes\n")
{
  return bgp_flag_modify_vty(vty, bcs_ENFORCE_FIRST_AS, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp bestpath compare-routerid" configuration.
 */
DEFUN (bgp_bestpath_compare_router_id,
       bgp_bestpath_compare_router_id_cmd,
       "bgp bestpath compare-routerid",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  return bgp_flag_modify_vty(vty, bcs_COMPARE_ROUTER_ID, bsc_set_on) ;
}

DEFUN (no_bgp_bestpath_compare_router_id,
       no_bgp_bestpath_compare_router_id_cmd,
       "no bgp bestpath compare-routerid",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "Compare router-id for identical EBGP paths\n")
{
  return bgp_flag_modify_vty(vty, bcs_COMPARE_ROUTER_ID, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp bestpath as-path ignore" configuration.
 */
DEFUN (bgp_bestpath_aspath_ignore,
       bgp_bestpath_aspath_ignore_cmd,
       "bgp bestpath as-path ignore",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  return bgp_flag_modify_vty(vty, bcs_ASPATH_IGNORE, bsc_set_on) ;
}

DEFUN (no_bgp_bestpath_aspath_ignore,
       no_bgp_bestpath_aspath_ignore_cmd,
       "no bgp bestpath as-path ignore",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Ignore as-path length in selecting a route\n")
{
  return bgp_flag_modify_vty(vty, bcs_ASPATH_IGNORE, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp bestpath as-path confed" configuration.
 */
DEFUN (bgp_bestpath_aspath_confed,
       bgp_bestpath_aspath_confed_cmd,
       "bgp bestpath as-path confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets "
                                           "& sequences in selecting a route\n")
{
  return bgp_flag_modify_vty(vty, bcs_ASPATH_CONFED, bsc_set_on) ;
}

DEFUN (no_bgp_bestpath_aspath_confed,
       no_bgp_bestpath_aspath_confed_cmd,
       "no bgp bestpath as-path confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "AS-path attribute\n"
       "Compare path lengths including confederation sets "
                                           "& sequences in selecting a route\n")
{
  return bgp_flag_modify_vty(vty, bcs_ASPATH_CONFED, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * "bgp bestpath med" configuration.
 */
static bool
do_bgp_bestpath_option(chs_c what, chs_c opt1, chs_c opt2)
{
  if ((opt1 != NULL) && (strncmp(opt1, what, strlen(opt1)) == 0))
    return true ;

  if ((opt2 != NULL) && (strncmp(opt2, what, strlen(opt2)) == 0))
    return true ;

  return false ;
} ;

static cmd_ret_t
do_bgp_bestpath_med(vty vty, chs_c opt1, chs_c opt2, bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  bgp_ret_t ret1, ret2 ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  ret1 = ret2 = BGP_SUCCESS ;

  if (do_bgp_bestpath_option("confed", opt1, opt2))
    ret1 = bgp_flag_modify_vty(vty, bcs_MED_CONFED, bsc) ;

  if (do_bgp_bestpath_option("missing-as-worst", opt1, opt2))
    ret2 = bgp_flag_modify_vty(vty, bcs_MED_MISSING_AS_WORST, bsc) ;

  return bgp_vty_return(vty, (ret1 != BGP_SUCCESS) ? ret1 : ret2) ;
}

DEFUN (bgp_bestpath_med,
       bgp_bestpath_med_cmd,
       "bgp bestpath med (confed|missing-as-worst)",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  return do_bgp_bestpath_med(vty, argv[0], NULL, bsc_set_on) ;
}

DEFUN (bgp_bestpath_med2,
       bgp_bestpath_med2_cmd,
       "bgp bestpath med confed missing-as-worst",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  return do_bgp_bestpath_med(vty, "confed", "missing-as-worst", bsc_set_on) ;
}

ALIAS (bgp_bestpath_med2,
       bgp_bestpath_med3_cmd,
       "bgp bestpath med missing-as-worst confed",
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

DEFUN (no_bgp_bestpath_med,
       no_bgp_bestpath_med_cmd,
       "no bgp bestpath med (confed|missing-as-worst)",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  return do_bgp_bestpath_med(vty, argv[0], NULL, bsc_unset) ;
}

DEFUN (no_bgp_bestpath_med2,
       no_bgp_bestpath_med2_cmd,
       "no bgp bestpath med confed missing-as-worst",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Compare MED among confederation paths\n"
       "Treat missing MED as the least preferred one\n")
{
  return do_bgp_bestpath_med(vty, "confed", "missing-as-worst", bsc_unset) ;
}

ALIAS (no_bgp_bestpath_med2,
       no_bgp_bestpath_med3_cmd,
       "no bgp bestpath med missing-as-worst confed",
       NO_STR
       "BGP specific commands\n"
       "Change the default bestpath selection\n"
       "MED attribute\n"
       "Treat missing MED as the least preferred one\n"
       "Compare MED among confederation paths\n")

/*------------------------------------------------------------------------------
 * "no bgp default ipv4-unicast".
 */
DEFUN (bgp_default_ipv4_unicast,
       bgp_default_ipv4_unicast_cmd,
       "bgp default ipv4-unicast",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  return bgp_flag_modify_vty(vty, bcs_DEFAULT_IPV4, bsc_set_on) ;
}

DEFUN (no_bgp_default_ipv4_unicast,
       no_bgp_default_ipv4_unicast_cmd,
       "no bgp default ipv4-unicast",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "Activate ipv4-unicast for a peer by default\n")
{
  return bgp_flag_modify_vty(vty, bcs_DEFAULT_IPV4, bsc_set_off) ;
}

/*------------------------------------------------------------------------------
 * "bgp import-check" configuration.
 */
DEFUN (bgp_network_import_check,
       bgp_network_import_check_cmd,
       "bgp network import-check",
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  return bgp_flag_modify_vty(vty, bcs_IMPORT_CHECK, bsc_set_on) ;
}

DEFUN (no_bgp_network_import_check,
       no_bgp_network_import_check_cmd,
       "no bgp network import-check",
       NO_STR
       "BGP specific commands\n"
       "BGP network command\n"
       "Check BGP network route exists in IGP\n")
{
  return bgp_flag_modify_vty(vty, bcs_IMPORT_CHECK, bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * Default Local Preference
 */
static cmd_ret_t
do_bgp_default_local_preference(vty vty, chs_c lp_str, bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  uint      local_pref ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  if (lp_str != NULL)
    VTY_GET_INTEGER_RANGE("local preference", local_pref, lp_str, 0,
                                                                  UINT32_MAX) ;
  else
    local_pref = 0 ;

  return bgp_vty_return(vty, bgp_local_pref_set(bgp, local_pref, bsc)) ;
}

DEFUN (bgp_default_local_preference,
       bgp_default_local_preference_cmd,
       "bgp default local-preference <0-4294967295>",
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")
{
  return do_bgp_default_local_preference(vty, argv[0], bsc_set_on) ;
}

DEFUN (no_bgp_default_local_preference,
       no_bgp_default_local_preference_cmd,
       "no bgp default local-preference",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n")
{
  return do_bgp_default_local_preference(vty, (argc > 0) ? argv[0] : NULL,
                                                                    bsc_unset) ;
}

ALIAS (no_bgp_default_local_preference,
       no_bgp_default_local_preference_val_cmd,
       "no bgp default local-preference <0-4294967295>",
       NO_STR
       "BGP specific commands\n"
       "Configure BGP defaults\n"
       "local preference (higher=more preferred)\n"
       "Configure default local preference value\n")

/*------------------------------------------------------------------------------
 * Redistribute VTY commands.
 */
static cmd_ret_t
do_bgp_redistribute(vty vty, qafx_t qafx, chs_c type_str, redist_set_t what,
                                chs_c rmap_name, chs_c metric_str, bgp_sc_t bsc)
{
  bgp_inst  bgp ;
  uint      metric ;
  bgp_redist_type_t r_type ;

  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  r_type = proto_redistnum (get_qAFI(qafx), type_str) ;
  if ((r_type > redist_type_count)|| (r_type == ZEBRA_ROUTE_BGP))
    return bgp_vty_return(vty, BGP_ERR_INVALID_ROUTE_TYPE) ;

  if (metric_str != NULL)
    VTY_GET_INTEGER_RANGE("metric", metric, metric_str, 0, UINT32_MAX) ;
  else
    metric = 0 ;

  return bgp_vty_return(vty, bgp_redistribute_set(bgp, qafx, r_type, what,
                                                      rmap_name, metric, bsc)) ;
} ;

DEFUN (bgp_redistribute_ipv4,
       bgp_redistribute_ipv4_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                                                            redist_set_action,
                                                       NULL, NULL, bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv4_rmap,
       bgp_redistribute_ipv4_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                                          redist_set_action | redist_set_rmap,
                                                    argv[1], NULL, bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv4_metric,
       bgp_redistribute_ipv4_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                                        redist_set_action | redist_set_metric,
                                                    NULL, argv[1], bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv4_rmap_metric,
       bgp_redistribute_ipv4_rmap_metric_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD
                                        " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                      redist_set_action | redist_set_rmap | redist_set_metric,
                                                 argv[1], argv[2], bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv4_metric_rmap,
       bgp_redistribute_ipv4_metric_rmap_cmd,
       "redistribute " QUAGGA_IP_REDIST_STR_BGPD
                                        " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                      redist_set_action | redist_set_rmap | redist_set_metric,
                                                 argv[2], argv[1], bsc_set_on) ;
}

DEFUN (no_bgp_redistribute_ipv4,
       no_bgp_redistribute_ipv4_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD)
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                      redist_set_action | redist_set_rmap | redist_set_metric,
                                                        NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv4_rmap,
       no_bgp_redistribute_ipv4_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0], redist_set_rmap,
                                                        NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv4_metric,
       no_bgp_redistribute_ipv4_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                                                            redist_set_metric,
                                                        NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv4_rmap_metric,
       no_bgp_redistribute_ipv4_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD
                                        " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv4_unicast, argv[0],
                                          redist_set_rmap | redist_set_metric,
                                                        NULL, NULL, bsc_unset) ;
}

ALIAS (no_bgp_redistribute_ipv4_rmap_metric,
       no_bgp_redistribute_ipv4_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP_REDIST_STR_BGPD
                                        " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")

#ifdef HAVE_IPV6
DEFUN (bgp_redistribute_ipv6,
       bgp_redistribute_ipv6_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                                                            redist_set_action,
                                                       NULL, NULL, bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv6_rmap,
       bgp_redistribute_ipv6_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                                        redist_set_action | redist_set_rmap,
                                                  argv[1], NULL, bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv6_metric,
       bgp_redistribute_ipv6_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                                      redist_set_action | redist_set_metric,
                                                  NULL, argv[1], bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv6_rmap_metric,
       bgp_redistribute_ipv6_rmap_metric_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD
                                        " route-map WORD metric <0-4294967295>",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                    redist_set_action | redist_set_rmap | redist_set_metric,
                                               argv[1], argv[2], bsc_set_on) ;
}

DEFUN (bgp_redistribute_ipv6_metric_rmap,
       bgp_redistribute_ipv6_metric_rmap_cmd,
       "redistribute " QUAGGA_IP6_REDIST_STR_BGPD
                                        " metric <0-4294967295> route-map WORD",
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                    redist_set_action | redist_set_rmap | redist_set_metric,
                                               argv[2], argv[1], bsc_set_on) ;
}

DEFUN (no_bgp_redistribute_ipv6,
       no_bgp_redistribute_ipv6_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD,
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD)
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                    redist_set_action | redist_set_rmap | redist_set_metric,
                                                      NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv6_rmap,
       no_bgp_redistribute_ipv6_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0], redist_set_rmap,
                                                      NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv6_metric,
       no_bgp_redistribute_ipv6_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                                                          redist_set_metric,
                                                      NULL, NULL, bsc_unset) ;
}

DEFUN (no_bgp_redistribute_ipv6_rmap_metric,
       no_bgp_redistribute_ipv6_rmap_metric_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD
                                        " route-map WORD metric <0-4294967295>",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Route map reference\n"
       "Pointer to route-map entries\n"
       "Metric for redistributed routes\n"
       "Default metric\n")
{
  return do_bgp_redistribute(vty, qafx_ipv6_unicast, argv[0],
                                        redist_set_rmap | redist_set_metric,
                                                      NULL, NULL, bsc_unset) ;
}

ALIAS (no_bgp_redistribute_ipv6_rmap_metric,
       no_bgp_redistribute_ipv6_metric_rmap_cmd,
       "no redistribute " QUAGGA_IP6_REDIST_STR_BGPD " metric <0-4294967295> route-map WORD",
       NO_STR
       "Redistribute information from another routing protocol\n"
       QUAGGA_IP6_REDIST_HELP_STR_BGPD
       "Metric for redistributed routes\n"
       "Default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Address family selection.
 */
DEFUN_ATTR (address_family_ipv4,
            address_family_ipv4_cmd,
            "address-family ipv4",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_IPV4_NODE)
{
  vty->node = BGP_IPV4_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv4_safi_unicast,
            address_family_ipv4_safi_unicast_cmd,
            "address-family ipv4 unicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV4_NODE)
{
  vty->node = BGP_IPV4_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv4_safi_multicast,
            address_family_ipv4_safi_multicast_cmd,
            "address-family ipv4 multicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV4M_NODE)
{
  vty->node = BGP_IPV4M_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6,
            address_family_ipv6_cmd,
            "address-family ipv6",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_IPV6_NODE)
{
  vty->node = BGP_IPV6_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6_safi_unicast,
            address_family_ipv6_safi_unicast_cmd,
            "address-family ipv6 unicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV6_NODE)
{
  vty->node = BGP_IPV6_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_ipv6_safi_multicast,
            address_family_ipv6_safi_multicast_cmd,
            "address-family ipv6 multicast",
            "Enter Address Family command mode\n"
            "Address family\n"
            "Address Family modifier\n",
            CMD_ATTR_NODE + BGP_IPV6M_NODE)
{
  vty->node = BGP_IPV6M_NODE ;
  return CMD_SUCCESS;
}

DEFUN_ATTR (address_family_vpnv4,
            address_family_vpnv4_cmd,
            "address-family vpnv4",
            "Enter Address Family command mode\n"
            "Address family\n",
            CMD_ATTR_NODE + BGP_VPNV4_NODE)
{
  vty->node = BGP_VPNV4_NODE ;
  return CMD_SUCCESS;
}

ALIAS_ATTR (address_family_vpnv4,
       address_family_vpnv4_unicast_cmd,
       "address-family vpnv4 unicast",
       "Enter Address Family command mode\n"
       "Address family\n"
       "Address Family Modifier\n",
       CMD_ATTR_NODE + BGP_VPNV4_NODE)

DEFUN_ATTR (exit_address_family,
            exit_address_family_cmd,
            "exit-address-family",
            "Exit from Address Family configuration mode\n",
            CMD_ATTR_NODE + BGP_NODE)
{
  node_type_t node = vty->node ;

  if (   node == BGP_IPV4_NODE
      || node == BGP_IPV4M_NODE
      || node == BGP_VPNV4_NODE
      || node == BGP_IPV6_NODE
      || node == BGP_IPV6M_NODE)
    {
      vty->node = BGP_NODE ;
      return CMD_SUCCESS ;
    }
  else
    {
      vty_out(vty, "%% No address family to leave\n") ;
      return CMD_WARNING ;
    } ;
} ;

/*==============================================================================
 * Peer and Peer-Group Creation/Deletion and Address Family Creation/Deletion
 *
 * Where a peer does not already exist, it is created by:
 *
 *   1) neighbor <ip> remote-as 99
 *
 *   2) neighbor <ip> peer-group xx
 *
 *      provided that the peer-group has a remote-as defined for it, and
 *      provided is not in a specific address family.
 *
 *      This binds the group for its general configuration settings. XXX
 *
 * Where a peer already exists:
 *
 *   1) neighbor <ip> remote-as 99
 *
 *      change the peer's AS -- except in a small number of cases where that
 *      conflicts with other existing settings.
 *
 *   2) neighbor <ip> peer-group xx
 *
 *      binds peer to the peer group:
 *
 *        * if no address family is selected, binds just for the general
 *          settings.
 *
 *        * if an address family is selected, binds for the address family
 *          only, and only for the address family settings.
 *
 *      Note that binding for an address family implicitly activates it !
 *
 *      NB: unlike previous Quagga, this version allows a peer to be bound
 *          to different groups:
 *
 *            a) at the general configuration level.
 *
 *            b) in each address family
 *
 *      To support existing configuration files, "BGP_OPT_LEGACY_GROUPS" will:
 *
 *        * activate IPv4/Unicast when binding the general configuration
 *          settings (ie when no address family is selected).
 *
 *        * bind the general configuration when binding an address family,
 *
 *      When outputting a configuration file the new code generates explicit
 *      'activate' and 'peer-group' commands, which state the configuration in
 *      "new" terms.  Reading that with "BGP_OPT_LEGACY_GROUPS" will bind
 *      the peer-group to the same address families as before.
 *
 *      NB: the legacy code is a bit of a mess.  If IPv4/Unicast is configured,
 *          and is set to use the group, then all is well.
 *
 *          Otherwise, the group's "general" configuration is applied when the
 *          group is bound to the address family... which has different
 *          semantics to binding before all other peer configuration settings
 *          are made.
 *
 *          So: BEWARE... the semantics of groups and group-binding is NOT THE
 *                        SAME AS IN LEGACY -- even if BGP_OPT_LEGACY_GROUPS !!
 *
 *          This code does NOT attempt to preserve old semantics for groups.
 *          The objective of BGP_OPT_LEGACY_GROUPS is simply to ensure that
 *          when reading an old configuration: (a) a peer-group bound to (say)
 *          IPv6/Unicast but not IPv4/Unicast is bound to the general
 *          configuration as well, and (b) that implicit activation of and
 *          binding to IPv4/Unicast is preserved.
 *
 *   3) no neighbor <ip> peer-group
 *
 *      unbinds peer from the peer group -- retains group's ASN if that was set.
 *
 *   4) no neighbor <ip>
 *
 *      dismantles the peer altogether
 *
 * Where a group does not already exist, it is created by:
 *
 *   1) neighbor <group> peer-group
 *
 * Where a group exists:
 *
 *   1) neighbor <group> remote-as 99
 *
 *      will set it to have an ASN... provided that either it has no members,
 *      or all members have the same ASN and this does not change to or from
 *      iBGP.
 *
 *   2) no neighbor <group> remote-as
 *
 *      will unset the ASN, and set all group members to have the ASN
 *      themselves.
 *
 *   3) no neighbor <group> peer-group
 *
 *      dismantles the group and unbinds all group members.
 */

/*------------------------------------------------------------------------------
 * neighbor remote-as
 *
 * neighbor <IP> remote-as      -- creates neighbor or changes ASN
 *
 * neighbor <group> remote-as   -- gives group a remote-as setting, which is
 *                                 powerful magic.
 *
 * no neighbor <IP>             -- deletes neighbor (if exists)
 *
 * no neighbor <group>          -- deletes group (if exists)
 *
 * no neighbor <IP> remote-as   -- deletes neighbor (if exists)
 *                                 ignoring the ASN
 */
DEFUN (neighbor_remote_as,
       neighbor_remote_as_cmd,
       NEIGHBOR_CMD2 "remote-as " CMD_AS_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a BGP neighbor\n"
       AS_STR)
{
  chs_c         p_str ;
  as_t          as;
  bgp_inst      bgp ;
  sockunion_t   su[1] ;
  bgp_ret_t     ret;
  bgp_peer      peer ;

  p_str = argv[0] ;

  VTY_GET_INTEGER_RANGE ("AS", as, argv[1], BGP_ASN_FIRST, BGP_ASN_LAST);

  /* We hand-craft this, because for the peer we do something different
   * depending on whether it exists, or not.
   */
  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  ret = bgp_peer_sex(argv[0], su, bpog_peer_or_group) ;

  switch (ret)
    {
      case BGP_OK_PEER_IP:
        peer = bgp_peer_lookup_su(bgp, su);

        if (peer != NULL)
          ret = bgp_peer_as_set(peer, as, bsc_set_on) ;
        else
          {
            ret = bgp_peer_create_peer(bgp, su, as, NULL) ;

            if ((ret == BGP_SUCCESS) && bgp_peer_ipv4_default(peer))
              {
                /* Here we do the legacy implicit IPv4/Unicast stuff.
                 */
                peer = bgp_peer_lookup_su(bgp, su);
                ret  = bgp_peer_af_set(peer, qafx_ipv4_unicast, bsc_set_on) ;
              } ;
          } ;

#if 0
          if (peer_address_self_check (su))
            {
              vty_out (vty, "%% Cannot configure the"
                                              " local system as neighbor\n") ;
              return CMD_WARNING;
            } ;
#endif
        break ;

      case BGP_OK_GROUP_NAME:
        peer = bgp_group_lookup_vty(vty, p_str) ;
        if (peer == NULL)
          return CMD_WARNING ;

        ret = bgp_peer_as_set(peer, as, bsc_set_on) ;
        break ;

      default:
        break ;
    } ;

#if 0
  switch (ret)
    {
      case BGP_ERR_PEER_GROUP_MEMBER:
        vty_out (vty, "%% Peer-group AS %u.  "
                   "Cannot configure remote-as for member\n", as);
        return CMD_WARNING;

      case BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT:
        vty_out (vty, "%% The AS# can not be changed from %u to %s, "
            "peer-group members must be all internal or all external\n",
                                                                    as, as_str);
        return CMD_WARNING;

      default:
        break ;
    } ;
#endif

  return bgp_vty_return (vty, ret);
}

/*------------------------------------------------------------------------------
 * no neighbor <IP>
 *
 * Destroy the neighbor.
 */
DEFUN (no_neighbor,
       no_neighbor_cmd,
       NO_NEIGHBOR_CMD2,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2)
{
  chs_c       p_str ;
  bgp_inst    bgp ;
  sockunion_t su[1] ;
  bgp_peer    peer ;
  bgp_ret_t   ret ;

  p_str = argv[0] ;

  /* We hand-craft this, because it is the one time we don't mind if the
   * peer or the peer-group is not there.
   */
  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  ret = bgp_peer_sex(p_str, su, bpog_peer_or_group) ;

  switch (ret)
    {
      case BGP_OK_PEER_IP:
        peer = bgp_peer_lookup_su(bgp, su);
        if (peer == NULL)
          return CMD_SUCCESS ;
        break ;

      case BGP_OK_GROUP_NAME:
        peer = bgp_peer_lookup_group(bgp, p_str) ;
        if (peer == NULL)
          return CMD_SUCCESS ;
        break ;

      default:
        return bgp_vty_return(vty, ret) ;
    } ;

   return bgp_vty_return(vty, bgp_peer_delete(peer)) ;
} ;

ALIAS (no_neighbor,
       no_neighbor_remote_as_cmd,
       NO_NEIGHBOR_CMD "remote-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Specify a BGP neighbor\n"
       AS_STR)

/*------------------------------------------------------------------------------
 * neighbor peer-group                  -- group creation
 * no neighbor peer-group               -- group destruction
 * no neighbor peer-group remote-as     -- remove remote-as from group, magic !
 */
DEFUN (neighbor_peer_group,
       neighbor_peer_group_cmd,
       "neighbor WORD peer-group",
       NEIGHBOR_STR
       "peer-group name\n"
       "Configure peer-group\n")
{
  chs_c       g_str ;
  bgp_inst    bgp ;
  sockunion_t su[1] ;
  bgp_peer    peer ;
  bgp_ret_t   ret ;

  g_str = argv[0] ;

  /* We hand-craft this, because we only handle a group name, here, and
   * if the group does not exist, we create it, but if it does exist, that's
   * fine.
   */
  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  ret = bgp_peer_sex(g_str, su, bpog_group_name) ;

  if (ret == BGP_OK_GROUP_NAME)
    {
      peer = bgp_peer_lookup_group(bgp, g_str);
      if (peer != NULL)
        ret = BGP_SUCCESS ;
      else
        {
          ret = bgp_peer_create_group(bgp, g_str) ;

          if ((ret == BGP_SUCCESS) && bgp_peer_ipv4_default(peer))
            {
              /* Here we do the legacy implicit IPv4/Unicast stuff.
               */
              peer = bgp_peer_lookup_group(bgp, g_str) ;
              ret  = bgp_peer_af_set(peer, qafx_ipv4_unicast, bsc_set_on) ;
            } ;
        } ;
    } ;

  return bgp_vty_return(vty, ret) ;
} ;

/*------------------------------------------------------------------------------
 * no neighbor <group-name> peer-group
 *
 * Destroy the group and unbind it everywhere.
 *
 * Note that for BGP_OPT_LEGACY_GROUPS both the general configuration and the
 * address family(ies) are bound to the group, and will all be unbound.
 */
DEFUN (no_neighbor_peer_group,
       no_neighbor_peer_group_cmd,
       "no neighbor WORD peer-group",
       NO_STR
       NEIGHBOR_STR
       "peer-group name\n"
       "Configure peer-group\n")
{
  bgp_inst    bgp ;
  chs_c       g_str ;
  sockunion_t su[1] ;
  bgp_peer    peer ;
  bgp_ret_t   ret ;

  g_str = argv[0] ;

  /* We hand-craft this, because we only handle a group name, here, and
   * if the group does exist, we delete it, but if it does not exist, that's
   * fine.
   */
  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  ret = bgp_peer_sex(argv[0], su, bpog_group_name) ;

   if (ret == BGP_OK_GROUP_NAME)
     {
       peer = bgp_peer_lookup_group(bgp, g_str);
       if (peer != NULL)
         ret = bgp_peer_delete(peer) ;
       else
         ret = BGP_SUCCESS ;
     } ;

   return bgp_vty_return(vty, ret) ;
} ;

/*------------------------------------------------------------------------------
 * no neighbor <group-name> remote-as [99]
 *
 * Drops just the remote-as setting.  All group-members become the owners of
 * their current remote-as setting.  This has no effect on the group-members,
 * other than that.
 */
DEFUN (no_neighbor_peer_group_remote_as,
       no_neighbor_peer_group_remote_as_as_cmd,
       "no neighbor WORD remote-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       "peer-group name\n"
       "Set neighbor AS\n"
       AS_STR)
{
  chs_c     g_str ;
  bgp_peer  peer ;
  as_t      as ;

  g_str = argv[0] ;

  peer = bgp_group_lookup_vty(vty, g_str);
  if (peer == NULL)
    return CMD_WARNING ;

  if (argc > 1)
    VTY_GET_INTEGER_RANGE ("AS", as, argv[1], BGP_ASN_FIRST, BGP_ASN_LAST);
  else
    as = BGP_ASN_NULL ;

  return bgp_vty_return(vty, bgp_peer_as_set(peer, as, bsc_unset));
} ;

ALIAS (no_neighbor_peer_group_remote_as,
       no_neighbor_peer_group_remote_as_cmd,
       "no neighbor WORD remote-as",
       NO_STR
       NEIGHBOR_STR
       "peer-group name\n"
       "setting neighbor AS\n")

/*------------------------------------------------------------------------------
 * neighbor <IP> peer-group <group-name>
 *
 * Add given peer to the given peer-group in the current afi/safi.
 *
 *   * if the peer does not exist, will create it iff the group has an AS
 *
 *     ... provided we do not have an address family selected !!
 *
 *   * if the peer exists, but is not activated for the afi/safi, this
 *     implicitly activates it -- *after* updating its configuration.
 *
 *     If no afi/safi is selected, binds the general configuration to it, and
 *     in BGP_OPT_LEGACY_GROUPS state will activate and bind IPv4/Unicast.
 */
DEFUN (neighbor_set_peer_group,
       neighbor_set_peer_group_cmd,
       NEIGHBOR_CMD "peer-group WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "peer-group name\n")
{
  chs_c         p_str, g_str ;
  bgp_inst      bgp ;
  sockunion_t   su[1] ;
  bgp_ret_t     ret;
  bgp_peer      peer, group ;

  p_str = argv[0] ;
  g_str = argv[1] ;

  /* First, find your bgp and group.
   */
  bgp = bgp_node_inst(vty) ;
  if (bgp == NULL)
    return CMD_WARNING ;

  group = bgp_group_lookup_vty(vty, g_str) ;
  if (group == NULL)
    return CMD_WARNING ;                /* group not found !    */

  /* Then, depending on whether the peer exist or not, bind or (if group has
   * a remote-as) create and bind.
   */
  ret = bgp_peer_sex(p_str, su, bpog_peer_ip) ;
  if (ret == BGP_OK_PEER_IP)
    {
      qafx_t qafx ;

      peer = bgp_peer_lookup_su(bgp, su);
      qafx = bgp_node_qafx_explicit(vty) ;

      ret = BGP_SUCCESS ;
      if (peer != NULL)
        {
          /* Wish to bind an existing peer to the given group, either in
           * general or in the given qafx.
           *
           * If BGP_OPT_LEGACY_GROUPS we treat no address family selected as
           * IPv4/Unicast.
           *
           * After a general bind, this will implicitly activate the qafx and
           * bind the group to it.
           */
          if (!bgp_option_check(BGP_OPT_LEGACY_GROUPS))
            {
              /* If no address family is selected, then bind the peer to the
               * general group configuration.
               *
               * Otherwise, will activate and bind the address family, below.
               */
              if (qafx == qafx_none)
                ret = bgp_peer_group_set(peer, group, qafx_none, bsc_set_on) ;
            }
          else
            {
              /* Legacy handling.
               *
               * Bind the peer to the general group configuration in any event.
               *
               * Then, if no address family is selected, set IPv4/Unicast.
               *
               * Will then activate and bind the address family, below.
               */
              qafx = qafx_ipv4_unicast ;
              ret = bgp_peer_group_set(peer, group, qafx_none, bsc_set_on) ;
            } ;
        }
      else
        {
          /* Wish to bind a non-existent peer to the given group.
           *
           * We refuse this if we are in an address family
           */
          if (qafx != qafx_none)
            ret = BGP_ERR_AF_NOT_CONFIGURED ;
          else
            {
              ret = bgp_peer_create_peer(bgp, su, BGP_ASN_NULL, group) ;

              if (bgp_peer_ipv4_default(peer))
                {
                  /* Prepare to do implicit IPv4/Unicast stuff.
                   */
                  peer = bgp_peer_lookup_su(bgp, su) ;
                  qafx = qafx_ipv4_unicast ;
                } ;
            } ;
        } ;

      /* Now do the implicit activation of the address family, and bind the
       * group to it, if required.
       */
      if ((ret == BGP_SUCCESS) && (qafx != qafx_none))
        {
          if (!pcs_qafx_config(peer->c, qafx))
            ret = bgp_peer_af_set(peer, qafx, bsc_set_on) ;

          if (ret == BGP_SUCCESS)
            ret = bgp_peer_group_set(peer, group, qafx, bsc_set_on) ;
        } ;
    } ;

  return bgp_vty_return (vty, ret);
}

/*------------------------------------------------------------------------------
 * no neighbor <IP> peer-group <group-name>
 *
 * Remove given peer from the given peer-group in the current afi/safi.
 *
 * If no afi/safi is selected, unbinds the general configuration.
 *
 * No effect if nothing is bound.
 *
 * Does nothing if afi/safi is not configured for the peer.
 *
 * For BGP_OPT_LEGACY_GROUPS:
 *
 *   * treat no address family as IPv4/Unicast and unbind that
 *
 *   * if after unbind, no address families are bound t the group, unbind
 *     the general configuration.
 */
DEFUN (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_group_cmd,
       NO_NEIGHBOR_CMD "peer-group WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n"
       "peer-group name\n")
{
  chs_c     p_str ;
  bgp_peer  peer ;
  qafx_t    qafx ;
  bgp_ret_t ret ;

  p_str = argv[0] ;

  peer = bgp_peer_lookup_vty(vty, p_str);
  if (peer == NULL)
    return CMD_WARNING ;

  if (argc > 1)
    {
      sockunion_t su[1] ;
      bgp_ret_t ret ;

      ret = bgp_peer_sex(argv[0], su, bpog_group_name) ;

      if (ret != BGP_OK_GROUP_NAME)
        bgp_vty_return(vty, ret) ;
    } ;

  qafx = bgp_node_qafx_explicit(vty) ;

  if ((qafx == qafx_none) && bgp_option_check(BGP_OPT_LEGACY_GROUPS))
    qafx = qafx_ipv4_unicast ;

  ret = bgp_peer_group_set(peer, NULL, qafx, bsc_unset) ;

  if ((ret == BGP_SUCCESS) && bgp_option_check(BGP_OPT_LEGACY_GROUPS))
    {
      bool used ;

      used = false ;
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_paf_config pafc ;

          if (!pcs_qafx_config(peer->c, qafx))
            continue ;

          pafc = peer->c->afc[qafx] ;
          qassert(pafc != NULL) ;
          if (pafc == NULL)
            continue ;

          if (pafc->ctype == BGP_CFT_MEMBER)
            {
              qassert(pafc->gafc != NULL) ;
              used = true ;
              break ;
            } ;

          qassert(pafc->gafc == NULL) ;
        } ;

      if (!used)
        ret = bgp_peer_group_set(peer, NULL, qafx_none, bsc_unset) ;
    } ;

  return bgp_vty_return(vty, ret) ;
} ;

ALIAS (no_neighbor_set_peer_group,
       no_neighbor_set_peer_group_cmd,
       NO_NEIGHBOR_CMD "peer-group",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Member of the peer-group\n")

/*------------------------------------------------------------------------------
 * Activate and de-activate peer or peer-group in the current afi/safi.
 */
static cmd_ret_t
do_neighbor_activate(vty vty, chs_c p_str, qafx_t qafx, bgp_sc_t bsc)
{
  bgp_peer peer;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  return bgp_vty_return(vty, bgp_peer_af_set(peer, qafx, bsc)) ;
} ;

DEFUN (neighbor_activate,
       neighbor_activate_cmd,
       NEIGHBOR_CMD2 "activate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  return do_neighbor_activate(vty, argv[0], bgp_node_qafx(vty), bsc_set_on) ;
}

DEFUN (no_neighbor_activate,
       no_neighbor_activate_cmd,
       NO_NEIGHBOR_CMD2 "activate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enable the Address Family for this Neighbor\n")
{
  return do_neighbor_activate(vty, argv[0], bgp_node_qafx(vty), bsc_set_on) ;
}

/*==============================================================================
 * Peer and Peer-Group Configuration
 */

/*------------------------------------------------------------------------------
 * Set or clear pcs_xxx setting which is a simple on/off flag.
 */
static cmd_ret_t
bgp_peer_flag_modify_vty(vty vty, chs_c p_str, bgp_pc_setting_t pcs,
                                                                  bgp_sc_t bsc)
{
  bgp_peer      peer ;

  qassert(pcs < pcs_count_of_flags) ;

  peer = bgp_peer_or_group_lookup_vty(vty, p_str);
  if (peer == NULL)
    return CMD_WARNING ;

  return bgp_vty_return(vty, bgp_peer_flag_modify(peer, pcs, bsc));
}

/*------------------------------------------------------------------------------
 * Set or clear pafcs_xxx setting which is a simple on/off flag.
 */
static cmd_ret_t
bgp_peer_af_flag_modify_vty(vty vty, chs_c p_str, qafx_t qafx,
                                         bgp_pafc_setting_t pafcs, bgp_sc_t bsc)
{
  bgp_peer peer ;

  qassert(pafcs < pafcs_count_of_flags) ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING ;

  return bgp_vty_return (vty, bgp_peer_af_flag_modify(peer, qafx, pafcs, bsc));
} ;

/*------------------------------------------------------------------------------
 * neighbor route-server-client
 */
DEFUN (neighbor_route_server_client,
       neighbor_route_server_client_cmd,
       NEIGHBOR_CMD2 "route-server-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                             pafcs_RSERVER_CLIENT, bsc_set_on) ;
} ;

DEFUN (no_neighbor_route_server_client,
       no_neighbor_route_server_client_cmd,
       NO_NEIGHBOR_CMD2 "route-server-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Server client\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                              pafcs_RSERVER_CLIENT, bsc_unset) ;
} ;

/*------------------------------------------------------------------------------
 * neighbor local-as
 */
static cmd_ret_t
do_neighbor_local_as(vty vty, chs_c p_str, chs_c as_str, bool no_prepend)
{
  bgp_peer      peer;
  bgp_sc_t      bsc ;
  as_t          local_as ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (as_str != NULL)
    {
      local_as = strtoul_s(as_str) ;
      bsc  = (local_as != BGP_ASN_NULL) ? bsc_set_on : bsc_set_off ;
    }
  else
    {
      local_as = BGP_ASN_NULL ;
      bsc      = bsc_unset ;
    } ;

  return bgp_vty_return (vty,
                      bgp_peer_local_as_set (peer, local_as, no_prepend, bsc) );
} ;

DEFUN (neighbor_local_as,
       neighbor_local_as_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")
{
  return do_neighbor_local_as(vty, argv[0], argv[1], false /* !no-prepend */) ;
}

DEFUN (neighbor_local_as_no_prepend,
       neighbor_local_as_no_prepend_cmd,
       NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")
{
  return do_neighbor_local_as(vty, argv[0], argv[1], true /* no-prepend */) ;
}

DEFUN (no_neighbor_local_as,
       no_neighbor_local_as_cmd,
       NO_NEIGHBOR_CMD2 "local-as",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n")
{
  return do_neighbor_local_as(vty, argv[0], NULL, false /* !no-prepend */) ;
}

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE,
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n")

ALIAS (no_neighbor_local_as,
       no_neighbor_local_as_val2_cmd,
       NO_NEIGHBOR_CMD2 "local-as " CMD_AS_RANGE " no-prepend",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify a local-as number\n"
       "AS number used as local AS\n"
       "Do not prepend local-as to updates from ebgp peers\n")

/*------------------------------------------------------------------------------
 * neighbor password
 */
static cmd_ret_t
do_neighbor_password(vty vty, chs_c p_str, chs_c password)
{
  bgp_peer      peer;
  bgp_sc_t      bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (password != NULL)
    bsc  = (password[0] != '\0') ? bsc_set_on : bsc_set_off ;
  else
    bsc  = bsc_unset ;

  return bgp_vty_return (vty, bgp_peer_password_set (peer, password, bsc) );
}
DEFUN (neighbor_password,
       neighbor_password_cmd,
       NEIGHBOR_CMD2 "password LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n"
       "The password\n")
{
  return do_neighbor_password(vty, argv[0], argv[1]) ;
}

DEFUN (no_neighbor_password,
       no_neighbor_password_cmd,
       NO_NEIGHBOR_CMD2 "password",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set a password\n")
{
  return do_neighbor_password(vty, argv[0], NULL) ;
}

/*------------------------------------------------------------------------------
 * neighbor passive.
 */
DEFUN (neighbor_passive,
       neighbor_passive_cmd,
       NEIGHBOR_CMD2 "passive",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_PASSIVE, bsc_set_on);
}

DEFUN (no_neighbor_passive,
       no_neighbor_passive_cmd,
       NO_NEIGHBOR_CMD2 "passive",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Don't send open messages to this neighbor\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_PASSIVE, bsc_unset);
}

/*------------------------------------------------------------------------------
 * Deprecated neighbor capability route-refresh.
 */
DEFUN_DEPRECATED (neighbor_capability_route_refresh,
                  neighbor_capability_route_refresh_cmd,
                  NEIGHBOR_CMD2 "capability route-refresh",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR2
                  "Advertise capability to the peer\n"
                  "Advertise route-refresh capability to this neighbor\n")
{
  return CMD_SUCCESS;
}

DEFUN_DEPRECATED (no_neighbor_capability_route_refresh,
                  no_neighbor_capability_route_refresh_cmd,
                  NO_NEIGHBOR_CMD2 "capability route-refresh",
                  NO_STR
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR2
                  "Advertise capability to the peer\n"
                  "Advertise route-refresh capability to this neighbor\n")
{
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * neighbor capability dynamic.
 */
DEFUN_DEPRECATED (neighbor_capability_dynamic,
       neighbor_capability_dynamic_cmd,
       NEIGHBOR_CMD2 "capability dynamic",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DYNAMIC_CAPABILITY,
                                                                    bsc_set_on);
}

DEFUN_DEPRECATED (no_neighbor_capability_dynamic,
       no_neighbor_capability_dynamic_cmd,
       NO_NEIGHBOR_CMD2 "capability dynamic",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise dynamic capability to this neighbor\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DYNAMIC_CAPABILITY,
                                                                     bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor dont-capability-negotiate
 */
DEFUN (neighbor_dont_capability_negotiate,
       neighbor_dont_capability_negotiate_cmd,
       NEIGHBOR_CMD2 "dont-capability-negotiate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DONT_CAPABILITY,
                                                                    bsc_set_on);
}

DEFUN (no_neighbor_dont_capability_negotiate,
       no_neighbor_dont_capability_negotiate_cmd,
       NO_NEIGHBOR_CMD2 "dont-capability-negotiate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Do not perform capability negotiation\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DONT_CAPABILITY,
                                                                     bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor capability orf prefix-list.
 */
static cmd_ret_t
peer_orfs_set_vty (vty vty, const char* plist_name, qafx_t qafx,
                                                        bgp_orf_cap_bits_t orfs)
{
  // TODO wire orfs back in
  vty_out(vty, "%% Not currently wired up") ;
  return CMD_WARNING ;
}

static cmd_ret_t
peer_orfs_unset_vty (vty vty, const char* plist_name, qafx_t qafx,
                                                        bgp_orf_cap_bits_t orfs)
{
  // TODO wire orfs back in
  vty_out(vty, "%% Not currently wired up") ;
  return CMD_WARNING ;
}

DEFUN (neighbor_capability_orf_prefix,
       neighbor_capability_orf_prefix_cmd,
       NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  bgp_orf_cap_bits_t orfs ;

  if (strncmp (argv[1], "s", 1) == 0)
    orfs = ORF_SM ;
  else if (strncmp (argv[1], "r", 1) == 0)
    orfs = ORF_RM ;
  else if (strncmp (argv[1], "b", 1) == 0)
    orfs = ORF_SM | ORF_RM ;
  else
    return CMD_WARNING;

  return peer_orfs_set_vty (vty, argv[0], bgp_node_qafx(vty), orfs);
}

DEFUN (no_neighbor_capability_orf_prefix,
       no_neighbor_capability_orf_prefix_cmd,
       NO_NEIGHBOR_CMD2 "capability orf prefix-list (both|send|receive)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Advertise capability to the peer\n"
       "Advertise ORF capability to the peer\n"
       "Advertise prefixlist ORF capability to this neighbor\n"
       "Capability to SEND and RECEIVE the ORF to/from this neighbor\n"
       "Capability to RECEIVE the ORF from this neighbor\n"
       "Capability to SEND the ORF to this neighbor\n")
{
  bgp_orf_cap_bits_t orfs ;

  if (strncmp (argv[1], "s", 1) == 0)
    orfs = ORF_SM;
  else if (strncmp (argv[1], "r", 1) == 0)
    orfs = ORF_RM;
  else if (strncmp (argv[1], "b", 1) == 0)
    orfs = ORF_SM | ORF_RM;
  else
    return CMD_WARNING;

  return peer_orfs_unset_vty (vty, argv[0], bgp_node_qafx(vty), orfs);
}

/*------------------------------------------------------------------------------
 * neighbor next-hop-self.
 */
DEFUN (neighbor_nexthop_self,
       neighbor_nexthop_self_cmd,
       NEIGHBOR_CMD2 "next-hop-self",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty (vty, argv[0], bgp_node_qafx(vty),
                                                pafcs_NEXTHOP_SELF, bsc_set_on);
}

DEFUN (no_neighbor_nexthop_self,
       no_neighbor_nexthop_self_cmd,
       NO_NEIGHBOR_CMD2 "next-hop-self",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disable the next hop calculation for this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty (vty, argv[0], bgp_node_qafx(vty),
                                                 pafcs_NEXTHOP_SELF, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor remove-private-AS.
 */
DEFUN (neighbor_remove_private_as,
       neighbor_remove_private_as_cmd,
       NEIGHBOR_CMD2 "remove-private-AS",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private AS number from outbound updates\n")
{
  return bgp_peer_af_flag_modify_vty (vty, argv[0], bgp_node_qafx(vty),
                                           pafcs_REMOVE_PRIVATE_AS, bsc_set_on);
}

DEFUN (no_neighbor_remove_private_as,
       no_neighbor_remove_private_as_cmd,
       NO_NEIGHBOR_CMD2 "remove-private-AS",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Remove private AS number from outbound updates\n")
{
  return bgp_peer_af_flag_modify_vty (vty, argv[0], bgp_node_qafx(vty),
                                            pafcs_REMOVE_PRIVATE_AS, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor send-community.
 */
DEFUN (neighbor_send_community,
       neighbor_send_community_cmd,
       NEIGHBOR_CMD2 "send-community",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                              pafcs_SEND_COMMUNITY, bsc_set_on);
}

DEFUN (no_neighbor_send_community,
       no_neighbor_send_community_cmd,
       NO_NEIGHBOR_CMD2 "send-community",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                               pafcs_SEND_COMMUNITY, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor send-community extended.
 */
static cmd_ret_t
do_neighbor_send_community_type(vty vty, chs_c p_str, char what,
                                                      qafx_t qafx, bgp_sc_t bsc)
{
  bgp_ret_t ret ;

  ret = BGP_SUCCESS ;

  if ((ret == BGP_SUCCESS) && ((what == 'b') || (what == 's')))
    ret = bgp_peer_af_flag_modify_vty(vty, p_str, qafx,
                                                    pafcs_SEND_COMMUNITY, bsc) ;

  if ((ret == BGP_SUCCESS) && ((what == 'b') || (what == 'e')))
    ret = bgp_peer_af_flag_modify_vty(vty, p_str, qafx,
                                                pafcs_SEND_EXT_COMMUNITY, bsc) ;

  return bgp_vty_return (vty, ret);
} ;

DEFUN (neighbor_send_community_type,
       neighbor_send_community_type_cmd,
       NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  return do_neighbor_send_community_type(vty, argv[0], argv[1][0],
                                               bgp_node_qafx(vty), bsc_set_on) ;
}

DEFUN (no_neighbor_send_community_type,
       no_neighbor_send_community_type_cmd,
       NO_NEIGHBOR_CMD2 "send-community (both|extended|standard)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Send Community attribute to this neighbor\n"
       "Send Standard and Extended Community attributes\n"
       "Send Extended Community attributes\n"
       "Send Standard Community attributes\n")
{
  return do_neighbor_send_community_type(vty, argv[0], argv[1][0],
                                                bgp_node_qafx(vty), bsc_unset) ;
}

/*------------------------------------------------------------------------------
 * neighbor soft-reconfig.
 */
DEFUN (neighbor_soft_reconfiguration,
       neighbor_soft_reconfiguration_cmd,
       NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                               pafcs_SOFT_RECONFIG, bsc_set_on);
}

DEFUN (no_neighbor_soft_reconfiguration,
       no_neighbor_soft_reconfiguration_cmd,
       NO_NEIGHBOR_CMD2 "soft-reconfiguration inbound",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Per neighbor soft reconfiguration\n"
       "Allow inbound soft reconfiguration for this neighbor\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                                pafcs_SOFT_RECONFIG, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor route-reflector-client
 */
DEFUN (neighbor_route_reflector_client,
       neighbor_route_reflector_client_cmd,
       NEIGHBOR_CMD2 "route-reflector-client",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                            pafcs_REFLECTOR_CLIENT, bsc_set_on);
}

DEFUN (no_neighbor_route_reflector_client,
       no_neighbor_route_reflector_client_cmd,
       NO_NEIGHBOR_CMD2 "route-reflector-client",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure a neighbor as Route Reflector client\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                             pafcs_REFLECTOR_CLIENT, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor nexthop-local unchanged
 */
DEFUN (neighbor_nexthop_local_unchanged,
       neighbor_nexthop_local_unchanged_cmd,
       NEIGHBOR_CMD2 "nexthop-local unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                     pafcs_NEXTHOP_LOCAL_UNCHANGED, bsc_set_on);
}

DEFUN (no_neighbor_nexthop_local_unchanged,
       no_neighbor_nexthop_local_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "nexthop-local unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Configure treatment of outgoing link-local-nexthop attribute\n"
       "Leave link-local nexthop unchanged for this peer\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                      pafcs_NEXTHOP_LOCAL_UNCHANGED, bsc_unset);
}

/*------------------------------------------------------------------------------
 * neighbor attribute-unchanged unchanged
 */
static bool
do_neighbor_attr_option(chs_c what, uint n, chs_c* v)
{
  uint  i ;

  for (i = 0 ; i < n ; ++i)
    {
      if (strncmp(v[i], what, strlen(v[i])) == 0)
        return true ;
    } ;

  return false ;
} ;

static cmd_ret_t
do_neighbor_attr_unchanged(vty vty, chs_c p_str, qafx_t qafx,
                               chs_c arg1, chs_c arg2, chs_c arg3, bgp_sc_t bsc)
{
  bgp_ret_t ret ;
  uint      n ;
  chs_c     v[3] ;

  n = 0 ;
  if (arg1 != NULL)
    v[n++] = arg1 ;
  if (arg2 != NULL)
    v[n++] = arg2 ;
  if (arg3 != NULL)
    v[n++] = arg3 ;

  ret = BGP_SUCCESS ;

  if ((ret == BGP_SUCCESS) && do_neighbor_attr_option("as-path", n, v))
    ret = bgp_peer_af_flag_modify_vty (vty, p_str, qafx,
                                                  pafcs_AS_PATH_UNCHANGED, bsc);
  if ((ret == BGP_SUCCESS) && do_neighbor_attr_option("next-hop", n, v))
    ret = bgp_peer_af_flag_modify_vty (vty, p_str, qafx,
                                                  pafcs_NEXTHOP_UNCHANGED, bsc);
  if ((ret == BGP_SUCCESS) && do_neighbor_attr_option("med", n, v))
    ret = bgp_peer_af_flag_modify_vty (vty, p_str, qafx,
                                                      pafcs_MED_UNCHANGED, bsc);

  return bgp_vty_return (vty, ret);
} ;

DEFUN (neighbor_attr_unchanged,
       neighbor_attr_unchanged_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                      "as-path", "next-hop", "med", bsc_set_on);
}

DEFUN (neighbor_attr_unchanged1,
       neighbor_attr_unchanged1_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                              argv[1], NULL, NULL, bsc_set_on) ;
}

DEFUN (neighbor_attr_unchanged2,
       neighbor_attr_unchanged2_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                         "as-path", argv[1], NULL, bsc_set_on) ;
}

DEFUN (neighbor_attr_unchanged3,
       neighbor_attr_unchanged3_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                        "next-hop", argv[1], NULL, bsc_set_on) ;
}

DEFUN (neighbor_attr_unchanged4,
       neighbor_attr_unchanged4_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                             "med", argv[1], NULL, bsc_set_on) ;
}

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged5_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged6_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged7_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged8_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged9_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (neighbor_attr_unchanged,
       neighbor_attr_unchanged10_cmd,
       NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

DEFUN (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                       "as-path", "next-hop", "med", bsc_unset);

}

DEFUN (no_neighbor_attr_unchanged1,
       no_neighbor_attr_unchanged1_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged (as-path|next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                               argv[1], NULL, NULL, bsc_unset) ;
}

DEFUN (no_neighbor_attr_unchanged2,
       no_neighbor_attr_unchanged2_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path (next-hop|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                          "as-path", argv[1], NULL, bsc_unset) ;
}

DEFUN (no_neighbor_attr_unchanged3,
       no_neighbor_attr_unchanged3_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop (as-path|med)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                         "next-hop", argv[1], NULL, bsc_unset) ;
}

DEFUN (no_neighbor_attr_unchanged4,
       no_neighbor_attr_unchanged4_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med (as-path|next-hop)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")
{
  return do_neighbor_attr_unchanged (vty, argv[0], bgp_node_qafx(vty),
                                              "med", argv[1], NULL, bsc_unset) ;
}

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged5_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path next-hop med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Nexthop attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged6_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged as-path med next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "As-path attribute\n"
       "Med attribute\n"
       "Nexthop attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged7_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop med as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "Med attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged8_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged next-hop as-path med",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Nexthop attribute\n"
       "As-path attribute\n"
       "Med attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged9_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med next-hop as-path",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "Nexthop attribute\n"
       "As-path attribute\n")

ALIAS (no_neighbor_attr_unchanged,
       no_neighbor_attr_unchanged10_cmd,
       NO_NEIGHBOR_CMD2 "attribute-unchanged med as-path next-hop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP attribute is propagated unchanged to this neighbor\n"
       "Med attribute\n"
       "As-path attribute\n"
       "Nexthop attribute\n")

/*------------------------------------------------------------------------------
 * neighbor transparent-as
 *
 * For old version Zebra compatibility.
 */
DEFUN_DEPRECATED (neighbor_transparent_as,
                  neighbor_transparent_as_cmd,
                  NEIGHBOR_CMD "transparent-as",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Do not append my AS number even peer is EBGP peer\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                           pafcs_AS_PATH_UNCHANGED, bsc_set_on);
}

DEFUN_DEPRECATED (neighbor_transparent_nexthop,
                  neighbor_transparent_nexthop_cmd,
                  NEIGHBOR_CMD "transparent-nexthop",
                  NEIGHBOR_STR
                  NEIGHBOR_ADDR_STR
                  "Do not change nexthop even peer is EBGP peer\n")
{
  return bgp_peer_af_flag_modify_vty(vty, argv[0], bgp_node_qafx(vty),
                                           pafcs_NEXTHOP_UNCHANGED, bsc_set_on);
}

/*------------------------------------------------------------------------------
 * EBGP multihop configuration.
 */
static cmd_ret_t
do_neighbor_ebgp_multihop(vty vty, chs_c p_str, chs_c ttl_str)
{
  bgp_peer peer;
  bgp_sc_t bsc ;
  uint     ttl;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (ttl_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("TTL", ttl, ttl_str, 1, TTL_MAX) ;
      bsc  = (ttl != 0) ? bsc_set_on : bsc_set_off ;
    }
  else
    {
      ttl = 0 ;
      bsc  = bsc_unset ;
    }

  return bgp_vty_return (vty, bgp_peer_multihop_set (peer, ttl, bsc));
}

DEFUN (neighbor_ebgp_multihop,
       neighbor_ebgp_multihop_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return do_neighbor_ebgp_multihop (vty, argv[0], "255");
}

DEFUN (neighbor_ebgp_multihop_ttl,
       neighbor_ebgp_multihop_ttl_cmd,
       NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")
{
  return do_neighbor_ebgp_multihop (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n")
{
  return do_neighbor_ebgp_multihop (vty, argv[0], NULL);
}

ALIAS (no_neighbor_ebgp_multihop,
       no_neighbor_ebgp_multihop_ttl_cmd,
       NO_NEIGHBOR_CMD2 "ebgp-multihop <1-255>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Allow EBGP neighbors not on directly connected networks\n"
       "maximum hop count\n")

/*------------------------------------------------------------------------------
 * neighbor disable-connected-check/enforce-multihop
 */
DEFUN (neighbor_disable_connected_check,
       neighbor_disable_connected_check_cmd,
       NEIGHBOR_CMD2 "disable-connected-check",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DISABLE_CONNECTED_CHECK,
                                                                    bsc_set_on);
}

DEFUN (no_neighbor_disable_connected_check,
       no_neighbor_disable_connected_check_cmd,
       NO_NEIGHBOR_CMD2 "disable-connected-check",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "one-hop away EBGP peer using loopback address\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_DISABLE_CONNECTED_CHECK,
                                                                     bsc_unset);
}

ALIAS (neighbor_disable_connected_check,
       neighbor_enforce_multihop_cmd,
       NEIGHBOR_CMD2 "enforce-multihop",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

ALIAS (no_neighbor_disable_connected_check,
       no_neighbor_enforce_multihop_cmd,
       NO_NEIGHBOR_CMD2 "enforce-multihop",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enforce EBGP neighbors perform multihop\n")

/*------------------------------------------------------------------------------
 * neighbor description.
 */
static cmd_ret_t
do_neighbor_description(vty vty, chs_c p_str, chs_c desc)
{
  bgp_peer peer;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  return bgp_vty_return (vty, bgp_peer_description_set (peer, desc));
} ;

DEFUN (neighbor_description,
       neighbor_description_cmd,
       NEIGHBOR_CMD2 "description .LINE",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")
{
  cmd_ret_t ret ;
  char *str;

  if (argc == 1)
    return do_neighbor_description(vty, argv[0], "") ;

  str = argv_concat(argv, argc, 1);
  ret = do_neighbor_description(vty, argv[0], str) ;
  XFREE (MTYPE_TMP, str);

  return ret ;
}

DEFUN (no_neighbor_description,
       no_neighbor_description_cmd,
       NO_NEIGHBOR_CMD2 "description",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n")
{
  return do_neighbor_description(vty, argv[0], NULL) ;
}

ALIAS (no_neighbor_description,
       no_neighbor_description_val_cmd,
       NO_NEIGHBOR_CMD2 "description .LINE",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Neighbor specific description\n"
       "Up to 80 characters describing this neighbor\n")

/*------------------------------------------------------------------------------
 * Neighbor update-source.
 *
 *   source_str: NULL => unset update-source -- if and addr, unset together
 *               IP   => set addr, unset if
 *               name => set if, unset addr
 */
static cmd_ret_t
do_neighbor_update_source(vty vty, chs_c p_str, chs_c source_str)
{
  bgp_peer  peer;
  bgp_ret_t ret ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (source_str != NULL)
    {
      sockunion_t su[1] ;

      if (sockunion_str2su (su, source_str))
        ret = bgp_peer_update_source_addr_set (peer, source_str, su);
      else
        ret = bgp_peer_update_source_if_set (peer, source_str);
    }
  else
    {
      ret = bgp_peer_update_source_unset (peer);
    } ;

  return bgp_vty_return (vty, ret) ;
}

#define BGP_UPDATE_SOURCE_STR "(A.B.C.D|X:X::X:X|WORD)"
#define BGP_UPDATE_SOURCE_HELP_STR \
  "IPv4 address\n" \
  "IPv6 address\n" \
  "Interface name (requires zebra to be running)\n"

DEFUN (neighbor_update_source,
       neighbor_update_source_cmd,
       NEIGHBOR_CMD2 "update-source " BGP_UPDATE_SOURCE_STR,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n"
       BGP_UPDATE_SOURCE_HELP_STR)
{
  return do_neighbor_update_source(vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_update_source,
       no_neighbor_update_source_cmd,
       NO_NEIGHBOR_CMD2 "update-source",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Source of routing updates\n")
{
  return do_neighbor_update_source (vty, argv[0], NULL);
}

/*------------------------------------------------------------------------------
 * neighbor default-originate.
 */
static cmd_ret_t
do_neighbor_default_originate(vty vty, chs_c p_str,
                                     qafx_t qafx, chs_c rmap_name, bgp_sc_t bsc)
{
  bgp_peer peer;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  return bgp_vty_return (vty,
                   bgp_peer_default_originate_set (peer, qafx, rmap_name, bsc));
}

DEFUN (neighbor_default_originate,
       neighbor_default_originate_cmd,
       NEIGHBOR_CMD2 "default-originate",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return do_neighbor_default_originate(vty, argv[0], bgp_node_qafx(vty),
                                                             NULL, bsc_set_on) ;
}

DEFUN (neighbor_default_originate_rmap,
       neighbor_default_originate_rmap_cmd,
       NEIGHBOR_CMD2 "default-originate route-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")
{
  return do_neighbor_default_originate(vty, argv[0], bgp_node_qafx(vty),
                                                          argv[1], bsc_set_on) ;
}

DEFUN (no_neighbor_default_originate,
       no_neighbor_default_originate_cmd,
       NO_NEIGHBOR_CMD2 "default-originate",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n")
{
  return do_neighbor_default_originate(vty, argv[0], bgp_node_qafx(vty),
                                                              NULL, bsc_unset) ;
}

ALIAS (no_neighbor_default_originate,
       no_neighbor_default_originate_rmap_cmd,
       NO_NEIGHBOR_CMD2 "default-originate route-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Originate default route to this neighbor\n"
       "Route-map to specify criteria to originate default\n"
       "route-map name\n")

/*------------------------------------------------------------------------------
 * Set/Unset neighbor's BGP port
 *
 * NULL port_str => unset
 * 0 port value  => off
 */
static cmd_ret_t
do_neighbor_port(vty vty, chs_c p_str, chs_c port_str)
{
  bgp_peer peer;
  uint16_t port;
  bgp_sc_t bsc ;

  peer = bgp_peer_lookup_vty(vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (port_str != NULL)
    {
      VTY_GET_INTEGER_RANGE("port", port, port_str, 0, 65535) ;
      bsc  = (port != 0) ? bsc_set_on : bsc_set_off ;
    }
  else
    {
      port = 0 ;
      bsc  = bsc_unset ;
    } ;

  return bgp_vty_return (vty, bgp_peer_port_set (peer, port, bsc));
}

DEFUN (neighbor_port,
       neighbor_port_cmd,
       NEIGHBOR_CMD "port <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")
{
  return do_neighbor_port(vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_port,
       no_neighbor_port_cmd,
       NO_NEIGHBOR_CMD "port",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n")
{
  return do_neighbor_port(vty, argv[0], NULL);
}

ALIAS (no_neighbor_port,
       no_neighbor_port_val_cmd,
       NO_NEIGHBOR_CMD "port <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Neighbor's BGP port\n"
       "TCP port number\n")

/*------------------------------------------------------------------------------
 * neighbor weight.
 */
static cmd_ret_t
do_neighbor_weight(vty vty, chs_c p_str, chs_c weight_str)
{
  bgp_peer      peer;
  bgp_sc_t      bsc ;
  uint          weight;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (weight_str != NULL)
    {
      VTY_GET_INTEGER_RANGE("weight", weight, weight_str, 0, 65535);
      bsc    = bsc_set_on ;
    }
  else
    {
      weight = 0 ;
      bsc    = bsc_unset ;
    } ;

  return bgp_vty_return (vty, bgp_peer_weight_set (peer, weight, bsc));
}

DEFUN (neighbor_weight,
       neighbor_weight_cmd,
       NEIGHBOR_CMD2 "weight <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")
{
  return do_neighbor_weight(vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_weight,
       no_neighbor_weight_cmd,
       NO_NEIGHBOR_CMD2 "weight",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n")
{
  return do_neighbor_weight(vty, argv[0], NULL);
}

ALIAS (no_neighbor_weight,
       no_neighbor_weight_val_cmd,
       NO_NEIGHBOR_CMD2 "weight <0-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Set default weight for routes from this neighbor\n"
       "default weight\n")

/*------------------------------------------------------------------------------
 * Override capability negotiation.
 */
DEFUN (neighbor_override_capability,
       neighbor_override_capability_cmd,
       NEIGHBOR_CMD2 "override-capability",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_OVERRIDE_CAPABILITY,
                                                                    bsc_set_on);
}

DEFUN (no_neighbor_override_capability,
       no_neighbor_override_capability_cmd,
       NO_NEIGHBOR_CMD2 "override-capability",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Override capability negotiation result\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_OVERRIDE_CAPABILITY,
                                                                     bsc_unset);
}

DEFUN (neighbor_strict_capability,
       neighbor_strict_capability_cmd,
       NEIGHBOR_CMD "strict-capability-match",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_STRICT_CAP_MATCH,
                                                                    bsc_set_on);
}

DEFUN (no_neighbor_strict_capability,
       no_neighbor_strict_capability_cmd,
       NO_NEIGHBOR_CMD "strict-capability-match",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Strict capability negotiation match\n")
{
  return bgp_peer_flag_modify_vty (vty, argv[0], pcs_STRICT_CAP_MATCH,
                                                                     bsc_unset);
}

/*------------------------------------------------------------------------------
 * Set neighbor's or group's timers.
 *
 * Sets the given values for KeepAliveTime and HoldTime
 */
static cmd_ret_t
do_neighbor_timers(vty vty, chs_c p_str, chs_c keep_str, chs_c hold_str)
{
  bgp_peer  peer;
  bgp_sc_t  bsc ;
  uint keepalive, holdtime;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (keep_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("Keepalive", keepalive, keep_str, 0, 65535);
      VTY_GET_INTEGER_RANGE ("Holdtime",  holdtime,  hold_str, 0, 65535);

      bsc = bsc_set_on ;
    }
  else
    {
      keepalive = holdtime = 0 ;
      bsc = bsc_unset ;
    }

  return bgp_vty_return (vty,
                         bgp_peer_timers_set (peer, keepalive, holdtime, bsc));
}

DEFUN (neighbor_timers,
       neighbor_timers_cmd,
       NEIGHBOR_CMD2 "timers <0-65535> <0-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "Keepalive interval\n"
       "Holdtime\n")
{
  return do_neighbor_timers(vty, argv[0], argv[1], argv[2]);
}

DEFUN (no_neighbor_timers,
       no_neighbor_timers_cmd,
       NO_NEIGHBOR_CMD2 "timers",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n")
{
  return do_neighbor_timers(vty, argv[0], NULL, NULL);
}

/*------------------------------------------------------------------------------
 * Set neighbor's or group's connect timer.
 *
 * Sets the given values for ConnectTime
 */
static cmd_ret_t
do_neighbor_timers_connect(vty vty, chs_c p_str, chs_c time_str)
{
  bgp_peer  peer;
  bgp_sc_t  bsc ;
  uint      connect_retry_secs;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (time_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("ConnectRetryTime",
                                       connect_retry_secs, time_str, 1, 65535) ;
      bsc = bsc_set_on ;
    }
  else
    {
      connect_retry_secs = 0 ;
      bsc = bsc_unset ;
    }

  return bgp_vty_return (vty,
                   bgp_peer_timers_connect_set (peer, connect_retry_secs, bsc));
}

DEFUN (neighbor_timers_connect,
       neighbor_timers_connect_cmd,
       NEIGHBOR_CMD2 "timers connect <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")
{
  return do_neighbor_timers_connect(vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_timers_connect,
       no_neighbor_timers_connect_cmd,
       NO_NEIGHBOR_CMD2 "timers connect",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n")
{
  return do_neighbor_timers_connect(vty, argv[0], NULL);
}

ALIAS (no_neighbor_timers_connect,
       no_neighbor_timers_connect_val_cmd,
       NO_NEIGHBOR_CMD2 "timers connect <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BGP per neighbor timers\n"
       "BGP connect timer\n"
       "Connect timer\n")

/*------------------------------------------------------------------------------
 * Set or clear the advertisement-interval for the given peer or group.
 */
static cmd_ret_t
do_neighbor_advertise_interval (vty vty, chs_c p_str, chs_c time_str)
{
  bgp_peer  peer ;
  bgp_sc_t  bsc ;
  uint      routeadv ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (time_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("advertise interval", routeadv, time_str, 1, 600);
      bsc = bsc_set_on ;
    }
  else
    {
      routeadv = 0 ;
      bsc      = bsc_unset ;
    } ;

  return bgp_vty_return (vty,
                         bgp_peer_advertise_interval_set (peer, routeadv, bsc));
}

DEFUN (neighbor_advertise_interval,
       neighbor_advertise_interval_cmd,
       NEIGHBOR_CMD2 "advertisement-interval <1-600>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")
{
  return do_neighbor_advertise_interval (vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n")
{
  return do_neighbor_advertise_interval (vty, argv[0], NULL);
}

ALIAS (no_neighbor_advertise_interval,
       no_neighbor_advertise_interval_val_cmd,
       NO_NEIGHBOR_CMD2 "advertisement-interval <1-600>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Minimum interval between sending BGP routing updates\n"
       "time in seconds\n")

/*------------------------------------------------------------------------------
 * neighbor interface
 */
static cmd_ret_t
do_neighbor_interface (vty vty, chs_c p_str, chs_c ifname)
{
  bgp_peer peer;
  bgp_sc_t  bsc ;

  peer = bgp_peer_lookup_vty(vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (ifname != NULL)
    bsc  = bsc_set_on ;
  else
    bsc  = bsc_unset ;

  return bgp_vty_return (vty, bgp_peer_interface_set (peer, ifname, bsc));
}

DEFUN_DEPRECATED (neighbor_interface,
       neighbor_interface_cmd,
       NEIGHBOR_CMD "interface WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return do_neighbor_interface (vty, argv[0], argv[1]);
}

DEFUN_DEPRECATED (no_neighbor_interface,
       no_neighbor_interface_cmd,
       NO_NEIGHBOR_CMD "interface WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR
       "Interface\n"
       "Interface name\n")
{
  return do_neighbor_interface (vty, argv[0], NULL);
}

/*------------------------------------------------------------------------------
 * neighbor distribute-list
 */
static cmd_ret_t
do_neighbor_distribute_list(vty vty, chs_c p_str, qafx_t qafx,
                                               chs_c name_str, chs_c direct_str)
{
  bgp_peer           peer ;
  bgp_pafc_setting_t setting ;
  bgp_sc_t           bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  switch (direct_str[0])
    {
      case 'i':
        setting = pafcs_dlist_in ;
        break ;

      case 'o':
        setting = pafcs_dlist_out ;
        break ;

      default:
        qassert(false) ;
        return CMD_WARNING ;
    } ;

  if (name_str != NULL)
    bsc = bsc_set_on ;
  else
    bsc = bsc_unset ;

  return bgp_vty_return (vty,
                      bgp_peer_filter_set(peer, qafx, setting, name_str, bsc)) ;
}

DEFUN (neighbor_distribute_list,
       neighbor_distribute_list_cmd,
       NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return do_neighbor_distribute_list(vty, argv[0], bgp_node_qafx(vty),
                                                              argv[1], argv[2]);
}

DEFUN (no_neighbor_distribute_list,
       no_neighbor_distribute_list_cmd,
       NO_NEIGHBOR_CMD2 "distribute-list (<1-199>|<1300-2699>|WORD) (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return do_neighbor_distribute_list(vty, argv[0], bgp_node_qafx(vty),
                                                                 NULL, argv[2]);
}

/*------------------------------------------------------------------------------
 * neighbor prefix-list
 */
static cmd_ret_t
do_neighbor_prefix_list(vty vty, chs_c p_str, qafx_t qafx,
                                               chs_c name_str, chs_c direct_str)
{
  bgp_peer           peer ;
  bgp_pafc_setting_t setting ;
  bgp_sc_t           bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  switch (direct_str[0])
    {
      case 'i':
        setting = pafcs_plist_in ;
        break ;

      case 'o':
        setting = pafcs_plist_out ;
        break ;

      default:
        qassert(false) ;
        return CMD_WARNING ;
    } ;

  if (name_str != NULL)
    bsc = bsc_set_on ;
  else
    bsc = bsc_unset ;

  return bgp_vty_return (vty,
                      bgp_peer_filter_set(peer, qafx, setting, name_str, bsc)) ;
} ;

DEFUN (neighbor_prefix_list,
       neighbor_prefix_list_cmd,
       NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return do_neighbor_prefix_list(vty, argv[0], bgp_node_qafx(vty),
                                                             argv[1], argv[2]) ;
}

DEFUN (no_neighbor_prefix_list,
       no_neighbor_prefix_list_cmd,
       NO_NEIGHBOR_CMD2 "prefix-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Filter updates to/from this neighbor\n"
       "Name of a prefix list\n"
       "Filter incoming updates\n"
       "Filter outgoing updates\n")
{
  return do_neighbor_prefix_list(vty, argv[0], bgp_node_qafx(vty),
                                                                NULL, argv[2]) ;
}

/*------------------------------------------------------------------------------
 * neighbor filter-list
 */
static cmd_ret_t
do_neighbor_filter_list(vty vty, chs_c p_str, qafx_t qafx,
                                               chs_c name_str, chs_c direct_str)
{
  bgp_peer           peer ;
  bgp_pafc_setting_t setting ;
  bgp_sc_t           bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  switch (direct_str[0])
    {
      case 'i':
        setting = pafcs_aslist_in ;
        break ;

      case 'o':
        setting = pafcs_aslist_out ;
        break ;

      default:
        qassert(false) ;
        return CMD_WARNING ;
    } ;

  if (name_str != NULL)
    bsc = bsc_set_on ;
  else
    bsc = bsc_unset ;

  return bgp_vty_return (vty,
                      bgp_peer_filter_set(peer, qafx, setting, name_str, bsc)) ;
} ;

DEFUN (neighbor_filter_list,
       neighbor_filter_list_cmd,
       NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return do_neighbor_filter_list(vty, argv[0], bgp_node_qafx(vty),
                                                             argv[1], argv[2]);
}

DEFUN (no_neighbor_filter_list,
       no_neighbor_filter_list_cmd,
       NO_NEIGHBOR_CMD2 "filter-list WORD (in|out)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Establish BGP filters\n"
       "AS path access-list name\n"
       "Filter incoming routes\n"
       "Filter outgoing routes\n")
{
  return do_neighbor_filter_list(vty, argv[0], bgp_node_qafx(vty),
                                                                 NULL, argv[2]);
}

/*------------------------------------------------------------------------------
 * neighbor route-map
 */
static cmd_ret_t
do_neighbor_route_map(vty vty, chs_c p_str, qafx_t qafx,
                                               chs_c name_str, chs_c direct_str)
{
  bgp_peer           peer ;
  bgp_pafc_setting_t setting ;
  bgp_sc_t           bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  switch (direct_str[0])
    {
      case 'e':                         /* export       */
        setting = pafcs_rmap_export ;
        break ;

      case 'i':
        switch (direct_str[1])
          {
            case 'm':                   /* import       */
              setting = pafcs_rmap_import ;
              break ;

            case 'n':                   /* in           */
              setting = pafcs_rmap_in ;
              break ;

            default:
              qassert(false) ;
              return CMD_WARNING ;
          }
        break ;

      case 'o':                         /* out          */
        setting = pafcs_rmap_out ;
        break ;

      case 'r':                         /* rs-in        */
        setting = pafcs_rmap_inx ;
        break ;

      default:
        qassert(false) ;
        return CMD_WARNING ;
    } ;

  if (name_str != NULL)
    bsc = bsc_set_on ;
  else
    bsc = bsc_unset ;

  return bgp_vty_return (vty,
                      bgp_peer_filter_set(peer, qafx, setting, name_str, bsc)) ;
}

DEFUN (neighbor_route_map,
       neighbor_route_map_cmd,
       NEIGHBOR_CMD2 "route-map WORD (in|rs-in|out|import|export)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to incoming Route-Server routes\n"
       "Apply map to outbound routes\n"
       "Apply map to routes going into a Route-Server client's table\n"
       "Apply map to routes coming from a Route-Server client")
{
  return do_neighbor_route_map(vty, argv[0], bgp_node_qafx(vty),
                                                              argv[1], argv[2]);
}

DEFUN (no_neighbor_route_map,
       no_neighbor_route_map_cmd,
       NO_NEIGHBOR_CMD2 "route-map WORD (in|rs-in|out|import|export)",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Apply route map to neighbor\n"
       "Name of route map\n"
       "Apply map to incoming routes\n"
       "Apply map to incoming Route-Server routes\n"
       "Apply map to outbound routes\n"
       "Apply map to routes going into a Route-Server client's table\n"
       "Apply map to routes coming from a Route-Server client")
{
  return do_neighbor_route_map(vty, argv[0], bgp_node_qafx(vty),
                                                                 NULL, argv[2]);
}

/*------------------------------------------------------------------------------
 * neighbor unsuppress-map
 */
static cmd_ret_t
do_neighbor_unsuppress_map(vty vty, chs_c p_str, qafx_t qafx, chs_c name_str)
{
  bgp_peer  peer ;
  bgp_sc_t  bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (name_str != NULL)
    bsc = bsc_set_on ;
  else
    bsc = bsc_unset ;

  return bgp_vty_return (vty,
                bgp_peer_filter_set(peer, qafx, pafcs_us_rmap, name_str, bsc)) ;
}

DEFUN (neighbor_unsuppress_map,
       neighbor_unsuppress_map_cmd,
       NEIGHBOR_CMD2 "unsuppress-map WORD",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return do_neighbor_unsuppress_map(vty, argv[0], bgp_node_qafx(vty), argv[1]) ;
}

DEFUN (no_neighbor_unsuppress_map,
       no_neighbor_unsuppress_map_cmd,
       NO_NEIGHBOR_CMD2 "unsuppress-map WORD",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Route-map to selectively unsuppress suppressed routes\n"
       "Name of route map\n")
{
  return do_neighbor_unsuppress_map(vty, argv[0], bgp_node_qafx(vty), NULL);
}

/*------------------------------------------------------------------------------
 * neighbor maximum-prefix
 */
static cmd_ret_t
do_neighbor_maximum_prefix(vty vty, chs_c p_str, qafx_t qafx,
            chs_c num_str, chs_c threshold_str, bool warning, chs_c restart_str)
{
  bgp_peer  peer ;
  bgp_sc_t  bsc ;
  uint32_t max;
  byte     threshold;
  uint16_t restart;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (num_str != NULL)
    {
      VTY_GET_INTEGER ("maximum number", max, num_str);

      if (threshold_str != NULL)
        threshold = atoi (threshold_str);
      else
        threshold = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

      if (restart_str != NULL)
        restart = atoi (restart_str);
      else
        restart = 0;

      bsc = bsc_set_on ;
    }
  else
    {
      max = threshold = restart = 0 ;
      warning = false ;

      bsc = bsc_unset ;
    } ;

  return bgp_vty_return (vty,
        bgp_peer_maximum_prefix_set (peer, qafx, max, threshold, warning, restart,
                                                                          bsc));
} ;

/* Maximum number of prefix configuration.  prefix count is different
   for each peer configuration.  So this configuration can be set for
   each peer configuration. */
DEFUN (neighbor_maximum_prefix,
       neighbor_maximum_prefix_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                    argv[1], NULL, false, NULL);
}

DEFUN (neighbor_maximum_prefix_threshold,
       neighbor_maximum_prefix_threshold_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                 argv[1], argv[2], false, NULL);
}

DEFUN (neighbor_maximum_prefix_warning,
       neighbor_maximum_prefix_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                     argv[1], NULL, true, NULL);
}

DEFUN (neighbor_maximum_prefix_threshold_warning,
       neighbor_maximum_prefix_threshold_warning_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                  argv[1], argv[2], true, NULL);
}

DEFUN (neighbor_maximum_prefix_restart,
       neighbor_maximum_prefix_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                 argv[1], NULL, false, argv[2]);
}

DEFUN (neighbor_maximum_prefix_threshold_restart,
       neighbor_maximum_prefix_threshold_restart_cmd,
       NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                              argv[1], argv[2], false, argv[3]);
}

DEFUN (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n")
{
  return do_neighbor_maximum_prefix(vty, argv[0], bgp_node_qafx(vty),
                                                       NULL, NULL, false, NULL);
}

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_val_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_warning_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> warning-only",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Only give warning message when limit is exceeded\n")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

ALIAS (no_neighbor_maximum_prefix,
       no_neighbor_maximum_prefix_threshold_restart_cmd,
       NO_NEIGHBOR_CMD2 "maximum-prefix <1-4294967295> <1-100> restart <1-65535>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Maximum number of prefix accept from this peer\n"
       "maximum no. of prefix limit\n"
       "Threshold value (%) at which to generate a warning msg\n"
       "Restart bgp connection after limit is exceeded\n"
       "Restart interval in minutes")

/*------------------------------------------------------------------------------
 * neighbor allowas-in
 */
static cmd_ret_t
do_neighbor_allow_as_in(vty vty, chs_c p_str, chs_c n_str)
{
  bgp_peer  peer;
  uint      allow;
  bgp_sc_t  bsc ;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (n_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("AS number", allow, n_str, 1, 10);
      bsc = bsc_set_on ;
    }
  else
    {
      allow = 0 ;
      bsc = bsc_unset ;
    }

  return bgp_vty_return (vty,
               bgp_peer_allow_as_in_set (peer, bgp_node_qafx(vty), allow, bsc));
}

DEFUN (neighbor_allow_as_in,
       neighbor_allow_as_in_cmd,
       NEIGHBOR_CMD2 "allowas-in",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n")
{
  return do_neighbor_allow_as_in(vty, argv[0], (argc == 2) ? argv[1] : "3") ;
}

ALIAS (neighbor_allow_as_in,
       neighbor_allow_as_in_arg_cmd,
       NEIGHBOR_CMD2 "allowas-in <1-10>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Accept as-path with my AS present in it\n"
       "Number of occurances of AS number\n")

DEFUN (no_neighbor_allow_as_in,
       no_neighbor_allow_as_in_cmd,
       NO_NEIGHBOR_CMD2 "allowas-in",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "allow local ASN appears in aspath attribute\n")
{
  return do_neighbor_allow_as_in(vty, argv[0], NULL) ;
}

/*------------------------------------------------------------------------------
 * neighbor ttl-security hops
 */
static cmd_ret_t
do_neighbor_ttl_security(vty vty, chs_c p_str, chs_c ttl_str)
{
  bgp_peer peer;
  bgp_sc_t bsc ;
  uint     ttl;

  peer = bgp_peer_or_group_lookup_vty (vty, p_str);
  if (peer == NULL)
    return CMD_WARNING;

  if (ttl_str != NULL)
    {
      VTY_GET_INTEGER_RANGE ("gtsm hops", ttl, ttl_str, 1, 254);
      bsc  = (ttl != 0) ? bsc_set_on : bsc_set_off ;
    }
  else
    {
      ttl = 0 ;
      bsc  = bsc_unset ;
    }

  return bgp_vty_return (vty, bgp_peer_ttl_security_hops_set(peer, ttl, bsc)) ;
}

DEFUN (neighbor_ttl_security,
       neighbor_ttl_security_cmd,
       NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  return do_neighbor_ttl_security(vty, argv[0], argv[1]);
}

DEFUN (no_neighbor_ttl_security,
       no_neighbor_ttl_security_cmd,
       NO_NEIGHBOR_CMD2 "ttl-security hops <1-254>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Specify the maximum number of hops to the BGP peer\n")
{
  return do_neighbor_ttl_security(vty, argv[0], NULL);
}

/*==============================================================================
 * Table of commands to be installed for bgp_config_vty
 */
CMD_INSTALL_TABLE(static, bgp_vty_cmd_table, BGPD) =
{
  { CONFIG_NODE,     &bgp_multiple_instance_cmd                         },
  { CONFIG_NODE,     &no_bgp_multiple_instance_cmd                      },

  { CONFIG_NODE,     &bgp_config_type_cmd                               },
  { CONFIG_NODE,     &no_bgp_config_type_cmd                            },

  /* Dummy commands (Currently not supported) */
  { BGP_NODE,        &no_synchronization_cmd                            },
  { BGP_NODE,        &no_auto_summary_cmd                               },

  { CONFIG_NODE,     &router_bgp_cmd                                    },
  { CONFIG_NODE,     &router_bgp_view_cmd                               },

  { CONFIG_NODE,     &no_router_bgp_cmd                                 },
  { CONFIG_NODE,     &no_router_bgp_view_cmd                            },

  { BGP_NODE,        &bgp_router_id_cmd                                 },
  { BGP_NODE,        &no_bgp_router_id_cmd                              },
  { BGP_NODE,        &no_bgp_router_id_val_cmd                          },

  { BGP_NODE,        &bgp_cluster_id_cmd                                },
  { BGP_NODE,        &bgp_cluster_id32_cmd                              },
  { BGP_NODE,        &no_bgp_cluster_id_cmd                             },
  { BGP_NODE,        &no_bgp_cluster_id_arg_cmd                         },

  { BGP_NODE,        &bgp_confederation_identifier_cmd                  },
  { BGP_NODE,        &no_bgp_confederation_identifier_cmd               },
  { BGP_NODE,        &no_bgp_confederation_identifier_arg_cmd           },

  { BGP_NODE,        &bgp_confederation_peers_cmd                       },
  { BGP_NODE,        &no_bgp_confederation_peers_cmd                    },

  { BGP_NODE,        &bgp_timers_cmd                                    },
  { BGP_NODE,        &no_bgp_timers_cmd                                 },
  { BGP_NODE,        &no_bgp_timers_arg_cmd                             },

  { BGP_NODE,        &no_bgp_client_to_client_reflection_cmd            },
  { BGP_NODE,        &bgp_client_to_client_reflection_cmd               },

  { BGP_NODE,        &bgp_always_compare_med_cmd                        },
  { BGP_NODE,        &no_bgp_always_compare_med_cmd                     },

  { BGP_NODE,        &bgp_deterministic_med_cmd                         },
  { BGP_NODE,        &no_bgp_deterministic_med_cmd                      },

  { BGP_NODE,        &bgp_graceful_restart_cmd                          },
  { BGP_NODE,        &no_bgp_graceful_restart_cmd                       },
  { BGP_NODE,        &bgp_graceful_restart_stalepath_time_cmd           },
  { BGP_NODE,        &no_bgp_graceful_restart_stalepath_time_cmd        },
  { BGP_NODE,        &no_bgp_graceful_restart_stalepath_time_val_cmd    },

  { BGP_NODE,        &bgp_fast_external_failover_cmd                    },
  { BGP_NODE,        &no_bgp_fast_external_failover_cmd                 },

  { BGP_NODE,        &bgp_enforce_first_as_cmd                          },
  { BGP_NODE,        &no_bgp_enforce_first_as_cmd                       },

  { BGP_NODE,        &bgp_bestpath_compare_router_id_cmd                },
  { BGP_NODE,        &no_bgp_bestpath_compare_router_id_cmd             },

  { BGP_NODE,        &bgp_bestpath_aspath_ignore_cmd                    },
  { BGP_NODE,        &no_bgp_bestpath_aspath_ignore_cmd                 },

  { BGP_NODE,        &bgp_bestpath_aspath_confed_cmd                    },
  { BGP_NODE,        &no_bgp_bestpath_aspath_confed_cmd                 },

  { BGP_NODE,        &bgp_bestpath_med_cmd                              },
  { BGP_NODE,        &bgp_bestpath_med2_cmd                             },
  { BGP_NODE,        &bgp_bestpath_med3_cmd                             },
  { BGP_NODE,        &no_bgp_bestpath_med_cmd                           },
  { BGP_NODE,        &no_bgp_bestpath_med2_cmd                          },
  { BGP_NODE,        &no_bgp_bestpath_med3_cmd                          },

  { BGP_NODE,        &no_bgp_default_ipv4_unicast_cmd                   },
  { BGP_NODE,        &bgp_default_ipv4_unicast_cmd                      },

  { BGP_NODE,        &bgp_network_import_check_cmd                      },
  { BGP_NODE,        &no_bgp_network_import_check_cmd                   },

  { BGP_NODE,        &bgp_default_local_preference_cmd                  },
  { BGP_NODE,        &no_bgp_default_local_preference_cmd               },
  { BGP_NODE,        &no_bgp_default_local_preference_val_cmd           },

  { BGP_NODE,        &neighbor_remote_as_cmd                            },
  { BGP_NODE,        &no_neighbor_cmd                                   },
  { BGP_NODE,        &no_neighbor_remote_as_cmd                         },

  { BGP_NODE,        &neighbor_peer_group_cmd                           },
  { BGP_NODE,        &no_neighbor_peer_group_cmd                        },
  { BGP_NODE,        &no_neighbor_peer_group_remote_as_as_cmd           },
  { BGP_NODE,        &no_neighbor_peer_group_remote_as_cmd              },

  { BGP_NODE,        &neighbor_local_as_cmd                             },
  { BGP_NODE,        &neighbor_local_as_no_prepend_cmd                  },
  { BGP_NODE,        &no_neighbor_local_as_cmd                          },
  { BGP_NODE,        &no_neighbor_local_as_val_cmd                      },
  { BGP_NODE,        &no_neighbor_local_as_val2_cmd                     },

  { BGP_NODE,        &neighbor_password_cmd                             },
  { BGP_NODE,        &no_neighbor_password_cmd                          },

  { BGP_NODE,        &neighbor_activate_cmd                             },
  { BGP_IPV4_NODE,   &neighbor_activate_cmd                             },
  { BGP_IPV4M_NODE,  &neighbor_activate_cmd                             },
  { BGP_IPV6_NODE,   &neighbor_activate_cmd                             },
  { BGP_IPV6M_NODE,  &neighbor_activate_cmd                             },
  { BGP_VPNV4_NODE,  &neighbor_activate_cmd                             },

  { BGP_NODE,        &no_neighbor_activate_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_activate_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_activate_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_activate_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_activate_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_activate_cmd                          },

  { BGP_NODE,        &neighbor_set_peer_group_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_set_peer_group_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_set_peer_group_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_set_peer_group_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_set_peer_group_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_set_peer_group_cmd                       },

  { BGP_NODE,        &no_neighbor_set_peer_group_group_cmd              },
  { BGP_IPV4_NODE,   &no_neighbor_set_peer_group_group_cmd              },
  { BGP_IPV4M_NODE,  &no_neighbor_set_peer_group_group_cmd              },
  { BGP_IPV6_NODE,   &no_neighbor_set_peer_group_group_cmd              },
  { BGP_IPV6M_NODE,  &no_neighbor_set_peer_group_group_cmd              },
  { BGP_VPNV4_NODE,  &no_neighbor_set_peer_group_group_cmd              },
  { BGP_NODE,        &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_set_peer_group_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_set_peer_group_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_set_peer_group_cmd                    },

  { BGP_NODE,        &neighbor_soft_reconfiguration_cmd                 },
  { BGP_NODE,        &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV4_NODE,   &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV4_NODE,   &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV4M_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV4M_NODE,  &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV6_NODE,   &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV6_NODE,   &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_IPV6M_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_IPV6M_NODE,  &no_neighbor_soft_reconfiguration_cmd              },
  { BGP_VPNV4_NODE,  &neighbor_soft_reconfiguration_cmd                 },
  { BGP_VPNV4_NODE,  &no_neighbor_soft_reconfiguration_cmd              },

  { BGP_NODE,        &neighbor_attr_unchanged_cmd                       },
  { BGP_NODE,        &neighbor_attr_unchanged1_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged2_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged3_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged4_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged5_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged6_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged7_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged8_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged9_cmd                      },
  { BGP_NODE,        &neighbor_attr_unchanged10_cmd                     },
  { BGP_NODE,        &no_neighbor_attr_unchanged_cmd                    },
  { BGP_NODE,        &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_NODE,        &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV4_NODE,   &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV4M_NODE,  &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV6_NODE,   &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_IPV6M_NODE,  &no_neighbor_attr_unchanged10_cmd                  },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged1_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged2_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged3_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged4_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged5_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged6_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged7_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged8_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged9_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_attr_unchanged10_cmd                     },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged1_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged2_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged3_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged4_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged5_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged6_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged7_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged8_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged9_cmd                   },
  { BGP_VPNV4_NODE,  &no_neighbor_attr_unchanged10_cmd                  },

  { BGP_IPV6_NODE,   &neighbor_nexthop_local_unchanged_cmd              },
  { BGP_IPV6_NODE,   &no_neighbor_nexthop_local_unchanged_cmd           },

  { BGP_NODE,        &neighbor_transparent_as_cmd                       },
  { BGP_NODE,        &neighbor_transparent_nexthop_cmd                  },

  { BGP_NODE,        &neighbor_nexthop_self_cmd                         },
  { BGP_NODE,        &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV4_NODE,   &neighbor_nexthop_self_cmd                         },
  { BGP_IPV4_NODE,   &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV4M_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_IPV4M_NODE,  &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV6_NODE,   &neighbor_nexthop_self_cmd                         },
  { BGP_IPV6_NODE,   &no_neighbor_nexthop_self_cmd                      },
  { BGP_IPV6M_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_IPV6M_NODE,  &no_neighbor_nexthop_self_cmd                      },
  { BGP_VPNV4_NODE,  &neighbor_nexthop_self_cmd                         },
  { BGP_VPNV4_NODE,  &no_neighbor_nexthop_self_cmd                      },

  { BGP_NODE,        &neighbor_remove_private_as_cmd                    },
  { BGP_NODE,        &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV4_NODE,   &neighbor_remove_private_as_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV4M_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV6_NODE,   &neighbor_remove_private_as_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_remove_private_as_cmd                 },
  { BGP_IPV6M_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_remove_private_as_cmd                 },
  { BGP_VPNV4_NODE,  &neighbor_remove_private_as_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_remove_private_as_cmd                 },

  { BGP_NODE,        &neighbor_send_community_cmd                       },
  { BGP_NODE,        &neighbor_send_community_type_cmd                  },
  { BGP_NODE,        &no_neighbor_send_community_cmd                    },
  { BGP_NODE,        &no_neighbor_send_community_type_cmd               },
  { BGP_IPV4_NODE,   &neighbor_send_community_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_send_community_type_cmd                  },
  { BGP_IPV4_NODE,   &no_neighbor_send_community_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_send_community_type_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_send_community_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_IPV4M_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_send_community_type_cmd               },
  { BGP_IPV6_NODE,   &neighbor_send_community_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_send_community_type_cmd                  },
  { BGP_IPV6_NODE,   &no_neighbor_send_community_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_send_community_type_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_send_community_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_IPV6M_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_send_community_type_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_send_community_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_send_community_type_cmd                  },
  { BGP_VPNV4_NODE,  &no_neighbor_send_community_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_send_community_type_cmd               },

  { BGP_NODE,        &neighbor_route_reflector_client_cmd               },
  { BGP_NODE,        &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV4_NODE,   &neighbor_route_reflector_client_cmd               },
  { BGP_IPV4_NODE,   &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV4M_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_IPV4M_NODE,  &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV6_NODE,   &neighbor_route_reflector_client_cmd               },
  { BGP_IPV6_NODE,   &no_neighbor_route_reflector_client_cmd            },
  { BGP_IPV6M_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_IPV6M_NODE,  &no_neighbor_route_reflector_client_cmd            },
  { BGP_VPNV4_NODE,  &neighbor_route_reflector_client_cmd               },
  { BGP_VPNV4_NODE,  &no_neighbor_route_reflector_client_cmd            },

  { BGP_NODE,        &neighbor_route_server_client_cmd                  },
  { BGP_NODE,        &no_neighbor_route_server_client_cmd               },
  { BGP_IPV4_NODE,   &neighbor_route_server_client_cmd                  },
  { BGP_IPV4_NODE,   &no_neighbor_route_server_client_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_IPV4M_NODE,  &no_neighbor_route_server_client_cmd               },
  { BGP_IPV6_NODE,   &neighbor_route_server_client_cmd                  },
  { BGP_IPV6_NODE,   &no_neighbor_route_server_client_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_IPV6M_NODE,  &no_neighbor_route_server_client_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_route_server_client_cmd                  },
  { BGP_VPNV4_NODE,  &no_neighbor_route_server_client_cmd               },

  { BGP_NODE,        &neighbor_passive_cmd                              },
  { BGP_NODE,        &no_neighbor_passive_cmd                           },

  { BGP_NODE,        &neighbor_capability_route_refresh_cmd             },
  { BGP_NODE,        &no_neighbor_capability_route_refresh_cmd          },

  { BGP_NODE,        &neighbor_capability_orf_prefix_cmd                },
  { BGP_NODE,        &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV4_NODE,   &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV4_NODE,   &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV4M_NODE,  &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV4M_NODE,  &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV6_NODE,   &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV6_NODE,   &no_neighbor_capability_orf_prefix_cmd             },
  { BGP_IPV6M_NODE,  &neighbor_capability_orf_prefix_cmd                },
  { BGP_IPV6M_NODE,  &no_neighbor_capability_orf_prefix_cmd             },

  { BGP_NODE,        &neighbor_capability_dynamic_cmd                   },
  { BGP_NODE,        &no_neighbor_capability_dynamic_cmd                },

  { BGP_NODE,        &neighbor_dont_capability_negotiate_cmd            },
  { BGP_NODE,        &no_neighbor_dont_capability_negotiate_cmd         },

  { BGP_NODE,        &neighbor_ebgp_multihop_cmd                        },
  { BGP_NODE,        &neighbor_ebgp_multihop_ttl_cmd                    },
  { BGP_NODE,        &no_neighbor_ebgp_multihop_cmd                     },
  { BGP_NODE,        &no_neighbor_ebgp_multihop_ttl_cmd                 },

  { BGP_NODE,        &neighbor_disable_connected_check_cmd              },
  { BGP_NODE,        &no_neighbor_disable_connected_check_cmd           },
  { BGP_NODE,        &neighbor_enforce_multihop_cmd                     },
  { BGP_NODE,        &no_neighbor_enforce_multihop_cmd                  },

  { BGP_NODE,        &neighbor_description_cmd                          },
  { BGP_NODE,        &no_neighbor_description_cmd                       },
  { BGP_NODE,        &no_neighbor_description_val_cmd                   },

  { BGP_NODE,        &neighbor_update_source_cmd                        },
  { BGP_NODE,        &no_neighbor_update_source_cmd                     },

  { BGP_NODE,        &neighbor_default_originate_cmd                    },
  { BGP_NODE,        &neighbor_default_originate_rmap_cmd               },
  { BGP_NODE,        &no_neighbor_default_originate_cmd                 },
  { BGP_NODE,        &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV4_NODE,   &neighbor_default_originate_cmd                    },
  { BGP_IPV4_NODE,   &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV4_NODE,   &no_neighbor_default_originate_cmd                 },
  { BGP_IPV4_NODE,   &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV4M_NODE,  &neighbor_default_originate_cmd                    },
  { BGP_IPV4M_NODE,  &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV4M_NODE,  &no_neighbor_default_originate_cmd                 },
  { BGP_IPV4M_NODE,  &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV6_NODE,   &neighbor_default_originate_cmd                    },
  { BGP_IPV6_NODE,   &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV6_NODE,   &no_neighbor_default_originate_cmd                 },
  { BGP_IPV6_NODE,   &no_neighbor_default_originate_rmap_cmd            },
  { BGP_IPV6M_NODE,  &neighbor_default_originate_cmd                    },
  { BGP_IPV6M_NODE,  &neighbor_default_originate_rmap_cmd               },
  { BGP_IPV6M_NODE,  &no_neighbor_default_originate_cmd                 },
  { BGP_IPV6M_NODE,  &no_neighbor_default_originate_rmap_cmd            },

  { BGP_NODE,        &neighbor_port_cmd                                 },
  { BGP_NODE,        &no_neighbor_port_cmd                              },
  { BGP_NODE,        &no_neighbor_port_val_cmd                          },

  { BGP_NODE,        &neighbor_weight_cmd                               },
  { BGP_NODE,        &no_neighbor_weight_cmd                            },
  { BGP_NODE,        &no_neighbor_weight_val_cmd                        },

  { BGP_NODE,        &neighbor_override_capability_cmd                  },
  { BGP_NODE,        &no_neighbor_override_capability_cmd               },

  { BGP_NODE,        &neighbor_strict_capability_cmd                    },
  { BGP_NODE,        &no_neighbor_strict_capability_cmd                 },

  { BGP_NODE,        &neighbor_timers_cmd                               },
  { BGP_NODE,        &no_neighbor_timers_cmd                            },

  { BGP_NODE,        &neighbor_timers_connect_cmd                       },
  { BGP_NODE,        &no_neighbor_timers_connect_cmd                    },
  { BGP_NODE,        &no_neighbor_timers_connect_val_cmd                },

  { BGP_NODE,        &neighbor_advertise_interval_cmd                   },
  { BGP_NODE,        &no_neighbor_advertise_interval_cmd                },
  { BGP_NODE,        &no_neighbor_advertise_interval_val_cmd            },

  { BGP_NODE,        &neighbor_version_cmd                              },

  /* "neighbor interface" commands. */
  { BGP_NODE,        &neighbor_interface_cmd                            },
  { BGP_NODE,        &no_neighbor_interface_cmd                         },

  { BGP_NODE,        &neighbor_distribute_list_cmd                      },
  { BGP_NODE,        &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV4_NODE,   &neighbor_distribute_list_cmd                      },
  { BGP_IPV4_NODE,   &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV4M_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_IPV4M_NODE,  &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV6_NODE,   &neighbor_distribute_list_cmd                      },
  { BGP_IPV6_NODE,   &no_neighbor_distribute_list_cmd                   },
  { BGP_IPV6M_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_IPV6M_NODE,  &no_neighbor_distribute_list_cmd                   },
  { BGP_VPNV4_NODE,  &neighbor_distribute_list_cmd                      },
  { BGP_VPNV4_NODE,  &no_neighbor_distribute_list_cmd                   },

  { BGP_NODE,        &neighbor_prefix_list_cmd                          },
  { BGP_NODE,        &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_prefix_list_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_prefix_list_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_prefix_list_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_prefix_list_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_prefix_list_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_prefix_list_cmd                       },

  { BGP_NODE,        &neighbor_filter_list_cmd                          },
  { BGP_NODE,        &no_neighbor_filter_list_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_filter_list_cmd                          },
  { BGP_IPV4_NODE,   &no_neighbor_filter_list_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_IPV4M_NODE,  &no_neighbor_filter_list_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_filter_list_cmd                          },
  { BGP_IPV6_NODE,   &no_neighbor_filter_list_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_IPV6M_NODE,  &no_neighbor_filter_list_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_filter_list_cmd                          },
  { BGP_VPNV4_NODE,  &no_neighbor_filter_list_cmd                       },

  { BGP_NODE,        &neighbor_route_map_cmd                            },
  { BGP_NODE,        &no_neighbor_route_map_cmd                         },
  { BGP_IPV4_NODE,   &neighbor_route_map_cmd                            },
  { BGP_IPV4_NODE,   &no_neighbor_route_map_cmd                         },
  { BGP_IPV4M_NODE,  &neighbor_route_map_cmd                            },
  { BGP_IPV4M_NODE,  &no_neighbor_route_map_cmd                         },
  { BGP_IPV6_NODE,   &neighbor_route_map_cmd                            },
  { BGP_IPV6_NODE,   &no_neighbor_route_map_cmd                         },
  { BGP_IPV6M_NODE,  &neighbor_route_map_cmd                            },
  { BGP_IPV6M_NODE,  &no_neighbor_route_map_cmd                         },
  { BGP_VPNV4_NODE,  &neighbor_route_map_cmd                            },
  { BGP_VPNV4_NODE,  &no_neighbor_route_map_cmd                         },

  { BGP_NODE,        &neighbor_unsuppress_map_cmd                       },
  { BGP_NODE,        &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV4_NODE,   &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV4_NODE,   &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV4M_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV4M_NODE,  &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV6_NODE,   &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV6_NODE,   &no_neighbor_unsuppress_map_cmd                    },
  { BGP_IPV6M_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_IPV6M_NODE,  &no_neighbor_unsuppress_map_cmd                    },
  { BGP_VPNV4_NODE,  &neighbor_unsuppress_map_cmd                       },
  { BGP_VPNV4_NODE,  &no_neighbor_unsuppress_map_cmd                    },

  { BGP_NODE,        &neighbor_maximum_prefix_cmd                       },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_NODE,        &neighbor_maximum_prefix_warning_cmd               },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_NODE,        &neighbor_maximum_prefix_restart_cmd               },
  { BGP_NODE,        &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_NODE,        &no_neighbor_maximum_prefix_cmd                    },
  { BGP_NODE,        &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_NODE,        &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_NODE,        &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_NODE,        &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV4_NODE,   &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV4_NODE,   &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV4M_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV4M_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV6_NODE,   &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV6_NODE,   &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_IPV6M_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_IPV6M_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_cmd             },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_warning_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_warning_cmd     },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_restart_cmd               },
  { BGP_VPNV4_NODE,  &neighbor_maximum_prefix_threshold_restart_cmd     },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_cmd                    },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_val_cmd                },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_cmd          },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_warning_cmd            },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_warning_cmd  },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_restart_cmd            },
  { BGP_VPNV4_NODE,  &no_neighbor_maximum_prefix_threshold_restart_cmd  },

  { BGP_NODE,        &neighbor_allow_as_in_cmd                          },
  { BGP_NODE,        &neighbor_allow_as_in_arg_cmd                      },
  { BGP_NODE,        &no_neighbor_allow_as_in_cmd                       },
  { BGP_IPV4_NODE,   &neighbor_allow_as_in_cmd                          },
  { BGP_IPV4_NODE,   &neighbor_allow_as_in_arg_cmd                      },
  { BGP_IPV4_NODE,   &no_neighbor_allow_as_in_cmd                       },
  { BGP_IPV4M_NODE,  &neighbor_allow_as_in_cmd                          },
  { BGP_IPV4M_NODE,  &neighbor_allow_as_in_arg_cmd                      },
  { BGP_IPV4M_NODE,  &no_neighbor_allow_as_in_cmd                       },
  { BGP_IPV6_NODE,   &neighbor_allow_as_in_cmd                          },
  { BGP_IPV6_NODE,   &neighbor_allow_as_in_arg_cmd                      },
  { BGP_IPV6_NODE,   &no_neighbor_allow_as_in_cmd                       },
  { BGP_IPV6M_NODE,  &neighbor_allow_as_in_cmd                          },
  { BGP_IPV6M_NODE,  &neighbor_allow_as_in_arg_cmd                      },
  { BGP_IPV6M_NODE,  &no_neighbor_allow_as_in_cmd                       },
  { BGP_VPNV4_NODE,  &neighbor_allow_as_in_cmd                          },
  { BGP_VPNV4_NODE,  &neighbor_allow_as_in_arg_cmd                      },
  { BGP_VPNV4_NODE,  &no_neighbor_allow_as_in_cmd                       },

  { BGP_NODE,        &address_family_ipv4_cmd                           },
  { BGP_NODE,        &address_family_ipv4_safi_unicast_cmd              },
  { BGP_NODE,        &address_family_ipv4_safi_multicast_cmd            },
#ifdef HAVE_IPV6
  { BGP_NODE,        &address_family_ipv6_cmd                           },
  { BGP_NODE,        &address_family_ipv6_safi_unicast_cmd              },
  { BGP_NODE,        &address_family_ipv6_safi_multicast_cmd            },
#endif /* HAVE_IPV6 */
  { BGP_NODE,        &address_family_vpnv4_cmd                          },
  { BGP_NODE,        &address_family_vpnv4_unicast_cmd                  },

  { BGP_IPV4_NODE,   &exit_address_family_cmd                           },
  { BGP_IPV4M_NODE,  &exit_address_family_cmd                           },
  { BGP_IPV6_NODE,   &exit_address_family_cmd                           },
  { BGP_IPV6M_NODE,  &exit_address_family_cmd                           },
  { BGP_VPNV4_NODE,  &exit_address_family_cmd                           },

  { BGP_NODE,        &bgp_redistribute_ipv4_cmd                         },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_cmd                      },
  { BGP_NODE,        &bgp_redistribute_ipv4_rmap_cmd                    },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_rmap_cmd                 },
  { BGP_NODE,        &bgp_redistribute_ipv4_metric_cmd                  },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_metric_cmd               },
  { BGP_NODE,        &bgp_redistribute_ipv4_rmap_metric_cmd             },
  { BGP_NODE,        &bgp_redistribute_ipv4_metric_rmap_cmd             },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_rmap_metric_cmd          },
  { BGP_NODE,        &no_bgp_redistribute_ipv4_metric_rmap_cmd          },
#ifdef HAVE_IPV6
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_cmd                         },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_cmd                      },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_rmap_cmd                    },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_rmap_cmd                 },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_metric_cmd                  },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_metric_cmd               },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_rmap_metric_cmd             },
  { BGP_IPV6_NODE,   &bgp_redistribute_ipv6_metric_rmap_cmd             },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_rmap_metric_cmd          },
  { BGP_IPV6_NODE,   &no_bgp_redistribute_ipv6_metric_rmap_cmd          },
#endif /* HAVE_IPV6 */

  { BGP_NODE,        &neighbor_ttl_security_cmd                         },
  { BGP_NODE,        &no_neighbor_ttl_security_cmd                      },

  CMD_INSTALL_END
} ;

extern void
bgp_vty_config_cmd_init (void)
{
  /* Set configuration writer for bgp configuration
   */
  cmd_install_node_config_write(BGP_NODE, bgp_config_write);

  cmd_install_table(bgp_vty_cmd_table) ;
}
