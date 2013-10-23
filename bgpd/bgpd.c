/* BGP Daemon -- header.
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
#include <zebra.h>
#include "misc.h"

#include "command.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp.h"

#include "bgpd/bgp_table.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_routemap.h"
#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */

/* BGP process wide configuration.
 */
struct bgp_env *bm;
static struct bgp_env bgp_master;

extern struct in_addr router_id_zebra;

qpn_nexus cli_nexus = NULL;
qpn_nexus be_nexus  = NULL;
qpn_nexus re_nexus  = NULL;

/* BGP community-list.
 */
struct community_list_handler *bgp_clist;

/* privileges
 */
static zebra_capabilities_t _caps_p [] =
{
    ZCAP_BIND,
    ZCAP_NET_RAW,
    ZCAP_NET_ADMIN,
};

struct zebra_privs_t bgpd_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
  .user      = QUAGGA_USER,
  .group     = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p    = _caps_p,
  .cap_num_p = sizeof(_caps_p)/sizeof(_caps_p[0]),
  .cap_num_i = 0,
};

/*------------------------------------------------------------------------------
 * The default arguments for a bgp instance -- extern in bgpd
 */
const bgp_defaults_t bgp_default_defaults =
{
  .port                  = BGP_PORT_DEFAULT,
  .ibgp_ttl              = 255,
  .cbgp_ttl              = 255,
  .ebgp_ttl              = 1,

  .local_pref            = BGP_DEFAULT_LOCAL_PREF,
  .med                   = BGP_MED_MIN,
  .weight                = 0,

  .holdtime_secs         = BGP_DEFAULT_HOLDTIME,
  .keepalive_secs        = BGP_DEFAULT_KEEPALIVE,
  .connect_retry_secs    = BGP_DEFAULT_CONNECT_RETRY,
  .accept_retry_secs     = BGP_DEFAULT_ACCEPT_RETRY,
  .open_hold_secs        = BGP_DEFAULT_OPENHOLDTIME,

  .ibgp_mrai_secs        = BGP_DEFAULT_IBGP_MRAI,
  .cbgp_mrai_secs        = BGP_DEFAULT_CBGP_MRAI,
  .ebgp_mrai_secs        = BGP_DEFAULT_EBGP_MRAI,

  .idle_hold_min_secs    = BGP_DEFAULT_IDLE_HOLD_MIN_SECS,
  .idle_hold_max_secs    = BGP_DEFAULT_IDLE_HOLD_MAX_SECS,
  .restart_time_secs     = BGP_DEFAULT_RESTART_TIME,
  .stalepath_time_secs   = BGP_DEFAULT_STALEPATH_TIME,

  .distance_ebgp         = ZEBRA_EBGP_DISTANCE_DEFAULT,
  .distance_ibgp         = ZEBRA_IBGP_DISTANCE_DEFAULT,
  .distance_local        = ZEBRA_IBGP_DISTANCE_DEFAULT,
};

/*------------------------------------------------------------------------------
 * A name index is used for most names in all configuration.
 *
 * The function of this name index is simply to facilitate establishing whether
 * two configuration settings are the same.
 */
static name_index bgp_name_index       = NULL ;
static qpt_mutex  bgp_name_index_mutex = NULL ;

inline static void BGP_NAME_INDEX_LOCK(void)
{
  qpt_mutex_lock(bgp_name_index_mutex) ;
} ;

inline static void BGP_NAME_INDEX_UNLOCK(void)
{
  qpt_mutex_unlock(bgp_name_index_mutex) ;
} ;

/*==============================================================================
 * Initialisation and shut-down.
 */

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_master_init (void)
{
  memset (&bgp_master, 0, sizeof (bgp_env_t));

  bm             = &bgp_master;

  bm->master     = master ;             /* copy of the thread global    */
  bm->start_time = bgp_clock ();

  qassert(master != NULL) ;             /* initialised earlier          */

  /* Implicitly:
   *
   *   address           = NULL   -- no special listen address
   *   options           = 0      -- no options set
   *   as2_speaker       = false  -- as4 speaker by default
   *   peer_linger_count = 0      -- no peers lingering
   */

  bgp_name_index       = name_index_new() ;
  bgp_name_index_mutex = NULL ;
} ;

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_init (void)
{
  /* BGP VTY commands installation.
   */
  bgp_vty_init ();

  /* Init zebra.
   */
  bgp_zebra_init ();

  /* BGP inits.
   */
  bgp_peer_index_init();
  bgp_attr_start();
  bgp_debug_init ();
  bgp_dump_init ();
  bgp_route_init ();
  bgp_route_map_init ();
  bgp_scan_init ();
  bgp_mplsvpn_init ();

  /* Access list initialize.
   */
  access_list_init();
  access_list_add_hook (bgp_peer_distribute_update);
  access_list_delete_hook (bgp_peer_distribute_update);

  /* Filter list initialize.
   */
  bgp_filter_init ();
  as_list_add_hook (bgp_peer_aslist_update);
  as_list_delete_hook (bgp_peer_aslist_update);

  /* Prefix list initialize
   */
  prefix_list_init();
  prefix_list_add_hook (bgp_peer_prefix_list_update);
  prefix_list_delete_hook (bgp_peer_prefix_list_update);

  /* Community list initialize.
   */
  bgp_clist = community_list_init ();

#ifdef HAVE_SNMP
  bgp_snmp_init ();
#endif /* HAVE_SNMP */
}

/*------------------------------------------------------------------------------
 * If not terminating, reset all peers now
 */
void
bgp_terminate (bool terminating, bool retain_mode)
{
  bgp_inst bgp;
  bgp_peer peer;
  struct listnode *node, *nnode;

  /* If we are retaining, then turn off changes to the FIB.
   */
  if (retain_mode)
    {
      assert(terminating) ;             /* Can only retain when terminating  */
      bgp_option_set(BGP_OPT_NO_FIB) ;
    } ;

  /* For all bgp instances...
   */
  for (bgp = ddl_head(bm->bgps) ; bgp != NULL ; bgp = ddl_next(bgp, bgp_list))
    {
      /* ...delete or down all peers.
       */
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        if (terminating)
          bgp_peer_delete(peer) ;
        else
          bgp_peer_down(peer, PEER_DOWN_USER_RESET) ;
    } ;
} ;

/*==============================================================================
 * BGP global configuration setting.
 */

/*------------------------------------------------------------------------------
 * Set a global bgp option.
 */
extern bgp_ret_t
bgp_option_set (bgp_option_t flag)
{
  switch (flag)
    {
      case BGP_OPT_NO_FIB:
      case BGP_OPT_MULTIPLE_INSTANCE:
      case BGP_OPT_CONFIG_CISCO:
        bm->options |= flag ;
        break ;

      default:
        return BGP_ERR_INVALID_FLAG;
    } ;

  return BGP_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Unset a global bgp option.
 */
extern bgp_ret_t
bgp_option_unset (bgp_option_t flag)
{
  bgp_inst bgp ;

  switch (flag)
    {
      case BGP_OPT_MULTIPLE_INSTANCE:
        bgp = ddl_head(bm->bgps) ;

        if ((bgp != NULL) && (ddl_next(bgp, bgp_list) != NULL))
          return BGP_ERR_MULTIPLE_INSTANCE_USED;
        fall_through ;

      case BGP_OPT_NO_FIB:
      case BGP_OPT_CONFIG_CISCO:
        bm->options &= ~flag ;
        break;

      default:
        return BGP_ERR_INVALID_FLAG;
    } ;

  return BGP_SUCCESS;
}

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Get bgp_nref for the given name -- incrementing its refcount.
 */
extern bgp_nref
bgp_nref_get(chs_c name)
{
  nref_c nref ;

  if ((name == NULL) || (name[0] == '\0'))
    return NULL ;

  BGP_NAME_INDEX_LOCK() ;

  nref = ni_nref_get_c(bgp_name_index, name) ;

  BGP_NAME_INDEX_UNLOCK() ;

  return nref ;
} ;

/*------------------------------------------------------------------------------
 * Increment refcount for given nref (if any).
 */
extern bgp_nref
bgp_nref_inc(bgp_nref nref)
{
  if (nref != NULL)
    {
      BGP_NAME_INDEX_LOCK() ;

      ni_nref_inc(nref) ;

      BGP_NAME_INDEX_UNLOCK() ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Decrement refcount for given nref (if any).
 */
extern bgp_nref
bgp_nref_dec(bgp_nref nref)
{
  if (nref != NULL)
    {
      BGP_NAME_INDEX_LOCK() ;

      ni_nref_dec(nref) ;

      BGP_NAME_INDEX_UNLOCK() ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set given pointer to nref to the given name.
 */
extern void
bgp_nref_set(bgp_nref* p_nref, chs_c name)
{
  if ((name != NULL) && (name[0] == '\0'))
    name = NULL ;

  BGP_NAME_INDEX_LOCK() ;

  ni_nref_set_c(p_nref, bgp_name_index, name) ;

  BGP_NAME_INDEX_UNLOCK() ;
} ;

extern void
bgp_nref_copy(bgp_nref* p_nref, bgp_nref nref)
{
  BGP_NAME_INDEX_LOCK() ;

  ni_nref_set_copy(p_nref, nref) ;

  BGP_NAME_INDEX_UNLOCK() ;
} ;

/*------------------------------------------------------------------------------
 *
 */
/*------------------------------------------------------------------------------
 * Does the name of the bgp instance match the given name ?
 *
 * NB: NULL and empty names are the same here.  So the "unnamed view" has two
 *     equivalent names.
 */
extern bool
bgp_name_match(chs_c name1, chs_c name2)
{
  if (name1 == NULL)
    name1 = "" ;

  if (name2 == NULL)
    name2 = "" ;

  return strsame(name1, name2) ;
} ;

