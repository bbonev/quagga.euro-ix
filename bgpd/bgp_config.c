/* BGP Configuration Handling
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

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_inst_config.h"
#include "bgpd/bgp_peer_config.h"

#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"


/*==============================================================================
 * Here we manage the configuration of bgp instances, peers and peer-groups.
 *
 * Also the transfer of that configuration to the running state for bgp
 * instances and peers.
 *
 *
 *
 */
/*------------------------------------------------------------------------------
 * Configuration changes handled here include:
 *
 *   * all changes to bgp instances
 *
 *   * all changes to peers  -- changes to the a peer itself, and to its
 *                              address families
 *
 *   * all changes to groups -- changes to the a group itself, and to its
 *                              address families.
 *
 * The "vty" makes changes to the "required" configuration.  The procedure is:
 *
 *   * before a change, signal that a change may be about to be made for
 *     one of the above parts of the configuration.
 *
 *     This will trigger the completion of changes made to a different part
 *     of the configuration.
 *
 *   * after a change, signal that a change has been made.
 *
 *     This will set pending the completion of the change, and any further
 *     changes to the same part.
 *
 *     A timer will be set to clear up pending changes.
 *
 * The completion of changes to a given part of the configuration means:
 *
 *   * making any further implied changes to the "required" configuration.
 *
 *     So, for changes to default values in a bgp instance, all peers and
 *     groups need to be updated.  And, for changes to groups, all members
 *     need to be updated.
 *
 *   * Merging the resulting changes into peers/sessions, and restarting
 *     those as required.
 *
 *==============================================================================
 * Group and Peer Relationship.
 *
 * Configuration settings come in various flavours:
 *
 *   * simple flags:  which may be true/false or on/off
 *
 *   * simple values: a single value, which may or may not include a NULL/empty
 *
 *                    where the value includes
 *
 *   * combination flags: where changing one may interact with others
 *
 *   * compound values: some combination of all the above.
 *
 * There are three distinct configuration operations:
 *
 *   * "set on"  -- so: simple flags are set to on
 *
 *                      simple values are set to a value which is not
 *                      NULL/empty
 *
 *                      combination flags and compound values have some
 *                      definite state.
 *
 *                  In all cases the setting has a definite value.
 *
 *   * "unset"   -- so: simple flags are set to off
 *
 *                      simple values are set NULL/empty and/or absent
 *
 *                      combination flags and compound values are off and/or
 *                      NULL/empty and/or absent.
 *
 *                  In all cases the setting definitely has no value.
 *
 * For values which do not have a NULL/empty value, a separate flag is required
 * to represent that.
 *
 * The third state is:
 *
 *   * "set off" -- so: simple flags are set to off
 *
 *                      simple values with a NULL/empty are set to that
 *
 *                      combination flags and compound values are set off
 *                      and/or NULL/empty.
 *
 *                  NB: values which do not have a NULL/empty cannot be
 *                      "set off", they can only be set to some definite value.
 *
 * The third state has significance for settings which may be inherited either
 * from a peer-group or from the bgp instance.
 *
 * The inheritance mechanism is affected by ordering.  Where a setting may be
 * inherited from a group what does it mean when:
 *
 *   * the setting is changed for the group-member and either:
 *
 *      a) the group setting is "unset"
 *
 *      b) the group setting is "set on/off".
 *
 *   * the setting is changed for the group and for a given member either:
 *
 *      a) the member setting is "unset"
 *
 *      b) the member setting is "set on/off".
 *
 *   * a peer is added to a group, and it currently has:
 *
 *      a) a setting which is "set on/off", and the group is "unset"
 *
 *      b) a setting which is "set on/off", and the group is "set on/off"
 *
 *   * a peer is removed from a group and has settings which are "locally"
 *     "set on/off".
 *
 *     Noting that removal from a group includes the dismantling of a group !
 *
 * The general solution to this conundrum is:
 *
 *   * for configuration files, groups are written before neighbors, so
 *     it is possible for neighbors to have individual settings, as variations
 *     from the group.
 *
 *     So... in general a setting changed for a group-member may override
 *     the current setting inherited from the group.
 *
 *   * changes made to the group immediately override all settings in all
 *     current members.
 *
 *     So... "edits" to the configuration made at the command line have simple
 *     semantics.  If there were a mechanism to allow individual peer settings
 *     to persist, then at the command line any change to the group would have
 *     to be followed by a check on the effect on all its members -- which is
 *     hard work... particularly as one might assume that 99% of the time
 *     changing all the members is the required effect.
 *
 *     When editing a configuration file, it is necessary to then check all
 *     group-members, and remove any individual setting they may have.
 *
 *   * adding a peer to a group immediately overrides all settings which are
 *     present in the group.
 *
 *     In current Quagga, this preserves some, but not all, existing peer
 *     settings where the group is unset.  This is less destructive than
 *     clearing all peer settings.  But has little else to recommend it.
 *
 *   * removing a peer from a group immediately clears all settings down to
 *     their default state.
 *
 * For the "legacy" Quagga a configuration setting in a group member may have
 * one of a number of relationships with the group.  Those are:
 *
 *   * "flag" semantics:
 *
 *        May be set true if not set true by group (or if already set true).
 *        May not unset if set true by group.
 *
 *        Group set/unset affects all members.
 *        Add to group: all flags follow group.
 *        Remove from/dismantle group: all flags unset.
 *
 *   * "group flag" semantics:
 *
 *        Group member may not change the flag at any time.
 *
 *        Otherwise, as "flag".
 *
 *   * "value" semantics (a) and (b):
 *
 *        May set at any time.
 *        Group member follows group when set.
 *        Unset reverts to group value (for group member), or to default/NULL.
 *
 *        Add to group: value follows group: (a) unsetting value if group unset
 *
 *                                           (b) leaving value if group unset
 *
 *        Remove from/dismantle group: (a) revert to default/NULL
 *
 *                                     (b) leave value if set.
 *
 *        A 'config' flag may be used to show the value is set.
 *
 *        There are some variations on this theme, where the peer setting and
 *        the group setting are the same as each other.
 *
 *   * "group value" semantics:
 *
 *        Group member may not set or unset value.
 *        Group members follow group value.
 *
 *        Add to group: value follows group
 *        Remove from/dismantle group: revert to default/NULL
 *
 * The new code
 *
 *
 */

/*------------------------------------------------------------------------------
 * A name index is used for most names in all configuration.
 *
 * The function of this name index is simply to facilitate establishing whether
 * two configuration settings are the same.
 */
name_index bgp_config_name_index ;      /* extern in .h         */

/*==============================================================================
 * Processing the required configuration into the running configuration.
 */

/*------------------------------------------------------------------------------
 * Signal a change to some part of the configuration.
 */
extern void
bgp_config_part_prepare(bgp_config_pending_part_t type, void* part)
{




} ;

/*------------------------------------------------------------------------------
 * Signal a change to the given bgp instance
 */
extern bgp_bconfig
bgp_config_inst_prepare(bgp_inst bgp)
{
  bgp_bconfig bc ;

  bc = bgp->c ;
  assert(bc != NULL) ;

  qassert(bc->parent_inst == bgp) ;

  return bc ;
} ;

/*------------------------------------------------------------------------------
 * Signal a change to the given bgp instance address family specific stuff
 */
extern bgp_baf_config
bgp_config_inst_af_prepare(bgp_inst bgp, qafx_t qafx)
{
  bgp_bconfig    bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  return bc->afc ;
} ;

/*------------------------------------------------------------------------------
 * Signal a change to peer or peer group.
 *
 * This is a stop gap, while the vty-stuff is still operating on bgp_peer
 * structures.
 */
extern bgp_pconfig
bgp_config_peer_prepare(bgp_peer peer)
{
  bgp_pconfig pc ;

  pc = peer->c ;

  if (peer->ptype == PEER_TYPE_GROUP)
    bgp_config_part_prepare(bgp_cpGroup, peer) ;
  else
    bgp_config_part_prepare(bgp_cpPeer, peer) ;

  qassert(pc->parent_peer == peer) ;

  return pc ;
} ;

/*------------------------------------------------------------------------------
 * Signal a change to peer or peer group.
 *
 * This is a stop gap, while the vty-stuff is still operating on bgp_peer
 * structures.
 */
extern bgp_paf_config
bgp_config_peer_af_prepare(bgp_peer peer, qafx_t qafx)
{
  bgp_pconfig pc ;
  bgp_paf_config  pafc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (!pcs_qafx_config(pc, qafx))
    pafc = NULL ;
  else
    {
      pafc = pc->afc[qafx] ;
      qassert(pafc != NULL) ;
    } ;

  return pafc ;
} ;












extern uint
bgp_config_part_changed(bgp_config_pending_part_t type,
                                          void* part, qafx_t qafx, uint setting)
{
  switch (type)
    {
      case bgp_cpInstance:
        ;

      case bgp_cpPeer:
        ;

      case bgp_cpGroup:
        ;

      default:
        break ;
    } ;

  return 0 ;
} ;

#if 0
extern uint
bgp_config_peer_changed(bgp_peer peer, qafx_t qafx, uint setting)
{
  if (peer->ptype == PEER_TYPE_GROUP)
    bgp_config_part_changed(bgp_cpGroup, peer->c.group, qafx, setting) ;
  else
    bgp_config_part_changed(bgp_cpPeer, peer, qafx, setting) ;

  return 0 ;
} ;
#endif











/*==============================================================================
 * Legacy Option Stuff
 *
 *
 *
 */

/*==============================================================================
 * Construction of a running state from a given bgp_peer_config.
 *
 */
static bgp_prib bgp_config_prib(bgp_prun prnew, bgp_paf_config pafconf,
                                                                  qafx_t qafx) ;

/*------------------------------------------------------------------------------
 * Construct a new, configured but otherwise empty prun and its prib(s).
 *
 *
 */
extern bgp_prun
bgp_config_prun(bgp_pconfig pconf)
{
  bgp_run          brun ;
  bgp_prun         prnew ;
  bgp_cops         cops ;
  bgp_session_args args ;
  uint          prib_count ;
  qafx_t        qafx ;
  qafx_set_t    af_set_up ;

  brun = pconf->parent_peer->parent_bgp->brun ;

  prnew = bgp_prun_new() ;

  /* The new prun has been zeroized, which sets:
   *
   *   * parent                 -- set below
   *
   *   * su_name                -- set below
   *   * name                   -- set below
   *   * p_desc                 -- set below
   *
   *   * brun                   -- X            -- set below
   *
   *   * state                  -- pInitial
   *   * idle                   -- X            -- set below
   *   * change                 -- bgp_ccNone
   *
   *   * nsf_enabled            -- false        -- not, yet
   *   * nsf_restarting         -- false        -- not, yet
   *
   *   * peer_ie                -- NULL         -- set if/when "started"
   *   * session                -- NULL         -- ditto
   *
   *   * session_state          -- pssInitial
   *
   *   * lock                   -- 0
   *
   *   * sort                   -- X            -- set below
   *
   *   * down_pending_r         -- XXX          TODO !!
   *
   *   * uptime                 -- 0            -- none, yet
   *   * readtime               -- 0            -- none, yet
   *   * resettime              -- 0            -- none, yet
   *
   *   * log                    -- NULL         -- none, yet
   *
   *   * shared_network         -- bool
   *   * nexthop                -- bgp_nexthop_t
   *
   *   * last_reset             -- PEER_DOWN_NULL
   *   * note                   -- NULL         -- none, yet
   *
   *   * af_set_up              -- set below -- starts qafx_empty_set
   *   * af_running             -- qafx_empty_set       -- none, yet
   *
   *   * prib                   -- set below, as required   -- starts NULLs
   *   * prib_running_count     -- set below, as required   -- starts 0
   *   * prib_running           -- set below, as required   -- starts NULLs
   *
   *   * rr_pending             -- NULLs        -- none, yet
   *
   *   * cops_r                 -- set below
   *   * args_r                 -- set below
   *
   *   * change_local_as        -- set below
   *   * change_local_as_prepend -- set below
   *   * disable_connected_check -- set below
   *   * weight                 -- set below
   *   * mrai                   -- set below
   *
   *   * qt_restart             -- NULL         -- none, yet
   *
   *   * idle_hold_time         -- 0            -- none, yet
   *   * v_asorig               -- XXX
   *   * v_gr_restart           -- XXX
   *
   *   * t_gr_restart           -- XXX
   *   * t_gr_stale             -- XXX
   *
   *   * established            -- 0            -- none, yet
   *   * dropped                -- 0            -- none, yet
   *
   *   * table_dump_index       -- 0            -- none, yet
   */
   confirm(bgp_pInitial     == 0) ;
   confirm(bgp_ccNone       == 0) ;
   confirm(bgp_pssInitial   == 0) ;
   confirm(PEER_DOWN_NULL   == 0) ;
   confirm(qafx_empty_set   == 0) ;

   prnew->idle = bgp_pisConfiguring ;

  /* The naming of the prun.
   *
   * For the description we just point at the pointer in the parent...
   * ...this does not affect the running state.
   *
   * Sadly, 'C' gets its underwear in a tangle and rejects:
   *
   *           prnew->p_desc = &((chs_c)(pconf->desc)) ;
   *
   * ...so we have to cast the result of the & :-(
   */
  prnew->parent_peer = pconf->parent_peer ;
  prnew->brun        = brun ;

  prnew->su_name = pconf->parent_peer->su_name ;
  prnew->name    = pconf->parent_peer->name ;
  prnew->p_desc  = (chs_c const*)&pconf->desc ;

  /* Initialise cops and args.
   */
  cops   = &prnew->cops_r ;
  bgp_cops_init_new(cops) ;

  args   = &prnew->args_r ;
  bgp_session_args_init_new(args) ;

  /* Fill in default values for things in the "brun".
   *
   *   * cops_r.port
   *           .connect_retry_secs
   *           .accept_retry_secs
   *           .open_hold_secs
   *
   *   * args_r.local_as
   *           .local_id
   *           .can_mp_ext
   *           .can_as4
   *           .can_rr
   *           .gr.can
   *           .holdtime_secs
   *           .keepalive_secs
   *
   *   * weight
   *   * mrai
   *
   *   * v_asorig               -- XXX
   *   * v_gr_restart           -- XXX
   *
struct bgp_run
{
  vhash_table   rc_name_index ;
  bgp_rcontext  rc_view ;

  in_addr_t     router_id_r;
  in_addr_t     cluster_id_r ;

  as_t    my_as ;
  as_t    ebgp_as ;

  as_t    confed_id_r ;
  asn_set confed_peers_r ;

  bool    check_confed_id_r ;
  bool    check_confed_id_all_r ;

  bool  do_graceful_restart ;
  bool  do_prefer_current_selection ;
  bool  do_enforce_first_as ;
  bool  do_import_check ;
  bool  do_log_neighbor_changes ;

  bool  no_client_to_client ;
  bool  no_fast_ext_failover ;

  bgp_args_t    args_r ;


struct bgp_args
  uint16_t port ;

  uint  local_pref;
  uint  med ;
  uint  weight ;

  uint  holdtime_secs ;
  uint  keepalive_secs ;
  uint  connect_retry_secs ;
  uint  accept_retry_secs ;
  uint  open_hold_secs ;

  uint  ibgp_mrai_secs ;
  uint  cbgp_mrai_secs ;
  uint  ebgp_mrai_secs ;

  uint  idle_hold_min_secs ;
  uint  idle_hold_max_secs ;

  uint  restart_time_secs ;
  uint  stalepath_time_secs ;

  byte  distance_ebgp ;
  byte  distance_ibgp ;
  byte  distance_local ;

   */








  /* Transfer stuff from the config->c_flags.
   *
   *   PEER_FLAG_SHUTDOWN              -- XXX
   *
   *   PEER_FLAG_PASSIVE                 )
   *   PEER_FLAG_ACTIVE                  )
   *   PEER_FLAG_DONT_CAPABILITY         )  see c_cops !
   *   PEER_FLAG_OVERRIDE_CAPABILITY     )
   *   PEER_FLAG_STRICT_CAP_MATCH        )
   *   PEER_FLAG_DYNAMIC_CAPABILITY      )
   *   PEER_FLAG_DYNAMIC_CAPABILITY_DEP  )
   *
   *   PEER_FLAG_DISABLE_CONNECTED_CHECK
   *   PEER_FLAG_CHANGE_LOCAL_AS_PREPEND
   */
  prnew->disable_connected_check =
                         (pconf->c_flags & PEER_FLAG_DISABLE_CONNECTED_CHECK) ;
  prnew->change_local_as_prepend =
                         (pconf->c_flags & PEER_FLAG_CHANGE_LOCAL_AS_PREPEND) ;

  /* Transfer other simple settings
   */
  prnew->sort                     = pconf->c_sort ;
  prnew->change_local_as_prepend  = pconf->c_change_local_as ;

  prnew->weight                   = pconf->c_weight ;
  prnew->mrai                     = pconf->c_mrai ;

  /* Transfer the cops -- making sure we start from a clean state.
   *
   * We copy everything, except for:
   *
   *   * su_remote              -- set to copy of su_name
   *
   *   * conn_state             -- copy only bgp_csMayMask
   *
   *   * ttl_out                -- 0    -- N/A
   *   * ttl_min                -- 0    -- N/A
   *
   *   * ifindex                -- 0    -- N/A
   */
  cops   = &prnew->cops_r ;
  c_cops = &pconf->c_cops ;

  bgp_cops_init_new(cops) ;

  sockunion_copy(&cops->su_remote, prnew->su_name) ;

  cops->su_local                = c_cops->su_local ;
  cops->port                    = c_cops->port ;
  cops->conn_state              = c_cops->conn_state & bgp_csMayMask ;
  cops->can_notify_before_open  = c_cops->can_notify_before_open ;
  cops->idle_hold_max_secs      = c_cops->idle_hold_max_secs ;
  cops->connect_retry_secs      = c_cops->connect_retry_secs ;
  cops->accept_retry_secs       = c_cops->accept_retry_secs ;
  cops->open_hold_secs          = c_cops->open_hold_secs ;
  cops->ttl                     = c_cops->ttl ;
  cops->gtsm                    = c_cops->gtsm ;

  strncpy(cops->password, c_cops->password, sizeof(cops->password)) ;
  confirm(sizeof(cops->password) == BGP_PASSWORD_SIZE) ;

  strncpy(cops->ifname, c_cops->ifname, sizeof(cops->ifname)) ;
  confirm(sizeof(cops->ifname) == IF_NAMESIZE) ;

  /* Transfer the args -- making sure we start from a clean state.
   *
   * We copy everything, except for:
   *
   *   * cap_suppressed         -- N/A
   *
   *   * can_af                 -- ????
   *
   *   * gr.can                 -- copied
   *   * gr.restarting          -- false   )
   *   * gr.restart_time        -- 0       )  Left clear
   *   * gr.can_preserve        -- empty   )
   *   * gr.has_preserved       -- empty   )
   */
  args   = &prnew->args_r ;
  c_args = &pconf->c_args ;

  bgp_session_args_init_new(args) ;

  args->local_as                = c_args->local_as ;
  args->local_id                = c_args->local_id ;
  args->remote_as               = c_args->remote_as ;
  args->remote_id               = c_args->remote_id ;
  args->can_capability          = c_args->can_capability ;
  args->can_mp_ext              = c_args->can_mp_ext ;
  args->can_as4                 = c_args->can_as4 ;
  args->cap_af_override         = c_args->cap_af_override ;
  args->cap_strict              = c_args->cap_strict ;
  args->can_rr                  = c_args->can_rr ;

  args->gr.can                  = c_args->gr.can ;

  args->can_orf                 = c_args->can_orf ;
  args->can_orf_pfx             = c_args->can_orf_pfx ;
  args->can_dynamic             = c_args->can_dynamic ;
  args->can_dynamic_dep         = c_args->can_dynamic_dep ;
  args->holdtime_secs           = c_args->holdtime_secs ;
  args->keepalive_secs          = c_args->keepalive_secs ;

  /* Now fill pribs for all the c_af_configured -- where the afi/safi is
   * not 'disabled'.
   */
  af_set_up     = qafx_empty_set ;
  prib_count    = 0 ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      qafx_bit_t  qb ;
      bgp_paf_config pafconf ;

      qb = qafx_bit(qafx) ;

      if (!(pconf->c_af_configured & qb))
        continue ;

      pafconf = pconf->c_af[qafx] ;

      qassert(pafconf != NULL) ;
      if (pafconf == NULL)
        continue ;

      if (pafconf->c_disabled)
        continue ;

      prnew->prib_running[prib_count] = bgp_config_prib(prnew, pafconf, qafx) ;

      prib_count += 1 ;
      af_set_up  |= qb ;
    } ;

  prnew->prib_running_count = prib_count ;
  prnew->af_set_up          = af_set_up ;

  /* And return what we have constructed.
   */
  return prnew ;
} ;

/*------------------------------------------------------------------------------
 *
 */
static bgp_prib
bgp_config_prib(bgp_prun prnew, bgp_paf_config pafconf, qafx_t qafx)
{
  bgp_prib  prib ;
  bgp_paf_flag_t  caff ;
  uint i ;

  prib = bgp_prib_new(prnew, qafx) ;

  /* Creation of the new prib leaves it pretty much empty, but attached to the
   * prnew bgp_prun so:
   *
   *   * prib->prun        = prnew
   *   * prnew->prib[qafx] = prib
   *
   * From the pafconf will now will in:
   *
   *   * soft_reconfig          -- false        )
   *   * route_server_client    -- false        )
   *   * route_reflector_client -- false        )
   *   * send_community         -- false        )
   *   * send_ecommunity        -- false        )
   *   * next_hop_self          -- false        )
   *   * next_hop_unchanged     -- false        )
   *   * next_hop_local_unchanged  -- false     )
   *   * as_path_unchanged      -- false        )
   *   * remove_private_as      -- false        )
   *   * med_unchanged          -- false        )
   *   * default_originate      -- false        )
   *
   *   * allow_as_in             -- 0            )
   *
   *   * dlist                  -- NULLs        -- none, yet
   *   * plist                  -- NULLs        -- none, yet
   *   * flist                  -- NULLs        -- none, yet
   *   * rmap                   -- NULLs        -- none, yet
   *   * us_rmap                -- NULL         -- none, yet
   *   * default_rmap           -- NULL         -- none, yet
   *   * orf_plist              -- NULL         -- none, yet
   *
   *   * pmax                   -- X            -- reset, below
   *
   */
  caff = pafconf->c_flags ;

  prib->soft_reconfig            = (caff & PEER_AFF_SOFT_RECONFIG) ;
  prib->route_server_client      = (caff & PEER_AFF_RSERVER_CLIENT) ;
  prib->route_reflector_client   = (caff & PEER_AFF_REFLECTOR_CLIENT) ;
  prib->send_community           = (caff & PEER_AFF_SEND_COMMUNITY) ;
  prib->send_ecommunity          = (caff & PEER_AFF_SEND_EXT_COMMUNITY) ;
  prib->next_hop_self            = (caff & PEER_AFF_NEXTHOP_SELF) ;
  prib->next_hop_unchanged       = (caff & PEER_AFF_NEXTHOP_UNCHANGED) ;
  prib->next_hop_local_unchanged = (caff & PEER_AFF_NEXTHOP_LOCAL_UNCHANGED) ;
  prib->as_path_unchanged        = (caff & PEER_AFF_AS_PATH_UNCHANGED) ;
  prib->remove_private_as        = (caff & PEER_AFF_REMOVE_PRIVATE_AS) ;
  prib->med_unchanged            = (caff & PEER_AFF_MED_UNCHANGED) ;
  prib->default_originate        = (caff & PEER_AFF_DEFAULT_ORIGINATE) ;

  prib->allow_as_in = pafconf->c_allow_as_in ;

  /* Filters and route-maps.
   *
   * NB: creates a reference to the filter/route-map, complete with ref-count.
   */
  for (i = FILTER_IN; i < FILTER_MAX; i++)
    {
      prib->dlist[i] = access_list_get_ref(get_qAFI(qafx),
                                                     pafconf->c_dlist_name[i]) ;
      prib->plist[i] = prefix_list_get_ref(get_qAFI(qafx),
                                                     pafconf->c_plist_name[i]) ;
      prib->flist[i] = as_list_get_ref(pafconf->c_flist_name[i]) ;
    } ;

  for (i = RMAP_IN; i < RMAP_COUNT; i++)
    prib->rmap[i] = route_map_get_ref(pafconf->c_rmap_name[i]) ;

  prib->us_rmap      = route_map_get_ref(pafconf->c_us_rmap_name) ;
  prib->default_rmap = route_map_get_ref(pafconf->c_default_rmap_name) ;

  prib->orf_plist    = prefix_list_get_ref(get_qAFI(qafx),
                                                    pafconf->c_orf_plist_name) ;
  /* Max prefix count.
   */
  prib->pmax = pafconf->c_pmax ;

  /* Return the filled in prib.
   */
  return prib ;
} ;






