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
#include "bgpd/bgpd.h"
#include "bgpd/bgp_config.h"
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
 * The new code:
 *
 *   *
 *
 *
 */

/*==============================================================================
 * Processing the required configuration into the running configuration.
 */

#if 0
/*------------------------------------------------------------------------------
 * Signal a change to some part of the configuration.
 */
extern void
bgp_config_part_prepare(bgp_config_pending_part_t type, void* part)
{




} ;
#endif

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

  return bc->afc[qafx] ;
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

#if 0
  if (peer->ptype == PEER_TYPE_GROUP)
    bgp_config_part_prepare(bgp_cpGroup, peer) ;
  else
    bgp_config_part_prepare(bgp_cpPeer, peer) ;
#endif

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

/*------------------------------------------------------------------------------
 * Signal that configuration for peer has changed.
 */
extern void
bgp_config_queue(bgp_peer peer)
{
  ;
}

/*==============================================================================
 * Legacy Option Stuff
 *
 *
 *
 */

/*==============================================================================
 * Making a parameter collection for a given BGP instance.
 *
 */
static bgp_prun_param bgp_assemble_peer(bgp_pconfig pc, bgp_run_param brp) ;
static bgp_grun bgp_assemble_grun(bgp_nref name, bgp_run_param brp) ;
static void bgp_assemble_peer_settings(bgp_prun_param prp,
                                            bgp_pconfig pc, bgp_run_param brp) ;
static as_t bgp_assemble_local_as(bgp_prun_param prp, bgp_run_param brp) ;
static uint bgp_assemble_default_mrai(bgp_prun_param prp, bgp_run_param brp) ;
static uint bgp_assemble_default_ttl(bgp_prun_param prp, bgp_run_param brp) ;
static void bgp_assemble_peer_af_settings(bgp_prib_param pribp,
                   bgp_paf_config pafc, bgp_run_param brp, bgp_prun_param prp) ;
static int bgp_grun_cmp_name (const cvp* p_name, const cvp* p_grun) ;

/*------------------------------------------------------------------------------
 * Assemble all the configuration for a BGP Instance.
 *
 * Note that this is an atomic operation wrt the configuration of the BGP
 * Instance and the configuration of all its peers and groups.
 */
extern bgp_assembly
bgp_assemble(bgp_inst bgp)
{
  bgp_assembly  assembly ;
  bgp_run_param brp ;
  bgp_bconfig   bc ;
  qafx_t        qafx ;
  bgp_peer      group, peer ;
  uint          i ;

  assembly = XCALLOC(MTYPE_BGP_ASSEMBLY, sizeof(bgp_assembly_t)) ;

  /* Zeroizing the assembly has set:
   *
   *   * parent_bgp             -- X            -- set below
   *   * brp                    -- X            -- set below
   *   * prun_params            -- empty vector -- set below
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;

  assembly->parent_bgp = bgp ;
  assembly->brp = brp  = XCALLOC(MTYPE_BGP_ASSEMBLY, sizeof(bgp_run_param_t)) ;

  /* Zeroizing the bgp_run_params has set:
   *
   *   * my_as                          -- follows config
   *   * my_as_ebgp                     -- X            -- set below
   *
   *   * confed_id                      -- BGP_ASN_NULL -- set if required
   *   * router_id                      -- BGP_ID_NULL  -- set if configured
   *   * cluster_id                     -- BGP_ID_NULL  -- set below
   *
   *   * cluster_id_set ;               -- false        -- set below
   *
   *   * do_check_confed_id             -- false        -- set below
   *   * do_check_confed_id_all         -- false        -- TODO
   *
   *   * no_client_to_client            -- bcs_NO_CLIENT_TO_CLIENT
   *   * do_enforce_first_as            -- bcs_ENFORCE_FIRST_AS
   *   * do_import_check                -- bcs_IMPORT_CHECK
   *   * no_fast_ext_failover           -- bcs_NO_FAST_EXT_FAILOVER
   *   * do_log_neighbor_changes        -- bcs_LOG_NEIGHBOR_CHANGES
   *   * do_graceful_restart            -- bcs_GRACEFUL_RESTART
   *
   *   * defs                           -- X            -- set below
   *
   *   * gruns                          -- empty vector -- set below
   *
   *   * afp                            -- NULLs        -- none yet
   *
   * From the bgp_bconfig we then set:
   *
   *   * my_as                          -- as per configuration
   *   * my_as_ebgp                     -- same as my_as unless confed_id is
   *                                       set
   *
   *   * flags which are set_on, as noted above
   *
   *   * router_id                      -- set if configuration sets it.
   *
   *   * confed_id                      -- if set 'on'
   *   * cluster_id                     -- if set 'on'
   *                                       otherwise, is copy of router_id.
   *
   *   * defs                           -- where set 'on'
   *
   *   * afc                            -- see below
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;
  confirm(BGP_ASN_NULL == 0) ;
  confirm(BGP_ID_NULL  == 0) ;

  bc = bgp->c ;

  brp->my_as      = bc->my_as ;
  brp->my_as_ebgp = bc->my_as ;         /* unless we have confed_id     */

  if (bcs_is_set_on(bc, bcs_router_id))
    brp->router_id = bc->router_id ;

  if (bcs_is_set_on(bc, bcs_confed_id))
    {
      brp->confed_id  = bc->confed_id ;
      brp->my_as_ebgp = bc->confed_id ;

      brp->do_check_confed_id = (brp->my_as != brp->my_as_ebgp) ;
    } ;

  if (bcs_is_set_on(bc, bcs_cluster_id))
    {
      brp->cluster_id_set = true ;
      brp->cluster_eid    = bc->cluster_id ;
    }
  else
    {
      brp->cluster_id_set = false ;
      brp->cluster_eid    = brp->router_id ;
    } ;

  brp->no_client_to_client      = bcs_is_set_on(bc, bcs_NO_CLIENT_TO_CLIENT) ;
  brp->do_enforce_first_as      = bcs_is_set_on(bc, bcs_ENFORCE_FIRST_AS) ;
  brp->do_import_check          = bcs_is_set_on(bc, bcs_IMPORT_CHECK) ;
  brp->no_fast_ext_failover     = bcs_is_set_on(bc, bcs_NO_FAST_EXT_FAILOVER) ;
  brp->do_log_neighbor_changes  = bcs_is_set_on(bc, bcs_LOG_NEIGHBOR_CHANGES) ;
  brp->do_graceful_restart      = bcs_is_set_on(bc, bcs_GRACEFUL_RESTART) ;

  memcpy(&brp->defs, &bgp_default_defaults, sizeof(bgp_defaults_t)) ;

  if (bcs_is_set(bc, bcs_port))
    brp->defs.port              = bc->defs.port ;
  if (bcs_is_set(bc, bcs_local_pref))
    brp->defs.local_pref        = bc->defs.local_pref ;

  if (bcs_is_set_on(bc, bcs_MED_MISSING_AS_WORST))
    brp->defs.med               = BGP_MED_MAX ;
  if (bcs_is_set(bc, bcs_med))
    brp->defs.med               = bc->defs.med ;

  if (bcs_is_set(bc, bcs_weight))
    brp->defs.weight            = bc->defs.weight ;
  if (bcs_is_set(bc, bcs_holdtime_secs))
    brp->defs.holdtime_secs     = bc->defs.holdtime_secs ;
  if (bcs_is_set(bc, bcs_keepalive_secs))
    brp->defs.keepalive_secs    = bc->defs.keepalive_secs ;
  if (bcs_is_set(bc, bcs_connect_retry_secs))
    brp->defs.connect_retry_secs = bc->defs.connect_retry_secs ;
  if (bcs_is_set(bc, bcs_accept_retry_secs))
    brp->defs.accept_retry_secs = bc->defs.accept_retry_secs ;
  if (bcs_is_set(bc, bcs_open_hold_secs))
    brp->defs.open_hold_secs    = bc->defs.open_hold_secs ;
  if (bcs_is_set(bc, bcs_ibgp_mrai_secs))
    brp->defs.ibgp_mrai_secs    = bc->defs.ibgp_mrai_secs ;
  if (bcs_is_set(bc, bcs_cbgp_mrai_secs))
    brp->defs.cbgp_mrai_secs    = bc->defs.cbgp_mrai_secs ;
  if (bcs_is_set(bc, bcs_ebgp_mrai_secs))
    brp->defs.ebgp_mrai_secs    = bc->defs.ebgp_mrai_secs ;
  if (bcs_is_set(bc, bcs_idle_hold_min_secs))
    brp->defs.idle_hold_min_secs = bc->defs.idle_hold_min_secs ;
  if (bcs_is_set(bc, bcs_idle_hold_max_secs))
    brp->defs.idle_hold_max_secs = bc->defs.idle_hold_max_secs ;
  if (bcs_is_set(bc, bcs_restart_time_secs))
    brp->defs.restart_time_secs = bc->defs.restart_time_secs ;
  if (bcs_is_set(bc, bcs_stalepath_time_secs))
    brp->defs.stalepath_time_secs = bc->defs.stalepath_time_secs ;
  if (bcs_is_set(bc, bcs_distance_ebgp))
    brp->defs.distance_ebgp     = bc->defs.distance_ebgp ;
  if (bcs_is_set(bc, bcs_distance_ibgp))
    brp->defs.distance_ibgp     = bc->defs.distance_ibgp ;
  if (bcs_is_set(bc, bcs_distance_local))
    brp->defs.distance_local    = bc->defs.distance_local ;

  /* Now the address family stuff, as required.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_rib_param     bribp ;
      bgp_baf_config    bafc ;
      bgp_redist_type_t rdt ;

      bafc = bc->afc[qafx] ;
      if (bafc == NULL)
        continue ;

      bribp = bgp_rib_param_init_new(NULL) ;

      bribp->do_always_compare_med = bcs_is_set_on(bc, bcs_ALWAYS_COMPARE_MED) ;
      bribp->do_deterministic_med  = bcs_is_set_on(bc, bcs_DETERMINISTIC_MED)
                                             && ! bribp->do_always_compare_med ;
      bribp->do_confed_compare_med = bcs_is_set_on(bc, bcs_MED_CONFED) ;
      bribp->do_prefer_current    = !bcs_is_set_on(bc, bcs_COMPARE_ROUTER_ID) ;
      bribp->do_aspath_ignore      = bcs_is_set_on(bc, bcs_ASPATH_IGNORE) ;
      bribp->do_aspath_confed      = bcs_is_set_on(bc, bcs_ASPATH_CONFED) ;

      bribp->do_damping  = bafcs_is_on(bafc, bafcs_DAMPING) ;

      for (rdt = redist_type_first ; rdt <= redist_type_last ; ++rdt)
        {
          if (bafc->redist[rdt].set)
            {
              bribp->redist[rdt].set         = true ;
              bribp->redist[rdt].metric_set  = bafc->redist[rdt].metric_set ;
              bribp->redist[rdt].metric      = bafc->redist[rdt].metric ;

              bgp_nref_copy(&bribp->redist[rdt].rmap_name,
                                                  bafc->redist[rdt].rmap_name) ;
            } ;
        };
    } ;

  /* Now construct the vector of grun objects.
   *
   * We don't care about the group state at run-time -- that is all factored
   * out -- but we do care about group membership.
   *
   * Note that we miss out any groups which are not used.
   *
   * The groups are in order in the bgp->groups vector, so will be in order in
   * the brp->gruns vector.
   */
  vector_re_init(brp->gruns, vector_length(bgp->groups)) ;
  i = 0 ;
  while ((group = vector_get_item(bgp->groups, i++)) != NULL)
    {
      /* The bgp->peers vector is sorted by the "name" of the peer, so
       * we will collect prun_params in order here !
       */
      bgp_pconfig  gc ;
      bool         used ;
      gc = group->c ;

      used = (vector_length(gc->group.members) != 0) ;
      qafx = qafx_first ;
      while (!used && (qafx < qafx_last))
        {
          if (pcs_qafx_config(gc, qafx))
            {
              bgp_paf_config gafc ;

              gafc = gc->afc[qafx] ;
              qassert(gafc != NULL) ;

              used = ((gafc != NULL) &&
                                    (vector_length(gafc->group.members) != 0)) ;
            } ;

          ++qafx ;
        } ;

      if (used)
        {
          bgp_grun  grun ;

          grun = XCALLOC(MTYPE_BGP_GRUN, sizeof(bgp_grun_t)) ;

          /* Zeroizing the bgp_grun has set:
           *
           *   * name                   -- NULL         -- set below
           *
           *   * prun_members           -- empty vector
           *   * prib_members           -- empty vectors
           *
           * NB: for group the name and cname are the same.
           */
          confirm(VECTOR_INIT_ALL_ZEROS) ;

          bgp_nref_copy(&grun->name, group->name) ;

          vector_push_item(brp->gruns, grun) ;
        } ;
    } ;

  /* Now assemble all the peers
   */
  vector_re_init(assembly->prun_params, vector_length(bgp->peers)) ;
  i = 0 ;
  while ((peer = vector_get_item(bgp->peers, i++)) != NULL)
    {
      /* The bgp->peers vector is sorted by the "name" of the peer, so
       * we will collect prun_params in order here !
       */
      vector_push_item(assembly->prun_params, bgp_assemble_peer(peer->c, brp)) ;
    } ;

  return assembly ;
} ;

/*------------------------------------------------------------------------------
 * Assemble a bgp_prun_param for the given peer-configuration with the given
 *                                                                bgp_run_param.
 *
 * Takes defaults from the bgp_run_param.
 *
 * Merges peer and any group configuration.
 *
 * Collects group membership in the existing bgp_run_param 'gruns' entries.
 *
 * Returns:  new bgp_prun_param object
 */
static bgp_prun_param
bgp_assemble_peer(bgp_pconfig pc, bgp_run_param brp)
{
  bgp_prun_param prp ;
  bgp_pconfig    gc ;
  qafx_t         qafx ;

  prp = XCALLOC(MTYPE_BGP_ASSEMBLY, sizeof(bgp_prun_param_t)) ;

  /* Zeroizing the bgp_prun_param sets:
   *
   *   * peer_id                        -- X            -- set below
   *   * name                           -- NULL         -- set below
   *   * cname                          -- NULL         -- set below
   *   * desc                           -- NULL         -- set below
   *
   *   * grun                           -- NULL         -- set if required
   *
   *   * sort                           -- bgp_peer_sort_t
   *
   *   * do_enforce_first_as            -- default set below
   *   * do_log_neighbor_changes        -- default set below
   *
   *   * cops_conf                      -- see below
   *   * sargs_conf                     -- see below
   *
   *   * change_local_as                -- default == BGP_ASN_NULL
   *   * do_change_local_as_prepend     -- default == false
   *
   *   * do_disable_connected_check     -- default == false
   *
   *   * weight                         -- default set below
   *   * default_local_pref             -- default set below
   *   * default_med                    -- default set below
   *
   *   * mrai                           -- default set below, when 'sort' set
   *
   *   * afp                            -- NULL         -- none, set as required
   */
  prp->peer_id = bgp_peer_index_lock_id(pc->parent_peer->peer_id) ;

  bgp_nref_copy(&prp->name, pc->parent_peer->name) ;
  bgp_nref_copy(&prp->cname, pc->parent_peer->cname) ;
  bgp_nref_copy(&prp->desc, pc->desc) ;

  gc = NULL ;
  if (pcs_is_set_on(pc, pcs_group))
    {
      qassert(pc->ctype == BGP_CFT_MEMBER) ;

      gc = pc->group.c ;
      qassert(gc != NULL) ;

      if (gc != NULL)
        prp->grun = bgp_assemble_grun(gc->parent_peer->name, brp) ;
    } ;

  prp->weight             = brp->defs.weight ;
  prp->default_local_pref = brp->defs.local_pref ;
  prp->default_med        = brp->defs.med ;

  /* The sort of the peer is fixed by its remote-as etc.
   *
   * If we are inheriting the remote-as, then make sure we have a value for it.
   *
   * Note that this is part of an atomic operation wrt to the configuration,
   * so we can reach back into the bgp_inst and use the confed_id and
   * confed_peers there.
   */
  if (!pcs_is_set_on(pc, pcs_remote_as))
    {
      qassert((gc != NULL) && pcs_is_set_on(gc, pcs_remote_as)) ;
      qassert(pc->remote_as == gc->remote_as) ;

      pc->remote_as = gc->remote_as ;
    }

  qassert(pc->remote_as != BGP_ASN_NULL) ;

  prp->sort = bgp_peer_as_sort(pc->parent_peer->parent_bgp, pc->remote_as) ;
  prp->mrai_secs = bgp_assemble_default_mrai(prp, brp) ;

  /* Flag settings -- defaults from bgp level.
   *
   * This is partly for convenience, and partly to allow for per peer
   * settings for these in future.
   */
  prp->do_enforce_first_as      = brp->do_enforce_first_as ;
  prp->do_log_neighbor_changes  = brp->do_log_neighbor_changes ;

  /* Set the cops_conf to empty, and then add:
   *
   *   * remote_su              -- copied from pconf
   *
   *   * port                   -- default set below
   *
   *   * can_notify_before_open -- default == true
   *
   *   * idle_hold_max_secs     -- default set below
   *   * connect_retry_secs     -- default set below
   *   * accept_retry_secs      -- default set below
   *   * open_hold_secs         -- default set below
   *
   *   * ttl                    -- default set below
   *
   * All other values are set to their default values, and may be set to
   * configured values in bgp_assemble_peer_settings().
   */
  bgp_cops_init_new(&prp->cops_conf) ;

  sockunion_copy(&prp->cops_conf.remote_su, pc->remote_su) ;

  prp->cops_conf.port   = brp->defs.port ;

  prp->cops_conf.can_notify_before_open = true ;

  prp->cops_conf.idle_hold_max_secs = brp->defs.idle_hold_max_secs ;
  prp->cops_conf.connect_retry_secs = brp->defs.connect_retry_secs ;
  prp->cops_conf.accept_retry_secs  = brp->defs.accept_retry_secs ;
  prp->cops_conf.open_hold_secs     = brp->defs.open_hold_secs ;

  prp->cops_conf.ttl = bgp_assemble_default_ttl(prp, brp) ;

  /* Set the sargs_conf to empty, and then add:
   *
   *   * local_as               -- our ASN for this peering
   *
   *       - iBGP == my_as
   *       - cBGP == my_as
   *       - eBGP == my_as_ebgp -- *except* when is change_local_as
   *
   *   * local_id               -- copy of router_id
   *
   *   * remote_as              -- copy of remote_as
   *
   *   * can_capability         -- default == true
   *   * can_mp_ext             -- default == true
   *   * can_as4                -- default == per BGP_OPT_AS2_SPEAKER
   *
   *   * can_rr                 -- default == bgp_form_both
   *
   *   * gr.can                 -- copy of do_graceful_restart
   *       .restart_time        -- default set below, iff gr.can
   *
   *   * can_orf                -- default == bgp_form_both
   *
   *   * holdtime_secs          -- default set below
   *   * keepalive_secs         -- default set below
   *
   * Other settings are done by bgp_assemble_peer_settings().
   */
  bgp_sargs_init_new(&prp->sargs_conf) ;

  prp->sargs_conf.local_as        = bgp_assemble_local_as(prp, brp) ;
  prp->sargs_conf.local_id        = brp->router_id ;
  prp->sargs_conf.remote_as       = pc->remote_as ;

  prp->sargs_conf.can_capability  = true ;
  prp->sargs_conf.can_mp_ext      = true ;
  prp->sargs_conf.can_as4         = !bgp_option_check (BGP_OPT_AS2_SPEAKER) ;

  prp->sargs_conf.can_rr          = bgp_form_both ;
  prp->sargs_conf.gr.can          = brp->do_graceful_restart ;

  if (brp->do_graceful_restart)
    prp->sargs_conf.gr.restart_time  = brp->defs.restart_time_secs ;

  prp->sargs_conf.can_orf         = bgp_form_both ;

  prp->sargs_conf.holdtime_secs   = brp->defs.holdtime_secs ;
  prp->sargs_conf.keepalive_secs  = brp->defs.keepalive_secs ;

  /* By the time we get to here, have all defaults set -- either to defaults
   * specified by the bgp instance, or the base settings.
   *
   * Now apply settings from group (if any) and then from peer itself.
   */
  if (gc != NULL)
    bgp_assemble_peer_settings(prp, gc, brp) ;

  bgp_assemble_peer_settings(prp, pc, brp) ;

  /* Now worry about the address families.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_prib_param pribp ;
      bgp_paf_config pafc, gafc ;

      if (!pcs_qafx_config(pc, qafx))
        continue ;

      pafc = pc->afc[qafx] ;
      qassert((pafc != NULL) && (qafx == pafc->qafx)) ;
      if (pafc == NULL)
        continue ;

      pribp = XCALLOC(MTYPE_BGP_ASSEMBLY, sizeof(bgp_prib_param_t)) ;

      prp->sargs_conf.can_af |= qafx_bit(qafx) ;
      prp->afp[qafx] = pribp ;

      /* Zeroizing has set:
       *
       *   * grun                           -- default == none
       *
       *   * do_soft_reconfig               -- default == false
       *   * is_route_server_client         -- default == false
       *   * is_route_reflector_client      -- default == false
       *   * do_send_community              -- default set below
       *   * do_send_ecommunity             -- default set below
       *   * do_next_hop_self               -- default == false
       *   * do_next_hop_unchanged          -- default == false
       *   * do_next_hop_local_unchanged    -- default == false
       *   * do_as_path_unchanged           -- default == false
       *   * do_remove_private_as           -- default == false
       *   * do_med_unchanged               -- default == false
       *   * do_default_originate           -- default == false
       *
       *   * allow_as_in                    -- default == 0
       *
       *   * filter_set[]                   -- default == none
       *
       *   * pmax .set                      -- default == false
       *          .warning                  -- false
       *          .trigger                  -- 0    )
       *          .limit                    -- 0    )
       *          .threshold                -- 0    )  unset
       *          .thresh_pc                -- 0    )
       *          .restart                  -- 0    )
       *
       * Now worry about any group setting and assemble the address family
       * settings.
       */
      gafc = NULL ;
      if (pafcs_is_set_on(pafc, pafcs_group))
        {
          qassert(pafc->ctype == BGP_CFT_MEMBER) ;
          gafc = pafc->group.afc ;

          qassert((gafc != NULL) && (qafx == gafc->qafx)) ;
          if (gafc != NULL)
            pribp->grun =
                 bgp_assemble_grun(gafc->parent_pconf->parent_peer->name, brp) ;
        } ;

      if (!bgp_option_check (BGP_OPT_CONFIG_CISCO))
        {
          pribp->do_send_community  = true ;
          pribp->do_send_ecommunity = true ;
        } ;

      if (gafc != NULL)
        bgp_assemble_peer_af_settings(pribp, gafc, brp, prp) ;

      bgp_assemble_peer_af_settings(pribp, pafc, brp, prp) ;
    } ;

  /*
   *
   */
  return prp ;
} ;

/*------------------------------------------------------------------------------
 * Assemble all settings from the given bgp_pconfig -- set default as required.
 */
static void
bgp_assemble_peer_settings(bgp_prun_param prp, bgp_pconfig pc,
                                                              bgp_run_param brp)
{
  if (pcs_is_set(pc, pcs_SHUTDOWN))
    prp->do_shutdown = pcs_is_on(pc, pcs_SHUTDOWN) ;

  /* For pcs_PASSIVE and pcs_ACTIVE only one can be set-on.
   *
   * Where pcs_PASSIVE is set off that => enable connect.
   * Where pcs_ACTIVE  is set off that => enable accept
   */
  if (pcs_is_set(pc, pcs_PASSIVE))
    {
      if (pcs_is_on(pc, pcs_PASSIVE))
        prp->cops_conf.conn_state  = bgp_csMayAccept ;
      else
        prp->cops_conf.conn_state |= bgp_csMayConnect ;
    } ;

  if (pcs_is_set(pc, pcs_ACTIVE))
    {
      if (pcs_is_on(pc, pcs_ACTIVE))
        prp->cops_conf.conn_state  = bgp_csMayConnect ;
      else
        prp->cops_conf.conn_state |= bgp_csMayAccept ;
    } ;

  /* Various simple flags
   */
  if (pcs_is_set(pc, pcs_DONT_CAPABILITY))
    prp->sargs_conf.can_capability  = !pcs_is_on(pc, pcs_DONT_CAPABILITY) ;

  if (pcs_is_set(pc, pcs_OVERRIDE_CAPABILITY))
    prp->sargs_conf.cap_af_override = pcs_is_on(pc, pcs_OVERRIDE_CAPABILITY) ;

  if (pcs_is_set(pc, pcs_STRICT_CAP_MATCH))
    prp->sargs_conf.cap_strict      = pcs_is_on(pc, pcs_STRICT_CAP_MATCH) ;

  if (pcs_is_set(pc, pcs_DYNAMIC_CAPABILITY))
    prp->sargs_conf.can_dynamic     = pcs_is_on(pc, pcs_DYNAMIC_CAPABILITY) ;

  if (pcs_is_set(pc, pcs_DYNAMIC_CAPABILITY_DEP))
    prp->sargs_conf.can_dynamic_dep = pcs_is_on(pc, pcs_DYNAMIC_CAPABILITY_DEP);

  if (pcs_is_set(pc, pcs_DISABLE_CONNECTED_CHECK))
    prp->do_disable_connected_check = pcs_is_on(pc,
                                                  pcs_DISABLE_CONNECTED_CHECK) ;

  /* Some value setting settings
   */
  if (pcs_is_set(pc, pcs_weight))
    {
      if (pcs_is_on(pc, pcs_weight))
        prp->weight  = pc->weight ;
      else
        prp->weight  = brp->defs.weight ;
    } ;

  if (pcs_is_set(pc, pcs_password))
    {
      memset(&prp->cops_conf.password, 0, sizeof(bgp_password_t)) ;

      if (pcs_is_on(pc, pcs_password))
        strncpy(prp->cops_conf.password, bgp_nref_name(pc->password),
                                                       sizeof(bgp_password_t)) ;
    } ;

  if (pcs_is_set(pc, pcs_update_source))
    {
      memset(prp->cops_conf.ifname, 0, sizeof(bgp_ifname_t)) ;
      sockunion_clear(&prp->cops_conf.local_su) ;

      if (pcs_is_on(pc, pcs_update_source))
        {
          chs_c update_source ;

          update_source = bgp_nref_name(pc->update_source) ;

          if (pc->update_source_if)
            strncpy(prp->cops_conf.ifname, update_source,
                                                         sizeof(bgp_ifname_t)) ;
          else
            sockunion_str2su (&prp->cops_conf.local_su, update_source) ;
        } ;
    } ;

  if (pcs_is_set(pc, pcs_timers))
    {
      if (pcs_is_on(pc, pcs_timers))
        {
          prp->sargs_conf.holdtime_secs   = pc->holdtime_secs ;
          prp->sargs_conf.keepalive_secs  = pc->keepalive_secs ;
        }
      else
        {
          prp->sargs_conf.holdtime_secs   = brp->defs.holdtime_secs ;
          prp->sargs_conf.keepalive_secs  = brp->defs.keepalive_secs ;
        } ;
    } ;

  if (pcs_is_set_on(pc, pcs_change_local_as))
    {
      if (pcs_is_on(pc, pcs_change_local_as))
        {
          prp->sargs_conf.local_as  = pc->change_local_as ;
          prp->change_local_as      = pc->change_local_as ;
          prp->do_local_as_prepend  = pc->local_as_prepend ;
        }
      else
        {
          prp->sargs_conf.local_as  = bgp_assemble_local_as(prp, brp) ;
          prp->change_local_as      = BGP_ASN_NULL ;
          prp->do_local_as_prepend  = false ;
        } ;
    } ;

  if (pcs_is_set(pc, pcs_connect_retry))
    {
      if (pcs_is_on(pc, pcs_connect_retry))
        prp->cops_conf.connect_retry_secs = pc->connect_retry_secs ;
      else
        prp->cops_conf.connect_retry_secs = brp->defs.connect_retry_secs ;
    } ;

  if (pcs_is_set(pc, pcs_port))
    {
      if (pcs_is_on(pc, pcs_port))
        prp->cops_conf.port = pc->port ;
      else
        prp->cops_conf.port = brp->defs.port ;
    } ;

  if (pcs_is_set(pc, pcs_mrai))
    {
      if (pcs_is_on(pc, pcs_mrai))
        prp->mrai_secs = pc->mrai_secs ;
      else
        prp->mrai_secs = bgp_assemble_default_mrai(prp, brp) ;
    } ;

  /* For pcs_multihop and pcs_ttl_security only one can be set-on.
   *
   * Where pcs_multihop     is set off that => set default ttl unless is gtsm
   * Where pcs_ttl_security is set off that => turn off gtsm
   */
  if (pcs_is_set(pc, pcs_multihop))
    {
      if (pcs_is_on(pc, pcs_multihop))
        {
          prp->cops_conf.ttl   = pc->ttl ;
          prp->cops_conf.gtsm  = false ;
        }
      else if (!prp->cops_conf.gtsm)
        {
          prp->cops_conf.ttl = bgp_assemble_default_ttl(prp, brp) ;
        } ;
    } ;

  if      (pcs_is_set(pc, pcs_ttl_security))
    {
      if (pcs_is_on(pc, pcs_ttl_security))
        {
          prp->cops_conf.ttl   = pc->ttl ;
          prp->cops_conf.gtsm  = true ;
        }
      else if (prp->cops_conf.gtsm)
        {
          prp->cops_conf.ttl = bgp_assemble_default_ttl(prp, brp) ;
          prp->cops_conf.gtsm  = false ;
        } ;
    } ;

  /* Finally... if capability negotiation is suppressed, then now is a
   *            good moment to clear everything from the sargs which
   *            requires negotiation.
   */
  if (!prp->sargs_conf.can_capability)
    bgp_sargs_suppress(&prp->sargs_conf) ;
} ;

/*------------------------------------------------------------------------------
 * Select the 'local_as' by sort
 */
static as_t
bgp_assemble_local_as(bgp_prun_param prp, bgp_run_param brp)
{
  switch (prp->sort)
    {
      case BGP_PEER_IBGP:
      case BGP_PEER_CBGP:
        return brp->my_as ;

      default:
        qassert(false) ;
        fall_through ;

      case BGP_PEER_EBGP:
        return brp->my_as_ebgp ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Select default mrai by 'sort'
 */
static uint
bgp_assemble_default_mrai(bgp_prun_param prp, bgp_run_param brp)
{
  switch (prp->sort)
    {
      case BGP_PEER_IBGP:
        return brp->defs.ibgp_mrai_secs ;

      case BGP_PEER_CBGP:
        return brp->defs.cbgp_mrai_secs ;

      default:
        qassert(false) ;
        fall_through ;

      case BGP_PEER_EBGP:
        return brp->defs.ebgp_mrai_secs ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Select default ttl by 'sort'
 */
static uint
bgp_assemble_default_ttl(bgp_prun_param prp, bgp_run_param brp)
{
  switch (prp->sort)
    {
      case BGP_PEER_IBGP:
        return brp->defs.ibgp_mrai_secs ;

      case BGP_PEER_CBGP:
        return brp->defs.cbgp_mrai_secs ;

      default:
        qassert(false) ;
        fall_through ;

      case BGP_PEER_EBGP:
        return brp->defs.ebgp_mrai_secs ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Assemble parameters for address family
 */
static void
bgp_assemble_peer_af_settings(bgp_prib_param pribp, bgp_paf_config pafc,
                                          bgp_run_param brp, bgp_prun_param prp)
{
  bgp_pafc_setting_t setting ;

  /* Running flags
   */
  if (pafcs_is_set(pafc, pafcs_SOFT_RECONFIG))
    pribp->do_soft_reconfig = pafcs_is_on(pafc, pafcs_SOFT_RECONFIG) ;

  if (pafcs_is_set(pafc, pafcs_RSERVER_CLIENT))
    pribp->is_route_server_client = pafcs_is_on(pafc, pafcs_RSERVER_CLIENT) ;

  if (pafcs_is_set(pafc, pafcs_REFLECTOR_CLIENT))
    pribp->is_route_reflector_client =
                                     pafcs_is_on(pafc, pafcs_REFLECTOR_CLIENT) ;

  if (pafcs_is_set(pafc, pafcs_SEND_COMMUNITY))
    pribp->do_send_community = pafcs_is_on(pafc, pafcs_SEND_COMMUNITY) ;

  if (pafcs_is_set(pafc, pafcs_SEND_EXT_COMMUNITY))
    pribp->do_send_ecommunity = pafcs_is_on(pafc, pafcs_SEND_EXT_COMMUNITY) ;

  if (pafcs_is_set(pafc, pafcs_NEXTHOP_SELF))
    pribp->do_next_hop_self = pafcs_is_on(pafc, pafcs_NEXTHOP_SELF) ;

  if (pafcs_is_set(pafc, pafcs_NEXTHOP_UNCHANGED))
    pribp->do_next_hop_unchanged = pafcs_is_on(pafc, pafcs_NEXTHOP_UNCHANGED) ;

  if (pafcs_is_set(pafc, pafcs_NEXTHOP_LOCAL_UNCHANGED))
    pribp->do_next_hop_local_unchanged =
                              pafcs_is_on(pafc, pafcs_NEXTHOP_LOCAL_UNCHANGED) ;

  if (pafcs_is_set(pafc, pafcs_AS_PATH_UNCHANGED))
    pribp->do_as_path_unchanged = pafcs_is_on(pafc, pafcs_AS_PATH_UNCHANGED) ;

  if (pafcs_is_set(pafc, pafcs_REMOVE_PRIVATE_AS))
    pribp->do_remove_private_as = pafcs_is_on(pafc, pafcs_REMOVE_PRIVATE_AS) ;

  if (pafcs_is_set(pafc, pafcs_MED_UNCHANGED))
    pribp->do_med_unchanged = pafcs_is_on(pafc, pafcs_MED_UNCHANGED) ;

  if (pafcs_is_set(pafc, pafcs_DEFAULT_ORIGINATE))
    pribp->do_default_originate = pafcs_is_on(pafc, pafcs_DEFAULT_ORIGINATE) ;

  /* ORF Prefix stuff.
   *
   *
   *    *   * can_orf                -- bgp_form_both
   *
   *   * can_orf_pfx[]          -- per "neighbor capability orf prefix-list"
   *
   */
  if (prp->sargs_conf.can_orf != bgp_form_none)
    {
      bgp_orf_cap_bits_t*  p_ocb ;

      p_ocb = &prp->sargs_conf.can_orf_pfx.af[pafc->qafx] ;

      if (pafcs_is_set(pafc, pafcs_ORF_SEND))
        {
          if (pafcs_is_on(pafc, pafcs_ORF_SEND))
            *p_ocb |=  ORF_SM ;
          else
            *p_ocb &= ~ORF_SM ;
        } ;

      if (pafcs_is_set(pafc, pafcs_ORF_RECV))
        {
          if (pafcs_is_on(pafc, pafcs_ORF_RECV))
            *p_ocb |=  ORF_RM ;
          else
            *p_ocb &= ~ORF_RM ;
        } ;
    } ;

  /* Settings with values
   */
  if (pafcs_is_set(pafc, pafcs_max_prefix))
    {
      if (pafcs_is_on(pafc, pafcs_max_prefix))
        {
          qassert(pafc->pmax.set) ;

          pribp->pmax = pafc->pmax ;
        }
      else
        {
          memset(&pribp->pmax, 0, sizeof(prefix_max_t)) ;
        } ;
    } ;

  if (pafcs_is_set(pafc, pafcs_allow_as_in))
    {
      if (pafcs_is_on(pafc, pafcs_allow_as_in))
        pribp->allow_as_in = pafc->allow_as_in ;
      else
        pribp->allow_as_in = 0 ;
    } ;

  /* Now the filter set.
   *
   * Note that here all we do is make a copy of the filter names.  When we
   * compile the assembly will worry about compiling the filters.
   */
  for (setting = pafcs_filter_first ; setting <= pafcs_filter_last ;
                                      ++setting)
    {
      bgp_filter_set_t  fs ;
      bgp_nref          name ;

      if (!pafcs_is_set(pafc, setting))
        continue ;

      fs = setting - pafcs_filter_first ;
      CONFIRM(bfs_dlist_in     == (pafcs_dlist_in     - pafcs_filter_first)) ;
      CONFIRM(bfs_dlist_out    == (pafcs_dlist_out    - pafcs_filter_first)) ;
      CONFIRM(bfs_plist_in     == (pafcs_plist_in     - pafcs_filter_first)) ;
      CONFIRM(bfs_plist_out    == (pafcs_plist_out    - pafcs_filter_first)) ;
      CONFIRM(bfs_aslist_in    == (pafcs_aslist_in    - pafcs_filter_first)) ;
      CONFIRM(bfs_aslist_out   == (pafcs_aslist_out   - pafcs_filter_first)) ;
      CONFIRM(bfs_rmap_in      == (pafcs_rmap_in      - pafcs_filter_first)) ;
      CONFIRM(bfs_rmap_inx     == (pafcs_rmap_inx     - pafcs_filter_first)) ;
      CONFIRM(bfs_rmap_out     == (pafcs_rmap_out     - pafcs_filter_first)) ;
      CONFIRM(bfs_rmap_import  == (pafcs_rmap_import  - pafcs_filter_first)) ;
      CONFIRM(bfs_rmap_export  == (pafcs_rmap_export  - pafcs_filter_first)) ;
      CONFIRM(bfs_us_rmap      == (pafcs_us_rmap      - pafcs_filter_first)) ;
      CONFIRM(bfs_default_rmap == (pafcs_default_rmap - pafcs_filter_first)) ;
      CONFIRM(bfs_orf_plist    == (pafcs_orf_plist    - pafcs_filter_first)) ;

      if (pafcs_is_on(pafc, setting))
        name = pafc->filter_set[fs] ;
      else
        name = NULL ;

      bgp_nref_copy(&pribp->filter_set[fs], name) ;
    } ;
} ;


/*------------------------------------------------------------------------------
 * Find the bgp_grun for the given group name.
 */
static bgp_grun
bgp_assemble_grun(nref_c name, bgp_run_param brp)
{
  bgp_grun grun ;

  grun = vector_bseek(brp->gruns, bgp_grun_cmp_name, bgp_nref_name(name)) ;
  qassert(grun != NULL) ;

  return grun ;
} ;

/*------------------------------------------------------------------------------
 * Grun name comparison function for sorting.
 */
static int
bgp_grun_cmp_name (const cvp* p_name, const cvp* p_grun)
{
  chs_c      n = *p_name ;
  bgp_grun_c p = *p_grun ;

  return strcmp(n, bgp_nref_name(p->name)) ;
} ;


/*------------------------------------------------------------------------------
 * Dismantle and discard the given assembly.
 *
 * Each set of prun_param holds a lock on the peer-id, which it must now
 * release.
 *
 * The prun_param will either have been copied into the respective prun, or
 * have been ignored because the prun is being shut-down.  Where the prun
 * contains nref's or any other pointers to things which are now in the
 * hands of the prun, those pointers will have been set NULL.  So we should
 * here tidy up any that remain before freeing the contents.
 */
static void
bgp_assembly_free(bgp_assembly assembly)
{
  bgp_prun_param prp ;
  qafx_t  qafx ;

  /* Deal with the vector of prun_params and all the dependent prib_params.
   */
  while ((prp = vector_ream(assembly->prun_params, keep_it)) != NULL)
    {
      prp->peer_id = bgp_peer_index_unlock_id(prp->peer_id) ;

      prp->name  = bgp_nref_dec(prp->name) ;
      prp->cname = bgp_nref_dec(prp->cname) ;
      prp->desc  = bgp_nref_dec(prp->desc) ;

      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_prib_param    pribp ;
          bgp_filter_set_t  fs ;

          pribp = prp->afp[qafx] ;
          if (pribp == NULL)
            continue ;

          for (fs = bfs_first ; fs <= bfs_last ; ++fs)
            pribp->filter_set[fs] = bgp_nref_dec(pribp->filter_set[fs]) ;

          XFREE(MTYPE_BGP_ASSEMBLY, pribp) ;
        } ;

      XFREE(MTYPE_BGP_ASSEMBLY, prp) ;
    } ;

  /* Deal with the run_params and the dependent rib_params.
   *
   * There is nothing of interest in the run_params, only the rib_params.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_rib_param     bribp ;
      bgp_redist_type_t rd ;

      bribp = assembly->brp->afp[qafx_count] ;
      if (bribp == NULL)
        continue ;

      for (rd = redist_type_first ; rd <= redist_type_last ; ++rd)
        bribp->redist[rd].rmap_name =
                                     bgp_nref_dec(bribp->redist[rd].rmap_name) ;

      XFREE(MTYPE_BGP_ASSEMBLY, bribp) ;
    }

  XFREE(MTYPE_BGP_ASSEMBLY, assembly->brp) ;
  XFREE(MTYPE_BGP_ASSEMBLY, assembly) ;
} ;

/*==============================================================================
 * Compilation phase
 */
static bgp_run_delta_t bgp_compile_brun_delta(bgp_run brun, bgp_run_param nrp) ;
static bgp_run_delta_t bgp_compile_rib_delta(bgp_rib rib, bgp_rib_param nribp) ;
static bgp_run_delta_t bgp_compile_prun_delta(bgp_prun prun,
                                                          bgp_prun_param nprp) ;
static bgp_run_delta_t bgp_compile_prib_delta(bgp_prib prib,
                                                        bgp_prib_param npribp) ;
static void bgp_compile_clear_groups(bgp_run brun) ;
static void bgp_compile_grun_add_prun(bgp_grun grun, bgp_prun prun) ;
static void bgp_compile_grun_add_prib(bgp_grun grun, bgp_prib prib,
                                                                  qafx_t qafx) ;

/*------------------------------------------------------------------------------
 * Compile an assembly.
 *
 * This is an "atomic" operation wrt all run-time operations (including itself).
 *
 * That may be achieved by bringing all run-time threads to a halt, and
 * preventing the dispatch of anything else until this operation completes.
 *
 *
 *
 */
extern void
bgp_compile(bgp_inst bgp, bgp_assembly assembly)
{
  bgp_run         brun ;
  bgp_run_delta_t bdelta ;
  uint            i ;
  bgp_prun        prun ;
  bgp_prun_param  nprp ;
  vector          old_pruns ;

  /* Create or suspend and run delta for existing bgp_run.
   */
  brun = bgp->brun ;
  if (brun == NULL)
    {
      chs_c view_name ;

      brun = XCALLOC(MTYPE_BGP_BRUN, sizeof(bgp_run_t)) ;
      bgp->brun = brun ;

      /* Zeroizing has set:
       *
       *   *
       *   * parent_inst        -- X            -- set below
       *   * brun_list          -- NULLs        -- set below
       *
       *   * view_name          -- X            -- set below
       *
       *   * rc_name_index      -- TODO
       *   * rc_view            -- TODO
       *   * prun_self          -- TODO
       *
       *   * pruns              -- empty vector
       *
       *   * rp                 -- X            -- set below
       *
       *   * rib                -- NULLs        -- none, yet
       *
       *   * real_rib           -- TODO
       */
      brun->parent_inst   = bgp ;
      ddl_append(bm->bruns, brun, brun_list) ;

      /* The name of the parent view cannot change -- so we can here set a
       * pointer to the name !
       */
      view_name = bgp_nref_name(bgp->name) ;
      if ((view_name != NULL) && (view_name[0] != '\0'))
        brun->view_name = view_name ;

      bdelta = brd_restart ;
    }
  else
    {
      /* We have an existing, running bgp instance.
       *
       * So: do what is required to suspend that        TODO
       *
       * Discard the group membership -- that is reconstructed as we compile.
       *
       * Clear the compiled and reselect flags for all ribs.
       *
       * Construct the delta for the bgp_run_param.
       */
      qafx_t          qafx ;

      bgp_compile_clear_groups(brun) ;

      bdelta = bgp_compile_brun_delta(brun, assembly->brp) ;

      /* Set the delta for all existing ribs.
       *
       * New ribs are handled separately.
       * Ribs which fall by the way-side are also handled separately.
       */
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_rib rib ;

          rib = brun->rib[qafx] ;

          if (rib != NULL)
            rib->delta = bdelta |
                          bgp_compile_rib_delta(rib, assembly->brp->afp[qafx]) ;
        } ;
    } ;

  /* We can now simply copy in the assembled bgp_run_param.
   *
   * NB: this pulls in the new gruns vector -- which is OK, because we
   *     emptied out all the group stuff above, if we had an existing running
   *     instance.
   *
   *     To be tidy we (re)initialise the assembled gruns vector, so that it
   *     is present in only one place.
   *
   * NB: this also pulls in the new address family parameters.  Those are
   *     currently pointing at the parameters in the current ribs, so it is
   *     not a problem to simply overwrite those.
   *
   *     To be tidy, we flush out the array in the brun->rp, so that we don't
   *     have it pointing to something which will disappear in due course.
   */
  brun->rp = *assembly->brp ;

  vector_init_new(assembly->brp->gruns, 0) ;

  memset(brun->rp.afp, 0, sizeof(brun->rp.afp)) ;
  confirm(sizeof(brun->rp.afp) == (qafx_count * sizeof(void*))) ;

  /* Move the exiting peers to a temporary vector and set to be deleted.
   */
  old_pruns = vector_move_here(NULL, brun->pruns) ;

  i = 0 ;
  while ((prun = vector_get_item(old_pruns, i++)) != NULL)
    prun->delta = brd_delete ;

  /* Now all the assembled peers.
   *
   * We re-create the vector of pruns known to the brun to include only those
   * for whom we have a configuration -- noting that this includes any which
   * are shut-down.  The vector in the assembly is in peer name order, so the
   * new vector will be, too.
   *
   * The old_pruns vector contains a pointer to all existing pruns.  When
   * we have completed this phase, that vector is emptied out and any pruns
   * which are unknown will then be deleted.
   */
  vector_init_new(brun->pruns, vector_length(assembly->prun_params)) ;

  i = 0 ;
  while ((nprp = vector_get_item(assembly->prun_params, i++)) != NULL)
    {
      bgp_prun        prun ;
      bgp_run_delta_t pdelta ;
      qafx_t          qafx ;

      prun = bgp_peer_index_prun_lookup(bgp_nref_name(nprp->cname)) ;

      /* The delta for the prun inherits the delta from the brun.
       *
       * The delta for each prib inherits from the prun, and is any prib
       * requires a restart, the prun state is updated.
       *
       * Once we have a restart for a given prun, we can short circuit all
       * other delta.
       */
      pdelta = bdelta ;

      if (prun == NULL)
        {
          /* This is a new run-time for the peer.
           *
           * If the entire brun is being shutdown or the peer is, then set
           * brd_shutdown, otherwise set brd_restart.
           *
           * Note that we do not set brd_continue to signal a new prun.
           */
          prun = bgp_prun_new(brun, nprp) ;

          if ((bdelta & brd_shutdown) || nprp->do_shutdown)
            pdelta = brd_shutdown ;
          else
            pdelta = brd_restart ;
        }
      else
        {
          /* If the entire brun is being shutdown or the peer is, then set
           * brd_shutdown.
           *
           * Otherwise, we inherit any other brun delta.
           *
           * In any case, set brd_continue to show existing prun.
           */
          if ((bdelta & brd_shutdown) || nprp->do_shutdown)
            pdelta = brd_shutdown | brd_continue ;
          else
            pdelta =       bdelta | brd_continue ;

          if (!(pdelta & (brd_shutdown | brd_restart)))
            pdelta |= bgp_compile_prun_delta(prun, nprp) ;

          /* We are about to replace the name, cname and desc, so we are
           * done with the current ones.
           *
           * We are also about to clear the rp.afp pointers, which currently
           * point into the active pribs, which will be set again, below.
           *
           * The grun pointer has already been cleared, and will also be
           * updated below.
           */
          prun->rp.name   = bgp_nref_dec(prun->rp.name) ;
          prun->rp.cname  = bgp_nref_dec(prun->rp.cname) ;
          prun->rp.desc   = bgp_nref_dec(prun->rp.desc) ;

          qassert(prun->rp.grun == NULL) ;
        } ;

      /* We now copy in the prun rp, which (inter alia) contains:
       *
       *   * name           -- nref for whose reference we co-opt
       *   * cname          -- ditto
       *   * desc           -- ditto
       *
       *   * grun           -- new group membership, which we now complete
       *
       *   * cops_conf      -- embedded and intended to be copied
       *   * sargs_conf     -- ditto
       *
       *   * afp            -- which we now need to clear
       */
      prun->rp = *nprp ;

      nprp->name   = NULL ;
      nprp->cname  = NULL ;
      nprp->desc   = NULL ;

      if (prun->rp.grun != NULL)
        bgp_compile_grun_add_prun(prun->rp.grun, prun) ;

      memset(prun->rp.afp, 0, sizeof(prun->rp.afp)) ;
      confirm(sizeof(prun->rp.afp) == (qafx_count * sizeof(void*))) ;

      /* Can now set the convenience pointer to the name -- this is everywhere
       * used in logging.
       */
      prun->name = bgp_nref_name(prun->rp.name) ;

      /* Now worry about address families and pribs.
       *
       * We collect a new prib_running vector and the count of same.
       *
       * Note that we do *not* include any prib which are now due to be
       * deleted.
       */
      prun->prib_running_count = 0 ;    /* reset                */
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_prib_param  npribp ;
          bgp_prib        prib ;
          bgp_run_delta_t pribdelta ;
          bgp_filter_set_t  fs ;

          npribp = nprp->afp[qafx] ;
          prib   = prun->prib[qafx] ;

          if (prib == NULL)
            {
              /* This is a new prib.
               *
               * If the prun is being shutdown, then set brd_shutdown,
               * otherwise set brd_restart.
               *
               * Note that we do not set brd_continue to signal a new prib.
               */
              prib = bgp_prib_new(prun, qafx) ;

              if (pdelta & brd_shutdown)
                pribdelta = brd_shutdown ;
              else
                pribdelta = brd_restart ;

              prun->prib[qafx] = prib ;
            }
          else
            {
              /* This is an existing prib.
               *
               * If the prun is being shutdown, then set brd_shutdown.
               *
               * Otherwise inherit most if the prun delta.
               *
               * In any case, set brd_continue to show existing prib.
               */
              if (pdelta & brd_shutdown)
                pribdelta = brd_shutdown | brd_continue ;
              else
                pribdelta = (pdelta & (brd_refresh_in | brd_refresh_out |
                                                        brd_reselect    |
                                                        brd_route_refresh))
                                         | brd_continue ;

              if (!(pribdelta & (brd_shutdown | brd_restart)))
                pribdelta |= bgp_compile_prib_delta(prib, npribp) ;

              /* We are about to replace the name, cname and desc, so we are
               * done with the current ones.
               *
               * We are also about to clear the rp.afp pointers, which currently
               * point into the active pribs, which will be set again, below.
               *
               * The grun pointer has already been cleared, and will also be
               * updated below.
               */
              for (fs = bfs_first ; fs <= bfs_last ; ++fs)
                prib->rp.filter_set[fs] =
                                         bgp_nref_dec(prib->rp.filter_set[fs]) ;

              qassert(prib->rp.grun == NULL) ;
            } ;

          /* If the prib is new or its delta requires a restart, set the
           * prun level to require a restart.
           *
           * Note that brd_restart on a prib is ignored... where the prun
           * itself does not require a restart, a later prib may signal the
           * need for a restart and that will not be set on an earlier prib
           * that does not require one.
           */
          prib->delta = (pribdelta & ~brd_restart) ;
          pdelta     |= (pribdelta &  brd_restart) ;

          /* Can now copy the prib rp into the prib, which (inter alia)
           * affects:
           *
           *   * grun           -- new group membership, which we now complete
           *
           *   * filter_set     -- whose nref we now co-opt.
           */
          prib->rp = *npribp ;

          if (prib->rp.grun != NULL)
            bgp_compile_grun_add_prib(prib->rp.grun, prib, qafx) ;

          for (fs = bfs_first ; fs <= bfs_last ; ++fs)
            npribp->filter_set[fs] = NULL ;

          /* The prun->rp.afp points into the prib once compiled.
           *
           * And the prib_running vector points at the compiled pribs.
           */
          prun->rp.afp[qafx] = &prib->rp ;

          prun->prib_running[prun->prib_running_count++] = prib ;
        } ;

      /* We have now compiled the prun and its dependent pribs.
       *
       * If there are no running address families (left) set the prun to
       * be shutdown.
       */
      if (prun->prib_running_count == 0)
        pdelta = brd_shutdown ;
      else if (pdelta == brd_delete)
        pdelta = brd_continue ;

      vector_push_item(brun->pruns, prun) ;

      prun->delta = pdelta ;
    } ;

  /* Now we ream out the old_pruns, and:
   *
   *   * delete any that need to be deleted
   *
   *   * shutdown any that need to be shutdown
   *
   *   * ...
   *
   * All pruns in the old_pruns which are not due to be deleted are now
   * sitting in the brun->pruns vector.
   */
  while ((prun = vector_ream(old_pruns, free_it)) != NULL)
    {
      if      (prun->delta & brd_delete)
        bgp_prun_delete(prun, PEER_DOWN_NEIGHBOR_DELETE /* TODO */) ;
      else if (prun->delta & brd_shutdown)
        bgp_prun_shutdown(prun, PEER_DOWN_USER_SHUTDOWN /* TODO */) ;
    } ;

  /* Nearly there... now we execute the pruns which we now have.
   */
  i = 0 ;
  while ((prun = vector_get_item(brun->pruns, i++)) != NULL)
    bgp_prun_execute(prun, PEER_DOWN_UNSPECIFIED /* TODO */) ;

  /* Can now discard the assembled parameters.
   *
   * NB: for all the prun_params this releases the lock the assembly process
   *     took on the peer-id.
   */
  bgp_assembly_free(assembly) ;
} ;

/*------------------------------------------------------------------------------
 * Establish the "delta" between the current brun running parameters and the
 * given ones.
 *
 * Note that this does not change the current state.
 *
 * Returns:  the "delta"
 */
static bgp_run_delta_t
bgp_compile_brun_delta(bgp_run brun, bgp_run_param nrp)
{
  bgp_run_param   rp ;
  bgp_run_delta_t brd ;

  /* Changes in the bgp_run_param:
   *
   *   * my_as                        x ) reflected in the 'local_as' or
   *   * my_as_ebgp                   x ) 'sort' of all peers.
   *   * confed_id                    x )
   *
   *   * router_id                   => brd_restart (all sessions)
   *
   *   * cluster_eid                 => brd_refresh_in | brd_refresh_out
   *   * cluster_id_set               x  no effect on routeing
   *
   *   * do_check_confed_id           x reflects other state
   *   * do_check_confed_id_all      => brd_refresh_in  (all sessions)
   *   * no_client_to_client         => brd_refresh_out (all sessions)
   *   * do_enforce_first_as          x peers have own setting
   *   * do_import_check              TODO
   *   * no_fast_ext_failover         x affects interface state change
   *   * do_log_neighbor_changes      x affects logging
   *   * do_graceful_restart          x affects future restarts
   *
   *   * defs
   *            port                  x peers have own setting
   *            ibgp_ttl              x peers have own setting
   *            cbgp_ttl              x peers have own setting
   *            ebgp_ttl              x peers have own setting
   *            local_pref            x peers have own setting
   *            med                   x peers have own setting
   *            weight                x peers have own setting
   *            holdtime_secs         x peers have own setting
   *            keepalive_secs        x peers have own setting
   *            connect_retry_secs    x peers have own setting
   *            accept_retry_secs     x peers have own setting
   *            open_hold_secs        x peers have own setting
   *            ibgp_mrai_secs        x peers have own setting
   *            cbgp_mrai_secs        x peers have own setting
   *            ebgp_mrai_secs        x peers have own setting
   *            idle_hold_min_secs    x affects future restarts
   *            idle_hold_max_secs    x affects future restarts
   *            restart_time_secs     x affects future restarts
   *            stalepath_time_secs   x affects future restarts
   *            distance_ebgp         TODO
   *            distance_ibgp         TODO
   *            distance_local        TODO
   *
   *   * gruns                        x no effect on anything
   *
   *   * afp
   *        real_rib              TODO
   *
   *        do_always_compare_med    => brd_reselect  )
   *        do_deterministic_med     => brd_reselect  )
   *        do_confed_compare_med    => brd_reselect  ) for RIB
   *        do_aspath_ignore         => brd_reselect  )
   *        do_aspath_confed         => brd_reselect  )
   *
   *        do_damping            x affects future activity
   *
   *        redist                TODO
   *
   * Note that as part of this process we clear the delta state for all
   * current ribs -- so do not short-circuit brd_restart.  (This is for the
   * bgp instance... so a little extra work does not matter.)
   */
  brd = brd_null ;

  rp  = &brun->rp ;

  if (nrp->router_id != rp->router_id)
    brd |= brd_restart ;

  if (nrp->cluster_eid != rp->cluster_eid)
    brd |= brd_refresh_in | brd_refresh_out ;

  if (nrp->do_check_confed_id_all != rp->do_check_confed_id_all)
    brd |= brd_refresh_in ;

  if (nrp->no_client_to_client != rp->no_client_to_client)
    brd |= brd_refresh_out ;

  return brd ;
} ;

/*------------------------------------------------------------------------------
 * Establish the "delta" between the current rib running parameters and the
 * given ones or the default ones (if none given).
 *
 * Note that this does not change the current state.
 *
 * Returns:  the "delta"
 */
static bgp_run_delta_t
bgp_compile_rib_delta(bgp_rib rib, bgp_rib_param nribp)
{
  bgp_rib_param   ribp ;
  bgp_rib_param_t nribp_s ;
  bgp_run_delta_t brd ;

  brd = brd_null ;

  if (nribp == NULL)
    nribp = bgp_rib_param_init_new(&nribp_s) ;

  ribp = &rib->rp ;

  if ( (nribp->do_always_compare_med  != ribp->do_always_compare_med)  ||
       (nribp->do_deterministic_med   != ribp->do_deterministic_med)   ||
       (nribp->do_confed_compare_med  != ribp->do_confed_compare_med)  ||
       (nribp->do_prefer_current      != ribp->do_prefer_current)      ||
       (nribp->do_aspath_ignore       != ribp->do_aspath_ignore)       ||
       (nribp->do_aspath_confed       != ribp->do_aspath_confed) )
    brd |= brd_reselect ;

 return brd ;
} ;

/*------------------------------------------------------------------------------
 * Establish the "delta" between the current prun running parameters and the
 * given ones.
 *
 * Note that this does not change the current state.
 *
 * Returns:  the "delta"
 */
static bgp_run_delta_t
bgp_compile_prun_delta(bgp_prun prun, bgp_prun_param nprp)
{
  bgp_prun_param  prp ;
  bgp_run_delta_t brd ;
  bgp_cops        cc, ncc ;
  bgp_sargs       sc, nsc ;

  /* Changes in the bgp_prun_param:
   *
   *   * name                         x affects logging
   *   * cname                        x no effect on routeing
   *   * desc                         x no effect on routeing
   *   * grun                         x no effect on routeing
   *
   *   * sort                        => brd_restart
   *
   *   * do_shutdown                  x dealt with separately
   *
   *   * do_enforce_first_as         => brd_restart
   *   * do_log_neighbor_changes      x affects logging
   *
   *   * cops_conf                      -- see below
   *   * sargs_conf                     -- see below
   *
   *   * change_local_as              => brd_restart
   *   * do_local_as_prepend          => brd_refresh_out
   *
   *   * do_disable_connected_check   => brd_restart
   *
   *   * weight                       => brd_refresh_in
   *   * default_local_pref           => brd_refresh_in
   *   * default_med                  => brd_refresh_in
   *
   *   * mrai_secs                    x  affects future updates
   *
   *   * afp                          x  dealt with per afi/safi
   */
  brd = brd_delete ;

  prp = &prun->rp ;

  if ( (nprp->sort                       != prp->sort)                ||
       (nprp->do_enforce_first_as        != prp->do_enforce_first_as) ||
       (nprp->change_local_as            != prp->change_local_as)     ||
       (nprp->do_disable_connected_check != prp->do_disable_connected_check))
    return brd_restart ;

  if ( (nprp->change_local_as != BGP_ASN_NULL) &&
       (nprp->do_local_as_prepend != prp->do_local_as_prepend) )
    brd |= brd_refresh_out ;

  if ( (nprp->weight             != prp->weight)               ||
       (nprp->default_local_pref != prp->default_local_pref)   ||
       (nprp->default_med        != prp->default_med)  )
    brd |= brd_refresh_in ;

  /* Changes in the cops_config:
   *
   *   * remote_su                   => brd_restart
   *   * local_su                    => brd_restart
   *   * port                        => brd_restart
   *
   *   * conn_state                  => brd_renew
   *
   *   * can_notify_before_open      => brd_renew
   *   * idle_hold_max_secs          => brd_renew
   *   * connect_retry_secs          => brd_renew
   *   * accept_retry_secs           => brd_renew
   *   * open_hold_secs              => brd_renew
   *
   *   * ttl                         => brd_restart
   *   * gtsm                        => brd_restart
   *
   *   * ttl_out                     x  N/A
   *   * ttl_min                     x  N/A
   *
   *   * password                    => brd_restart
   *
   *   * ifname                      => brd_restart
   *   * ifindex                     x  N/A
   *
   * Those things which are brd_renew will affect the next connection to be
   * made, and may affect current not-yet-established connections.
   */
  ncc = &nprp->cops_conf ;
  cc  = &prp->cops_conf ;

  if ( !sockunion_same(&ncc->remote_su, &cc->remote_su) ||
       !sockunion_same(&ncc->local_su,  &cc->local_su)  ||
       (ncc->port != cc->port)                          ||
       (ncc->ttl  != cc->ttl)                           ||
       (ncc->gtsm != cc->gtsm)                          ||
       !strsame(ncc->password, cc->password)            ||
       !strsame(ncc->ifname,   cc->ifname) )
    return brd | brd_restart ;

  if ( (ncc->conn_state             != cc->conn_state)             ||
       (ncc->can_notify_before_open != cc->can_notify_before_open) ||
       (ncc->idle_hold_max_secs     != cc->idle_hold_max_secs)     ||
       (ncc->connect_retry_secs     != cc->connect_retry_secs)     ||
       (ncc->accept_retry_secs      != cc->accept_retry_secs)      ||
       (ncc->open_hold_secs         != cc->open_hold_secs) )
    brd |= brd_renew ;

  /* Changes in the sargs_config:
   *
   *   * local_as                    => brd_restart
   *   * local_id                    => brd_restart
   *   * remote_as                   => brd_restart
   *   * remote_id                   x  N/A
   *
   *   * can_capability              => brd_restart
   *   * can_mp_ext                  => brd_restart
   *   * can_as4                     => brd_restart
   *
   *   * cap_suppressed              x  N/A
   *
   *   * cap_af_override             => brd_restart
   *   * cap_strict                  => brd_restart
   *
   *   * can_af                      => brd_restart
   *   * can_rr                      => brd_restart
   *
   *   * gr                          => brd_restart  and see below
   *
   *   * can_orf                     => brd_restart
   *   * can_orf_pfx                 => brd_restart
   *
   *   * can_dynamic                 => brd_restart
   *   * can_dynamic_dep             => brd_restart
   *
   *   * holdtime_secs               => brd_renew
   *   * keepalive_secs              => brd_renew
   *
   * NB: can_af at this point should include all the address families for
   *     which the peer is configured.
   *
   * Those things which are brd_renew will affect the next connection to be
   * made, and may affect current not-yet-established connections.
   */
  nsc = &nprp->sargs_conf ;
  sc  = &prp->sargs_conf ;

  if ( (nsc->local_as         != sc->local_as)           ||
       (nsc->local_id         != sc->local_id)           ||
       (nsc->can_capability   != sc->can_capability)     ||
       (nsc->can_mp_ext       != sc->can_mp_ext)         ||
       (nsc->can_as4          != sc->can_as4)            ||
       (nsc->cap_af_override  != sc->cap_af_override)    ||
       (nsc->cap_strict       != sc->cap_strict)         ||
       (nsc->can_af           != sc->can_af)             ||
       (nsc->can_rr           != sc->can_rr)             ||
       (nsc->gr.can           != sc->gr.can)             ||
       (nsc->can_orf          != sc->can_orf)            ||
       (nsc->can_af           != sc->can_af)             ||
       (nsc->remote_as        != sc->remote_as) )
    return brd | brd_restart ;

  if (nsc->gr.can)
    {
      /* TODO ... not sure whether a change in the restart time should
       *          cause a reset -- though perhaps the other end needs to
       *          know what to expect on a restart ?
       *
       *          change in what may be preserved on a restart is probably
       *          something the other end does need to know ?
       */
      if ( (nsc->gr.can_preserve != sc->gr.can_preserve) ||
           (nsc->gr.restart_time != sc->gr.restart_time) )
        return brd | brd_restart ;
    } ;

  if ( (nsc->holdtime_secs    != sc->holdtime_secs)      ||
       (nsc->keepalive_secs   != sc->keepalive_secs) )
    brd |= brd_renew ;

  return brd ;
} ;

/*------------------------------------------------------------------------------
 * Establish the "delta" between the current prib running parameters and the
 * given ones.
 *
 * Note that this does not change the current state.
 *
 * Returns:  the "delta"
 */
static bgp_run_delta_t
bgp_compile_prib_delta(bgp_prib prib, bgp_prib_param npribp)
{
  bgp_prib_param  pribp ;
  bgp_run_delta_t brd ;
  bgp_nref*       fs, * nfs ;

  /* Changes in the bgp_prun_param:
   *
   *   * grun                        x  N/A
   *
   *   * do_soft_reconfig            => brd_restart
   *   * is_route_server_client      => brd_restart
   *   * is_route_reflector_client   => brd_restart
   *
   *   * do_send_community           => brd_refresh_out
   *   * do_send_ecommunity          => brd_refresh_out
   *   * do_next_hop_self            => brd_refresh_out
   *   * do_next_hop_unchanged       => brd_refresh_out
   *   * do_next_hop_local_unchanged => brd_refresh_out
   *   * do_as_path_unchanged        => brd_refresh_out
   *   * do_remove_private_as        => brd_refresh_out
   *   * do_med_unchanged            => brd_refresh_out
   *
   *   * do_default_originate        => brd_restart
   *
   *   * allow_as_in                 => brd_refresh_in
   *
   *   * filter_set                  => brd_refresh_in/_out
   *
   *   * pmax                        x  affects continuing session
   */
  brd = brd_delete ;

  pribp = &prib->rp ;

  if ( (npribp->do_soft_reconfig          != pribp->do_soft_reconfig)       ||
       (npribp->is_route_server_client    != pribp->is_route_server_client) ||
       (npribp->is_route_reflector_client != pribp->is_route_reflector_client)||
       (npribp->do_default_originate      != pribp->do_default_originate) )
    return brd_restart ;

  if ( (npribp->do_send_community     != pribp->do_send_community)     ||
       (npribp->do_send_ecommunity    != pribp->do_send_ecommunity)    ||
       (npribp->do_next_hop_self      != pribp->do_next_hop_self)      ||
       (npribp->do_next_hop_unchanged != pribp->do_next_hop_unchanged) ||
       (npribp->do_next_hop_local_unchanged
                                      != pribp->do_next_hop_local_unchanged) ||
       (npribp->do_as_path_unchanged  != pribp->do_as_path_unchanged)  ||
       (npribp->do_remove_private_as  != pribp->do_remove_private_as)  ||
       (npribp->do_next_hop_unchanged != pribp->do_next_hop_unchanged) ||
       (npribp->do_med_unchanged      != pribp->do_med_unchanged) )
    brd |= brd_refresh_out ;

  if ( (npribp->allow_as_in           != pribp->allow_as_in) )
    brd |= brd_refresh_in ;

  nfs = npribp->filter_set ;
  fs  = pribp->filter_set ;

  if ( (nfs[bfs_dlist_in]    != fs[bfs_dlist_in]) ||
       (nfs[bfs_plist_in]    != fs[bfs_plist_in]) ||
       (nfs[bfs_aslist_in]   != fs[bfs_aslist_in]) ||
       (nfs[bfs_rmap_in]     != fs[bfs_rmap_in]) ||
       (nfs[bfs_rmap_inx]    != fs[bfs_rmap_inx]) ||
       (nfs[bfs_rmap_import] != fs[bfs_rmap_import]) ||
       (nfs[bfs_rmap_export] != fs[bfs_rmap_export]) )
    brd |= brd_refresh_in ;

  if ( (nfs[bfs_dlist_out]  != fs[bfs_dlist_out]) ||
       (nfs[bfs_plist_out]  != fs[bfs_plist_out]) ||
       (nfs[bfs_aslist_out] != fs[bfs_aslist_out]) ||
       (nfs[bfs_rmap_out]   != fs[bfs_rmap_out]) )
    brd |= brd_refresh_in ;

  if ( (nfs[bfs_us_rmap] != fs[bfs_us_rmap]) ||
       (nfs[bfs_default_rmap] != fs[bfs_default_rmap]) )
    brd |= brd_restart ;

  if ( (nfs[bfs_orf_plist] != fs[bfs_orf_plist]) )
    brd |= brd_route_refresh ;

  return brd ;
} ;

/*------------------------------------------------------------------------------
 * Clear out the given brun group membership.
 *
 * Releases all the bgp_grun objects and all their members.
 */
static void
bgp_compile_clear_groups(bgp_run brun)
{
  bgp_grun grun ;

  while ((grun = vector_ream(brun->rp.gruns, keep_it)) != NULL)
    {
      bgp_prun  prun ;
      qafx_t    qafx ;

      while ((prun = vector_ream(grun->prun_members, keep_it)) != NULL)
        prun->rp.grun = NULL ;

      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_prib  prib ;

          while ((prib = vector_ream(grun->prib_members[qafx], keep_it))
                                                                        != NULL)
            prib->rp.grun = NULL ;
        } ;

      ni_nref_clear(&grun->name) ;
      XFREE(MTYPE_BGP_GRUN, grun) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given prun to those atteched to the given grun
 */
static void
bgp_compile_grun_add_prun(bgp_grun grun, bgp_prun prun)
{
  ;
} ;

/*------------------------------------------------------------------------------
 * Add given prun to those atteched to the given grun
 */
static void
bgp_compile_grun_add_prib(bgp_grun grun, bgp_prib prib, qafx_t qafx)
{
  ;
} ;


#if 0


/*------------------------------------------------------------------------------
 * Construct a new, configured but otherwise empty prun and its prib(s).
 *
 *
 */
extern bgp_prun
bgp_config_prun(bgp_pconfig pconf)
{
  bgp_run       brun ;
  bgp_prun      prnew ;
  bgp_cops      cops ;
  bgp_sargs     sargs ;
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
  cops   = &prnew->rp.cops ;
  bgp_cops_init_new(cops) ;

  sargs   = &prnew->rp.sargs ;
  bgp_sargs_init_new(sargs) ;

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
  prnew->rp.disable_connected_check =
                         (pconf->c_flags & PEER_FLAG_DISABLE_CONNECTED_CHECK) ;
  prnew->rp.do_local_as_prepend =
                         (pconf->c_flags & PEER_FLAG_CHANGE_LOCAL_AS_PREPEND) ;

  /* Transfer other simple settings
   */
  prnew->rp.sort                     = pconf->c_sort ;
  prnew->rp.do_local_as_prepend  = pconf->c_change_local_as ;

  prnew->rp.weight                   = pconf->c_weight ;
  prnew->rp.mrai_secs                     = pconf->c_mrai ;

  /* Transfer the cops -- making sure we start from a clean state.
   *
   * We copy everything, except for:
   *
   *   * remote_su              -- set to copy of su_name
   *
   *   * conn_state             -- copy only bgp_csMayMask
   *
   *   * ttl_out                -- 0    -- N/A
   *   * ttl_min                -- 0    -- N/A
   *
   *   * ifindex                -- 0    -- N/A
   */
  cops   = &prnew->rp.cops ;
  c_cops = &pconf->c_cops ;

  bgp_cops_init_new(cops) ;

  sockunion_copy(&cops->remote_su, prnew->su_name) ;

  cops->local_su                = c_cops->local_su ;
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
  sargs   = &prnew->rp.sargs ;
  c_args = &pconf->c_args ;

  bgp_sargs_init_new(sargs) ;

  sargs->local_as                = c_args->local_as ;
  sargs->local_id                = c_args->local_id ;
  sargs->remote_as               = c_args->remote_as ;
  sargs->remote_id               = c_args->remote_id ;
  sargs->can_capability          = c_args->can_capability ;
  sargs->can_mp_ext              = c_args->can_mp_ext ;
  sargs->can_as4                 = c_args->can_as4 ;
  sargs->cap_af_override         = c_args->cap_af_override ;
  sargs->cap_strict              = c_args->cap_strict ;
  sargs->can_rr                  = c_args->can_rr ;

  sargs->gr.can                  = c_args->gr.can ;

  sargs->can_orf                 = c_args->can_orf ;
  sargs->can_orf_pfx             = c_args->can_orf_pfx ;
  sargs->can_dynamic             = c_args->can_dynamic ;
  sargs->can_dynamic_dep         = c_args->can_dynamic_dep ;
  sargs->holdtime_secs           = c_args->holdtime_secs ;
  sargs->keepalive_secs          = c_args->keepalive_secs ;

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

  prib->rp.do_soft_reconfig            = (caff & PEER_AFF_SOFT_RECONFIG) ;
  prib->rp.is_route_server_client      = (caff & PEER_AFF_RSERVER_CLIENT) ;
  prib->rp.is_route_reflector_client   = (caff & PEER_AFF_REFLECTOR_CLIENT) ;
  prib->rp.do_send_community           = (caff & PEER_AFF_SEND_COMMUNITY) ;
  prib->rp.do_send_ecommunity          = (caff & PEER_AFF_SEND_EXT_COMMUNITY) ;
  prib->rp.do_next_hop_self            = (caff & PEER_AFF_NEXTHOP_SELF) ;
  prib->rp.do_next_hop_unchanged       = (caff & PEER_AFF_NEXTHOP_UNCHANGED) ;
  prib->rp.do_next_hop_local_unchanged = (caff & PEER_AFF_NEXTHOP_LOCAL_UNCHANGED) ;
  prib->rp.do_as_path_unchanged        = (caff & PEER_AFF_AS_PATH_UNCHANGED) ;
  prib->rp.do_remove_private_as        = (caff & PEER_AFF_REMOVE_PRIVATE_AS) ;
  prib->rp.do_med_unchanged            = (caff & PEER_AFF_MED_UNCHANGED) ;
  prib->rp.do_default_originate        = (caff & PEER_AFF_DEFAULT_ORIGINATE) ;

  prib->rp.allow_as_in = pafconf->c_allow_as_in ;

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

#endif




