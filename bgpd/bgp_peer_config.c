/* BGP Peer and Peer-Group Configuration
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Restructured: Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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
#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_peer_config.h"
#include "bgpd/bgp_inst_config.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"

#include "vty.h"

/*==============================================================================
 * Output of peer configuration
 */
static void bgp_peer_af_config_write (vty vty, bgp_peer peer, qafx_t qafx) ;

/*------------------------------------------------------------------------------
 * BGP peer configuration display function.
 */
extern bool
bgp_peer_config_write (vty vty, bgp_peer peer, bool done_peer)
{
  bgp_pconfig     pc, gc ;
  chs_c           pgn ;
  qafx_t          qafx ;

  pgn  = peer->name ;           /* for group this is the group name     */
  pc   = peer->c ;

  /* Set: gc -> group configuration if is member of group
   */
  gc   = NULL ;

  if (pc->ctype != BGP_CFT_MEMBER)
    {
      qassert(pcs_is_off(pc, pcs_group)) ;
      qassert(pc->gc == NULL) ;
    }
  else
    {
      qassert(pcs_is_on(pc, pcs_group)) ;
      qassert(pc->gc != NULL) ;
      gc = pc->gc ;
    } ;

  /* Now either the neighbor or group heading
   */
  if (done_peer)
    vty_out(vty, "\n") ;                /* separate neighbors   */
  else
    done_peer = true ;

  if (gc == NULL)
    {
      /* Not a peer group member, so:
       *
       *   * may be a peer group -- so start with its pgn, followed
       *                            by an AS, if any.
       *
       *   * otherwise must be a real peer, with an explicit AS -- WILL have !
       */
      if (pc->ctype == BGP_CFT_GROUP)
        vty_out (vty, " neighbor %s peer-group\n", pgn);
      else
        qassert(pc->ctype == BGP_CFT_PEER) ;

      if (pcs_is_on(pc, pcs_remote_as) || (pc->ctype == BGP_CFT_PEER))
        vty_out (vty, " neighbor %s remote-as %u\n", pgn, pc->remote_as) ;
      else
        qassert(pc->ctype == BGP_CFT_GROUP) ;
    }
  else
    {
      /* Is a peer group member, so must be a real peer.
       *
       * If the group has an AS, then the real peer will inherit that.
       *
       * NB: in BGP_OPT_LEGACY_GROUPS state the reader of the configuration
       *     will activate IPv4/Unicast -- if not implicitly activated by
       *     DEFAULT_IPV4.  So, for BGP_OPT_LEGACY_GROUPS we also have to
       *     turn off IPv4/Unicast !
       */
      qassert(pc->ctype == BGP_CFT_PEER) ;

      if (!pcs_is_on(gc, pcs_remote_as))
        vty_out (vty, " neighbor %s remote-as %u\n", pgn, pc->remote_as) ;

      vty_out (vty, " neighbor %s peer-group %s\n", pgn,
                                                        gc->parent_peer->name) ;
    } ;

  if (pcs_is_set(pc, pcs_change_local_as))
    vty_out (vty, " neighbor %s local-as %u%s\n", pgn,
                pc->change_local_as,
                pc->change_local_as_prepend ? "" : " no-prepend") ;

  if (pcs_is_set(pc, pcs_description))
    vty_out (vty, " neighbor %s description %s\n", pgn, pc->desc);

  if (pcs_is_set(pc, pcs_SHUTDOWN))
    vty_out (vty, " neighbor %s shutdown\n", pgn);

  if (pcs_is_set(pc, pcs_password))      // TODO !!
    vty_out (vty, " neighbor %s password %s\n", pgn,
                                              ni_nref_name(pc->password)) ;

  if (pcs_is_set(pc, pcs_port))
    vty_out (vty, " neighbor %s port %u\n", pgn, pc->port);

#if 0
  /* Deprecated and now removed
   */
  if ((pc->c_cops.ifname[0] != '\0') && !(pc->c_set & PEER_CONFIG_INTERFACE))
    vty_out (vty, " neighbor %s interface %s\n", pgn, pc->c_cops.ifname);
#endif

  if (pcs_is_set(pc, pcs_PASSIVE))
    vty_out (vty, " neighbor %s passive\n", pgn);

  if (pcs_is_set(pc, pcs_ACTIVE))
    vty_out (vty, " neighbor %s active\n", pgn);   // TODO

  if (pcs_is_set(pc, pcs_ttl_security))
    vty_out (vty, " neighbor %s ttl-security hops %u\n", pgn, pc->ttl) ;
  else if (pcs_is_set(pc, pcs_multihop))
    vty_out (vty, " neighbor %s ebgp-multihop %u\n", pgn, pc->ttl) ;

  if (pcs_is_set(pc, pcs_DISABLE_CONNECTED_CHECK))
    vty_out (vty, " neighbor %s disable-connected-check\n", pgn);

  if (pcs_is_set(pc, pcs_update_source))
    vty_out (vty, " neighbor %s update-source %s\n", pgn,
                                          ni_nref_name(pc->update_source)) ;

  if (pcs_is_set(pc, pcs_mrai))
    vty_out (vty, " neighbor %s advertisement-interval %u\n", pgn,
                                                           pc->mrai_secs) ;

  if (pcs_is_set(pc, pcs_timers))
    vty_out (vty, " neighbor %s timers %u %u\n", pgn,
                                  pc->keepalive_secs, pc->holdtime_secs) ;

  if (pcs_is_set(pc, pcs_connect_retry))
    vty_out (vty, " neighbor %s timers connect %u\n", pgn,
                                                  pc->connect_retry_secs) ;

  if (pcs_is_set(pc, pcs_weight))
    vty_out (vty, " neighbor %s weight %u\n", pgn, pc->weight) ;

  if (pcs_is_set(pc, pcs_DONT_CAPABILITY))
    vty_out (vty, " neighbor %s dont-capability-negotiate\n", pgn);

  if (pcs_is_set(pc, pcs_OVERRIDE_CAPABILITY))
    vty_out (vty, " neighbor %s override-capability\n", pgn);

  if (pcs_is_set(pc, pcs_STRICT_CAP_MATCH))
    vty_out (vty, " neighbor %s strict-capability-match\n", pgn);

  /* Now the address family stuff
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    bgp_peer_af_config_write (vty, peer, qafx) ;

  return done_peer ;
} ;

/*------------------------------------------------------------------------------
 * BGP peer configuration display function.
 */
static void
bgp_peer_af_config_write (vty vty, bgp_peer peer, qafx_t qafx)
{
  bgp_pconfig     pc ;
  bgp_paf_config  pafc, gafc ;
  chs_c           pgn, fn ;
  uint  i ;
  chs_c no ;

  pgn  = peer->name ;           /* for group this is the group name     */

  pc   = peer->c ;
  pafc = NULL ;

  if (pcs_qafx_config(pc, qafx))
    {
      pafc = pc->afc[qafx] ;
      qassert(pafc != NULL) ;
    } ;

  if (pafc == NULL)
    {
      /* Special for turning *off* default IPv4 if required.
       */
      if (qafx == qafx_ipv4_unicast)
        {
          if (bgp_peer_ipv4_default(peer) ||
                                  bgp_option_check(BGP_OPT_LEGACY_IPV4_DEFAULT))
            vty_out (vty, " no neighbor %s activate\n", pgn) ;
        } ;

      return ;
    }

  /* Set: gafc -> group afc if is member of group in this afc
   */
  gafc = NULL ;

  if (pafc->ctype != BGP_CFT_MEMBER)
    {
      qassert(!pafcs_is_on(pafc, pafcs_group)) ;
      qassert(pafc->gafc == NULL) ;
    }
  else
    {
      qassert(pafcs_is_on(pafc, pafcs_group)) ;

      gafc = pafc->gafc ;
      qassert((gafc != NULL) && (pcs_qafx_config(gafc->parent_pconf, qafx))
                             && (gafc == gafc->parent_pconf->afc[qafx])) ;
    } ;

  /* Worry about the address family selection and activate the address family.
   *
   * With default IPv4 this is redundant for that... but does no harm.
   *
   * Note that legacy configuration activates address family when binding
   * to a group, if not already activated !
   */
  bgp_config_write_family_header(vty, qafx, NULL) ;
  vty_out (vty, " neighbor %s activate\n", pgn);

  /* Worry about group setting
   */
  if (gafc != NULL)
    {
      vty_out (vty, " neighbor %s peer-group %s\n", pgn,
                                         gafc->parent_pconf->parent_peer->name);

      qassert((pafc->set_on & gafc->set_on) == 0) ;

      pafc->set_on &= ~gafc->set_on ;
    } ;

  /* So now the configuration....
   */
  i = 0 ;
  if (pafcs_is_set(pafc, pafcs_ORF_SEND))
    i |= 1 ;
  if (pafcs_is_set(pafc, pafcs_ORF_RECV))
    i |= 2 ;

  if (i != 0)
    {
      static chs_c const what[] =
          {
              [1]       = "send",
              [2]       = "receive",
              [3]       = "both"
          };
                        ;
      vty_out (vty, " neighbor %s capability orf prefix-list %s\n", pgn,
                                                                       what[i]);
    } ;

  if (pafcs_is_set(pafc, pafcs_REFLECTOR_CLIENT))
    vty_out (vty, " neighbor %s route-reflector-client\n", pgn);

  if (pafcs_is_set(pafc, pafcs_NEXTHOP_SELF))
    vty_out (vty, " neighbor %s next-hop-self\n", pgn);

  if (pafcs_is_set(pafc, pafcs_REMOVE_PRIVATE_AS))
    vty_out (vty, " neighbor %s remove-private-AS\n", pgn);

  i = 0 ;
  if (pafcs_is_set(pafc, pafcs_SEND_COMMUNITY))
    i |= 1 ;
  if (pafcs_is_set(pafc, pafcs_SEND_EXT_COMMUNITY))
    i |= 2 ;

  if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
    no = "" ;
  else
    {
      no = "no " ;
      i ^= 3 ;
    } ;

  if (i != 0)
    {
      static chs_c const what[] =
          {
              [1]       = "",
              [2]       = " extended",
              [3]       = " both",
          };
                        ;
      vty_out (vty, " %sneighbor %s send-community%s\n", no, pgn, what[i]);
    } ;

  if (pafcs_is_set(pafc, pafcs_DEFAULT_ORIGINATE))
    {
      fn = ni_nref_name(pafc->filter_set[bfs_default_rmap]) ;
      vty_out (vty, " neighbor %s default-originate", pgn);
      if (pafcs_is_set(pafc, pafcs_default_rmap))
        vty_out (vty, " route-map %s", fn);
      vty_out (vty, "\n");
    }

  if (pafcs_is_set(pafc, pafcs_SOFT_RECONFIG))
    vty_out (vty, " neighbor %s soft-reconfiguration inbound\n", pgn);

  if (pafcs_is_set(pafc, pafcs_max_prefix))
    {
      vty_out (vty, " neighbor %s maximum-prefix %u", pgn,
                                                           pafc->pmax.limit);
      if (pafc->pmax.thresh_pc != MAXIMUM_PREFIX_THRESHOLD_DEFAULT)
        vty_out (vty, " %d", pafc->pmax.thresh_pc);
      if (pafc->pmax.warning)
        vty_out (vty, " warning-only");
      if (pafc->pmax.restart != 0)
        vty_out (vty, " restart %d", pafc->pmax.restart);
      vty_out (vty, "\n");
    }

  if (pafcs_is_set(pafc, pafcs_RSERVER_CLIENT))
    vty_out (vty, " neighbor %s route-server-client%s", pgn, VTY_NEWLINE);

  if (pafcs_is_set(pafc, pafcs_NEXTHOP_LOCAL_UNCHANGED))
    vty_out (vty, " neighbor %s nexthop-local unchanged\n", pgn);

  if (pafcs_is_set(pafc, pafcs_allow_as_in))
    {
      if (pafc->allow_as_in == 3)
        vty_out (vty, " neighbor %s allowas-in\n", pgn);
      else
        vty_out (vty, " neighbor %s allowas-in %d\n", pgn, pafc->allow_as_in);
    }

  fn = ni_nref_name(pafc->filter_set[bfs_dlist_in]) ;
  if (pafcs_is_set(pafc, pafcs_dlist_in))
    vty_out (vty, " neighbor %s distribute-list %s in\n", pgn, fn) ;

  fn = ni_nref_name(pafc->filter_set[bfs_dlist_out]) ;
  if (pafcs_is_set(pafc, pafcs_dlist_out))
    vty_out (vty, " neighbor %s distribute-list %s out\n", pgn, fn) ;

  fn = ni_nref_name(pafc->filter_set[bfs_plist_in]) ;
  if (pafcs_is_set(pafc, pafcs_plist_in))
    vty_out (vty, " neighbor %s prefix-list %s in\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_plist_out]) ;
  if (pafcs_is_set(pafc, pafcs_plist_out))
    vty_out (vty, " neighbor %s prefix-list %s in\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_rmap_in]) ;
  if (pafcs_is_set(pafc, pafcs_rmap_in))
    vty_out (vty, " neighbor %s route-map %s in\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_rmap_out]) ;
  if (pafcs_is_set(pafc, pafcs_rmap_out))
    vty_out (vty, " neighbor %s route-map %s out\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_rmap_inx]) ;
  if (pafcs_is_set(pafc, pafcs_rmap_inx))
    vty_out (vty, " neighbor %s route-map %s rs-in\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_rmap_export]) ;
  if (pafcs_is_set(pafc, pafcs_rmap_export))
    vty_out (vty, " neighbor %s route-map %s export\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_rmap_import]) ;
  if (pafcs_is_set(pafc, pafcs_rmap_import))
    vty_out (vty, " neighbor %s route-map %s import\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_us_rmap]) ;
  if (pafcs_is_set(pafc, pafcs_us_rmap))
    vty_out (vty, " neighbor %s unsuppress-map %s import\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_aslist_in]) ;
  if (pafcs_is_set(pafc, pafcs_aslist_in))
    vty_out (vty, " neighbor %s filter-list %s in\n", pgn, fn);

  fn = ni_nref_name(pafc->filter_set[bfs_aslist_out]) ;
  if (pafcs_is_set(pafc, pafcs_aslist_out))
    vty_out (vty, " neighbor %s filter-list %s out\n", pgn, fn);

  i = 0 ;
  if (pafcs_is_set(pafc, pafcs_AS_PATH_UNCHANGED))
    i |= 1 ;
  if (pafcs_is_set(pafc, pafcs_NEXTHOP_UNCHANGED))
    i |= 2 ;
  if (pafcs_is_set(pafc, pafcs_MED_UNCHANGED))
    i |= 4 ;

  if (i != 0)
    {
      static chs_c const what[] =
          {
              [1]       = " as-path",
              [2]       =            " next-hop",
              [3]       = " as-path" " next-hop",
              [4]       =                        " med",
              [5]       = " as-path"             " med",
              [6]       =            " next-hop" " med",
              [7]       = "",
          };

      vty_out (vty, " neighbor %s attribute-unchanged%s\n", pgn, what[i]) ;
    } ;
} ;

/*==============================================================================
 * Creation and destruction of peers/peer-groups and binding of same.
 *
 */
static bgp_peer bgp_peer_new(bgp_inst bgp, bgp_peer_type_t ptype, chs_c name,
                                                            sockunion su_name) ;
static bgp_peer bgp_peer_free(bgp_peer peer) ;
static bgp_paf_config bgp_peer_get_af_config(bgp_peer peer, qafx_t qafx) ;
static bgp_paf_config bgp_peer_free_af_config(bgp_paf_config pafc) ;

static bgp_ret_t bgp_peer_bind_general(bgp_pconfig pc, bgp_pconfig gc) ;
static bgp_ret_t bgp_peer_bind_af(bgp_paf_config pafc, bgp_paf_config gafc) ;
static bgp_ret_t bgp_peer_unbind_general(bgp_pconfig pc) ;
static bgp_ret_t bgp_peer_unbind_af(bgp_paf_config pafc) ;

extern bgp_peer_sorts_t bgp_peer_explicit_sorts(bgp_peer peer) ;
static bgp_peer_sorts_t bgp_peer_implicit_sorts(bgp_peer peer) ;
static bgp_peer_sorts_t bgp_peer_implicit_af_sorts(bgp_peer peer) ;
static bgp_peer_sorts_t bgp_peer_as_sorts(bgp_peer peer, as_t asn) ;

static bgp_ret_t bgp_config_pcs_change(bgp_pconfig pc, bgp_pc_setting_t pcs,
                                                                 bgp_sc_t bsc) ;
static bgp_ret_t bgp_config_pafcs_change(bgp_paf_config pafc,
                                       bgp_pafc_setting_t pafcs, bgp_sc_t bsc) ;

static int bgp_peer_cmp (const cvp* p_p1, const cvp* p_p2) ;
static int bgp_peer_config_cmp (const cvp* p_pc1, const cvp* p_pc2) ;
static int bgp_peer_af_config_cmp (const cvp* p_pc1, const cvp* p_pc2) ;

static int bgp_peer_cmp_su(const cvp* p_su, const cvp* p_p) ;
static int bgp_peer_cmp_name(const cvp* p_n, const cvp* p_p) ;

/*------------------------------------------------------------------------------
 * Create a new peer, with given AS or bound to group and it's AS.
 *
 * If binding to group, it MUST have an AS.
 *
 * No peer with the given address may exist, already.
 *
 * Returns:  BGP_SUCCESS  -- all set.
 */
extern bgp_ret_t
bgp_peer_create_peer(bgp_inst bgp, sockunion su, as_t as, bgp_peer group)
{
  bgp_peer      peer ;
  bgp_pconfig   pc ;
  bool          group_as ;

  /* Check whether we can do this.
   */
  group_as = false ;

  if (group != NULL)
    {
      /* If group has a remote-as, then peer must follow -- and cannot try to
       * set a different ASN.
       */
      if (pcs_is_on(group->c, pcs_remote_as))
        {
          if (as == BGP_ASN_NULL)
            as = group->c->remote_as ;
          else if (as != group->c->remote_as)
            return BGP_ERR_CANNOT_SET_AS_AND_GROUP ;

          group_as = true ;
        } ;
    } ;

  if (as == BGP_ASN_NULL)
    {
      if (group == NULL)
        return BGP_ERR_PEER_NEEDS_REMOTE_AS ;
      else
        return BGP_ERR_GROUP_NEEDS_REMOTE_AS ;
    } ;

  if (bcs_is_on(bgp->c, bcs_confed_id) && (as == bgp->c->confed_id))
    {
      if (bgp_peer_as_sort(bgp, as) == BGP_PEER_EBGP)
        return BGP_ERR_AS_IS_CONFED_ID ;
    } ;

  peer = bgp_peer_lookup_su(NULL, su) ;
  if (peer != NULL)
    {
      if (peer->parent_bgp == bgp)
        return BGP_ERR_PEER_EXISTS_IN_VIEW ;
      else
        return BGP_ERR_PEER_EXISTS ;
    } ;

  /* OK... we are all set to create a new peer.
   *
   * Make empty configuration, with no address families.
   *
   * Note that the text name is constructed from the su, so is in canonical
   * form.
   */
  peer = bgp_peer_new(bgp, PEER_TYPE_REAL, sutoa(su).str, su) ;
  pc   = peer->c ;

  /* Bind to the group, if any -- simple, since we have an empty configuration
   * in any case !
   */
  if (group != NULL)
    {
      bgp_pconfig   gc ;

      gc = group->c ;

      pc->gc      = gc ;
      pc->ctype   = BGP_CFT_MEMBER ;

      qassert(gc->members != NULL) ;
      vector_binsert(gc->members, bgp_peer_config_cmp, pc) ;
    } ;

  /* Now set the ASN
   *
   * Note that we set remote_as even if we are actually inheriting from the
   * group.  This is an exception from the general rule that "unset" settings
   * have no value !
   */
  pc->remote_as = as ;
  if (!group_as)
    {
      pc->set     |= pcs_bit(pcs_remote_as) ;
      pc->set_on  |= pcs_bit(pcs_remote_as) ;
    } ;

  /* All set XXX add peer to changed list ???
   */
  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Create a new group for the given bgo instance
 */
extern bgp_ret_t
bgp_peer_create_group(bgp_inst bgp, chs_c g_str)
{
  bgp_peer group ;
  bgp_ret_t ret ;

  /* Check whether we can do this.
   */
  ret = bgp_peer_sex(g_str, NULL, bpog_group_name) ;
  if (ret != BGP_OK_GROUP_NAME)
    return ret ;

  group = bgp_peer_lookup_group(bgp, g_str) ;
  if (group != NULL)
    return BGP_ERR_PEER_GROUP_EXISTS ;

  /* OK... we are all set to create a new peer.
   *
   * Make empty configuration -- with no address families.
   */
  group = bgp_peer_new(bgp, PEER_TYPE_GROUP, g_str, NULL) ;

  /* All set
   */
  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Delete the given peer/peer-group from the configuration
 */
extern bgp_ret_t
bgp_peer_delete (bgp_peer peer)
{
  peer = bgp_peer_free(peer) ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Set/Unset the ASN for the given peer/peer-group.
 *
 * For peer:       may not set if is member of group which sets the ASN.
 *
 *                 may not unset or set off at any time !
 *
 *                 Note that ASN is an exception to the general rule that
 *                 peers may override the group if they wish.
 *
 * For peer-group: may set iff there are no members, or all members currently
 *                 have the given ASN !  Note that this allows the ASN of an
 *                 existing group with an ASN to be changed.
 *
 *                 may unset at any time -- all dependent peers gain an
 *                 explicit setting, same like the current setting.
 *
 * Setting the ASN may change the sort of the peer... now we begin to wish
 * this was not allowed !  Some peer sort changes are denied by the implied
 * restrictions for some settings -- see bgp_peer_implicit_sorts().
 */
extern bgp_ret_t
bgp_peer_as_set(bgp_peer peer, as_t as, bgp_sc_t bsc)
{
  bgp_pconfig pc, gc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if ((as < BGP_ASN_FIRST) || (as > BGP_ASN_LAST))
        return BGP_ERR_INVALID_AS ;
    }
  else
    as = BGP_ASN_NULL ;

  switch (pc->ctype)
    {
      case BGP_CFT_MEMBER:
        if ((bsc == bsc_set_on) && !pcs_is_on(pc, pcs_remote_as))
          {
            qassert(pc->gc != NULL) ;
            qassert(pcs_is_on(pc->gc, pcs_remote_as)) ;

            return BGP_ERR_PEER_CANNOT_SET_AS ;
          } ;

        fall_through ;

      case BGP_CFT_PEER:
        if (bsc != bsc_set_on)
          return BGP_ERR_PEER_CANNOT_UNSET_AS ;

        break ;

      case BGP_CFT_GROUP:
        gc = pc ;               /* for clarity  */

        if (bsc == bsc_set_on)
          {
            bgp_pconfig mc ;
            uint i ;

            i = 0 ;
            while ((mc = vector_get_item(gc->members, i++)) != NULL)
              {
                if (pcs_is_on(mc, pcs_remote_as))
                  {
                    /* Have a member claiming to have a remote-as.
                     *
                     * Must be trying to set an ASN for the group after the
                     * event, which we allow iff they have the given ASN !
                     */
                    qassert(!pcs_is_on(gc, pcs_remote_as)) ;

                    if (mc->remote_as != as)
                      return BGP_ERR_GROUP_CANNOT_SET_AS ;
                    ;
                  }
                else
                  {
                    /* Member does not have a remote-as -- so must already be
                     * following the group, so that's fine.  (We require the
                     * member's remote-as value to be set... unlike other
                     * inherited values.)
                     */
                    qassert(pcs_is_on(gc, pcs_remote_as)) ;
                    qassert(mc->remote_as == gc->remote_as) ;
                  } ;
              } ;
          }
        else
          {
            /* Unsetting for group...
             *
             * ...need do nothing if not set.
             *
             * ...otherwise, clear the group setting and then set all members.
             * This does not actually change anything -- except that each
             * member is now the master of its own fate !
             */
            bgp_pconfig mc ;
            uint        i ;
            bool        group_as ;

            group_as = pcs_is_on(gc, pcs_remote_as) ;
            if (group_as)
              bgp_config_pcs_change(gc, pcs_remote_as, bsc_unset) ;

            i = 0 ;
            while ((mc = vector_get_item(gc->members, i++)) != NULL)
              {
                if (pcs_is_on(mc, pcs_remote_as))
                  {
                    /* Have a member claiming to have an ASN.
                     *
                     * So the group must NOT have one !
                     */
                    qassert(!pcs_is_on(gc, pcs_remote_as)) ;
                  }
                else
                  {
                    /* Member does not have an remote-as -- so must be
                     * following the group, so we can give back mastery over
                     * the remote-as setting.
                     */
                    qassert(pcs_is_on(gc, pcs_remote_as)) ;
                    qassert(mc->remote_as == gc->remote_as) ;

                    mc->set      |= pcs_bit(pcs_remote_as) ;
                    mc->set_on   |= pcs_bit(pcs_remote_as) ;
                    mc->remote_as = gc->remote_as ;     /* make sure    */
                  } ;
              } ;

            return BGP_SUCCESS ;        /* done group unset     */
          } ;
        break ;

      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
    } ;

  /* About to set remote-as for a peer or a peer-group.
   *
   * As a side effect the sort of the peer-group or peer may change.  In some
   * cases that change is disallowed -- where the peer-group or peer has one
   * or more settings which imply a limited set of sorts.
   *
   * For a peer-group we know that either:
   *
   *   * the peer-group already has a remote-as set -- in which case all the
   *     group members share the existing remote-as and sort with the group.
   *
   *   * we are setting a remote-as on the peer-group for the first time -- in
   *     which case all the group members have (by the time we get here) the
   *     same remote-as as the one we are setting for the group.
   *
   * ...in both cases, the peer-group and its members are fully aligned,
   * remote-as-wise and hence sort-wise -- so we need consider only the state
   * of the peer-group.
   *
   * bgp_peer_implicit_sorts() returns the set of sorts which the current
   * settings are compatible with.
   *
   * bgp_peer_as_sorts() returns the sort that the given as implies (as a set
   * with just one member).
   */
  qassert(bsc == bsc_set_on) ;

  if (!(bgp_peer_implicit_sorts(peer) & bgp_peer_as_sorts(peer, as)))
    return BGP_ERR_CANNOT_CHANGE_AS ;

  /* OK... we can do this thing.
   */
  pc->remote_as = as ;

  return bgp_config_pcs_change(pc, pcs_remote_as, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set/Unset group association for given peer and afi/safi.
 *
 * For qafx_none -- set/unset the general configuration association.
 *
 * For set:   will reject if the qafx is not configured.
 *
 *            will do nothing if the given group is already configured.
 *
 *            will reject if a different group is already configured.
 *
 *            will reject if given group has no configuration for the afi/safi
 *
 *            otherwise: bind the general configuration.
 *
 * For unset: does not care if afi/safi is configured
 *
 *            is perfectly happy if no group is configured.
 *
 * Unbinding leaves all existing peer specific settings, and if the group
 * set the remote-as, the peer will retain that.
 */
extern bgp_ret_t
bgp_peer_group_set(bgp_peer peer, bgp_peer group, qafx_t qafx, bgp_sc_t bsc)
{
  bgp_pconfig       pc, gc ;
  bgp_paf_config    pafc, gafc ;

  pc = bgp_config_peer_prepare(peer) ;

  gc = NULL ;

  if (bsc == bsc_set_on)
    {
      if (group == NULL)
        return BGP_ERR_INVALID_VALUE ;

      gc = group->c ;
    } ;

  /* Deal with binding of general configuration.
   */
  if (qafx == qafx_none)
    {
      switch (pc->ctype)
        {
          case BGP_CFT_PEER:
            qassert(pc->gc == NULL) ;

            if (bsc == bsc_set_on)
              return bgp_peer_bind_general(pc, gc) ;
            else
              return BGP_SUCCESS ;

          case BGP_CFT_MEMBER:
            qassert(pc->gc != NULL) ;

            if (bsc == bsc_set_on)
              {
                if (pc->gc == gc)
                  return BGP_SUCCESS ;
                else
                  return BGP_ERR_PEER_GROUP_CANNOT_CHANGE ;
              }
            else
              {
                return bgp_peer_unbind_general(pc) ;
              } ;

          default:
            qassert(false) ;
            break ;
        } ;

      return BGP_ERR_BUG ;
    } ;

  /* Binding afi/safi specific configuration.
   */
  pafc = NULL ;
  if (pcs_qafx_config(pc, qafx))
    {
      pafc = pc->afc[qafx] ;
      qassert(pafc != NULL) ;
    } ;

  if (pafc == NULL)
    {
      if (bsc == bsc_set_on)
        return BGP_ERR_AF_NOT_CONFIGURED ;
      else
        return BGP_SUCCESS ;
    } ;

  gafc = NULL ;
  if (pcs_qafx_config(gc, qafx))
    {
      gafc = gc->afc[qafx] ;
      qassert(gafc != NULL) ;
    } ;

  if (gafc == NULL)
    {
      if (bsc == bsc_set_on)
        return BGP_ERR_PEER_GROUP_AF_NOT_CONFIGURED ;
      else
        return BGP_SUCCESS ;
    } ;

  switch (pafc->ctype)
    {
      case BGP_CFT_PEER:
        qassert(pafc->gafc == NULL) ;

        if (bsc == bsc_set_on)
          return bgp_peer_bind_af(pafc, gafc) ;
        else
          return BGP_SUCCESS ;

      case BGP_CFT_MEMBER:
        qassert(pafc->gafc != NULL) ;

        if (bsc == bsc_set_on)
          {
            if (pafc->gafc == gafc)
              return BGP_SUCCESS ;
            else
              return BGP_ERR_PEER_GROUP_CANNOT_CHANGE ;
          }
        else
          return bgp_peer_unbind_af(pafc) ;

      default:
        qassert(false) ;
        break ;
    } ;

  return BGP_ERR_BUG ;
} ;

/*------------------------------------------------------------------------------
 * Bind given peer's general configuration to the given group's, if possible.
 *
 * Binding wipes out all peer's general settings, except for remote-as.  If the
 * group has a remote-as, then the peer will lose their remote-as setting.  If
 * the group does not have a remote-as, the peer keeps theirs.
 *
 * The binding will fail if the peer or any of its address families have
 * settings which are inconsistent with the group -- ignoring any which are
 * unset by binding !
 */
static bgp_ret_t
bgp_peer_bind_general(bgp_pconfig pc, bgp_pconfig gc)
{
  bool adopt_remote_as ;

  qassert((pc->ctype == BGP_CFT_PEER) && (pc->gc == NULL)) ;
  qassert((gc->ctype == BGP_CFT_GROUP)) ;

  if (pcs_is_on(gc, pcs_remote_as))
    {
      /* The group is going to set the remote-as... so we need to check
       * that none of the address families of the peer have any implied
       * peer sort effect.
       *
       * We get psset -- the set of sorts compatible with the peer's address
       *                 family settings -- we ignore the general configuration,
       *                 because that will be wiped.
       *
       *        gsset -- the sort of the group -- specified by its remote-as
       *                 (a set with a single member).
       *
       * If there is anything set in the psset which is not set in the gsset,
       * then we have a clash and cannot bind.
       */
      bgp_peer_sorts_t psset, gsset ;

      psset = bgp_peer_implicit_af_sorts(pc->parent_peer) ;
      gsset = bgp_peer_explicit_sorts(gc->parent_peer) ;

      if (!(psset & gsset))
        return BGP_ERR_CANNOT_BIND_GROUP ;

      /* We are all set to bind the peer to the group, and adopt the group's
       * remote-as.
       */
      adopt_remote_as = true ;
    }
  else
    {
      /* The peer is going to retain its remote-as... so we need to check
       * that the group does not contain settings which clash with that.
       *
       * We get psset -- the sort of the peer -- specified by its remote-as
       *                 (a set with a single member).
       *
       *        gsset -- the set of sorts compatible with the group's settings.
       */
      bgp_peer_sorts_t psset, gsset ;

      psset = bgp_peer_explicit_sorts(pc->parent_peer) ;
      gsset = bgp_peer_implicit_sorts(gc->parent_peer) ;

      if (!(psset & gsset))
        return BGP_ERR_CANNOT_BIND_GROUP ;

      /* We are all set to bind the peer to the group, but keep the peer's
       * remote-as.
       */
      adopt_remote_as = false ;
    } ;

  /* Bind general configuration -- with or without remote-as.
   *
   * Unset everything except the qafx configured bits.
   */
  pc->set    &= pcs_qafx_mask ;
  pc->set_on &= pcs_qafx_mask ;

  if (adopt_remote_as)
    {
      pc->remote_as = gc->remote_as ;
    }
  else
    {
      pc->set    |= pcs_remote_as ;
      pc->set_on |= pcs_remote_as ;
    } ;

  pc->gc = gc ;
  vector_binsert(gc->members, bgp_peer_config_cmp, pc) ;

  return bgp_config_pcs_change(pc, pcs_group, bsc_set_on) ;
} ;

/*------------------------------------------------------------------------------
 * Bind given peer's address family configuration to the given group's, if
 * possible.
 *
 * Binding wipes out all peer's address family settings.
 *
 * The binding will fail if:
 *
 *   * the group has a definite sort which is not the same as the peer's.
 *
 *     ie, the group has a remote_as, and the sort set by that is not the same
 *         as the peer's.
 *
 *   * the group has any settings (general or address family) which are
 *     incompatible with the sort of the peer.
 */
static bgp_ret_t
bgp_peer_bind_af(bgp_paf_config pafc, bgp_paf_config gafc)
{
  bgp_peer_sorts_t psset, gsset ;

  qassert((pafc->ctype == BGP_CFT_PEER) && (pafc->gafc == NULL)) ;
  qassert((gafc->ctype == BGP_CFT_GROUP)) ;

  /* If the group has an remote-as, then that dictates what may be bound to
   * it explicitly, otherwise the the group setting may do that implicitly.
   */
  psset = bgp_peer_explicit_sorts(pafc->parent_pconf->parent_peer) ;
  gsset = bgp_peer_explicit_sorts(gafc->parent_pconf->parent_peer) ;

  if (gsset == BGP_PSORTS_NONE)
    gsset = bgp_peer_implicit_sorts(gafc->parent_pconf->parent_peer) ;

  if (!(psset & gsset))
     return BGP_ERR_CANNOT_BIND_GROUP ;

  /* Bind address-family configuration
   *
   * Unset everything.
   */
  pafc->set    = 0 ;
  pafc->set_on = 0 ;

  pafc->gafc   = gafc ;
  vector_binsert(gafc->members, bgp_peer_af_config_cmp, pafc) ;

  return bgp_config_pafcs_change(pafc, pafcs_group, bsc_set_on) ;
} ;

/*------------------------------------------------------------------------------
 * Unbind the given peer from the group it is bound to for general settings.
 */
static bgp_ret_t
bgp_peer_unbind_general(bgp_pconfig pc)
{
  bgp_pconfig gc ;

  qassert((pc->ctype == BGP_CFT_MEMBER) && pcs_is_on(pc, pcs_group)) ;
  qassert(pc->gc != NULL) ;

  gc = pc->gc ;
  if (gc == NULL)
    return BGP_ERR_BUG ;

  /* Unbind general configuration -- making sure any remote-as is set again for
   * the peer.
   *
   * Apart from pcs_remote_as and pcs_group, we do nothing with the pc->set and
   * pc->set_on state -- all set settings are retained, all unset ones will
   * revert to default values.
   */
  if (pcs_is_on(gc, pcs_remote_as))
    {
      qassert(pc->remote_as == gc->remote_as) ;
      qassert(pcs_is_off(pc, pcs_remote_as)) ;

      pc->remote_as = gc->remote_as ;

      bgp_config_pcs_change(pc, pcs_remote_as, bsc_set_on) ;
    } ;

  vector_bdelete(gc->members, bgp_peer_config_cmp, pc) ;
  pc->gc = NULL ;

  return bgp_config_pcs_change(pc, pcs_group, bsc_unset) ;
} ;

/*------------------------------------------------------------------------------
 * Unbind the given peer from the group it is bound to for general settings.
 */
static bgp_ret_t
bgp_peer_unbind_af(bgp_paf_config pafc)
{
  bgp_paf_config gafc ;

  qassert(pafc->ctype == BGP_CFT_MEMBER) ;
  qassert(pafc->gafc  != NULL) ;

  gafc = pafc->gafc ;
  if (gafc == NULL)
    return BGP_ERR_BUG ;

  /* Unbind address family configuration.
   *
   * Apart from pafcs_group, we do nothing with the pafc->set and pafc->set_on
   * state -- all set settings are retained, all unset ones will revert to
   * default values.
   */
  vector_bdelete(gafc->members, bgp_peer_af_config_cmp, pafc) ;
  pafc->gafc = NULL ;

  return bgp_config_pafcs_change(pafc, pafcs_group, bsc_unset) ;
} ;

/*------------------------------------------------------------------------------
 * Set/Clear configuration for the given address family.
 *
 * Do nothing if already set or already clear.
 */
extern bgp_ret_t
bgp_peer_af_set(bgp_peer peer, qafx_t qafx, bgp_sc_t bsc)
{
  bgp_pconfig    pc ;
  bgp_paf_config pafc ;

  pc   = peer->c ;
  pafc = NULL ;
  if (pcs_qafx_config(pc, qafx))
    {
      pafc = pc->afc[qafx] ;
      qassert(pafc != NULL) ;
    } ;

  if (bsc == bsc_set_on)
    {
      if (pafc != NULL)
        return BGP_SUCCESS ;

      pc->afc[qafx] = bgp_peer_get_af_config(peer, qafx) ;
    }
  else
    {
      if (pafc == NULL)
        return BGP_SUCCESS ;


    } ;

  return bgp_config_pcs_change(pc, pcs_qafx_bit(qafx), bsc) ;
} ;

/*==============================================================================
 * Finding peer objects and state of same
 */
static int bgp_peer_do_cmp (bgp_peer_c p1, bgp_peer_c p2) ;

/*------------------------------------------------------------------------------
 * Look-up peer by its address in the given bgp instance or all such.
 *
 * If the given 'bgp' is NULL, will return peer in any 'view', otherwise
 * the peer *must* be in the given view.
 *
 * Returns:  peer (PEER_TYPE_REAL) if found -- NULL if not found
 *                                             (or not found in view)
 */
extern bgp_peer
bgp_peer_lookup_su(bgp_inst bgp, sockunion su)
{
  bgp_peer peer;

  peer = bgp_peer_index_peer_lookup(su) ;

  if ((peer != NULL) && (bgp != NULL) && (peer->parent_bgp != bgp))
    return NULL ;

  qassert(peer->ptype == PEER_TYPE_REAL) ;
  qassert(peer == vector_bseek(peer->parent_bgp->peers, bgp_peer_cmp_su, su)) ;

  return peer ;
} ;

/*------------------------------------------------------------------------------
 * Lookup peer-group -- scoped with 'view', so must have one !
 *
 * Returns:  peer (PEER_TYPE_GROUP) if found -- NULL if not found
 */
extern bgp_peer
bgp_peer_lookup_group(bgp_inst bgp, chs_c g_str)
{
  bgp_peer peer;

  if (bgp == NULL)
    {
      qassert(false) ;
      return NULL ;
    }

  peer = vector_bseek(bgp->groups, bgp_peer_cmp_name, g_str) ;

  qassert((peer == NULL) || (peer->ptype == PEER_TYPE_GROUP)) ;

  return peer ;
}

/*------------------------------------------------------------------------------
 * Do we want IPv4/Unicast to be configured (activated) by default for the
 * given peer ?
 *
 * Legacy default is to configure by default.  That can be set from the command
 * line, which sets the bgp_option BGP_OPT_LEGACY_IPV4_DEFAULT.
 *
 * That default can be overridden on a per bgp instance basis by command.
 */
extern bool
bgp_peer_ipv4_default(bgp_peer peer)
{
  if (bcs_is_set(peer->parent_bgp->c, bcs_DEFAULT_IPV4))
    return bcs_is_on(peer->parent_bgp->c, bcs_DEFAULT_IPV4) ;

  return bgp_option_check(BGP_OPT_LEGACY_IPV4_DEFAULT) ;
} ;

/*------------------------------------------------------------------------------
 * Sex the given string to establish if it is a valid peer address
 *                                                            or peer-group name
 *
 * Returns:  BGP_OK_PEER_IP     -- is valid:  su filled in
 *           BGP_OK_GROUP_NAME  -- is a valid group name
 *           BGP_ERR_xxx        -- is not valid
 */
extern bgp_ret_t
bgp_peer_sex(chs_c p_str, sockunion su, bgp_peer_or_group_t bpog)
{
  chs_c p ;
  bool ok ;
  uint n ;

  if (str2sockunion (p_str, su) == 0)
    {
      /* We have a peer address -- if we are allowed same, that's fine.
       *
       * Otherwise, we have an IP address where we expected a group name !
       */
      if (bpog & bpog_peer_ip)
        return BGP_OK_PEER_IP ;
      else
        return BGP_ERR_GROUP_NOT_PEER ; /* wanted group, not peer       */
    } ;

  /* We have what may be a group name
   */
  p = p_str ;
  ok = isalpha(*p) ;
  while (ok && (*p != '\0'))
    {
      ++p ;
      ok = isalnum(*p) || (*p == '-') || (*p == '_') ;
    } ;

  if (ok)
    {
      if (bpog & bpog_group_name)
        return BGP_OK_GROUP_NAME ;
      else
        return BGP_ERR_PEER_NOT_GROUP ; /* wanted peer, not group       */
    } ;

  if (!(bpog & bpog_group_name))
    {
      /* Not expecting a group name, so since this is neither an IP nor
       * a group... reject as invalid IP.
       */
      return BGP_ERR_INVALID_PEER_IP ;
    } ;

  if (!(bpog & bpog_peer_ip))
    {
      /* Not expecting an IP, so since this is neither an IP nor
       * a group... reject as invalid name
       */
      return BGP_ERR_INVALID_GROUP_NAME ;
    } ;

  /* It's not a valid IP and its not a valid group.
   *
   * We would have accepted either... so need to decide how to reject.
   */
  n = strspn(p_str, "0123456789") ;
  if ((n != 0) && (p_str[n] == '.'))
    return BGP_ERR_INVALID_PEER_IP ;    /* quacks like an IPv4  */

  n = strspn(p_str, "0123456789abcdefABCDEF") ;
  if ((n != 0) && (p_str[n] == ':'))
    return BGP_ERR_INVALID_PEER_IP ;    /* quacks like an IPv6  */

  return BGP_ERR_INVALID_GROUP_NAME ;   /* probably             */
} ;



/*------------------------------------------------------------------------------
 * Peer comparison function for sorting.
 */
static int
bgp_peer_cmp (const cvp* p_p1, const cvp* p_p2)
{
  bgp_peer_c p1 = *p_p1 ;
  bgp_peer_c p2 = *p_p2 ;

  return bgp_peer_do_cmp(p1, p2) ;
} ;

/*------------------------------------------------------------------------------
 * Peer configuration comparison function for sorting bgp_pconfig items.
 */
static int
bgp_peer_config_cmp (const cvp* p_pc1, const cvp* p_pc2)
{
  bgp_pconfig_c pc1 = *p_pc1 ;
  bgp_pconfig_c pc2 = *p_pc2 ;

  return bgp_peer_do_cmp(pc1->parent_peer, pc2->parent_peer) ;
} ;

/*------------------------------------------------------------------------------
 * Peer configuration comparison function for sorting bgp_pconfig items.
 */
static int
bgp_peer_af_config_cmp (const cvp* p_pc1, const cvp* p_pc2)
{
  bgp_paf_config_c pafc1 = *p_pc1 ;
  bgp_paf_config_c pafc2 = *p_pc2 ;

  return bgp_peer_do_cmp(pafc1->parent_pconf->parent_peer,
                         pafc2->parent_pconf->parent_peer) ;
} ;

/*------------------------------------------------------------------------------
 * Peer comparison function for sorting.
 */
static int
bgp_peer_do_cmp (bgp_peer_c p1, bgp_peer_c p2)
{
  if (p1->ptype != p2->ptype)
    return (p1->ptype < p2->ptype) ? -1 : +1 ;

  switch (p1->ptype)
  {
    case PEER_TYPE_NULL:                /* should not happen    */
    case PEER_TYPE_SELF:                /* can only be one !    */
    default:                            /* ugh ?                */
      qassert(false) ;
      return 0 ;

    case PEER_TYPE_GROUP:
      return strcmp(p1->name, p2->name) ;

    case PEER_TYPE_REAL:
      return sockunion_cmp(p1->su_name, p2->su_name) ;
  } ;
} ;

/*------------------------------------------------------------------------------
 * Peer comparison function for sorting.
 */
static int
bgp_peer_cmp_su(const cvp* p_su, const cvp* p_p)
{
  sockunion_c su = *p_su ;
  bgp_peer_c  p  = *p_p ;

  return sockunion_cmp(su, p->su_name) ;
} ;

/*------------------------------------------------------------------------------
 * Peer comparison function for sorting.
 */
static int
bgp_peer_cmp_name(const cvp* p_n, const cvp* p_p)
{
  chs_c      n = *p_n ;
  bgp_peer_c p = *p_p ;

  return strcmp(n, p->name) ;
} ;

/*==============================================================================
 * Creation and destruction of peer objects
 */

/*------------------------------------------------------------------------------
 * Allocate new peer object -- for peer or peer-group
 *
 * Constructs completely empty peer and pconfig, with the given name and
 * (for real peers) the given su_name.
 *
 * Points the peer at the parent-bgp, and for:
 *
 *   * real peer:  adds peer to the peer index and sets the peer_id.
 *                 adds peer to the bgp's peers vector.
 *
 *   * peer-group: adds group to the bgp's groups vector and sets group-id.
 */
static bgp_peer
bgp_peer_new(bgp_inst bgp, bgp_peer_type_t ptype, chs_c name, sockunion su_name)
{
  bgp_peer      peer ;
  bgp_pconfig   pc ;

  assert(bgp != NULL) ;

  /* Allocate new peer: point it at owning bgp instance and take a lock on that.
   *
   * All types of peer have a bgp parent.
   */
  peer = XCALLOC (MTYPE_BGP_PEER, sizeof(bgp_peer_t));

  peer->parent_bgp = bgp ;
  peer->ptype      = ptype ;

  /* Zeroizing has set:
   *
   *   * parent_bgp             -- X            -- set, above
   *   * ptype                  -- X            -- set, above
   *
   *   * peer_id                -- X            -- set by caller
   *   * group_id               -- X            -- set by caller
   *
   *   * name                   -- X            -- set below
   *   * cname                  -- NULL         -- none
   *
   *   * su_name                -- AF_UNSPEC    -- set below, if PEER_TYPE_REAL
   *   * prun                   -- NULL         -- none, yet
   *
   *   * changed                -- false
   *   * pending                -- NULLs
   *
   *   * c                      -- NULL         -- see below
   */
  confirm(AF_UNSPEC == 0) ;

  peer->name = XSTRDUP(MTYPE_BGP_NAME, name) ;

  pc = XCALLOC (MTYPE_BGP_PEER_CONFIG, sizeof(bgp_pconfig_t));
  peer->c = pc ;

  /* The peer-config has been created, all zeros, setting:
   *
   *   * parent_peer            -- X            -- set below
   *   * desc                   -- NULL         -- none, yet
   *
   *   * ctype                  -- BGP_CFT_NULL -- set below
   *   * group                  -- NULL         -- none, yet
   *   * members                -- NULL         -- set below, for group
   *
   *   * remote_as              -- BGP_ASN_NULL -- set by caller
   *
   *   * set                    -- 0            -- nothing set
   *   * set_on                 -- 0            -- nothing at all
   *
   *   * port                   -- 0            )
   *   * local_pref             -- 0            )
   *   * med                    -- 0            )
   *   * weight                 -- 0            )
   *   * holdtime_secs          -- 0            )
   *   * keepalive_secs         -- 0            )
   *   * connect_retry_secs     -- 0            )  utterly empty
   *   * accept_retry_secs      -- 0            )
   *   * open_hold_secs         -- 0            )
   *   * mrai_secs              -- 0            )
   *   * change_local_as        -- BGP_ASN_NULL )
   *   * change_local_as_prepend -- false       )
   *   * ttl                    -- 0            )
   *   * gtsm                   -- false        )
   *   * password               -- NULL         )
   *   * update_source          -- NULL         )
   *
   *   * afc                    -- NULLs           -- nothing, yet
   */
  confirm(BGP_CFT_NULL         == 0) ;
  confirm(BGP_ASN_NULL         == 0) ;
  confirm(BGP_PEER_UNSPECIFIED == 0) ;

  pc->parent_peer = peer ;

  switch (ptype)
    {
      case PEER_TYPE_SELF:
        qassert(false) ;                // XXX
        break ;

      case PEER_TYPE_GROUP:
        pc->ctype = BGP_CFT_GROUP ;

        pc->members = vector_new(20) ;

        peer->group_id = vector_binsert(bgp->groups, bgp_peer_cmp, peer) ;
        break ;

      case PEER_TYPE_REAL:
        pc->ctype = BGP_CFT_PEER ;

        sockunion_copy(peer->su_name, su_name) ;
        peer->peer_id = bgp_peer_index_register(peer) ;

        vector_binsert(bgp->peers, bgp_peer_cmp, peer) ;
        break ;

      case PEER_TYPE_NULL:
      default:
        qassert(false) ;
        break ;
    } ;

  /* Done
   */
  return peer ;
} ;

/*------------------------------------------------------------------------------
 *
 */
static bgp_peer
bgp_peer_free(bgp_peer peer)
{
  if (peer != NULL)
    {
      XFREE(MTYPE_BGP_PEER, peer);
    } ;

  return NULL ;
}

/*------------------------------------------------------------------------------
 * Get address family configuration for given BGP instance.
 *
 * Create an empty configuration if required.
 *
 * NB: points the new bgp_paf_config at the peer's bgp_pconfig, but does not
 *     set the pcs_qafx_xxx bit or the pc->afc[qafx].
 *
 * Returns:  the address family configuration for the peer
 */
static bgp_paf_config
bgp_peer_get_af_config(bgp_peer peer, qafx_t qafx)
{
  bgp_pconfig    pc ;
  bgp_paf_config pafc ;

  pc   = peer->c ;
  pafc = pc->afc[qafx] ;

  if (pafc != NULL)
    {
      /* We have configuration.  If is set configured, we are done.
       */
      if (pcs_qafx_config(pc, qafx))
        return pafc ;

      /* Have configuration, but is not set configured, so discard what
       * we appear to have.
       */
      qassert(false) ;

      pafc = bgp_peer_free_af_config(pafc) ;
    } ;

  /* Create a brand new peer address family configuration.
   */
  pafc = XCALLOC (MTYPE_BGP_PEER_AF_CONFIG, sizeof(bgp_paf_config_t));

  /* Zeroizing has set:
   *
   *   * parent_pconf           -- X            -- set below
   *   * qafx                   -- X            -- set below
   *   * ctype                  -- BGP_CFT_NULL -- set below
   *
   *   * group                  -- NULL         -- none, yet
   *   * members                -- NULL         -- set for group, below
   *
   *   * set                    -- 0            -- nothing set
   *   * set_on                 -- 0            -- absolutely nothing
   *
   *   * allow_as_in            -- 0            )
   *   * filter_set             -- NULLs        )
   *   * pmax                   -- empty        )
   *         .set               -- false        )  utterly empty
   *         .warning           -- 0            )
   *         .trigger           -- 0            )
   *         .limit             -- 0            )
   *         .threshold         -- 0            )
   *         .thresh_pc         -- 0            )
   *         .restart           -- 0            )
   */
  pafc->parent_pconf = pc ;
  pafc->qafx         = qafx ;

  /* Type follows the general configuration, except that address family has
   * separate group membership.
   */
  switch (pc->ctype)
    {
      case BGP_CFT_PEER:
      case BGP_CFT_MEMBER:
        pafc->ctype = BGP_CFT_PEER ;
        break ;

      case BGP_CFT_GROUP:
        pafc->ctype   = BGP_CFT_GROUP ;
        pafc->members = vector_new(20) ;
        break ;

      case BGP_CFT_NULL:
      default:
        qassert(false) ;
        break ;
    } ;

  /* We default to sending communities
   */
  if (! bgp_option_check (BGP_OPT_CONFIG_CISCO))
    {
      pafc->set_on |= pafcs_bit(pafcs_SEND_COMMUNITY) |
                      pafcs_bit(pafcs_SEND_EXT_COMMUNITY) ;
      pafc->set    |= pafc->set_on ;
    } ;

  return pafc ;
} ;

/*------------------------------------------------------------------------------
 *
 */
static bgp_paf_config
bgp_peer_free_af_config(bgp_paf_config pafc)
{
  if (pafc != NULL)
    {
      XFREE(MTYPE_BGP_PEER_AF_CONFIG, pafc);
    } ;

  return NULL ;
}

/*==============================================================================
 * peer->sort and related values.
 *
 * The peer->sort depends on:
 *
 *   bgp->my_as         -- our ASN -- per router BGP <ASN>
 *
 *                         If we are in a CONFED, this is our CONFED Member AS.
 *
 *                         NB: once a bgp instance has been created, it is not
 *                             possible to change the bgp->my_as.
 *
 *   bgp->confed_id     -- if we are in a CONFED, our ASN as far as the
 *                         outside world (beyond the CONFED) is concerned.
 *
 *                         So this is our eBGP ASN if in a CONFED.
 *
 *                         When bgp->confed_id is set, changed or cleared, all
 *                         the affected peers are checked for a change of
 *                         peer->sort.
 *
 *   bgp->confed_peers  -- all known CONFED Member ASN
 *
 *                         If bgp->confed_id is set, then after any changes to
 *                         the confed_peers set, all the affected peers are
 *                         checked for a change of peer->sort.
 *
 *   peer->args.remote_as -- the peer's ASN -- per neighbor remote-as <ASN>
 *
 * The peer->args.local_as will be bgp->my_as, unless we are in a CONFED and
 * the peer->sort is EBGP, in which case peer->args.local_as is bgp->my_as.
 */

/*------------------------------------------------------------------------------
 * Establish sort of asn we have.
 *
 * Note that to be a CONFED there must be a confed_id configured.  The
 * set of confed_peers has an independent lifetime.
 *
 * Returns:  the sort -- will be BGP_PEER_UNSPECIFIED if asn == BGP_ASN_NULL
 */
extern bgp_peer_sort_t
bgp_peer_as_sort(bgp_inst bgp, as_t asn)
{
  assert(bgp != NULL) ;

  if (asn == BGP_ASN_NULL)
    return BGP_PEER_UNSPECIFIED ;

  if (asn == bgp->c->my_as)
    return BGP_PEER_IBGP ;

  if (bcs_is_on(bgp->c, bcs_confed_id))
    {
      if (asn_set_contains(bgp->c->confed_peers, asn))
        return BGP_PEER_CBGP ;
    } ;

  return BGP_PEER_EBGP ;
} ;

/*------------------------------------------------------------------------------
 * Establish sort of asn we have -- as a sort set.
 *
 * Returns:  the sort set -- *exactly*one* bit set, , or...
 *                                    ...BGP_PSORTS_NONE if asn == BGP_ASN_NULL.
 */
static bgp_peer_sorts_t
bgp_peer_as_sorts(bgp_peer peer, as_t asn)
{
  bgp_peer_sort_t sort ;

  sort = bgp_peer_as_sort(peer->parent_bgp, asn) ;

  if (sort == BGP_PEER_UNSPECIFIED)
    return BGP_PSORTS_NONE ;

  confirm(BGP_PSORTS_IBGP_BIT == BIT(BGP_PEER_IBGP - 1)) ;
  confirm(BGP_PSORTS_CBGP_BIT == BIT(BGP_PEER_CBGP - 1)) ;
  confirm(BGP_PSORTS_EBGP_BIT == BIT(BGP_PEER_EBGP - 1)) ;

  return BIT(sort - 1) ;
} ;

/*------------------------------------------------------------------------------
 * Is a setting which is compatible only with the given sort(s) of peer
 *                                      allowed for the given peer/peer-group ?
 *
 * Returns:  true <=> the setting is allowed.
 */
static bool
bgp_peer_sorts_allow(bgp_peer peer, bgp_peer_sorts_t sset_allow)
{
  bgp_peer_sorts_t sset ;
  bgp_pconfig pc, gc, mc ;
  uint        i ;
  qafx_t      qafx ;

  pc = peer->c ;

  /* If we have an explicit sort (ie we have a remote-as) then that decides the
   * issue.
   */
  sset = bgp_peer_explicit_sorts(peer) ;

  if (sset != BGP_PSORTS_NONE)
    return sset_allow & sset ;

  /* We don't have an ASN, so we MUST be a group with no remote-as.
   *
   * Consider:  (1) the sorts implied by any group general and address family
   *                setting
   *
   *            (2) the sorts of all general group members
   *
   *            (3) the sorts of all address family group members
   *
   * Here we are looking for things which will *disallow* the setting.
   */
  gc = pc ;
  qassert(gc->ctype == BGP_CFT_GROUP) ;

  sset = bgp_peer_implicit_sorts(peer) ;        /* general and af settings */

  if (!(sset_allow & sset))
    return false ;                              /* denied               */

  i = 0 ;
  while ((mc = vector_get_item(gc->members, i++)) != NULL)
    {
      /* Collect sort(s) of all general group members -- disallow if we find
       * a peer sort which is incompatible.
       */
      qassert(mc->ctype == BGP_CFT_MEMBER) ;
      qassert(mc->gc    == gc) ;
      qassert(pcs_is_on(mc, pcs_remote_as)) ;

      if (!(sset_allow & bgp_peer_explicit_sorts(mc->parent_peer)))
        return false ;          /* denied       */
    } ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_paf_config gafc, mafc ;

      if (!pcs_qafx_config(gc, qafx))
        continue ;

      gafc = gc->afc[qafx] ;

      qassert(gafc != NULL) ;
      if (gafc == NULL)
        continue ;

      i = 0 ;
      while ((mafc = vector_get_item(gafc->members, i++)) != NULL)
        {
          /* Collect sort(s) of all address family group members
           */
          qassert(mafc->ctype == BGP_CFT_MEMBER) ;
          qassert(mafc->gafc  == gafc) ;

          mc = mafc->parent_pconf ;
          qassert(pcs_is_on(mc, pcs_remote_as)) ;

          if (!(sset_allow & bgp_peer_explicit_sorts(mc->parent_peer)))
            return false ;      /* denied       */
        } ;
    } ;

  return true ;                 /* allowed      */
} ;

/*------------------------------------------------------------------------------
 * Establish the explicit sort of for the given peer or peer-group, if any.
 *
 * For peers the remote-as explicitly dictates the sort of the, and all peers
 * have a remote-as -- either of their own, or inherited from a peer-group.
 *
 * For a peer-group with a remote-as, the same is true.
 *
 * For a peer-group with no remote-as there is no explicit type.
 *
 * Returns:  the sort set -- *exactly*one* bit set, or...
 *                             ...BGP_PSORTS_NONE if is group with no remote-as
 */
extern bgp_peer_sorts_t
bgp_peer_explicit_sorts(bgp_peer peer)
{
  bgp_pconfig pc ;
  as_t        asn ;

  pc = peer->c ;

  /* The remote_as value is present, unless this is a peer-group with no
   * remote-as -- it is set for group members whether or not the peer-group
   * has a setting.
   */
  asn = pc->remote_as ;

  switch (pc->ctype)
    {
      case BGP_CFT_PEER:
        qassert(asn != BGP_ASN_NULL) ;
        qassert(pcs_is_on(pc, pcs_remote_as)) ;
        break ;

      case BGP_CFT_MEMBER:
        qassert(asn != BGP_ASN_NULL) ;
        if (!pcs_is_on(pc, pcs_remote_as))
          {
            qassert(asn == pc->gc->remote_as) ;
            qassert(pcs_is_on(pc->gc, pcs_remote_as)) ;
          } ;
        break ;

      case BGP_CFT_GROUP:
        if (pcs_is_on(pc, pcs_remote_as))
          qassert(asn != BGP_ASN_NULL) ;
        else
          asn = BGP_ASN_NULL ;
        break ;

      default:
        qassert(false) ;
        return 0 ;
    } ;

    return bgp_peer_as_sorts(peer, asn) ;
} ;

/*------------------------------------------------------------------------------
 * The sorts the given peer/peer-group is compatible with, by virtue of
 *                                    their general and address family settings.
 *
 * There are then a small number of settings which apply only to some sorts of
 * peer-groups/peers, so if present they implicitly restrict the sort of same.
 *
 *   * Route Reflector Client => iBGP          (in any address family !)
 *
 *   * Change Local AS        => eBGP
 *
 *   * Remove Private AS      => cBGP or eBGP  (in any address family !)
 *
 * Note that for peer-groups this only considers the state of the peer-group.
 *
 * This is used for peer-groups which do not have a remote-as setting, and for
 * both peer-groups and peers when trying to change the remote-as setting.
 *
 * Returns:  the sort set -- may be BGP_PSORTS_NONE (!)
 */
static bgp_peer_sorts_t
bgp_peer_implicit_sorts(bgp_peer peer)
{
  bgp_peer_sorts_t  sset ;

  sset = bgp_peer_implicit_af_sorts(peer) ;

  if (pcs_is_on(peer->c, pcs_change_local_as))
    sset &= ~BGP_PSORTS_IBGP_BIT ;

  return sset ;
} ;

/*------------------------------------------------------------------------------
 * The sorts the given peer/peer-group is compatible with, by virtue of
 *                                                their address family settings.
 *
 * The address family specific part of bgp_peer_implicit_sorts() -- see above.
 *
 * Returns:  the sort set -- may be BGP_PSORTS_NONE (!)
 */
static bgp_peer_sorts_t
bgp_peer_implicit_af_sorts(bgp_peer peer)
{
  bgp_pconfig       pc ;
  qafx_t            qafx ;
  bgp_peer_sorts_t  sset ;

  pc   = peer->c ;
  sset = BGP_PSORTS_EBGP_BIT | BGP_PSORTS_CBGP_BIT | BGP_PSORTS_IBGP_BIT ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_paf_config pafc ;

      if (!pcs_qafx_config(pc, qafx))
        continue ;

      pafc = pc->afc[qafx] ;
      qassert(pafc != NULL) ;
      if (pafc == NULL)
        continue ;

      if (pafcs_is_on(pafc, pafcs_REFLECTOR_CLIENT))
        sset &=  BGP_PSORTS_IBGP_BIT ;

      if (pafcs_is_on(pafc, pafcs_REMOVE_PRIVATE_AS))
        sset &= ~BGP_PSORTS_IBGP_BIT ;
    } ;

  return sset ;
} ;













/*------------------------------------------------------------------------------
 * Check whether the given address is of any local interface.
 *
 * Returns:  true <=> address is of a local interface
 */
static bool
peer_address_self_check (sockunion su)
{
  struct interface *ifp = NULL;

  if (su->sa.sa_family == AF_INET)
    ifp = if_lookup_by_ipv4_exact (&su->sin.sin_addr);
#ifdef HAVE_IPV6
  else if (su->sa.sa_family == AF_INET6)
    ifp = if_lookup_by_ipv6_exact (&su->sin6.sin6_addr);
#endif /* HAVE IPV6 */

  return (ifp != NULL) ;
}





/*==============================================================================
 * Configuration settings for peer/peer-group configuration.
 *
 * All of these require the peer to have been created already.
 */

/*------------------------------------------------------------------------------
 * Deal with a "pcs_xxx" change.
 *
 * Sets or clears the appropriate pcs_bit(s).  In some cases setting one
 * bit will clear one (or more) others -- we take care of that here.
 *
 * For individual peer, add to list of pending peers -- if not already
 * queued.
 *
 * For peer-group -- unset all group members, and add each to list of pending
 * peers -- if not already queued.
 *
 * Returns:  BGP_SUCCESS
 *
 * NB: some callers assume that this operation cannot fail.
 */
static bgp_ret_t
bgp_config_pcs_change(bgp_pconfig pc, bgp_pc_setting_t pcs, bgp_sc_t bsc)
{
  bgp_pc_set_t  set ;
  bgp_pc_set_t  mask ;
  bgp_pconfig   mc ;
  uint          i ;

  set = mask = pcs_bit(pcs) ;

  /* Dealing with related or mutually exclusive settings.
   *
   * In general, when a group setting is changed, the group member setting
   * will be *unset* -- which means that its value is implicitly the group's
   * value.  So the impact on the group member is simple !
   *
   * For related or mutually exclusive settings:
   *
   *   * setting one "on" will:  (a) unset the others
   *
   *                             (b) for group members: unset all of the
   *                                 related/mutually exclusive settings.
   *
   *   * unsetting one or
   *   * setting one "off" will: (a) leave the others
   *
   *                             (b) for group members: unset the one setting
   *                                 affected
   */
  switch (pcs)
    {
      case pcs_PASSIVE:
      case pcs_ACTIVE:
        if (bsc == bsc_set_on)
          mask = pcs_bit(pcs_PASSIVE) |
                 pcs_bit(pcs_ACTIVE) ;
        break ;

      case pcs_multihop:
      case pcs_ttl_security:
        if (bsc == bsc_set_on)
          mask = pcs_bit(pcs_multihop) |
                 pcs_bit(pcs_ttl_security) ;
        break ;

      case pcs_DYNAMIC_CAPABILITY:
      case pcs_DYNAMIC_CAPABILITY_DEP:
        mask = pcs_bit(pcs_DYNAMIC_CAPABILITY) |
               pcs_bit(pcs_DYNAMIC_CAPABILITY_DEP) ;
        break ;

      case pcs_STRICT_CAP_MATCH:
        /* If we are setting STRICT_CAP_MATCH 'on', we make sure neither
         * DONT_CAPABILITY nor OVERRIDE_CAPABILITY are set.  For a group this
         * will unset all group members.
         *
         * If we are setting STRICT_CAP_MATCH 'off' we leave the other states
         * as they are...
         *
         *   ...if was 'on', then the others must be 'off' or 'unset', so
         *      nothing is changing.
         *
         *   ...if was 'off' or 'unset', then we should not change the others.
         *
         * This applies equally to a group and its members.
         */
        if (bsc == bsc_set_on)
          mask |= pcs_bit(pcs_DONT_CAPABILITY) |
                  pcs_bit(pcs_OVERRIDE_CAPABILITY) ;
        break ;

      case pcs_DONT_CAPABILITY:
      case pcs_OVERRIDE_CAPABILITY:
        /* If we are setting DONT_CAPABILITY or OVERRIDE_CAPABILITY 'on', we
         * make sure that STRICT_CAP_MATCH is unset.  For a group this will
         * unset all group members.
         *
         * If we are setting DONT_CAPABILITY or OVERRIDE_CAPABILITY 'off' we
         * leave STRICT_CAP_MATCH as it is...
         *
         *   ...if was 'on', then STRICT_CAP_MATCH must be 'off' or 'unset', so
         *      nothing is changing.
         *
         *   ...if was 'off' or 'unset', then we should not change
         *      STRICT_CAP_MATCH.
         *
         * This applies equally to a group and its members.
         */
        if (bsc == bsc_set_on)
          mask |= pcs_bit(pcs_STRICT_CAP_MATCH) ;
        break ;

      default:
        break ;
    } ;

  pc->set &= ~(set | mask) ;            /* unset setting & mask         */
  if (bsc & bsc_set)
    pc->set    |= set ;                 /* set setting if required      */

  pc->set_on &= pc->set ;               /* unset => off                 */
  if (bsc == bsc_set_on)
    pc->set_on |= set ;                 /* set "on" if required         */

  switch (pc->ctype)
    {
      case BGP_CFT_PEER:
      case BGP_CFT_MEMBER:
        bgp_config_queue(pc->parent_peer) ;
        break ;

      case BGP_CFT_GROUP:
        /* For Group we propagate the change by unsetting the item in all
         * members.
         *
         * Note that this has no effect on any value(s) -- the peer may have
         * a value for anything, but only the 'set' ones are actually used.
         */
        i = 0 ;
        while ((mc = vector_get_item(pc->members, i++)) != NULL) ;
          {
            qassert(mc->ctype == BGP_CFT_MEMBER) ;
            mc->set    &= ~(set | mask) ;
            mc->set_on &= mc->set ;
            bgp_config_queue(mc->parent_peer) ;
          } ;

        break ;

      default:
        qassert(false) ;
        break ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Deal with a "pafcs_xxx" change.
 *
 * Sets or clears the appropriate pafcs_bit(s).  In some cases setting one
 * bit will clear one (or more) others -- we take care of that here.
 *
 * For individual peer, add to list of pending peers -- if not already
 * queued.
 *
 * For peer-group -- unset all group members, and add each to list of pending
 * peers -- if not already queued.
 *
 * Returns:  BGP_SUCCESS
 *
 * NB: some callers assume that this operation cannot fail.
 */
static bgp_ret_t
bgp_config_pafcs_change(bgp_paf_config pafc, bgp_pafc_setting_t pafcs,
                                                                   bgp_sc_t bsc)
{
  bgp_pafc_set_t  set ;
  bgp_pafc_set_t  mask ;
  uint            i ;
  bgp_paf_config  mafc ;

  set = mask = pcs_bit(pafcs) ;

  /* Dealing with related or mutually exclusive settings.
   */
  switch (pafcs)
    {
    case pafcs_dlist_in:
    case pafcs_plist_in:
      /* dlist and plist cannot be set at the same time.
       */
      if (bsc == bsc_set_on)
        mask = pafcs_bit(pafcs_dlist_in) | pafcs_bit(pafcs_plist_in) ;
      break ;

    case pafcs_dlist_out:
    case pafcs_plist_out:
      /* dlist and plist cannot be set at the same time.
       */
      if (bsc == bsc_set_on)
        mask = pafcs_bit(pafcs_dlist_in) | pafcs_bit(pafcs_plist_in) ;
      break ;

      default:
        break ;
    } ;

  pafc->set &= ~(set | mask) ;          /* unset setting & mask         */
  if (bsc & bsc_set)
    pafc->set    |= set ;               /* set setting if required      */

  pafc->set_on &= pafc->set ;           /* unset => off                 */
  if (bsc == bsc_set_on)
    pafc->set_on |= set ;               /* set "on" if required         */

  switch (pafc->ctype)
    {
      case BGP_CFT_PEER:
      case BGP_CFT_MEMBER:
        bgp_config_queue(pafc->parent_pconf->parent_peer) ;
        break ;

      case BGP_CFT_GROUP:
        /* For Group we propagate the change by unsetting the item in all
         * members.
         *
         * Note that this has no effect on any value(s) -- the peer may have
         * a value for anything, but only the 'set' ones are actually used.
         */
        i = 0 ;
        while ((mafc = vector_get_item(pafc->members, i++)) != NULL)
          {
            qassert(mafc->ctype == BGP_CFT_MEMBER) ;
            mafc->set    &= ~(set | mask) ;
            mafc->set_on &= mafc->set ;
            bgp_config_queue(mafc->parent_pconf->parent_peer) ;
          } ;

        break ;

      default:
        qassert(false) ;
        break ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Modify given peer "flag".
 *
 * These are states of a peer or peer-group which are conceptually flags --
 * which can be set "on"/"off or unset altogether.
 *
 * Modifying a peer-group will unset the flag in all dependent peers.
 */
extern bgp_ret_t
bgp_peer_flag_modify(bgp_peer peer, bgp_pc_setting_t pcs, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  qassert(pcs < pcs_count_of_flags) ;

  pc = bgp_config_peer_prepare(peer) ;

  /* Validity checking, as required.
   */
  switch (pcs)
    {
      /* SHUTDOWN.... somewhat special TODO
       */
      case pcs_SHUTDOWN:
        break ;

      /* Settings with no further checks.
       */
      case pcs_DISABLE_CONNECTED_CHECK:
      case pcs_PASSIVE:
      case pcs_ACTIVE:
        break ;

      /* Strict Capability checking
       *
       * Cannot be strict and either disable capabilities or override address
       * families.
       *
       * If we are allowed to set the group, then that will unset the group
       * members for all these settings.
       *
       * Unsetting or setting Strict Capability off has no effect on the
       * other settings.  Group members will be unset for Strict Capability.
       */
      case pcs_STRICT_CAP_MATCH:
        if (bsc == bsc_set_on)
          {
            if (pcs_is_on(pc, pcs_OVERRIDE_CAPABILITY))
              return BGP_ERR_PEER_FLAG_CONFLICT_1 ;

            if (pcs_is_on(pc, pcs_DONT_CAPABILITY))
              return BGP_ERR_PEER_FLAG_CONFLICT_1 ;
          } ;
        break ;

      /* Overriding Address Family Capabilities -- cannot while strict.
       *
       * If we are allowed to set the group, then that will unset the group
       * members for this setting and strict.
       *
       * Unsetting or setting Strict Capability off has no effect on the
       * other settings.  Group members will be unset for Override.
       */
      case pcs_OVERRIDE_CAPABILITY:
        if (bsc == bsc_set_on)
          {
            if (pcs_is_on(pc, pcs_STRICT_CAP_MATCH))
              return BGP_ERR_PEER_FLAG_CONFLICT_2 ;
          } ;
        break ;

      /* Disabling Capabilities -- cannot disable while have Strict !
       *
       * If we are allowed to set the group, then that will unset the group
       * members for this setting and strict.
       *
       * Unsetting or setting Dissabling Capability off has no effect on the
       * other settings.  Group members will be unset for Disabling.
       */
      case pcs_DONT_CAPABILITY:
        if (bsc == bsc_set_on)
          {
            if (pcs_is_on(pc, pcs_STRICT_CAP_MATCH))
              return BGP_ERR_PEER_FLAG_CONFLICT_3 ;
          } ;
        break ;

      /* Dynamic Capability support
       *
       * Setting one clears the other.   Group members will be unset for both,
       * and hence follow the group.
       *
       * Unsetting or setting one off has no effect on the other.  Group
       * members will be unset.
       */
      case pcs_DYNAMIC_CAPABILITY:
      case pcs_DYNAMIC_CAPABILITY_DEP:
        /* For the time being... not supported     TODO
         */
        if (bsc == bsc_set_on)
          return BGP_ERR_INVALID_VALUE ;

        break ;

      /* Anything else is not valid.
       */
      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
  } ;

  return bgp_config_pcs_change(pc, pcs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Modify given peer address family "flag".
 *
 * These are states of a peer or peer-group address family which are
 * conceptually flags -- which can be set "on"/"off or unset altogether.
 *
 * Modifying a peer-group will unset the flag in all dependent peers.
 */
extern bgp_ret_t
bgp_peer_af_flag_modify (bgp_peer peer, qafx_t qafx,
                                       bgp_pafc_setting_t pafcs, bgp_sc_t bsc)
{
  bgp_paf_config    pafc ;

  qassert(pafcs < pafcs_count_of_flags) ;

  pafc = bgp_config_peer_af_prepare(peer, qafx) ;

  if (pafc == NULL)
    return  BGP_ERR_AF_NOT_CONFIGURED ;

  /* Validity checking, as required.
   *
   * NB: group may be BGP_PEER_UNSPECIFIED
   */
  switch (pafcs)
    {
      case pafcs_REFLECTOR_CLIENT:
        if (bsc == bsc_set_on)
          {
            /* Is OK for iBGP or (for group) undecided.
             */
            if (!bgp_peer_sorts_allow(peer, BGP_PSORTS_IBGP_BIT))
              return BGP_ERR_NOT_INTERNAL_PEER;
          } ;
        break ;

      case pafcs_REMOVE_PRIVATE_AS:
        if (bsc == bsc_set_on)
          {
            /* Is OK for cBGP or eBGP or (for group) undecided.
             */
            if (!bgp_peer_sorts_allow(peer, BGP_PSORTS_CBGP_BIT |
                                            BGP_PSORTS_EBGP_BIT))
              return BGP_ERR_REMOVE_PRIVATE_AS;
          } ;
        break ;

        case pafcs_SOFT_RECONFIG:
        case pafcs_RSERVER_CLIENT:
        case pafcs_SEND_COMMUNITY:
        case pafcs_SEND_EXT_COMMUNITY:
        case pafcs_NEXTHOP_SELF:
        case pafcs_NEXTHOP_UNCHANGED:
        case pafcs_NEXTHOP_LOCAL_UNCHANGED:
        case pafcs_AS_PATH_UNCHANGED:
        case pafcs_MED_UNCHANGED:
        case pafcs_DEFAULT_ORIGINATE:
          break ;

      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
        break ;
    } ;

  /* Register the change in set state -- which propagates across peer group
   * members as required.
   */
  return bgp_config_pafcs_change(pafc, pafcs, bsc) ;
} ;


























/*------------------------------------------------------------------------------
 * multihop configuration set -- allowed for any sort of peer
 *
 * NB: cannot set ebgp-multihop if ttl-security (GTSM) is set, on the group
 *     or any of its members.
 *
 * Unsetting or setting multi-hop has no effect on any GTSM.
 *
 * Note also that all members of a group are of the same sort.
 */
extern bgp_ret_t
bgp_peer_multihop_set (bgp_peer peer, ttl_t ttl, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  /* If we are setting multi-hop, need to worry about whether is already
   * set to GTSM.
   *
   * If we are unsetting multi-hop, or setting it off, we do not change the
   * ttl or the gtsm flag -- which may be set for GTSM, which is unaffected !
   */
  if (bsc == bsc_set_on)
    {
      /* Cannot set pcs_multihop when is already pcs_ttl_security.
       */
      if (pcs_is_on(pc, pcs_ttl_security))
        return BGP_ERR_NO_MULTIHOP_WITH_GTSM;

      if (pc->ctype == BGP_CFT_GROUP)
        {
          /* Cannot unset the GTSM state of a group member by setting
           * multi-hop for the group.
           */
          bgp_pconfig   mc ;
          uint          i ;

          qassert((pc->gc != NULL) && (pc->gc->members != NULL)) ;

          i = 0 ;
          while ((mc = vector_get_item(pc->gc->members, i++)) != NULL)
            {
              if (pcs_is_on(mc, pcs_ttl_security))
                return BGP_ERR_NO_MULTIHOP_WITH_GTSM;
            } ;
        } ;

      /* Set the given multi-hop value.
       */
      pc->ttl = (ttl <= TTL_MAX) ? ttl : TTL_MAX ;
      pc->gtsm = false ;            /* for completeness     */
    } ;

#if 0
  bgp_peer_cops_recharge(peer, PEER_DOWN_MULTIHOP_CHANGE) ;
#endif

  return bgp_config_pcs_change(pc, pcs_multihop, bsc) ;
}

/*------------------------------------------------------------------------------
 * ttl-security hops configuration set -- allowed for any sort of peer
 *
 * ttl == 0 <=> unset.
 *
 * Setting ttl-security hops is similar to setting multi-hop, except that it
 * also enables the GTSM -- if available.
 *
 * Note also that all members of a group are of the same sort.
 *
 * NB: cannot set ttl-security (GTSM) if multi-hop is set.
 *
 *     cannot set ttl-security (GTSM) on a group if multi-hop is set on
 *     any group member.
 */
extern bgp_ret_t
bgp_peer_ttl_security_hops_set (bgp_peer peer, ttl_t ttl, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  /* If we are setting GTSM, need to worry about whether is already
   * set to multi-hop.
   *
   * If we are unsetting GTSM, or setting it off, we do not change the
   * ttl -- which may be set for multi-hop, which is unaffected !
   */
  if (bsc == bsc_set_on)
    {
      if (pcs_is_on(pc, pcs_multihop))
        {
          /* Cannot set pcs_ttl_security when is already pcs_multihop
           */
          return BGP_ERR_NO_MULTIHOP_WITH_GTSM;
        } ;

      if (pc->ctype == BGP_CFT_GROUP)
        {
          /* Cannot unset the multi-hop state of a group member by setting
           * GTSM for the group.
           */
          uint          i ;
          bgp_pconfig   mc ;

          qassert((pc->gc != NULL) && (pc->gc->members != NULL)) ;

          i = 0 ;
          while ((mc = vector_get_item(pc->gc->members, i++)) != NULL)
            {
              if (pcs_is_on(mc, pcs_multihop))
                return BGP_ERR_NO_MULTIHOP_WITH_GTSM;
            } ;
        } ;

      /* Set GTSM.
       */
      pc->ttl  = (ttl <= TTL_MAX) ? ttl : TTL_MAX ;
      pc->gtsm = true ;
    }
  else
    {
      /* Unset or set GTSM off
       */
      pc->gtsm = false ;
    } ;

  return bgp_config_pcs_change(pc, pcs_ttl_security, bsc) ;
}

/*------------------------------------------------------------------------------
 * Neighbor description.
 *
 * Note that this is an exception to the usual rule... the change has
 * immediate effect on any running peer.
 *
 * Group value has no effect on group members.
 */
extern bgp_ret_t
bgp_peer_description_set (bgp_peer peer, chs_c desc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (pc->desc != NULL)
    XFREE (MTYPE_PEER_DESC, pc->desc);

  if (desc != NULL)
    pc->desc = XSTRDUP (MTYPE_PEER_DESC, desc);
  else
    pc->desc = NULL ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Neighbor update-source -- interface form
 *
 * Setting an interface replaces any previous interface or address.
 */
extern bgp_ret_t
bgp_peer_update_source_if_set (bgp_peer peer, chs_c ifname)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if ((ifname == NULL) || (ifname[0] == '\0')
                       || (strlen(ifname) >= sizeof(IF_NAMESIZE)))
    return BGP_ERR_INVALID_IF_NAME ;

  ni_nref_set_c(&pc->update_source, bgp_config_name_index, ifname) ;

  return bgp_config_pcs_change(pc, pcs_update_source, bsc_set_on) ;
} ;

/*------------------------------------------------------------------------------
 * Neighbor update-source -- address form
 *
 * Caller may present an su version of the address, if they wish -- in which
 * case the addr string is ignored.
 *
 * Setting an address unsets any previous address or interface.
 */
extern bgp_ret_t
bgp_peer_update_source_addr_set (bgp_peer peer, chs_c addr, sockunion su)
{
  bgp_pconfig pc ;
  sockunion_string_t ss ;
  sockunion_t su_s ;

  pc = bgp_config_peer_prepare(peer) ;

  if    (su == NULL)
    {
      if ((addr == NULL) || (addr[0] == '\0'))
        return BGP_ERR_INVALID_VALUE ;

      su = &su_s ;
      if (str2sockunion(addr, su) != 0)
        return BGP_ERR_INVALID_IP_ADDRESS;
    } ;

  /* make canonical form of address
   */
  ss = sutoa(su) ;

  ni_nref_set_c(&pc->update_source, bgp_config_name_index, ss.str) ;

  return bgp_config_pcs_change(pc, pcs_update_source, bsc_set_on) ;
} ;

/*------------------------------------------------------------------------------
 * Unset update_source and update_if
 *
 * For groups, unset the group and all members.
 */
extern bgp_ret_t
bgp_peer_update_source_unset (bgp_peer peer)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  ni_nref_clear(&pc->update_source) ;

  return bgp_config_pcs_change(pc, pcs_update_source, bsc_unset) ;
} ;

/*------------------------------------------------------------------------------
 * Set neighbor interface for given *real* peer.
 * Previously deprecated.  Now Removed.
 */
extern bgp_ret_t
bgp_peer_interface_set (bgp_peer peer, chs_c ifname, bgp_sc_t bsc)
{
  bgp_pconfig pc  Unused ;

  pc = bgp_config_peer_prepare(peer) ;

  return BGP_ERR_NOT_SUPPORTED;
}

/*------------------------------------------------------------------------------
 * Require default route to be originated.
 *
 * bsc_set_on:  rmap_name == NULL  => leave as is
 *                        == empty => set off
 *                        == xx    => set
 *
 * bsc_set_off: rmap_name == NULL  => leave as is
 *                        == empty => set off
 *                        == xx    => set
 *
 * bsc_unset:   rmap_name == NULL  => unset
 *                        == empty => set off
 *                        == xx    => set
 */
extern bgp_ret_t
bgp_peer_default_originate_set (bgp_peer peer, qafx_t qafx, chs_c rmap_name,
                                                                bgp_sc_t bsc)
{
  bgp_paf_config  pafc ;
  bgp_ret_t ret1, ret2 ;

  pafc = bgp_config_peer_af_prepare(peer, qafx) ;
  if (pafc == NULL)
    return BGP_ERR_AF_NOT_CONFIGURED ;

  ret1 = bgp_config_pafcs_change(pafc, pafcs_DEFAULT_ORIGINATE, bsc) ;

  if (rmap_name != NULL)
    {
      ni_nref_set_c(&pafc->filter_set[bfs_default_rmap], bgp_config_name_index,
                                                                   rmap_name) ;
      bsc = (rmap_name[0] != '\0') ? bsc_set_on : bsc_set_off ;
    }
  else
    {
      if (bsc != bsc_unset)
        return ret1 ;

      ni_nref_clear(&pafc->filter_set[bfs_default_rmap]) ;
    } ;

  ret2 = bgp_config_pafcs_change(pafc, pafcs_default_rmap, bsc) ;

  return (ret1 != BGP_SUCCESS) ? ret1 : ret2 ;
} ;

/*------------------------------------------------------------------------------
 * Set the port to be used.
 *
 * Setting the group value overrides all group member settings.
 * Group members may have their own setting.
 *
 * The PEER_CONFIG_PORT flag means that an explicit port has been set.
 * When a group value is set, it will have PEER_CONFIG_PORT, but as the
 * group members are forced to the group value, they will not.
 */
extern bgp_ret_t
bgp_peer_port_set (bgp_peer peer, uint16_t port, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if ((port < 1) || (port > 65535))
        return BGP_ERR_INVALID_VALUE;
    }
  else
    {
      port = 0 ;
    } ;

  pc->port = port;

  return bgp_config_pcs_change(pc, pcs_port, bsc) ;
}

/*------------------------------------------------------------------------------
 * set neighbor weight.
 *
 * Setting the group value overrides all group member settings.
 * Group members may have their own setting.
 *
 * The PEER_CONFIG_WEIGHT flag means that an explicit weight has been set.
 * When a group value is set, it will have PEER_CONFIG_WEIGHT, but as the
 * group members are forced to the group value, they will not.
 */
extern bgp_ret_t
bgp_peer_weight_set (bgp_peer peer, uint weight, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if (weight > 65535)
        return BGP_ERR_INVALID_VALUE;
    }
  else
    {
      weight = 0 ;
    } ;

  pc->weight = weight ;

  return bgp_config_pcs_change(pc, pcs_weight, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set the config_keepalive and holdtime for given peer or group
 *
 * NB: will set whatever keepalive time the administrator asks for, whether
 *     or not that is more or less than holdtime, and whether or not it is
 *     zero and/or holdtime is.
 *
 *     When the HoldTime for a session is, finally, negotiated then (and only
 *     then) with the configured KeepAlive be taken into account.
 */
extern bgp_ret_t
bgp_peer_timers_set (bgp_peer peer, uint keepalive, uint holdtime, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if (keepalive > 65535)
        return BGP_ERR_INVALID_VALUE;

      if (holdtime > 65535)
        return BGP_ERR_INVALID_VALUE;

      if ((holdtime < 3) && (holdtime != 0))
        return BGP_ERR_INVALID_VALUE;
    }
  else
    {
      holdtime  = 0 ;
      keepalive = 0 ;
    }

  pc->holdtime_secs  = holdtime;
  pc->keepalive_secs = keepalive;

  return bgp_config_pcs_change(pc, pcs_timers, bsc) ;
}

/*------------------------------------------------------------------------------
 * Set the config_connect time for given peer or group
 */
extern bgp_ret_t
bgp_peer_timers_connect_set (bgp_peer peer, uint connect_retry_secs,
                                                                   bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if ((connect_retry_secs < 0) || (connect_retry_secs > 65535))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      connect_retry_secs = 0 ;
    }

  pc->connect_retry_secs = connect_retry_secs;

  return bgp_config_pcs_change(pc, pcs_connect_retry, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set the given peer's or group's route advertisement interval.
 */
extern bgp_ret_t
bgp_peer_advertise_interval_set (bgp_peer peer, uint mrai_secs, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      if ((mrai_secs < 1) || (mrai_secs > 600))
        return BGP_ERR_INVALID_VALUE;
    }
  else
    {
      mrai_secs  = 0 ;
    }

  pc->mrai_secs = mrai_secs ;

  return bgp_config_pcs_change(pc, pcs_mrai, bsc) ;
}

/*------------------------------------------------------------------------------
 * Allow-as in.
 */
extern bgp_ret_t
bgp_peer_allow_as_in_set (bgp_peer peer, qafx_t qafx, uint allow, bgp_sc_t bsc)
{
  bgp_paf_config  pafc ;

  pafc = bgp_config_peer_af_prepare(peer, qafx) ;
  if (pafc == NULL)
    return BGP_ERR_AF_NOT_CONFIGURED ;

  if (bsc == bsc_set_on)
    {
      if ((allow < 1) || (allow > 10))
        return BGP_ERR_INVALID_VALUE;
    }
  else
    {
      allow = 0 ;
    }

  pafc->allow_as_in = allow ;

  return bgp_config_pafcs_change(pafc, pafcs_allow_as_in, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set neighbor nnn local-as <ASN> [no-prepend]
 *
 * The <ASN> may not be the same as the bgp->my_as or the bgp->confed_id !
 *
 * The "no-prepend" cannot be set separately from the local-as.
 */
extern bgp_ret_t
bgp_peer_local_as_set(bgp_peer peer, as_t local_as, bool no_prepend,
                                                                   bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  if (bsc == bsc_set_on)
    {
      bgp_bconfig bc ;

      if ((local_as < BGP_ASN_FIRST) || (local_as > BGP_ASN_LAST))
        return BGP_ERR_INVALID_VALUE;

      confirm(BGP_ASN_NULL < BGP_ASN_FIRST) ;

      if (!bgp_peer_sorts_allow(peer, BGP_PSORTS_EBGP_BIT))
        return BGP_ERR_LOCAL_AS_ALLOWED_ONLY_FOR_EBGP ;

      bc = peer->parent_bgp->c ;

      if (bcs_is_on(bc, bcs_confed_id))
        {
          if (local_as == bc->confed_id)
            return BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_CONFED_ID ;
        }
      else
        {
          if (local_as == bc->my_as)
            return BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS ;
        } ;
    }
  else
    {
      local_as   = BGP_ASN_NULL ;
      no_prepend = true ;
    }

  pc->change_local_as         = local_as ;
  pc->change_local_as_prepend = !no_prepend ;

  return bgp_config_pcs_change(pc, pcs_change_local_as, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set password for authenticating with the peer
 *
 * May not set an empty password !
 */
extern bgp_ret_t
bgp_peer_password_set (bgp_peer peer, chs_c password, bgp_sc_t bsc)
{
  bgp_pconfig pc ;

  pc = bgp_config_peer_prepare(peer) ;

  switch (bsc)
    {
      case bsc_set_on:
        if ((password == NULL) || (password[0] == '\0'))
          return BGP_ERR_INVALID_VALUE ;

        confirm(BGP_PASSWORD_MIN_LEN == 1) ;

        if (strlen(password)  > BGP_PASSWORD_MAX_LEN)
          return BGP_ERR_INVALID_VALUE;

        break ;

      default:
        qassert(false) ;
        fall_through ;

      case bsc_set_off:
      case bsc_unset:
        password = NULL ;
    } ;

  ni_nref_set_c(&pc->password, bgp_config_name_index, password) ;

  return bgp_config_pcs_change(pc, pcs_password, bsc) ;
}

/*------------------------------------------------------------------------------
 * Set maximum prefix parameters
 */
extern bgp_ret_t
bgp_peer_maximum_prefix_set (bgp_peer peer, qafx_t qafx, uint32_t max,
                   byte thresh_pc, bool warning, uint16_t restart, bgp_sc_t bsc)
{
  bgp_paf_config  pafc ;
  prefix_max      pmax ;

  pafc = bgp_config_peer_af_prepare(peer, qafx) ;
  if (pafc == NULL)
    return BGP_ERR_AF_NOT_CONFIGURED ;

  pmax = &pafc->pmax ;
  memset(pmax, 0, sizeof(prefix_max_t)) ;

  switch (bsc)
    {
      case bsc_set_on:
        if (thresh_pc > 100)
          thresh_pc = 100 ;             /* clamp        */

        pmax->set       = true ;
        pmax->warning   = warning ;

        pmax->limit     = max ;
        pmax->threshold = ((urlong)max * thresh_pc) / 100 ; ;
        pmax->thresh_pc = thresh_pc ;
        pmax->restart   = restart ;

        break ;

      default:
        qassert(false) ;
        fall_through ;

      case bsc_set_off:
      case bsc_unset:
        break ;
    } ;

  return bgp_config_pafcs_change(pafc, pafcs_max_prefix, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set given filter set name
 */
extern bgp_ret_t
bgp_peer_filter_set(bgp_peer peer, qafx_t qafx, bgp_pafc_setting_t setting,
                                                       chs_c name, bgp_sc_t bsc)
{
  bgp_paf_config        pafc ;
  bgp_filter_set_t      fs ;
  bool                  conflict ;

  pafc = bgp_config_peer_af_prepare(peer, qafx) ;
  if (pafc == NULL)
    return BGP_ERR_AF_NOT_CONFIGURED ;

  conflict = false ;
  switch (setting)
    {
      case pafcs_dlist_in:
        fs = bfs_dlist_in ;
        conflict = pafcs_is_on(pafc, pafcs_plist_in) ;
        break ;

      case pafcs_dlist_out:
        fs = bfs_dlist_out ;
        conflict = pafcs_is_on(pafc, pafcs_plist_out) ;
        break ;

      case pafcs_plist_in:
        fs = bfs_plist_in ;
        conflict = pafcs_is_on(pafc, pafcs_dlist_in) ;
        break ;

      case pafcs_plist_out:
        fs = bfs_plist_out ;
        conflict = pafcs_is_on(pafc, pafcs_dlist_out) ;
        break ;

      case pafcs_aslist_in:
        fs = bfs_aslist_in ;
        break ;

      case pafcs_aslist_out:
        fs = bfs_aslist_out ;
        break ;

      case pafcs_rmap_in:
        fs = bfs_rmap_in ;
        break ;

      case pafcs_rmap_inx:
        fs = bfs_rmap_inx ;
        break ;

      case pafcs_rmap_export:
        fs = bfs_rmap_export ;
        break ;

      case pafcs_rmap_import:
        fs = bfs_rmap_import ;
        break ;

      case pafcs_rmap_out:
        fs = bfs_rmap_out ;
        break ;

      case pafcs_us_rmap:
        fs = bfs_us_rmap ;
        break ;

      case pafcs_default_rmap:
        fs = bfs_default_rmap ;
        break ;

      default:
        return BGP_ERR_INVALID_VALUE;
    } ;

  switch (bsc)
    {
      case bsc_set_on:
        if ((name == NULL) || (name[0] == '\0'))
          return BGP_ERR_INVALID_VALUE ;

        if (conflict)
          return BGP_ERR_PEER_FILTER_CONFLICT;

        break ;

      default:
        qassert(false) ;
        fall_through ;

      case bsc_set_off:
      case bsc_unset:
        name = NULL ;
    } ;

  ni_nref_set_c(&pafc->filter_set[fs], bgp_config_name_index, name) ;

  return bgp_config_pafcs_change(pafc, setting, bsc) ;
} ;

/*==============================================================================
 * Call-backs for filter changes
 */

/*------------------------------------------------------------------------------
 * This is the call-back used when a distribute-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * distribute-list...  but that is for another day !
 */
extern void
bgp_peer_distribute_update (access_list alist)
{
}

/*------------------------------------------------------------------------------
 * This is the all-back used when a prefix-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * prefix-list...  but that is for another day !
 */
extern void
bgp_peer_prefix_list_update (struct prefix_list *plist)
{
}

/*------------------------------------------------------------------------------
 * This is the all-back used when an as-list is changed.
 *
 * This used to deal with the linking of names to active lists, but that is no
 * longer required.
 *
 * Arguably, this should prompt a re-appraisal of anything affected by the
 * as-list...  but that is for another day !
 */
extern void
bgp_peer_aslist_update (void)
{
}

/*==============================================================================
  */

#if 0

/* Side effect handling for changing of peer c_flags
 *
 * Actions required after a change of state of a peer.
 */
enum peer_change_type
{
  peer_change_none,       /* no further action                          */
  peer_change_reset,      /* drop any existing session and restart      */
  peer_change_reset_in,   /* if possible, ask for route refresh,
                             otherwise drop and restart.                */
  peer_change_reset_out,  /* re-announce everything                     */
} ;

typedef enum peer_change_type peer_change_type_t ;

/* Structure which defines the side effect of one or more c_flags.
 */
typedef const struct peer_flag_action  peer_flag_action_t ;
typedef const struct peer_flag_action* peer_flag_action ;

struct peer_flag_action
{
  /* Flag(s) to which the side effect applies
   */
  uint  flag;

  /* This flag can be set for peer-group member.
   */
  bool  not_for_member;

  /* Action when the flag is changed.
   */
  peer_change_type_t ctype;

  /* Peer down cause
   */
  peer_down_t peer_down;
};

/*------------------------------------------------------------------------------
 * Look up action for given c_flags.
 *
 * Returns: address of required peer_flag_action structure,
 *      or: NULL if no action found for the given combination of c_flags.
 *
 * This mechanism is generally used when setting/clearing one flag at a time.
 *
 * The table may contain entries with more than one flag.  In these cases,
 * any combination of those c_flags may be set/cleared together -- any c_flags
 * which are not mentioned are not affected.
 *
 * The given c_flags value must either exactly match a single flag entry, or be
 * a subset of a multiple flag entry.  The table is searched in the order
 * given, and proceeds to the end before stopping.
 */
static peer_flag_action
peer_flag_action_find (peer_flag_action action, uint32_t flag)
{
  if (flag != 0)
    {
      while (action->flag != 0)
        {
          if ((action->flag & flag) == flag)
            return action ;

          action++ ;
        } ;
    } ;

  return NULL ;
} ;

static const struct peer_flag_action peer_af_flag_action_list[] =
  {
    {  PEER_AFF_NEXTHOP_SELF,
                 true, peer_change_reset_out,  PEER_DOWN_NULL },
    {  PEER_AFF_SEND_COMMUNITY
     | PEER_AFF_SEND_EXT_COMMUNITY,
                 true, peer_change_reset_out,  PEER_DOWN_NULL },
    {  PEER_AFF_SOFT_RECONFIG,
                false, peer_change_reset_in,   PEER_DOWN_CONFIG_CHANGE },
    {  PEER_AFF_REFLECTOR_CLIENT,
                 true, peer_change_reset,      PEER_DOWN_RR_CLIENT_CHANGE },
    {  PEER_AFF_RSERVER_CLIENT,
                 true, peer_change_reset,      PEER_DOWN_RS_CLIENT_CHANGE },
    {  PEER_AFF_AS_PATH_UNCHANGED
     | PEER_AFF_NEXTHOP_UNCHANGED
     | PEER_AFF_MED_UNCHANGED,
                 true, peer_change_reset_out,  PEER_DOWN_NULL },
    {  PEER_AFF_REMOVE_PRIVATE_AS,
                 true, peer_change_reset_out,  PEER_DOWN_NULL },
    {  PEER_AFF_ALLOWAS_IN,
                false, peer_change_reset_in,   PEER_DOWN_ALLOWAS_IN_CHANGE },
#if 0
    {  PEER_AFF_ORF_PFX_SM
     | PEER_AFF_ORF_PFX_RM,
                 true, peer_change_reset,      PEER_DOWN_CONFIG_CHANGE },
#endif
    {  PEER_AFF_NEXTHOP_LOCAL_UNCHANGED,
                false, peer_change_reset_out,  PEER_DOWN_NULL },
    { 0, false, peer_change_none, PEER_DOWN_NULL }
  };

static void peer_af_flag_modify_action (bgp_prib prib, peer_flag_action action,
                              qafx_t qafx, bgp_paf_flag_t flag, bool c_set) ;

/*------------------------------------------------------------------------------
 * Change specified peer->af_flags flag(s) and deal with any side effects.
 *
 * 'set' == true means:  set all the bits given by 'flag'
 *       == false means: clear all the bits given by 'flag'
 *
 * NB: side effects only apply to PEER_TYPE_REAL peers.
 *
 * NB: clearing PEER_AFF_SOFT_RECONFIG is a special case.
 */
static void
peer_af_flag_modify_action (bgp_prib prib, peer_flag_action action,
                                qafx_t qafx, bgp_paf_flag_t flag, bool set)
{
  bgp_paf_flag_t* p_aff ;
  bgp_paf_flag_t  now ;
  bgp_peer peer ;

  peer = prib->peer ;

  p_aff = &peer->c->c_af[qafx]->c_flags ;
  now   = *p_aff & flag ;

  if (set)
    {
      if (now != flag)
        *p_aff |= flag ;
      else
        return ;                /* no change            */
    }
  else
    {
      if (now != 0)
        *p_aff ^= now ;
      else
        return ;                /* no change            */
    } ;

  if (peer->c_type != PEER_TYPE_REAL)
    return;

  if ((action->flag == PEER_AFF_SOFT_RECONFIG) && !set)
    {
      if (peer->state == bgp_pEstablished)
        bgp_clear_adj_in (prib, false /* not graceful */);
    }
  else
    {
      /* Perform action after change of state of a peer for the given afi/safi.
       *
       * If has to down the peer (drop any existing session and restart), then
       * requires a peer_down_t to record why.
       */
      switch (action->ctype)
        {
          case  peer_change_none:
            break ;

          case peer_change_reset:
            bgp_peer_down(prib->peer, action->peer_down) ;
            break ;

          case peer_change_reset_in:
            if (peer->state == bgp_pEstablished)
              {
                if (peer->session->args_r->can_rr != bgp_form_none)
                  bgp_route_refresh_send (prib, 0, 0, 0);
                else
                  bgp_peer_down(peer, action->peer_down);
              } ;
            break ;

          case peer_change_reset_out:
            bgp_announce_family (peer, qafx, 10) ;
                                /* Does nothing if !pEstablished        */
          break ;

          default:
            zabort("unknown peer_change_type") ;
            break ;
        } ;
    } ;
} ;
#endif
