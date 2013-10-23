/* BGP Peer Group Handling
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
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
#include "misc.h"

#include "bgpd/bgp_peer_group.h"
#include "bgpd/bgp_peer.h"

/*==============================================================================
 * Peer Group Configuration handling
 */
#if 0
/*------------------------------------------------------------------------------
 * Peer Group comparison function for sorting.
 *
 * The list of groups hung from the parent bgp instance uses this to keep the
 * list in group "name" order.
 */
extern int
peer_group_cmp (bgp_peer_group g1, bgp_peer_group g2)
{
  return strcmp (g1->name, g2->name);
} ;

/*------------------------------------------------------------------------------
 * Create a Peer Group stucture
 */
static bgp_peer_group peer_group_new (void)
{
  return XCALLOC (MTYPE_PEER_GROUP, sizeof (bgp_peer_group_t)) ;
}

/*------------------------------------------------------------------------------
 * Destroy a Peer Group stucture
 */
static void
peer_group_free (bgp_peer_group group)
{
  XFREE (MTYPE_PEER_GROUP, group);
}

/*------------------------------------------------------------------------------
 * Lookup group in given bgp instance.
 *
 * NB: unlike peer_lookup(), this will NOT scan all bgp instances if bgp is
 *     NULL -- will CRASH instead.
 */
extern bgp_peer_group
peer_group_lookup (bgp_inst bgp, const char* name)
{
  bgp_peer_group group;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    {
      if (strcmp (group->name, name) == 0)
        return group;
    }
  return NULL;
}

/*------------------------------------------------------------------------------
 * Get existing peer-group in given bgp instance, or make a new one.
 *
 * Returns: the peer-group (pre-existing or new)
 */
extern bgp_peer_group
peer_group_get (bgp_inst bgp, const char* name)
{
  bgp_peer_group group;

  group = peer_group_lookup (bgp, name);
  if (group == NULL)
    {
      bgp_peer  conf ;

      group = peer_group_new ();
      conf  = bgp_peer_new(bgp, PEER_TYPE_GROUP) ;
      conf->group = group;

      group->parent_bgp  = bgp;                /* the conf owns a lock */
      group->name = strdup (name);
      group->conf = bgp_peer_lock (conf);

      listnode_add_sort (bgp->group, group);

      if (! bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4))
        conf->af_configured |= qafx_ipv4_unicast_bit ;

      conf->host            = XSTRDUP (MTYPE_BGP_PEER_HOST, name);
      conf->args.remote_as  = BGP_ASN_NULL ;
      conf->cops.ttl        = 1;
      conf->cops.gtsm       = false ;
    } ;

  return group ;
} ;

/*------------------------------------------------------------------------------
 * Peer group delete -- deletes all peers bound to the group, too.
 */
extern bgp_ret_t
peer_group_delete (bgp_peer_group group)
{
  bgp_inst bgp;
  bgp_peer peer;

  bgp = group->parent_bgp;

  while ((peer = ddl_pop(&peer->c, group->members, member.list)) != NULL)
    {
      /* Deleting a peer-group deletes all the peers which are bound to it.
       *
       * Note that the pointer to the group structure is cleared first, to
       * stop bgp_peer_delete() from deleting the peer from the list !!
       */
      peer->group = NULL;
      bgp_peer_delete (peer);
    } ;

  free (group->name);
  group->name = NULL;

  /* Delete the peer-group configuration.
   *
   * Note that the pointer to the group structure is cleared first -- otherwise
   * bgp_peer_delete() will attempt to remove the configuration from the
   * group's list of peers !!
   */
  group->conf->group = NULL;
  bgp_peer_delete (group->conf);

  /* Delete from all peer_group list.
   */
  listnode_delete (bgp->group, group);

  peer_group_free (group);

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Have unset rsclient state for a peer that was a distinct rsclient.
 *
 * Tidy up the data structures.
 *
 * NB: does not down the peer or deal with other consequences.
 */
extern void
peer_rsclient_unset(bgp_peer peer, qafx_t qafx, bool keep_export)
{
  bgp_prib prib ;

  prib = peer->prib[qafx] ;

  assert(prib != NULL) ;

  /* Discard the rsclient prib
   */
#if 0
  bgp_clear_rsclient_rib (peer, qafx);
#endif

  /* Discard import policy unconditionally
   */
  prib->rmap[RMAP_IMPORT] = route_map_clear_ref(prib->rmap[RMAP_IMPORT]) ;

  /* Discard export policy unless should be kept.
   */
  if (!keep_export)
    prib->rmap[RMAP_EXPORT] = route_map_clear_ref(prib->rmap[RMAP_EXPORT]) ;
} ;


#if 0
/*------------------------------------------------------------------------------
 * If peer is RSERVER_CLIENT in at least one address family and is not member
 * of a peer_group for that family, return true.
 *
 * Used to check whether the peer is included in list bgp->rsclient.
 */
extern bool
peer_rsclient_active (bgp_peer peer)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    if ((peer->x_af_flags_x[qafx] & PEER_AFF_RSERVER_CLIENT)
                                                && ! peer->af_group[qafx])
      return true ;

  return false ;
}
#endif


/*==============================================================================
 * Peer Group and Peer related functions
 */
static void peer_group2peer_config_copy (bgp_peer peer, bgp_peer_group group,
                                                                  qafx_t qafx) ;

/*------------------------------------------------------------------------------
 * Unset peer-group's remote-as
 */
extern bgp_ret_t
peer_group_remote_as_delete (bgp_peer_group group)
{
  bgp_peer peer;

  if (group->conf->args.remote_as == BGP_ASN_NULL)
    return BGP_SUCCESS ;

  for (peer = ddl_head(peer->group->members) ;
       peer != NULL ;
       peer = ddl_next(peer->c, member.list))
    {
      /* Unsetting a peer-group remote-as deletes all the peers which are bound
       * to it.
       *
       * Note that the pointer to the group structure is cleared first, to
       * stop bgp_peer_delete() from deleting the peer from the list !!
       */
      peer->group = NULL;
      bgp_peer_delete (peer);
    } ;

  group->conf->args.remote_as = BGP_ASN_NULL ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set peer-group's remote-as
 */
extern bgp_ret_t
peer_group_remote_as (bgp_inst bgp, const char* group_name, as_t* p_as)
{
  bgp_peer_group group;
  bgp_peer   peer;

  group = peer_group_lookup (bgp, group_name);
  if (group == NULL)
    return BGP_ERR_INVALID_VALUE ;

  if (group->conf->args.remote_as == *p_as)
    return BGP_SUCCESS ;

  /* When we setup peer-group AS number all peer group member's AS
   * number must be updated to same number.
   */
  peer_as_change (group->conf, *p_as);

  for (peer = ddl_head(peer->group->members) ;
       peer != NULL ;
       peer = ddl_next(peer->c, member_list))
    {
      if (peer->args.remote_as != *p_as)
        peer_as_change (peer, *p_as);
    }

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Bind specified peer to peer group.
 *
 * If the peer does not exist:
 *
 *   * iff the group specifies a remote-as, create peer and bind it.
 *
 *   * otherwise return an error.
 *
 * If peer does exist
 */
extern bgp_ret_t
peer_group_bind (bgp_inst bgp, sockunion su,
                                     bgp_peer_group group, qafx_t qafx, as_t* p_asn)
{
  bgp_peer        peer ;
  bgp_prib        prib ;
  bgp_peer_sort_t group_sort ;
  bool first_member ;

  /* Check peer group's address family.
   */
  if (! peer_family_is_active(group->conf, qafx))
    return BGP_ERR_PEER_GROUP_AF_NOT_CONFIGURED;

  /* Lookup the peer in the given bgp instance.
   */
  peer = bgp_peer_lookup_su (bgp, su) ;

  /* Create a new peer -- iff is unique and group specifies a remote-as.
   */
  if (peer == NULL)
    {
      if (group->conf->args.remote_as == BGP_ASN_NULL)
        return BGP_ERR_PEER_GROUP_NO_REMOTE_AS ;

      if (bgp_peer_lookup_su (NULL, su) != NULL)
        return BGP_ERR_PEER_EXISTS ;

      peer = bgp_peer_create (su, bgp, group->conf->args.remote_as, qafx);
      peer->group = group;
      ddl_append(group->members, peer->c, member_list) ;
      peer->c_af_member |= qafx_bit(qafx) ;

      peer_group2peer_config_copy(peer, group, qafx);

      return BGP_SUCCESS ;      /* Done         */
    } ;

  qassert(peer->ptype == PEER_TYPE_REAL) ;
  qassert(bgp == peer->parent_bgp) ;

  prib = peer->prib[qafx] ;

  /* When the peer already belongs to peer group, check the consistency.
   */
  if ((peer->group != NULL) && (prib != NULL))
    {
      qassert(prib->af_group_member ==
                                    (peer->c_af_member & qafx_bit(qafx))) ;
      qassert((peer->group == group) ==
                                      strsame(peer->group->name, group->name)) ;

      if (prib->af_group_member)
        {
          /* This afi/safi is already a member of a group.
           *
           * Need do nothing if is already a member of the intended group.
           *
           * Otherwise, reject attempt to change group !
           */
          if (peer->group == group)
            return BGP_SUCCESS ;        /* already bound as required    */
          else
            return BGP_ERR_PEER_GROUP_CANNOT_CHANGE ;
        }
      else
        {
          /* This afi/safi is not a member of a group, but at least one other
           * afi/safi is.
           *
           * Can proceed only if is trying to set the same group as the
           * other afi/safi(s) for this peer.
           */
          if (peer->group != group)
            return BGP_ERR_PEER_GROUP_MISMATCH ;
        } ;
    } ;

  /* It is a rule that all members of a peer-group must be of the same sort.
   *
   * This appears to be to avoid confusion with attributes which depend on
   * the peer sort... not that it does a very good job of that.
   */
  first_member = false ;
  group_sort   = peer_sort (group->conf) ;

  if (group_sort == BGP_PEER_UNSPECIFIED)
    {
      first_member = true ;
      group_sort = peer->sort ;
      if (group_sort == BGP_PEER_CBGP)
        group_sort = BGP_PEER_EBGP ;
    }
  else
    {
      if (group_sort != peer->sort)
        {
          if (p_asn != NULL)
            *p_asn = peer->args.remote_as ;

          return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
        } ;
    } ;

  /* Can join the group.
   *
   * NB: if we get to here, then we know that this afi/safi was NOT a member
   *     of any group.
   *
   * Note that this appears to implicitly activate the afi/safi... but does
   * not go through the rest of the activation process ???
   *
   * TODO: why does implicit activation of afi/safi not do more work ?
   */
  qassert(!(peer->c_af_member & qafx_bit(qafx))) ;

  if (peer->group == NULL)
    {
      peer->group = group;
      ddl_append(group->members, peer->c, member.list) ;
    }
  else
    assert (peer->group == group) ;

  /* Further magic stuff to do with group sort, when group was empty.
   *
   * This sets certain attributes of the group according to the sort it is
   */
  if (first_member)
    {
      /* ebgp-multihop reset
       */
      peer_sort_init_ttl_gtsm(group->conf, group_sort) ;

      /* local-asn reset
       */
      if (group_sort != BGP_PEER_EBGP)
        {
          group->conf->change_local_as         = BGP_ASN_NULL ;
          group->conf->change_local_as_prepend = false ;
        }
    } ;

  /* Worry about rsclient state of the peer for this afi/safi.
   *
   * A peer cannot be an rsclient separately from its group.
   *
   * This peer was not previously a member of any group for this afi/safi.
   *
   * So if the peer is an rsclient for this afi/safi, it had better stop
   * that now.
   */
  if (peer->c->c_af[qafx]->c_flags & PEER_AFF_RSERVER_CLIENT)
    {
      /* Now that we have set peer->af_group_member for this afi/safi, this peer
       * may no longer have any distinct rsclient status, in which case it
       * must be removes from list bgp->rsclient.
       *
       * Note that it must have had distinct rsclient status, because it is
       * an rsclient in this afi/safi, and it was not a group member in this
       * afi/safi.
       *
       * We discard any import and export route map, except if the group is
       * an rsclient, when we keep the export route map.
       */
      peer->c->c_af[qafx]->c_flags &= ~PEER_AFF_RSERVER_CLIENT ;

      peer_rsclient_unset(peer, qafx,
         (group->conf->c->c_af[qafx]->c_flags & PEER_AFF_RSERVER_CLIENT)) ;
    }

  /* Now deal with the rest of the group configuration.
   */
  peer_group2peer_config_copy (peer, group, qafx);

  /* And down the peer to push into new state.
   */
  bgp_peer_down(peer, PEER_DOWN_GROUP_BIND) ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Unbind specified peer from specified group for given afi/safi.
 *
 * Does nothing, and is OK if the peer is:
 *
 *   * not a member of any group in the afi/safi
 *
 *   * not activated for the afi/safi
 *
 * Fails if the peer is:
 *
 *   * a member of some other group in the afi/safi
 */
extern bgp_ret_t
peer_group_unbind (bgp_peer peer, bgp_peer_group group, qafx_t qafx)
{
  qassert(peer->ptype == PEER_TYPE_REAL) ;

  if (!(peer->c_af_member & qafx_bit(qafx)))
    return BGP_SUCCESS ;                /* not in this afi/safi         */

  if (group != peer->group)
    return BGP_ERR_PEER_GROUP_MISMATCH; /* quit if not member of this group */

  /* So is a member of this group for this afi/safi.
   *
   * This is an implied deactivation for this peer.  That is taken care of in
   * bgp_peer_down().
   */
  peer->c_af_member &= ~qafx_bit(qafx) ;
  peer_deactivate_family (peer, qafx) ;

  /* If is now no longer a member of this group in any afi/safi at all,
   * then remove the group setting and remove from the list of peers attached
   * to the group.
   *
   * If the group has a 'remote-as' set, then we can delete the peer altogether.
   */
  if (peer->c_af_member == qafx_empty_set)
    {
      ddl_del(group->members, peer->c, member_list);
      peer->group = NULL;

      if (group->conf->args.remote_as != BGP_ASN_NULL)
        {
          bgp_peer_delete (peer);
          return BGP_SUCCESS ;
        } ;

      peer_global_config_reset (peer);
    } ;

  /* Reset the peer
   */
  bgp_peer_down(peer, PEER_DOWN_GROUP_UNBIND) ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Copy such config as applies from given peer-group to given peer,
 *                                                               for given qafx.
 */
static void
peer_group2peer_config_copy (bgp_peer peer, bgp_peer_group group, qafx_t qafx)
{
  enum
    {
      in  = FILTER_IN,
      out = FILTER_OUT,
    } ;

  bgp_peer   conf;
  bgp_prib   prib, g_prib ;

  conf    = group->conf;

  prib   = peer->prib[qafx] ;
  g_prib = conf->prib[qafx] ;

  /* Various sets of c_flags apply
   */
  peer->c->c_flags           = conf->c->c_flags;
  peer->c->c_af[qafx]->c_flags = conf->c->c_af[qafx]->c_flags ;

  /* remote-as, local-as & allowas-in
   *
   * For completeness we set the sort after
   */
  if (conf->args.remote_as != BGP_ASN_NULL)
    peer->args.remote_as = conf->args.remote_as;

  peer_sort_set(peer, peer_sort(peer)) ;

  if (conf->change_local_as != BGP_ASN_NULL)
    peer->change_local_as = conf->change_local_as;

  prib->allow_as_in = g_prib->allow_as_in ;

  /* TTL & GTSM
   */
  if (peer->sort != BGP_PEER_IBGP)
    {
      peer->cops.ttl  = conf->cops.ttl;
      peer->cops.gtsm = conf->cops.gtsm;
    } ;

  /* The group's configuration for:
   *
   *   PEER_CONFIG_WEIGHT
   *   PEER_CONFIG_TIMER
   *   PEER_CONFIG_MRAI
   *   PEER_CONFIG_CONNECT_RETRY ;
   *
   * take precedence over the peer's settings, and wipe out those settings.
   *
   * NB: when the given peer is removed from the group, any previous
   *     configuration is lost, and reverts to the default.)
   */
  peer->c->c_set = (peer->c->c_set & ~PEER_CONFIG_GROUP_OVERRIDE) |
                      (conf->c->c_set &  PEER_CONFIG_GROUP_OVERRIDE) ;

  peer->c_weight              = conf->c_weight;
  peer->args.holdtime_secs  = conf->args.holdtime_secs ;
  peer->args.keepalive_secs = conf->args.keepalive_secs ;
  peer->c->c_mrai        = conf->c->c_mrai ;

  peer->cops.connect_retry_secs = conf->cops.connect_retry_secs ;
  peer->cops.accept_retry_secs  = conf->cops.accept_retry_secs ;
  peer->cops.open_hold_secs     = conf->cops.open_hold_secs ;

  /* password apply
   */
  strncpy(peer->cops.password, conf->cops.password, BGP_PASSWORD_SIZE) ;
  confirm(sizeof(peer->cops.password) == BGP_PASSWORD_SIZE) ;

  /* maximum-prefix
   */
  prib->c_pmax = g_prib->c_pmax;

  /* route-server-client
   */
  if (group->conf->c->c_af[qafx]->c_flags & PEER_AFF_RSERVER_CLIENT)
    {
      /* Make peer's RIB point to group's RIB.
       */
      peer->prib[qafx] = group->conf->prib[qafx];
    } ;

  /* default-originate route-map
   */
  if (g_prib->default_rmap != NULL)
    {
      route_map_clear_ref(prib->default_rmap) ;
      prib->default_rmap = route_map_set_ref(g_prib->default_rmap) ;
    }

  /* update-source apply
   */
  if (conf->cops.ifname[0] != '\0')
    sockunion_clear(&peer->cops.su_local) ;

      else if (sockunion_family(&conf->cops.su_local) != AF_UNSPEC)
        sockunion_copy(&peer->cops.su_local, &conf->cops.su_local) ;

      strncpy(peer->cops.ifname, conf->cops.ifname, IF_NAMESIZE) ;
      confirm(sizeof(peer->cops.ifname) == IF_NAMESIZE) ;

  /* Inbound filters and route-maps apply -- if peer does not have own.
   */
  if (prib->dlist[in] == NULL)
    prib->dlist[in] = access_list_set_ref(g_prib->dlist[in]) ;

  if (prib->plist[in] == NULL)
    prib->plist[in] = prefix_list_set_ref(g_prib->plist[in]) ;

  if (prib->flist[in] == NULL)
    prib->flist[in] = as_list_set_ref(g_prib->flist[in]) ;

  if (prib->rmap[RMAP_IN] == NULL)
    prib->rmap[RMAP_IN] = route_map_set_ref(g_prib->rmap[RMAP_IN]) ;

  if (prib->rmap[RMAP_INX] == NULL)
    prib->rmap[RMAP_INX] = route_map_set_ref(g_prib->rmap[RMAP_INX]) ;

  /* outbound filters and route-maps apply -- unconditionally.
   */
  access_list_clear_ref(prib->dlist[out]) ;
  prib->dlist[out] = access_list_set_ref(g_prib->dlist[out]) ;

  prefix_list_clear_ref(prib->plist[out]) ;
  prib->plist[out] = prefix_list_set_ref(g_prib->plist[out]) ;

  as_list_clear_ref(prib->flist[out]) ;
  prib->flist[out] = as_list_set_ref(g_prib->flist[out]) ;

  route_map_clear_ref(prib->rmap[RMAP_OUT]) ;
  prib->rmap[RMAP_OUT] = route_map_set_ref(g_prib->rmap[RMAP_OUT]) ;

  /* RS-Client export and import filters.
   *
   * For reasons unknown -- TODO -- the 'export' filter (which stands in place
   * of the 'out' filter for the peer) is treated like an inbound filter, where
   * the 'import' filter (which stands in place of the )
   */
  if (prib->rmap[RMAP_EXPORT] == NULL)
    prib->rmap[RMAP_EXPORT] =
                              route_map_set_ref(g_prib->rmap[RMAP_EXPORT]) ;

  route_map_clear_ref(prib->rmap[RMAP_IMPORT]) ;
  prib->rmap[RMAP_IMPORT] =
                            route_map_set_ref(g_prib->rmap[RMAP_IMPORT]) ;

  /* Unsuppress route-map
   */
  route_map_clear_ref(prib->us_rmap) ;
  prib->us_rmap = route_map_set_ref(g_prib->us_rmap) ;
} ;
#endif
