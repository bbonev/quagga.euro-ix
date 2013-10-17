/* BGP Peer Handling
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

#include "bgpd/bgp_peer.h"

#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_names.h"

#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "thread.h"
#include "log.h"
#include "memory.h"
#include "plist.h"
#include "mqueue.h"
#include "workqueue.h"
#include "if.h"
#include "qatomic.h"
#include "qrand.h"


#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */


#if 0

/*------------------------------------------------------------------------------
 * Establish sort of peer or peer-group from first principles.
 *
 * For peer, this depends on the peer->args.remote_as, bgp->my_as and
 * confederation state.
 *
 * For peer-group:
 *
 *   * if the peer-group has a remote-as set, then that will specify the
 *     peer-group sort.
 *
 *   * otherwise, if the peer-group has a member, then the sort of the first
 *     member is the sort of the peer-group -- noting that all members must
 *     be of the *same* sort.
 *
 *   * otherwise, the peer-group does not have a specified sort -- ie it is
 *     BGP_PEER_UNSPECIFIED.
 *
 * NB: for a peer-group we do not care about the distinction between an eBGP
 *     peer and a CONFED peer (a peer with a different Member-AS), and this
 *     function will return BGP_PEER_EBGP for both cases.
 *
 * NB: bgp->my_as cannot be changed once set.  So a peer or peer-group which is
 *     BGP_PEER_IBGP is unaffected by changes in the confederation state.
 *
 *     For a peer-group, we only care whether the members are BGP_PEER_IBGP
 *     or not (which we treat as BGP_PEER_EBGP).  So a peer-group which is
 *     (nominally) BGP_PEER_EBGP is also unaffected  by changes in the
 *     confederation state.
 *
 * Returns:  the sort
 */
extern bgp_peer_sort_t
bgp_peer_sort(bgp_inst bgp, as_t asn)
{
  bgp_peer_sort_t sort ;

  assert(bgp != NULL) ;

  if (peer->ptype == PEER_TYPE_GROUP)
    {
      /* Peer-group
       *
       * If the group's ASN (remote ASN) is set, return iBGP or eBGP depending
       *                                         on the bgp ASN.
       *
       * Otherwise: look at first peer in group (if any) and return iBGP or
       *            eBGP, depending on that peer's ASN and the bgp ASN.
       *
       *            Note that all peers in a group must all be of the same sort.
       *
       * Otherwise: return BGP_PEER_UNSPECIFIED.
       *
       * Note that does not distinguish BGP_PEER_CBGP from BGP_PEER_EBGP.
       */
      if (peer->args.remote_as != BGP_ASN_NULL)
        {
          if (peer->args.remote_as == bgp->c->c_my_as)
            sort = BGP_PEER_IBGP ;
          else
            sort = BGP_PEER_EBGP ;
        }
      else
        {
          bgp_peer first_member;

          first_member = ddl_head(peer->group->members) ;
          if (first_member != NULL)
            {
              if (first_member->args.remote_as == bgp->c->c_my_as)
                sort = BGP_PEER_IBGP ;
              else
                sort = BGP_PEER_EBGP ;
            }
          else
            sort = BGP_PEER_UNSPECIFIED ;
        } ;
    }
  else
    {
      /* Normal peer
       *
       *   1) if peer's remote and the bgp instance's asns are the same,
       *      return iBGP
       *
       *      If we are in a CONFED, then iBGP means within the same
       *      CONFED Member AS.
       *
       *   2) if we are in a CONFED, and the peer's remote ASN is one of
       *      the (other) Member ASes, return BGP_PEER_CBGP.
       *
       *   3) return eBGP
       */
      if (peer->args.remote_as == bgp->c->c_my_as)
        sort = BGP_PEER_IBGP ;
      else if (bgp_confederation_peers_check (bgp, peer->args.remote_as))
        sort = BGP_PEER_CBGP ;
      else
        sort = BGP_PEER_EBGP ;

      qassert((peer->sort == BGP_PEER_UNSPECIFIED) || (peer->sort == sort)) ;
    } ;

  return sort ;
}



/*==============================================================================
 * CONFEDERATION stuff
 */

/*------------------------------------------------------------------------------
 * If the given bgp instance is a CONFED, is the given AS a CONFED Member AS,
 * for a *different* CONFED Member.
 *
 * Note that to be a CONFED there must be a confed_id configured.  The
 * set of confed_peers has an independent lifetime.
 *
 * Returns:  true <=> bgp != NULL and this is a CONFED
 *                                and the given AS is a CONFED Member AS
 *                                and the given AS is NOT the bgp->my_as
 *
 * NB: bgp->confed_peers should not contain the current bgp->my_as, but we
 *     check for asn == bgp->my_as in any case -- apart from safety, one notes
 *     that there may be a large number of iBGP sessions.
 */
extern bool
bgp_confederation_peers_check (bgp_inst bgp, as_t asn)
{
  if ((bgp != NULL) && (bgp->confed_id != BGP_ASN_NULL))
    return  (asn != bgp->c.my_as) && asn_set_contains(bgp->confed_peers, asn) ;

  return false ;
}

#endif










/*==============================================================================
 *
 */
#if 0

static void peer_deactivate_family (bgp_peer peer, qafx_t qafx) ;
static void peer_global_config_reset (bgp_peer peer) ;

static bgp_peer bgp_peer_free(bgp_peer peer) ;
static bgp_pconfig bgp_peer_config_new(void) ;


/*------------------------------------------------------------------------------
 * Allocate new peer_config object.
 *
 * Returns:  address of new, empty, peer_config object.
 */
static bgp_pconfig
bgp_peer_config_new(void)
{
  bgp_pconfig config ;

  config = XCALLOC (MTYPE_BGP_PEER_CONFIG, sizeof(bgp_pconfig_t));

  /* Zeroizing has set:
   *
   *   * c_flags        -- PEER_FLAG_NOTHING
   *   * c_set          -- PEER_CONFIG_NOTHING
   *   * c_weight       -- none set
   *   * c_mrai         -- none set
   *   * c_af[]         -- NULLs
   */
  confirm(PEER_FLAG_NOTHING    == 0) ;
  confirm(PEER_CONFIG_NOTHING  == 0) ;

  return config ;
} ;

/*------------------------------------------------------------------------------
 * Discard peer_config object, if any.
 *
 * Returns:  NULL
 */
static bgp_pconfig
bgp_peer_config_free(bgp_pconfig config)
{
  if (config != NULL)
    {
      qafx_t    qafx ;

      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        config->c_af = bgp_peer_af_config_free(config->c_af) ;

      XFREE (MTYPE_BGP_PEER_CONFIG, config) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Allocate new peer_af_config object
 *
 * Returns:  NULL.
 */
static bgp_paf_config
bgp_peer_af_config_new(void)
{
  bgp_paf_config af_config ;

  af_config = XCALLOC (MTYPE_BGP_PEER_AF_CONFIG, sizeof(bgp_paf_config)) ;

  /* Zeroizing has set:
   *
   *   * c_flags        -- PEER_AFF_NOTHING
   *
   *   * c_dlist[]      -- NULLs        -- none, yet
   *   * c_plist[]      -- NULLs        -- ditto
   *   * c_flist[]      -- NULLs        -- ditto
   *   * c_rmap[]       -- NULLs        -- ditto
   *   * c_us_rmap      -- NULL         -- ditto
   *   * c_default_rmap -- NULL         -- ditto
   *
   *   * c_orf_plist    -- NULL         -- ditto
   *
   *   * c_pmax         -- X            -- set, below
   */
  confirm(PEER_AFF_NOTHING    == 0) ;

  bgp_prib_pmax_reset(&af_config->c_pmax) ;

  return af_config ;
} ;

/*------------------------------------------------------------------------------
 * Discard peer_af_config object, if any.
 *
 * Returns:  NULL
 */
static bgp_paf_config
bgp_peer_af_config_free(bgp_paf_config af_config)
{
  if (af_config != NULL)
    {
      /* Clear neighbor filter, route-map and unsuppress map
       */
      for (i = FILTER_IN; i < FILTER_MAX; i++)
        {
          prib->dlist[i] = access_list_clear_ref(prib->dlist[i]) ;
          prib->plist[i] = prefix_list_clear_ref(prib->plist[i]) ;
          prib->flist[i] = as_list_clear_ref(prib->flist[i]) ;
        } ;

      for (i = RMAP_IN; i < RMAP_COUNT; i++)
        prib->rmap[i] = route_map_clear_ref(prib->rmap[i]) ;

      prib->us_rmap      = route_map_clear_ref(prib->us_rmap) ;
      prib->default_rmap = route_map_clear_ref(prib->default_rmap) ;

      XFREE (MTYPE_BGP_PEER_AF_CONFIG, af_config) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Create new BGP peer -- if an AFI/SAFI is given, activate & enable for that.
 *
 * Peer starts in pDown state.
 *
 * This is creating a PEER_TYPE_REAL, which is placed on the bgp->peer list.
 * (This is NOT creating a peer-group config object, or a "self" peer object.)
 *
 * The 'local_as' will be: bgp->my_as     unless...
 *                         bgp->confed_id ...we are a CONFED and the peer is
 *                                           external to the CONFED.
 *
 * Returns:  address of new peer
 *
 * NB: the peer is locked once, by virtue of having been added to the bgp->peer
 *     list.
 *
 * NB: copies the given su -- caller responsible for the original
 */
extern bgp_peer
bgp_peer_create(sockunion su, bgp_inst bgp, as_t remote_as, qafx_t qafx)
{
  bgp_peer peer ;
  struct servent *sp;

  /* Creating a new peer sets:
   *
   * Since we are creating a real peer, set that and add self to the bgp
   * instance's list of peer.  Note that this counts as a reference to the
   * peer.
   */
  peer = bgp_peer_new (bgp, PEER_TYPE_REAL);
  listnode_add_sort (bgp->peer, bgp_peer_lock (peer));

  peer->state     = bgp_pDown;

  /* Set basic properties of peer -- evaluate and set the peer sort.
   *
   * After bgp_peer_new we have to consider:
   *
   *   * state                  -- bgp_pInitial
   *
   *   * peer_ie                -- need to set
   *   * session                -- need to create
   *
   *   * sort                   -- need to set after args
   *
   *   * su_name                -- need to set
   *   * host                   -- need to set
   *
   *   * readtime;              -- set to now
   *   * resettime;             -- set to now
   *
   *   * shared_network         -- false        -- not
   *   * nexthop                -- 0's          -- none, yet
   *
   *   * args                   -- set local_as
   *
   *   * cops
   *         .su_remote         -- copy of peer->su_name (by default)
   *         .port              -- set to default
   *         .can_notify_before_open   -- set true (by default)
   *         .idle_hold_max_secs       -- set to default
   *         .connect_retry_secs       -- ditto
   *         .accept_retry_secs        -- ditto
   *         .open_hold_secs           -- ditto
   *         .ttl                      -- set depending on peer->sort
   *
   * Evaluation of the peer sort depends on the peer->args.remote_as, the
   * peer->bgp->my_as, and the confederation state.
   *
   * Setting the sort also sets values which depend on the sort:
   *
   *   * peer->args.local_as  -- set to bgp->my_as, except...
   *                             ...if eBGP and CONFED is enabled, when must be
   *                                bgp->confed_id
   *
   *   * peer->cops.ttl       -- if the sort changes, then we set the default
   *   * peer->cops.gtsm         values for the new sort.
   */
  peer->su_name         = sockunion_dup(su) ;
  peer->host            = sockunion_su2str (su, MTYPE_BGP_PEER_HOST) ;
  peer->args.remote_as  = remote_as;
  peer->args.local_id   = bgp->router_id;

  qassert(peer->sort            == BGP_PEER_UNSPECIFIED) ;
  qassert(peer->args.remote_as  != BGP_ASN_NULL) ;
  qassert(peer->args.local_as   == BGP_ASN_NULL) ;
  qassert(peer->change_local_as == BGP_ASN_NULL) ;

  sockunion_copy (&peer->cops.su_remote, peer->su_name) ;

  peer_sort_set(peer, peer_sort(peer)) ;
  peer_global_config_reset (peer) ;

  sp = getservbyname ("bgp", "tcp");
  peer->cops.port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);

  /* Last read time and reset time set
   */
  peer->readtime = peer->resettime = bgp_clock ();

  /* Set up session and register the peer.
   */
  bgp_session_init_new(peer);

  /* If required, activate given AFI/SAFI -- eg "default ipv4-unicast"
   */
  if (qafx != qafx_undef)
    peer_set_af(peer, qafx, true /* enable */) ;

  return peer;
} ;

/*------------------------------------------------------------------------------
 * Delete peer from configuration.
 *
 * To delete a peer we must first shutdown any current session, .... XXX XXX XXX XXX
 *
 *
 *
 * At the end of the process this releases the initial, self-reference counted
 * in bgp_peer_new().  That may free the peer structure (which will remove
 * the peer's reference to the bgp instance, which may in turn free that).
 *
 * However, there may be other locks on the peer structure, in which case the
 * peer has been set to a dead-end "Deleted" neighbour-state, to allow it to
 * "cool off".  When the refcount hits 0, the peer will be freed -- noting that
 * the owning bgp instance remains in existence (at least) until then.
 *
 * TODO ... sort out PEER_TYPE_xxx differences.
 *
 * Returns:  NULL
 */
extern bgp_peer
bgp_peer_delete (bgp_peer peer)
{
  qafx_t   qafx ;
  bgp_inst bgp;

  bgp = peer->parent_bgp ;

  /* Once peer is pDeleting it should be impossible to find in order to
   * bgp_peer_delete() it !
   */
  assert (peer->state != bgp_pDeleting);

  if (peer->ptype == PEER_TYPE_REAL)
    {
      /* If the peer is active, then need to shut it down now.  If there are
       * any stale routes, flush them now.
       *
       * There may be a session in existence.  If so, it must either be
       * sLimping or sDisabled.
       *
       * Changing to pDeleting state turns off all timers.
       */
      bgp_peer_down(peer, PEER_DOWN_NEIGHBOR_DELETE) ;
      qassert(peer->state == bgp_pDown) ;

      bgp_peer_change_status (peer, bgp_pDeleting);

      /* Increment count of peers lingering in pDeleting
       *
       * The count is used while terminating bgpd -- keeps all the nexuses
       * running until this count drops to zero.
       *
       * NB: counts all sorts of peer objects, including peer-group
       *     configurations.
       *
       *     This is counted down again in bgp_peer_free().
       */
      ++bm->peer_linger_count ;

      /* If this peer belongs to peer group, clear up the relationship.
       */
      if (peer->group != NULL)
        {
          ddl_del(peer->group->members, peer->c, member.list) ;
          peer->group = NULL;
        } ;
    } ;


  /* Delete from bgp->peer list, if required.
   */
  if (peer->ptype == PEER_TYPE_REAL)
    {
      struct listnode *pn;
      pn = listnode_lookup (bgp->peer, peer) ;

      assert(pn != NULL) ;

      bgp_peer_unlock (peer);   /* bgp peer list reference      */
      list_delete_node (bgp->peer, pn);
    } ;

  /* Shut down and release all pribs.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    peer_deactivate_family (peer, qafx) ;

  /* Unregister the peer and tear down the session.
   *
   * NB: the peer can no longer be looked up by its 'name'.
   *
   *     In particular this means that the accept() logic in the BGP Engine
   *     will conclude that the session should not be accepting connections.
   *
   * NB: also (currently) releases the peer_id -- which may not be so clever ?
   */
  bgp_session_delete(peer) ;

  /* Finally: count down the initial reference, which will delete the peer
   * iff everything else has finished with it.
   */
  bgp_peer_unlock (peer);       /* initial, self reference      */

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * increase reference count on a bgp_peer
 */
extern bgp_peer
bgp_peer_lock (bgp_peer peer)
{
  ++peer->lock ;
  return peer;
}

/*------------------------------------------------------------------------------
 * decrease reference count on a bgp_peer * If is last reference, the structure is freed and NULL returned
 */
extern bgp_peer
bgp_peer_unlock (bgp_peer peer)
{
  qassert(peer->lock > 0);

  if (peer->lock > 1)
    {
      --peer->lock ;
      return NULL ;
    } ;

  return bgp_peer_free (peer);
} ;

/*------------------------------------------------------------------------------
 * Dismantle and free peer data structure.
 *
 * The peer structure has a reference to the owning bgp instance, and the
 * reference has a lock on that.  When the peer structure has been dismantled,
 * the lock is released.
 */
static bgp_peer
bgp_peer_free (bgp_peer peer)
{
  bgp_inst bgp ;

  assert (peer->state   == bgp_pDeleting);
  assert (peer->session == NULL) ;      /* session holds a lock on peer */

  if (peer->ptype == PEER_TYPE_REAL)
    --bm->peer_linger_count ;

  bgp = peer->parent_bgp ;

  if (peer->desc)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  /* Discard name and text form thereof
   */
  peer->su_name = sockunion_free(peer->su_name);

  if (peer->host != NULL)
    XFREE (MTYPE_BGP_PEER_HOST, peer->host) ;   /* sets peer->host NULL */


  // TODO full dismantle of bgp_peer structure etc....

  memset (peer, 0, sizeof(bgp_peer_t));
  peer->lock = -54321 ;
  XFREE (MTYPE_BGP_PEER, peer);

  bgp_unlock(bgp);

  return NULL ;
} ;



/*==============================================================================
 * Address Family activation and deactivation.
 *
  */

/*------------------------------------------------------------------------------
 * Configure the peer or peer group for specified AFI/SAFI.
 *
 * If given address family is not configured, configure to default state.
 *
 * Then for real peers:
 *
 *   * if 'enable' and the address family is not already enabled:
 *
 *   XXX XXX XXX
 *
 *   * if not 'enable' and the address family is not already disabled:
 *
 *   XXX XXX XXX
 */
extern bgp_ret_t
peer_set_af(bgp_peer peer, qafx_t qafx, bool enable)
{
  bgp_prib   prib ;
  qafx_bit_t qb ;

  qb = qafx_bit(qafx) ;

  prib = peer->prib[qafx] ;

  if (prib == NULL)
    {
      /* Create address family configuration.
       */
      qassert(!(peer->af_configured & qb)) ;

      prib = bgp_prib_new(peer, qafx) ;
      peer->af_configured |= qb ;
    } ;

  if ((qafx != qafx_ipv4_unicast) && !peer->args.can_capability
                                  && !peer->args.cap_af_override)
    enable = false ;

  if (peer->ptype == PEER_TYPE_REAL)
    {
      qafx_set_t af_was_enabled ;       /* old value    */

      af_was_enabled = peer->args.can_af ;

      if (enable)
        {
          prib->af_status &= ~PEER_AFS_DISABLED ;
          peer->args.can_af = af_was_enabled |  qb ;
        }
      else
        {
          prib->af_status |=  PEER_AFS_DISABLED ;
          peer->args.can_af = af_was_enabled & ~qb ;
        } ;

      if (peer->args.can_af != af_was_enabled)
        {
          /* The enabled state of one or more address families has changed.
           *
           * Update the peer->idle state.
           */
          qassert((af_was_enabled == qafx_empty_set)
                                                == (peer->idle & bgp_pisNoAF)) ;

          if    (af_was_enabled == qafx_empty_set)
            {
              /* We had nothing, and now we have something !
               */
              peer->idle &= ~bgp_pisNoAF ;
            }
          else if (peer->args.can_af == qafx_empty_set)
            {
              /* We had something, and now we have nothing.
               */
              peer->idle &= ~bgp_pisNoAF ;
            } ;

          /* For address families which have been disabled, we withdraw all
           * routes and discard the adj-out.
           *
           * For address families which have been enabled:
           */
          switch (peer->state)
            {
              case bgp_pDown:
                if (peer->idle == bgp_pisRunnable)
                  bgp_peer_start_running(peer) ;
                break ;

              case bgp_pStarted:
              case bgp_pEstablished:
                bgp_peer_restart(peer, PEER_DOWN_AF_ACTIVATE) ;
                break ;

              case bgp_pResetting:
              case bgp_pDeleting:
                break ;

              default:
                qassert(false) ;
                break ;
            } ;
        } ;
    }
  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Deactivate the peer or peer group for specified AFI and SAFI.
 */
extern bgp_ret_t
peer_deactivate (bgp_peer peer, qafx_t qafx)
{
  bgp_prib  prib ;
  qafx_bit_t qb ;

  qb = qafx_bit(qafx) ;

  if (peer->ptype != PEER_TYPE_GROUP)
    {
      if (peer->c_af_member & qb)
        return BGP_ERR_PEER_BELONGS_TO_GROUP;
    }
  else
    {
      bgp_peer member ;

      for (member = ddl_head(peer->group->members) ;
           member != NULL ;
           member = ddl_next(member->c, member.list))
        {
          if (member->c_af_member & qb)
            return BGP_ERR_PEER_GROUP_MEMBER_EXISTS;
        } ;
    } ;

  /* If we arrive here, the peer is either:
   *
   *   - a real peer which is not a group member for this afi/safi
   *
   *   - a group which has no members in this afi/safi
   *
   * De-activate the address family configuration.
   */
  peer_deactivate_family (peer, qafx);

  /* Deal with knock on effect on real peer
   */
  if (peer->ptype == PEER_TYPE_REAL)
    {
      bool down = true ;

      if (down)
        bgp_peer_down(peer, PEER_DOWN_AF_DEACTIVATE) ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Activate the given address family for the given peer.
 *
 * Dismantles all address-family specific configuration....
 */
static void
peer_activate_family (bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
  int i;
  bgp_orf_name orf_name ;

  prib = peer->prib[qafx] ;
  if (prib != NULL)
    return ;

  peer->prib[qafx] = prib = bgp_prib_new(peer, qafx) ;

  /* Set default neighbor send-community.
   */
  if (! bgp_option_check (BGP_OPT_CONFIG_CISCO))
    peer->c->c_af[qafx]->c_flags |= (PEER_AFF_SEND_COMMUNITY |
                                          PEER_AFF_SEND_EXT_COMMUNITY) ;

  /* Set defaults for neighbor maximum-prefix -- unset
   */
  bgp_prib_pmax_reset(prib) ;
} ;

/*------------------------------------------------------------------------------
 * Deactivate the given address family for the given peer.
 *
 * Dismantles all address-family specific configuration, which means that
 * dismantles the peer_rib for the address family.
 */
static void
peer_deactivate_family (bgp_prun prun, qafx_t qafx)
{
  bgp_prib prib ;
  int i;

  prib = prun->prib[qafx] ;
  if (prib == NULL)
    return ;

  /* Clear neighbor filter, route-map and unsuppress map
   */
  for (i = FILTER_IN; i < FILTER_MAX; i++)
    {
      prib->dlist[i] = access_list_clear_ref(prib->dlist[i]) ;
      prib->plist[i] = prefix_list_clear_ref(prib->plist[i]) ;
      prib->flist[i] = as_list_clear_ref(prib->flist[i]) ;
    } ;

  for (i = RMAP_IN; i < RMAP_COUNT; i++)
    prib->rmap[i] = route_map_clear_ref(prib->rmap[i]) ;

  prib->us_rmap      = route_map_clear_ref(prib->us_rmap) ;
  prib->default_rmap = route_map_clear_ref(prib->default_rmap) ;

  /* Clear all neighbor's address family c_flags.
   */
  prun->c->c_af[qafx]->c_flags = 0 ;
  prib->af_status               = 0 ;

  /* Clear ORF info
   */
  prib->orf_plist = prefix_bgp_orf_delete(prib->orf_plist) ;

  /* Can now free the peer_rib structure.
   */
  prun->prib[qafx] = bgp_prib_free(prib) ;
} ;

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
static void peer_sort_init_local_as(bgp_peer peer, bgp_peer_sort_t sort) ;
static void peer_sort_init_ttl_gtsm(bgp_peer peer, bgp_peer_sort_t sort) ;

/*------------------------------------------------------------------------------
 * Set the given peer->sort and set/update things which depend on that:
 *
 *   * peer->args.local_as  -- set to bgp->my_as, except...
 *                             ...if eBGP and CONFED is enabled, when must be
 *                                bgp->confed_id, except...
 *                             ...if eBGP and change_local_as is enabled, when
 *                                must be peer->change_local_as
 *
 *   * peer->config->mrai    -- if the sort changes, then we discard any
 *                             explicit MRAI, reverting to the default.
 *
 *   * peer->cops.ttl and   -- if the sort changes, then we set the default
 *     peer->cops.gtsm         values for the new sort.
 *
 *   * route reflector client -- if the new sort is not IBGP, then must clear
 *                               all Route Reflector Client bits.
 *
 * Returns: true <=> any of the above have changed.
 */
extern bool
peer_sort_set(bgp_peer peer, bgp_peer_sort_t sort)
{
  bgp_peer_sort_t old_sort ;
  as_t  old_local_as ;
  bool  changed ;

  qassert(sort != BGP_PEER_UNSPECIFIED) ;

  old_sort   = peer->sort ;
  peer->sort = sort ;
  changed = (old_sort != peer->sort) ;

  /* Update peer->args.local_as as required
   */
  old_local_as = peer->args.local_as ;

  peer_sort_init_local_as(peer, peer->sort) ;
  if (old_local_as != peer->args.local_as)
    changed = true ;

  /* If the sort has changed, set default MRAI  TODO really ??
   */
  if (old_sort != peer->sort)
    {
      peer->c->c_set  &= ~PEER_CONFIG_MRAI ;
      peer->c->c_mrai  = 0 ;         /* for completeness     */
    } ;

  /* TTL reset, depending on the old and new sorts as shown:
   *
   *     -------|----------- new -----------|
   *     old    |   iBGP  |  eBGP  | Confed |
   *     -------|---------|--------|--------|
   *       iBGP |   stet  |  eBGP  |  eBGP  | -- sans GTSM
   *     -------|---------|--------|--------|
   *       eBGP |   iBGP  |  stet  |  stet  |
   *     -------|---------|--------|--------|
   *     Confed |   iBGP  |  stet  |  stet  |
   *     -------|---------|--------|--------|
   */
  if (old_sort != peer->sort)
    {
      ttl_t old_ttl ;
      bool  old_gtsm ;

      old_ttl  = peer->cops.ttl ;
      old_gtsm = peer->cops.gtsm ;

      peer_sort_init_ttl_gtsm(peer, peer->sort) ;

      if ( (old_ttl  != peer->cops.ttl) ||
           (old_gtsm != peer->cops.gtsm) )
        changed = true ;
    } ;

  /* If is not now IBGP, then cannot be Route Reflector Client.
   */
  if (peer->sort != BGP_PEER_IBGP)
    {
      qafx_t qafx ;

      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          bgp_prib prib ;

          prib = peer->prib[qafx] ;
          if (prib == NULL)
            continue ;

          if (prib->route_reflector_client)
            {
              prib->route_reflector_client = false ;
              changed = true ;
            } ;
        } ;
    } ;

  return changed ;
} ;

/*------------------------------------------------------------------------------
 * Peer global config reset, after unbinding from group and at creation.
 *
 * Requires the peer->sort to have been established, already.
 */
static void
peer_global_config_reset (bgp_peer peer)
{
  qassert(peer->ptype == PEER_TYPE_REAL) ;

  peer_sort_init_local_as(peer, peer->sort) ;
  peer_sort_init_ttl_gtsm(peer, peer->sort) ;

  peer->change_local_as         = BGP_ASN_NULL ;
  peer->change_local_as_prepend = false ;

  sockunion_clear(&peer->cops.su_local) ;
  memset(peer->cops.ifname, 0, IF_NAMESIZE) ;
  confirm(sizeof(peer->cops.ifname) == IF_NAMESIZE) ;

  peer->c->c_flags    = PEER_FLAG_NOTHING ;
  peer->c->c_set     &= ~PEER_CONFIG_GROUP_OVERRIDE ;

  peer->c->c_weight = 0 ;
  peer->c->c_mrai   = 0 ;

  peer->args.holdtime_secs  = peer->parent_bgp->default_holdtime ;
  peer->args.keepalive_secs = peer->parent_bgp->default_keepalive ;

  peer->cops.idle_hold_max_secs  = peer->parent_bgp->default_idle_hold_max_secs ;
  peer->cops.connect_retry_secs  = peer->parent_bgp->default_connect_retry_secs ;
  peer->cops.accept_retry_secs   = peer->parent_bgp->default_accept_retry_secs ;
  peer->cops.open_hold_secs      = peer->parent_bgp->default_open_hold_secs ;
} ;

/*------------------------------------------------------------------------------
 * Set the peer->args.local_as given the sort, peer->bgp
 *                                                    and peer->change_local_as
 *
 * Sets according to the given sort:
 *
 *   * BGP_PEER_IBGP:  peer->bgp->my_as
 *
 *   * BGP_PEER_CBGP:  peer->bgp->my_as
 *
 *   * BGP_PEER_EBGP:  peer->change_local_as, if that is set
 *          otherwise: peer->bgp->ebgp_as
 *
 * NB: where peer->change_local_as == peer->bgp->ebgp_as, the change_local_as
 *     action is suppressed, but that does not affect the setting of local_as.
 */
static void
peer_sort_init_local_as(bgp_peer peer, bgp_peer_sort_t sort)
{
  if      (sort != BGP_PEER_EBGP)
    peer->args.local_as = peer->parent_bgp->c->c_my_as ;
  else if (peer->change_local_as != BGP_ASN_NULL)
    peer->args.local_as = peer->change_local_as ;
  else
    peer->args.local_as = peer->parent_bgp->ebgp_as ;
} ;

/*------------------------------------------------------------------------------
 * Init the given peer->ttl according to the given sort of peer,
 *                                                         and clear peer->gtsm.
 */
static void
peer_sort_init_ttl_gtsm(bgp_peer peer, bgp_peer_sort_t sort)
{
  if (sort == BGP_PEER_IBGP)
    {
      peer->cops.ttl  = MAXTTL ;
      peer->cops.gtsm = false ;
    }
  else
    {
      if (peer->group == NULL)
        {
          peer->cops.ttl  = 1;
          peer->cops.gtsm = false ;
        }
      else
        {
          peer->cops.ttl  = peer->group->conf->cops.ttl ;
          peer->cops.gtsm = peer->group->conf->cops.gtsm ;
        }
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set the given peer's 'remote-as' -- ie peer->args.remote_as
 *
 * Updates peer->sort etc. as required -- see peer_sort_set().
 *
 * Returns:  true <=> peer->args.remote_as or anything else changes.
 */
static bool
peer_as_set(bgp_peer peer, as_t asn)
{
  bgp_peer_sort_t sort ;
  as_t            old_asn ;

  old_asn = peer->args.remote_as ;
  peer->args.remote_as = asn ;

  if      (peer->args.remote_as == peer->parent_bgp->c->c_my_as)
    sort = BGP_PEER_IBGP ;
  else if (bgp_confederation_peers_check (peer->parent_bgp, peer->args.remote_as))
    sort = BGP_PEER_CBGP ;
  else
    sort = BGP_PEER_EBGP ;

  return peer_sort_set(peer, sort) || (old_asn != peer->args.remote_as) ;
} ;

/*------------------------------------------------------------------------------
 * Change peer's AS number.
 *
 * This is pretty dramatic...
 */
static void
peer_as_change (bgp_peer peer, as_t asn)
{
  bool change ;

  change = peer_as_set(peer, asn) ;

  if (change && (peer->ptype == PEER_TYPE_REAL))
    bgp_peer_down(peer, PEER_DOWN_REMOTE_AS_CHANGE) ;
} ;

/*------------------------------------------------------------------------------
 * If peer does not exist, create new one.
 *
 * If peer already exists, set AS number to the peer.  If the
 */
extern bgp_ret_t
peer_remote_as (bgp_inst bgp, sockunion su, as_t* p_as, qafx_t qafx)
{
  bgp_peer peer;

  peer = bgp_peer_lookup_su (bgp, su);

  if (peer != NULL)
    {
      /* The peer already exists.
       *
       * If is a member of a group, then:
       *
       *   1) if the group has a 'remote-as', then we cannot change the
       *      'remote-as' for the peer -- so we return the group's 'remote-as'
       *       and an error.
       *
       *   2) if the group is iBGP, then ....
       */
      if (peer->group != NULL)
        {
          if (peer->group->conf->args.remote_as != BGP_ASN_NULL)
            {
              /* Return peer group's AS number.
               */
              *p_as = peer->group->conf->args.remote_as;
              return BGP_ERR_PEER_GROUP_MEMBER;
            } ;

          if (peer_sort(peer->group->conf) == BGP_PEER_IBGP)
            {
              if (*p_as != bgp->c->c_my_as)
                {
                  *p_as = peer->args.remote_as;
                  return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
          else
            {
              if (*p_as == bgp->c->c_my_as)
                {
                  *p_as = peer->args.remote_as;
                  return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
        }

      /* Existing peer's AS number change.
       */
      if (*p_as != peer->args.remote_as)
        peer_as_change (peer, *p_as);
    }
  else
    {
      /* Check that the neighbor IP is unique
       */
      if (bgp_peer_lookup_su (NULL, su) != NULL)
        return BGP_ERR_PEER_EXISTS ;

      /* Create and auto-enable if IPv4/Unicast, unless BGP_FLAG_NO_DEFAULT_IPV4
       */
      if ((qafx == qafx_ipv4_unicast) &&
                                !bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4))
        peer = bgp_peer_create (su, bgp, *p_as, qafx);
      else
        peer = bgp_peer_create (su, bgp, *p_as, qafx_undef);
    }

  return BGP_SUCCESS ;
}

#endif

/*==============================================================================
 * For the given interface name, get a suitable address so can bind() before
 * connect() so that we use the required interface.
 *
 * If has a choice, uses address that best matches the peer's address.
 */
extern sockunion
bgp_peer_get_ifaddress(bgp_prun peer, const char* ifname, sa_family_t af)
{
#if 0
  struct interface* ifp ;
  struct connected* connected;
  struct listnode*  node;
  prefix   best_prefix ;
  prefix_t peer_prefix[1] ;
  int   best, this ;

  if (peer->cops.ifname[0] == '\0')
    return NULL ;

  ifp = if_lookup_by_name (peer->cops.ifname) ;
  if (ifp == NULL)
    {
      zlog_err("Peer %s interface %s is not known", peer->host, ifname) ;
      return NULL ;
    } ;

  prefix_from_sockunion(peer_prefix, peer->su_name) ;
  best_prefix = NULL ;
  best = -1 ;

  for (ALL_LIST_ELEMENTS_RO (ifp->connected, node, connected))
    {
      if (connected->address->family != af)
        continue ;

      this = prefix_common_bits (connected->address, peer_prefix) ;
      if (this > best)
        {
          best_prefix = connected->address ;
          best = this ;
        } ;
    } ;

  if (best_prefix != NULL)
    return sockunion_new_prefix(NULL, best_prefix) ;

  zlog_err("Peer %s interface %s has no suitable address", peer->host, ifname);
#endif

  return NULL ;
} ;

#if 0

/*------------------------------------------------------------------------------
 * Set the given Peer to be a Route-Server-Client, or the given Group to
 * be a group of same.
 */
static bgp_lcontext
peer_rsclient_set(struct vty *vty, bgp_peer peer)
{

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set the given Peer to be a Route-Server-Client, or the given Group to
 * be a group of same.
 */
static cmd_ret_t
peer_rsclient_set_vty (struct vty *vty, const char *peer_str, qafx_t qafx)
{
  int ret;
  bgp_inst bgp;
  bgp_peer peer;
  bgp_lcontext lc ;
  bgp_rcontext rc ;
  bool         added ;

  bgp_peer_group group;
  struct listnode *node, *nnode;
  struct bgp_filter *pfilter;
  struct bgp_filter *gfilter;

  if ((qafx < qafx_first) || (qafx > qafx_last))
    {
      vty_out (vty, "%% unknown qafx %u -- BUG", qafx) ;
      return CMD_WARNING ;
    } ;

  /* Lookup the Peer or Group -- issues message if not found.
   */
  peer = bgp_peer_or_group_lookup_vty (vty, peer_str);
  if (peer == NULL)
    return CMD_WARNING;

  /* If it is already a RS-Client, don't do anything, otherwise set state.
   */
  if (peer->c->afc[qafx]->flags & PEER_AFF_RSERVER_CLIENT)
    return CMD_SUCCESS;

  ret = peer_af_flag_modify(peer, qafx, pafcs_RSERVER_CLIENT, true /* set */);
  if (ret < 0)
    return bgp_vty_return (vty, ret);

  /* The group or the peer is not already an RS-Client in this qafx, but
   * may be in another.
   */
  rc = bgp_rcontext_lookup(peer->parent_bgp, peer->name, rc_is_rs_client, &added) ;

  /* Worry about the local-context for this client or group there-of
   */



#if 0
  /* Check for existing 'network' and 'redistribute' routes.
   */
  bgp_check_local_routes_rsclient (peer, qafx);
#endif

  /* Check for routes for peers configured with 'soft-reconfiguration'.
   */
  bgp_soft_reconfig_rsclient_in (peer, qafx);

  if (peer->ptype == PEER_TYPE_GROUP)
    {
#if 0
      group   = peer->group;
      gfilter = &group->conf->filter[qafx];

      for (ALL_LIST_ELEMENTS (group->members, node, nnode, peer))
        {
          pfilter = &peer->filter[qafx];

          /* Members of a non-RS-Client group should not be RS-Clients, as that
           * is checked when the become part of the peer-group
           */
          ret = peer_af_flag_modify (peer, qafx, PEER_AFF_RSERVER_CLIENT, true);
          if (ret < 0)
            return bgp_vty_return (vty, ret);

          /* Make peer's RIB point to group's RIB.
           */
          peer->prib[qafx] = group->conf->prib[qafx];

          /* Import policy.
           */
          route_map_clear_ref(pprib->filter.rmap[RMAP_IMPORT]) ;
          pprib->filter.rmap[RMAP_IMPORT]
                          = route_map_set_ref(gprib->filter.rmap[RMAP_IMPORT]) ;

          /* Export policy.
           */
          if (pprib->filter.rmap[RMAP_EXPORT] == NULL)
            pprib->filter.rmap[RMAP_EXPORT]
                               = route_map_set_ref(gprib->filter.rmap[RMAP_EXPORT]) ;
        }
#endif
    }
  return CMD_SUCCESS;
}

static cmd_ret_t
peer_rsclient_unset_vty (struct vty *vty, const char *peer_str,
                         qAFI_t q_afi, qSAFI_t q_safi)
{
  int ret;
  bgp_inst bgp;
  bgp_peer peer;
  bgp_peer_group group;
  struct listnode *node, *nnode;
  qafx_t qafx ;

  qafx = qafx_from_q(q_afi, q_safi) ;

  bgp = vty->index;

  peer = bgp_peer_or_group_lookup_vty (vty, peer_str);
  if ( ! peer )
    return CMD_WARNING;

  assert(bgp == peer->parent_bgp) ;

  /* If it is not a RS-Client, don't do anything. */
  if ( ! true)
    return CMD_SUCCESS;

  /* If this is a Peer Group, then need to undo the relevant rsclient state
   * for all the group members.
   *
   * That means clearing the state flag and the pointer to the shared RIB.
   *
   * TODO: peer_af_flag_modify PEER_AFF_RSERVER_CLIENT fails for group members ?
   */
  if (peer->ptype == PEER_TYPE_GROUP)
    {
#if 0
      group = peer->group;

      for (ALL_LIST_ELEMENTS (group->members, node, nnode, peer))
        {
          ret = peer_af_flag_modify (peer, qafx, PEER_AFF_RSERVER_CLIENT, false);
          if (ret < 0)
            return bgp_vty_return (vty, ret);

          peer->prib[qafx] = NULL;
        }

        peer = group->conf;
#endif
    }

  /* Unset the rsclient flag and remove from rsclient list if no longer a
   * distinct rsclient.
   *
   * NB: this takes care of downing the peer, if required.
   */
  ret = peer_af_flag_modify (peer, qafx, pafcs_RSERVER_CLIENT,
                                                             false /* unset */);
  if (ret < 0)
    return bgp_vty_return (vty, ret);

  /* Now tidy up the data structures.                                   */
  peer_rsclient_unset(peer, qafx, false) ;

  return CMD_SUCCESS;
}
#endif
