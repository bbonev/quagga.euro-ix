/* BGP Peer Run Handling
 * Copyright (C) 1996, 97, 98 Kunihiro Ishiguro
 *
 * Recast for pthreaded bgpd: Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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
#include <misc.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_rib.h"
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

/*==============================================================================
 * This is the high level management of BGP Peers and peering conversations.
 *
 * The BGP Engine looks after the opening, running and closing of BGP sessions.
 *
 * Here we look after...
 *
 *   * the peer state and the effects of changes in that state
 *
 *   * timers for advertisements, graceful restart, ...
 *
 * The naming of peers/sessions and bgp_session_index
 * --------------------------------------------------
 *
 * Each peer/session is known by its IP address (IPv4 or IPv6) -- see the
 * "neighbor" commands.
 *
 * No matter how many bgp instances there may be, only one peer/session can
 * exist with a given IP address.
 *
 * The bgp_peer_index maps IP addresses to the peer, and hence to the session
 * (if any exists and is active).
 *
 * [To support multi-instance BGP, might be nice to use the "update source"
 *  address as part of the name of a peer.  But that is another story.]
 *
 */

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Create a new, empty bgp_prun object.
 */
extern bgp_prun
bgp_prun_new(void)
{
  bgp_prun  prun ;

  prun = XCALLOC(MTYPE_BGP_PEER, sizeof(bgp_prun_t)) ;

  /*
   *
   */




  return prun ;
} ;




/*------------------------------------------------------------------------------
 * Allocate new peer object -- for peer or peer-group
 *
 * Attaches to the
 *
 * Adds structure to the
 *
 * Returns:  address of new peer object.
 *
 * NB: the peer object owns a lock on itself.
 *
 *     That lock is cleared by bgp_peer_delete().
 */
extern bgp_peer
bgp_peer_new(bgp_inst bgp, bgp_peer_type_t type, chs_c name)
{
  bgp_peer peer;

  /* bgp argument is absolutely required
   */
  assert (bgp != NULL) ;

  /* Allocate new peer: point it at owning bgp instance and take a lock on that.
   *
   * All types of peer have a bgp parent.
   */
  peer = XCALLOC (MTYPE_BGP_PEER, sizeof(bgp_peer_t));

  peer->parent_bgp  = bgp_lock (bgp) ;
  peer->ptype = type ;

  /* Zeroizing has set:
   *
   *   * bgp                    -- X            -- set, above
   *   * type                   -- X            -- set, above
   *
   *   * state                  -- bgp_pInitial
   *   * config                 -- X            -- set, below
   *
   *   * peer_ie                -- NULL         -- none, yet
   *   * session                -- NULL         -- none, yet
   *
   *   * session_state          -- bgp_pssInitial
   *
   *   * lock                   -- 0
   *
   *   * group                  -- NULL         -- none, yet
   *   * member.list/.base      -- NULLs        -- none, yet
   *
   *   * sort                   -- BGP_PEER_UNSPECIFIED
   *   * down_pending           -- false        -- not at present
   *
   *   * su_name                -- NULL         -- none, yet
   *   * host                   -- NULL         -- none, yet
   *   * desc                   -- NULL         -- none, yet
   *
   *   * uptime;                -- 0
   *   * readtime;              -- 0
   *   * resettime;             -- 0
   *
   *   * log                    -- NULL         -- none, yet
   *
   *   * shared_network         -- false        -- not
   *   * nexthop                -- 0's          -- none, yet
   *
   *   * last_reset             -- PEER_DOWN_NULL
   *   * note                   -- NULL         -- none, yet
   *
   *   * af_configured          -- qafx_empty_set  -- none, yet
   *   * af_running             -- qafx_empty_set  -- none, yet
   *
   *   * prib[]                 -- NULLs        -- none, yet
   *   * prib_running_count     -- 0            -- none, yet
   *   * prib_running[]         -- NULLs        -- none, yet
   *
   *   * rr_pending             -- NULLs        -- none, yet
   *
   *   * args                   -- X            -- initialised below
   *
   *   * change_local_as        -- BGP_ASN_NULL -- none, yet
   *   * change_local_as_prepend  -- false
   *
   *   * disable_connected_check  -- false
   *
   *   * weight                 -- 0            -- not set
   *   * config_mrai            -- 0            -- unset
   *
   *   * sflags                 -- PEER_STATUS_NONE
   *   * idle                   -- X            -- set, below
   *
   *   * cops                   -- X            -- initialised, below
   *
   *   * qt_restart             -- NULL         -- none, yet
   *
   *   * idle_hold_time         -- X            -- set, below
   *
   *   * v_asorig               -- X            -- set, below
   *   * v_gr_restart           -- 0
   *
   *   * t_gr_restart           -- NULL         -- none, yet
   *   * t_gr_stale             -- NULL         -- none, yet
   *
   *   * established            -- 0
   *   * dropped                -- 0
   *
   *   * table_dump_index       -- 0
   */
  confirm(qafx_empty_set       == 0) ;
  confirm(bgp_pInitial         == 0) ;
  confirm(bgp_pssInitial       == 0) ;
  confirm(BGP_PEER_UNSPECIFIED == 0) ;
  confirm(PEER_DOWN_NULL       == 0) ;
  confirm(PEER_STATUS_NONE     == 0) ;

  peer->c = bgp_peer_config_new() ;

  bgp_session_args_init_new(&peer->args) ;

  peer->idle = bgp_pisDeconfigured ;    /* so far       */

  bgp_cops_init_new(&peer->cops) ;

  /* Set some default values -- common to all types of peer object
   */
  peer->idle_hold_time = QTIME(peer->parent_bgp->default_idle_hold_min_secs) ;

  peer->v_asorig  = BGP_DEFAULT_ASORIGINATE;

  return bgp_peer_lock (peer) ;         /* initial, self reference      */
} ;

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
 * Creation and destruction of peer_rib structures.
 */

/*------------------------------------------------------------------------------
 * Create new, empty peer_rib structure.
 *
 * Requires that there is currently no peer_rib for the given qafx.  (Will leak
 * memory if there is, and the peer_rib will simply be cast loose.)
 *
 * Creates a completely empty 'rib_main' peer_rib.
 *
 * If there is no 'rib_main' bgp_rib, creates an empty one.
 *
 * Returns:  address of the new peer_rib
 */
extern bgp_prib
bgp_prib_new(bgp_prun prun, qafx_t qafx)
{
  bgp_prib prib ;

  qassert(prun->prib[qafx] == NULL) ;

  prib = XCALLOC(MTYPE_BGP_PEER_RIB, sizeof(bgp_prib_t)) ;

  /* Zeroising has set:
   *
   *   * prun                   -- X            -- set below
   *
   *   * rib                    -- NULL         -- none, yet
   *   * prib_list              -- NULLs        -- none, yet
   *
   *   * lc_id                  -- lc_id_null   -- none, yet
   *   * lc_list                -- NULLs        -- none, yet
   *
   *   * walker                 -- NULL         -- none yet
   *   * walk_list              -- NULLs        -- none, yet
   *
   *   * refresh                -- false        -- not, yet
   *   * eor_required           -- false        -- not, yet
   *
   *   * qafx                   -- X            -- set below
   *   * i_afi                  -- X            -- set below
   *   * i_safi                 -- X            -- set below
   *   * is_mpls                -- X            -- set below
   *
   *   * real_rib               -- false
   *   * session_up             -- false        -- not, yet
   *
   *   * soft_reconfig          -- false        )
   *   * route_server_client    -- false        )  empty initial config
   *   * route_reflector_client -- false        )
   *   * send_community         -- false        )
   *   * send_ecommunity        -- false        )
   *   * next_hop_self          -- false        )
   *   * next_hop_unchanged     -- false        )
   *   * next_hop_local_unchanged  -- false     )
   *   * as_path_unchanged      -- false        )
   *   * remove_private_as      -- false        )
   *
   *   * med_unchanged          -- false        )
   *   * default_originate      -- false        )
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
   *   * nsf_mode               -- false        )  empty initial state
   *   * default_sent           -- false        )
   *   * eor_sent               -- false        )
   *   * eor_received           -- false        )
   *   * max_prefix_threshold   -- false        )
   *   * max_prefix_limit       -- false        )
   *   * gr_can_preserve        -- false        )
   *   * gr_has_preserved       -- false        )
   *   * orf_pfx_can_send       -- false        )
   *   * orf_pfx_sent           -- false        )
   *   * orf_pfx_may_recv       -- false        )
   *   * orf_pfx_wait           -- 0            )
   *   * pcount_recv            -- 0            )
   *   * pcount_in              -- 0            )
   *   * pcount_sent            -- 0            )
   *
   *   The following are set up by bgp_adj_in_init().
   *
   *   * adj_in                 -- NULL         -- none, yet
   *   * stale_routes           -- NULLs        -- none, yet
   *   * pending_routes         -- NULLs        -- none, yet
   *   * in_state               -- ai_next
   *   * in_attrs               -- NULL         -- none, yet
   *
   *   The following are set up by bgp_adj_out_init()
   *
   *   * adj_out                -- ihash_table
   *   * batch_delay            -- 0
   *   * batch_delay_extra      -- 0
   *   * announce_delay         -- 0
   *   * mrai_delay             -- 0
   *   * mrai_delay_left        -- 0
   *   * period_origin          -- 0
   *   * now                    -- 0
   *   * t0                     -- 0
   *   * tx                     -- 0
   *
   *   * fifo_batch             -- NULL
   *   * fifo_mrai              -- NULL
   *   * announce_queue         -- NULL
   *   * withdraw_queue         -- NULLs
   *   * attr_flux_hash         -- NULL
   *   * eor                    -- 0's
   *   * dispatch_delay         -- 0
   *   * dispatch_time          -- 0
   *   * dispatch_qtr           -- NULL
   */
  confirm(ai_next == 0) ;

  prib->prun    = prun ;
  prib->qafx    = qafx ;
  prib->i_afi   = get_iAFI(qafx) ;
  prib->i_safi  = get_iSAFI(qafx) ;

  prib->is_mpls = qafx_is_mpls_vpn(qafx) ;

  bgp_prib_pmax_reset(prib) ;

#if 0
  /* Now worry about the bgp->rib.
   *
   * The peer_rib is automatically associated with the Main bgp_rib.  If there
   * is no such rib, then we create an empty one here and now.
   *
   * If the peer is later set to be a Route-Server Client, then the peer_rib
   * will be associated with the RS bgp_rib (and that will be created, if
   * necessary).  Note that even if there are no Main RIB peers, there is
   * always a Main RIB.
   */
  rib =  prun->brun->rib[qafx] ;
  if (rib == NULL)
    rib = prun->brun->rib[qafx] = bgp_rib_new(prun->brun, qafx) ;
  prib->rib = rib ;

  rib->peer_count += 1 ;
#endif

  /* Set and return the new prib.
   */
  return prun->prib[qafx] = prib ;
} ;

/*------------------------------------------------------------------------------
 * Discard peer_rib structure.
 */
extern bgp_prib
bgp_prib_free(bgp_prib prib)
{


  XFREE(MTYPE_BGP_PEER_RIB, prib) ;
  return NULL ;
} ;


#if 0
/*------------------------------------------------------------------------------
 * If the given peer is not already an RS Client for the AFI/SAFI, set it to be
 *                                                                 an RS Client.
 *
 * Does nothing if is already a rib_rs peer.
 *
 * Creates a completely empty peer_rib, if one does not exist.  Creates as a
 * rib_main peer, associated with the rib_main bgp_rib (creating that, if
 * required).
 *
 * Creates a rib_rs bgp_rib if required.
 *
 * If was a rib_main peer, then discards any walker with which the peer was
 * associated.
 *
 * Returns:  address of the new peer_rib
 */
extern bgp_prib
peer_rib_set_rs(bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
  bgp_rib  rib ;

  prib = peer->prib[qafx] ;

  if (prib == NULL)
    prib = bgp_prib_new(peer, qafx) ;   /* creates rib_main bgp_rib if
                                         * required                     */
  else if (prib->rib_type == rib_rs)
    return prib ;

  /* We (now) have a prib, and it is rib_main.
   */
  rib = prib->rib ;                     /* the rib_main bgp_rib         */

  bgp_rib_walker_detach(prib) ;         /* stop if walking rib_main     */

  rib->peer_count -= 1 ;

  rib = peer->bgp->rib[qafx] ;
  if (rib == NULL)
    rib = peer->bgp->rib[qafx] = bgp_rib_new(peer->bgp, qafx) ;

  prib->rib = rib ;

  rib->peer_count += 1 ;

  return prib ;
} ;

/*------------------------------------------------------------------------------
 * If the given peer is an RS Client for the AFI/SAFI, unset that.
 *
 * Creates a completely empty peer_rib, if one does not exist.  Creates as a
 * rib_main peer, associated with the rib_main bgp_rib (creating that, if
 * required).
 *
 * Creates a rib_rs bgp_rib if required.
 *
 * Does nothing if is already a rib_rs peer.
 *
 * If was a rib_main peer, then discards any walker with which the peer was
 * associated.
 *
 * Returns:  address of the new peer_rib
 */
extern bgp_prib
peer_rib_unset_rs(bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
  bgp_rib  rib ;

  prib = peer->prib[qafx] ;

  if (prib == NULL)
    prib = bgp_prib_new(peer, qafx) ;   /* creates rib_main bgp_rib if
                                         * required                     */

  if (prib->rib_type == rib_main)
    return prib ;

  /* We (now) have a prib, and it is rib_rs.
   */
  rib = prib->rib ;                     /* the rib_rs bgp_rib           */
  qassert(rib->rib_type == rib_rs) ;

  bgp_rib_walker_detach(prib) ;         /* stop if walking rib_rs       */

  rib->peer_count -= 1 ;

  rib = peer->bgp->rib[qafx][rib_main] ;
  qassert(rib != NULL) ;

  prib->rib_type = rib_main ;
  prib->rib = rib ;

  rib->peer_count += 1 ;

  return prib ;
} ;

#endif












/*==============================================================================
 *
 */


static void bgp_peer_change_status (bgp_prun prun, bgp_peer_state_t new_state) ;
static void bgp_peer_restart_timer_cancel (bgp_prun prun) ;

static void bgp_peer_start_running(bgp_prun prun) ;
static void bgp_peer_set_idle(bgp_prun prun, bgp_peer_idle_state_t new_idle,
                                          bgp_note note, peer_down_t why_down) ;
static void bgp_peer_set_down(bgp_prun prun, bgp_peer_idle_state_t new_idle,
                                          bgp_note note, peer_down_t why_down) ;
static void bgp_peer_stop_running(bgp_prun prun, bgp_note note,
                                                         peer_down_t why_down) ;
static void bgp_peer_restart_timer_cancel (bgp_prun prun) ;
static void bgp_graceful_restart_timer_cancel (bgp_prun prun) ;
static void bgp_graceful_stale_timer_cancel (bgp_prun prun) ;
static bgp_note bgp_peer_map_peer_down(peer_down_t why_down) ;



























/*------------------------------------------------------------------------------
 * Something has changed such that the peer may start, if it can.
 *
 * This will do nothing at all if is: (a) not pDown
 *                                    (b) not pisRunnable
 */
extern void
bgp_peer_start(bgp_prun prun)
{
  if (prun->state != bgp_pDown)
    return ;

  bgp_peer_start_running(prun) ;
} ;

/*------------------------------------------------------------------------------
 * Something has changed such that the peer may restart, if it can.
 *
 *
 *
 */
extern void
bgp_peer_restart(bgp_prun prun, peer_down_t why_down)
{
  switch (prun->state)
    {
      /* pInitial or some state that we don't recognise, do nothing.
       */
      default:
        qassert(false) ;
        fall_through ;

      case bgp_pInitial:
        break ;

      /* pDown, so must not have been pisRunnable, so if we now are, we can
       * kick off session.
       */
      case bgp_pDown:
        if (prun->idle == bgp_pisRunnable)
          bgp_peer_start_running(prun) ;
        break ;

      /* pStarted, so:
       *
       *   * if we are not now runnable, signal a stop.
       *
       *   * if are (still) runnable, signal a possible change of configuration
       *     or arguments, which may or may not trigger a stop.
       */
      case bgp_pStarted:
        if (prun->idle != bgp_pisRunnable)
          bgp_peer_stop_running(prun, NULL, why_down) ;
        else
          {
            bgp_note note ;

            note = bgp_peer_map_peer_down(why_down) ;

            note = bgp_session_recharge(prun->session, note) ;
            bgp_note_free(note) ;                 // TODO ???
          } ;
        break ;

        /* pEnabled, so:
         *
         *   * if we are not now runnable, signal a stop.
         *
         *   * if are (still) runnable, we need to reset.
         */
        if (prun->idle != bgp_pisRunnable)
          bgp_peer_stop_running(prun, NULL, why_down) ;
        else
          bgp_peer_set_idle(prun, bgp_pisReset, NULL, why_down) ;
        break ;

      /* pResetting, so ????....
       *
       *
       */
      case bgp_pResetting:
        break ;

      /* pDeleting, so don't expect any change of runability, but it makes
       * no difference in any case.
        */
      case bgp_pDeleting:
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Something has changed in the cops, so (may) need to tell the session and
 *                                         its Acceptor, and may restart things.
 *
 *
 */
extern void
bgp_peer_cops_recharge(bgp_prun prun, peer_down_t why_down)
{
  ;
} ;

/*------------------------------------------------------------------------------
 * Start the given peer, provided is pisRunnable.
 *
 * Peer must be pDown or pResetting, and pssStopped.
 *
 * If is pisRunnable changes up to pStarted, and kicks off a session.  This is
 * the moment to make sure that the pribs for all af_
 */
static void
bgp_peer_start_running(bgp_prun prun)
{
  qassert((prun->state == bgp_pDown) || (prun->state == bgp_pResetting)) ;
  qassert(prun->session_state   == bgp_pssStopped) ;

  if (prun->idle == bgp_pisRunnable)
    {
      bgp_peer_change_status(prun, bgp_pStarted) ;
      bgp_session_start(prun->session);
    } ;
} ;

/*------------------------------------------------------------------------------
 * Something has happened to a pStarted/pEstablished peer, such that the
 * session must be reset.
 *
 * The new_idle for the connection may be *one* of:
 *
 *   * bgp_pisMaxPrefixWait -- max prefix limit biting -- temporary
 *
 *   * bgp_pisReset         -- general reset
 *
 * which will stop any running session (but not the acceptor).
 *
 * NB: if is pStarted then this unconditionally stops the current session.
 *
 *     The changing of connection options and/or session arguments may not
 *     always require a pStarted session to be completely stopped, or a
 *     pEstablished session to to be stopped.
 *
 *     So, this is for those cases where it is definitely known that anything
 *     pssRunning MUST stop -- eg. pisDown or pisMaxPrefixWait (the second
 *     only occurs in pEstablished).
 *
 * NB: takes responsibility for the notification.
 */
static void
bgp_peer_set_idle(bgp_prun prun, bgp_peer_idle_state_t new_idle,
                                            bgp_note note, peer_down_t why_down)
{
  qassert((prun->state          == bgp_pStarted) ||
          (prun->state          == bgp_pEstablished) );
  qassert(prun->session_state   == bgp_pssRunning) ;
  qassert(prun->idle            == bgp_pisRunnable) ;

  /* Check and set new level of idle-ness
   */
  switch (new_idle)
    {
      default:
        qassert(false) ;
        new_idle = bgp_pisReset ;
        fall_through ;

      case bgp_pisMaxPrefixWait:
      case bgp_pisReset:
        break ;
    } ;

  prun->idle |= new_idle ;

  bgp_peer_stop_running(prun, note, why_down) ;
} ;

/*------------------------------------------------------------------------------
 * Something has changed such that the peer is now down, if was not before.
 *
 * The new_idle for the connection may be *one* of:
 *
 *   * bgp_pisDeconfigured  -- for deleting a peer
 *
 *   * bgp_pisShutdown      -- for 'neighbor shutdown'
 *
 *   * bgp_pisNoAF          -- for when no address families are left enabled
 *
 *   * bgp_pisMaxPrefixStop -- max prefix limit biting -- permanent !
 *
 * which are all members of bgp_pisDown, and will all stop any session and
 * acceptor operations.  pisDeconfigured overrides pisShutdown which overrides
 * pisNoAF which overrides pisMaxPrefixStop.
 *
 * NB: takes responsibility for the notification.
 */
extern void
bgp_peer_set_down(bgp_prun prun, bgp_peer_idle_state_t new_idle,
                                            bgp_note note, peer_down_t why_down)
{
  bgp_peer_idle_state_t old_idle ;

  /* Insist on a single pisDown state.
   */
  switch (new_idle)
    {
      default:
        qassert(false) ;
        new_idle = bgp_pisDeconfigured ;        /* dramatic default !   */
        break ;

      case bgp_pisDeconfigured:
      case bgp_pisShutdown:
      case bgp_pisNoAF:
      case bgp_pisMaxPrefixStop:
        break ;
    } ;

  confirm(bgp_pisDown == (bgp_pisDeconfigured  |
                          bgp_pisShutdown      |
                          bgp_pisNoAF          |
                          bgp_pisMaxPrefixStop)) ;

  /* The various forms of pisDown can escalate,
   */
  old_idle = prun->idle ;

  if (old_idle & bgp_pisDown)
    {
      /* Is already down, this may escalate, but has no effect on cops.
       */
      if ((old_idle & bgp_pisDown) < new_idle)
        prun->idle = new_idle | (old_idle & ~bgp_pisDown) ;

      confirm(bgp_pisDeconfigured > bgp_pisShutdown) ;
      confirm(bgp_pisShutdown     > bgp_pisNoAF) ;
      confirm(bgp_pisNoAF         > bgp_pisMaxPrefixStop) ;

      qassert( (prun->state != bgp_pStarted) &&
               (prun->state != bgp_pEstablished) ) ;
      qassert(prun->session_state != bgp_pssRunning) ;

      bgp_note_free(note) ;     /* discard      */
      return ;
    } ;

  /* Going down (first time)... forget any pisMaxPrefixWait and any running
   * restart timer.
   *
   * We preserve any pisClearing and pisReset... but may set those below,
   * in any case.
   */
  qassert(!(old_idle & bgp_pisDown)) ;

  bgp_peer_restart_timer_cancel(prun) ;

  new_idle |= (old_idle & ~bgp_pisMaxPrefixWait) ;

  prun->idle = new_idle ;

  /* At this point: is now pisDown, but was not previously, so this is the
   *                                                      transition to pisDown.
   *
   * If the session is bgp_pssRunning then we need down the session and
   * acceptor.  Otherwise, we need to down just the acceptor.
   */
  switch (prun->session_state)
    {
      /* Make the transition to pResetting/pssLimping.  If was pEstablished,
       * then start the clearing process running.
       *
       * When the session responds with a session-has-stopped message, can make
       * the transition out of pResetting, if is ready to do so.
       */
      case bgp_pssRunning:
        qassert((prun->state == bgp_pStarted) ||
                (prun->state == bgp_pEstablished)) ;

        bgp_peer_stop_running(prun, note, why_down) ;
        break ;

      /* These states are unchanged by going pisDown.
       */
      case bgp_pssInitial:
      case bgp_pssDeleted:
        break ;

      /* Going pisDown will affect the acceptor -- recharging the session
       * clears csTrack, which will stop the Acceptor.
       */
      case bgp_pssLimping:
      case bgp_pssStopped:
        bgp_session_recharge(prun->session, NULL) ;
    } ;

  bgp_note_free(note) ;       /* done with (if any)   */
} ;

/*------------------------------------------------------------------------------
 * Stop the current pssRunning session session.
 *
 * If is pStarted, will stop the session -- unconditionally.
 *
 * If is pEstablished, will start the clearing process and set pisClearing.
 *
 * When the dust settles, the session may automatically restart.
 *
 * Expects: prun->idle            to not be pisRunnable, any more.
 *          prun->cops.conn_state to not be csRun, any more.
 *
 * NB: takes responsibility for the notification
 */
static void
bgp_peer_stop_running(bgp_prun prun, bgp_note note, peer_down_t why_down)
{
  qassert(prun->session_state   == bgp_pssRunning) ;
  qassert((prun->state          == bgp_pStarted) ||
          (prun->state          == bgp_pEstablished) );
  qassert(prun->idle            != bgp_pisRunnable) ;

  if (note == NULL)
    note = bgp_peer_map_peer_down(why_down) ;

  note = bgp_session_recharge(prun->session, note) ;
  bgp_note_free(note) ;                 // TODO ???

  prun->session_state = bgp_pssLimping ;
  bgp_peer_change_status(prun, bgp_pResetting) ;

#if 0
  if (prun->state == bgp_pEstablished)
    bgp_peer_start_clearing(prun) ;
#endif

  prun->last_reset = why_down ;
} ;

/*------------------------------------------------------------------------------
 * Construct notification based on the reason for bringing down the session
 *
 * Where the session is brought down by the other end, returns NULL.
 */
static bgp_note
bgp_peer_map_peer_down(peer_down_t why_down)
{
  bgp_nom_code_t    code ;
  bgp_nom_subcode_t subcode ;

  code    = BGP_NOMC_CEASE ;            /* Default values       */
  subcode = BGP_NOMS_UNSPECIFIC ;

  switch (why_down)
    {
      case PEER_DOWN_NULL:
        return NULL ;

      /* Session taken down at this end for some unspecified reason
       */
      case PEER_DOWN_UNSPECIFIED:
        break ;

      /* Configuration changes that cause a session to be reset.
       */
      case PEER_DOWN_CONFIG_CHANGE:
      case PEER_DOWN_RID_CHANGE:
      case PEER_DOWN_REMOTE_AS_CHANGE:
      case PEER_DOWN_LOCAL_AS_CHANGE:
      case PEER_DOWN_CLID_CHANGE:
      case PEER_DOWN_CONFED_ID_CHANGE:
      case PEER_DOWN_CONFED_PEER_CHANGE:
      case PEER_DOWN_RR_CLIENT_CHANGE:
      case PEER_DOWN_RS_CLIENT_CHANGE:
      case PEER_DOWN_UPDATE_SOURCE_CHANGE:
      case PEER_DOWN_AF_ACTIVATE:
      case PEER_DOWN_GROUP_BIND:
      case PEER_DOWN_GROUP_UNBIND:
      case PEER_DOWN_DONT_CAPABILITY:
      case PEER_DOWN_OVERRIDE_CAPABILITY:
      case PEER_DOWN_STRICT_CAP_MATCH:
      case PEER_DOWN_CAPABILITY_CHANGE:
      case PEER_DOWN_PASSIVE_CHANGE:
      case PEER_DOWN_MULTIHOP_CHANGE:
      case PEER_DOWN_GTSM_CHANGE:
      case PEER_DOWN_AF_DEACTIVATE:
      case PEER_DOWN_PASSWORD_CHANGE:
      case PEER_DOWN_ALLOWAS_IN_CHANGE:
        subcode = BGP_NOMS_C_CONFIG ;
        break ;

      /* Other actions that cause a session to be reset
       */
      case PEER_DOWN_USER_SHUTDOWN:
        subcode = BGP_NOMS_C_SHUTDOWN ;
        break ;

      case PEER_DOWN_USER_RESET:
        subcode = BGP_NOMS_C_RESET ;
        break ;

      case PEER_DOWN_NEIGHBOR_DELETE:
        subcode = BGP_NOMS_C_DECONFIG ;
        break ;

      case PEER_DOWN_INTERFACE_DOWN:
        return NULL ;             /* nowhere to send a notification !     */

      /* Errors and problems that cause a session to be reset
       *
       * SHOULD really have a notification constructed for these, but for
       * completeness construct an "unspecified" for these.
       */
      case PEER_DOWN_MAX_PREFIX:
        subcode = BGP_NOMS_C_MAX_PREF ;
        break ;

      case PEER_DOWN_HEADER_ERROR:
        code = BGP_NOMC_HEADER ;
        break ;

      case PEER_DOWN_OPEN_ERROR:
        code = BGP_NOMC_OPEN ;
        break ;

      case PEER_DOWN_UPDATE_ERROR:
        code = BGP_NOMC_UPDATE ;
        break ;

      case PEER_DOWN_HOLD_TIMER:
        code = BGP_NOMC_HOLD_EXP ;
        break ;

      case PEER_DOWN_FSM_ERROR:
        code = BGP_NOMC_FSM ;
        break ;

      case PEER_DOWN_DYN_CAP_ERROR:
        code = BGP_NOMC_DYN_CAP ;
        break ;

      /* Things the far end can do to cause a session to be reset
       */
      case PEER_DOWN_NOTIFY_RECEIVED:
        return NULL ;             /* should not get here !                */

      case PEER_DOWN_CLOSE_SESSION:
      case PEER_DOWN_NSF_CLOSE_SESSION:
        return NULL ;             /* nowhere to send a notification !     */

      /* To keep the compiler happy.
       */
      case PEER_DOWN_count:
      default:
        qassert(false) ;
        break ;                   /* should have asserted already         */
    } ;

  return bgp_note_new(code, subcode) ;
} ;

/*------------------------------------------------------------------------------
 * Construct reason for bringing down the session based on the notification
 */
static peer_down_t
bgp_peer_map_notification(bgp_note note)
{
  if (note == NULL)
    return PEER_DOWN_UNSPECIFIED ;

  switch (note->code)
    {
      case BGP_NOMC_UNDEF:
        break ;

      case BGP_NOMC_HEADER:
        return PEER_DOWN_HEADER_ERROR ;

      case BGP_NOMC_OPEN:
        return PEER_DOWN_OPEN_ERROR ;

      case BGP_NOMC_UPDATE:
        return PEER_DOWN_UPDATE_ERROR ;

      case BGP_NOMC_HOLD_EXP:
        return PEER_DOWN_HOLD_TIMER ;

      case BGP_NOMC_FSM:
        return PEER_DOWN_FSM_ERROR ;

      case BGP_NOMC_CEASE:
        switch (note->subcode)
        {
          case BGP_NOMS_C_MAX_PREF:
            return PEER_DOWN_MAX_PREFIX ;

          case BGP_NOMS_C_SHUTDOWN:
            return PEER_DOWN_USER_SHUTDOWN ;

          case BGP_NOMS_C_DECONFIG:
            return PEER_DOWN_NEIGHBOR_DELETE ;

          case BGP_NOMS_C_RESET:
            return PEER_DOWN_USER_RESET ;

          case BGP_NOMS_C_REJECTED:       /* should not get here  */
            return PEER_DOWN_NULL ;

          case BGP_NOMS_C_CONFIG:
            return PEER_DOWN_CONFIG_CHANGE ;

          case BGP_NOMS_C_COLLISION:      /* should not get here  */
            return PEER_DOWN_NULL ;

          case BGP_NOMS_C_RESOURCES:      /* not used             */
            return PEER_DOWN_NULL ;

          default:
            break ;
        } ;
        break ;

      case BGP_NOMC_DYN_CAP:
        return PEER_DOWN_DYN_CAP_ERROR ;

      default:
        break ;
    } ;

  return PEER_DOWN_UNSPECIFIED ;
} ;

/*------------------------------------------------------------------------------
 * Set new prun state.
 *
 * If state changes log state change if required and deal with dropping back to
 * pIdle.
 *
 * In any case, set timers for the new state -- so if state hasn't changed,
 * will restart those timers.
 */
static void
bgp_peer_change_status (bgp_prun prun, bgp_peer_state_t new_state)
{
  bgp_peer_state_t old_state ;

  old_state = prun->state ;

  if (old_state == new_state)
    return ;

  prun->state = new_state ;

  if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("peer %s went from %s to %s", prun->name,
                           map_direct(bgp_peer_status_map, old_state).str,
                           map_direct(bgp_peer_status_map, new_state).str) ;

  /* Tidying up on entry to new state.
   */
  switch (prun->state)
    {
      /* Nothing to do on.
       */
      case bgp_pInitial:
        break;

      /* On entry to pDown...
       */
      case bgp_pDown:
        break;

      /* On entry to pStarted...
       */
      case bgp_pStarted:
        break;

      /* On entry to pEstablished only the the Graceful Stale Timer is left
       * running.
       *
       * Any Graceful Restart Timer can be cancelled -- have established in
       * time.
       */
      case bgp_pEstablished:
        bgp_graceful_restart_timer_cancel(prun) ;
        break;

      /* On entry to pResetting...
       */
      case bgp_pResetting:
        BGP_TIMER_OFF (prun->t_gr_restart);

        bgp_graceful_stale_timer_cancel(prun) ;
        break ;

      /* Take a rubust vuew of unknown states...
       */
      default:
        qassert(false) ;
        fall_through ;                  /* treat as pDeleting   */

      /* On entry to pDeleting, turn off all timers.
       */
      case bgp_pDeleting:
        BGP_TIMER_OFF (prun->t_gr_restart);
        BGP_TIMER_OFF (prun->t_gr_stale);
        break;
    } ;
} ;

/*==============================================================================
 * Peer Restart and Restart Timer Handling.
 */
static void bgp_peer_restart_timer_start(bgp_prun prun, qtime_t interval) ;
static void bgp_peer_restart_timer_expired (qtimer qtr, void* timer_info,
                                                            qtime_mono_t when) ;


/*------------------------------------------------------------------------------
 * Set the restart timer running.
 */
static void
bgp_peer_restart_timer_start(bgp_prun prun, qtime_t interval)
{
  static qrand_seq_t seed ;

  if (prun->qt_restart == NULL)
     prun->qt_restart = qtimer_init_new(NULL, re_nexus->pile, NULL, prun) ;

  qtimer_set_interval(prun->qt_restart, interval + qrand(seed, QTIME(0.25)),
                                               bgp_peer_restart_timer_expired) ;
} ;

/*------------------------------------------------------------------------------
 * If the restart timer is running, cancel it now.
 *
 * NB: clears pisMaxPrefixWait (if set), but does NOT restart the peer.
 *
 *     It is the callers responsibility to look after the larger state.
 */
static void
bgp_peer_restart_timer_cancel (bgp_prun prun)
{
  if (prun->idle & bgp_pisMaxPrefixWait)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s Maximum-prefix restart timer cancelled", prun->name) ;

      prun->idle &= ~bgp_pisMaxPrefixWait ;

      qassert(prun->qt_restart != NULL) ;
    } ;

  if (prun->qt_restart != NULL)
    qtimer_unset(prun->qt_restart) ;
} ;

/*------------------------------------------------------------------------------
 * Peer restart timer expired.
 *
 * The restart timer may be running because is pisMaxPrefixWait, or because was
 * set by bgp_peer_may_restart().
 */
static void
bgp_peer_restart_timer_expired(qtimer qtr, void* timer_info, qtime_mono_t when)
{
  bgp_prun              prun;
  bgp_peer_idle_state_t idle ;

  prun = timer_info ;
  qassert(prun->qt_restart == qtr) ;

  idle = prun->idle ;

  /* If peer was down because of a max-prefix overflow, then clear that state,
   * and see if is now ready to restart.
   */
  if (BGP_DEBUG (events, EVENTS) && (idle & bgp_pisMaxPrefixWait))
    zlog_debug ("%s Maximum-prefix restart timer expired, restore peering",
                                                                   prun->name) ;

  /* Clear pisReset (if any) and pisMaxPrefixWait (if any), then:
   *
   *   * if is not bc_is_up...
   *
   *   * ...or peer is not pDown,
   *
   *   * ...or session_state is not pssStopped,
   *
   * ...then we are not yet ready to restart, so make sure is bc_is_reset and
   * exit -- something else must happen to set the restart timer again.
   */
  idle &= ~(bgp_pisReset | bgp_pisMaxPrefixWait) ;

  if ((prun->state != bgp_pDown) || (prun->session_state != bgp_pssStopped))
    {
      /* If we are not bgp_pDown, then we are still resetting, so restore
       * that state.
       *
       * If the session has not stopped, ditto.
       */
      idle |= bgp_pisReset ;
    }

  /* Update the idles state at set things running if can do so.
   */
  prun->idle = idle ;

  if (idle == bgp_pisRunnable)
    bgp_peer_start_running(prun);
} ;

/*==============================================================================
 * Max-Prefix Handling
 */

/*------------------------------------------------------------------------------
 * Reset the given prib's pmax settings.
 */
extern prefix_max
bgp_prib_pmax_reset(bgp_prib prib)
{
  prefix_max pmax ;

  pmax = &prib->pmax ;
  memset(pmax, 0, sizeof(prefix_max_t)) ;

  /* Zeroizing sets:
   *
   *    * set          -- false
   *    * warning      -- false
   *
   *    * trigger      -- X         -- set to indefinitely big, below
   *
   *    * limit        -- 0
   *    * threshold    -- 0
   *
   *    * thresh_pc    -- X         -- set to default, below
   *    * restart      -- 0
   */
  pmax->trigger   = UINT_MAX ;
  pmax->thresh_pc = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;

  return pmax ;
} ;

/*------------------------------------------------------------------------------
 * Check for maximum prefix ...
 */
extern bool
bgp_peer_pmax_check(bgp_prib prib)
{
  if (prib->pcount_recv > prib->pmax.limit)
    {
      /* We have exceeded the max-prefix limit
       */
      bgp_note note ;
      ptr_t p ;

      if (prib->pmax.trigger < UINT_MAX)
        {
          /* First time we have seen this, so report.
           */
          zlog (prib->prun->log, LOG_INFO,
              "%%MAXPFXEXCEED: No. of %s prefix received from %s %u exceed, "
                "limit %u", get_qafx_name(prib->qafx), prib->prun->name,
                                         prib->pcount_recv, prib->pmax.limit) ;

          /* Set the trigger so we don't come back !
           *
           * This should be required only when we have pmax.warning.
           */
          prib->pmax.trigger = UINT_MAX ;
        } ;

      if (prib->pmax.warning)
        return true ;                   /* it's OK, though      */

      /* Signal max-prefix overflow to peer
       */
      note = bgp_note_new(BGP_NOMC_CEASE, BGP_NOMS_C_MAX_PREF) ;
      p = bgp_note_prep_data(note, 2 + 1 + 4) ;

      store_ns(&p[0], get_iAFI(prib->qafx)) ;
      store_b (&p[2], get_iSAFI(prib->qafx)) ;
      store_nl(&p[3], prib->pmax.limit) ;

      qassert((prib->prun->state == bgp_pEstablished) &&
                                (prib->prun->session_state == bgp_pssRunning)) ;

      if (prib->pmax.restart == 0)
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix stop.", prib->prun->name) ;

          bgp_peer_set_down(prib->prun, bgp_pisMaxPrefixStop, note,
                                                         PEER_DOWN_MAX_PREFIX) ;
        }
      else
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
                                        prib->prun->name, prib->pmax.restart) ;

          bgp_peer_restart_timer_start(prib->prun, QTIME(prib->pmax.restart));

          bgp_peer_set_idle(prib->prun, bgp_pisMaxPrefixWait, note,
                                                         PEER_DOWN_MAX_PREFIX) ;
        } ;

      return false ;            /* STOP !!!     */
    } ;

  if (prib->pcount_recv > prib->pmax.threshold)
    {
      /* We have exceeded the max-prefix threshold.
       */
      if (prib->pmax.trigger < prib->pmax.limit)
        {
          /* First time we have seen this, so report.
           */
          zlog (prib->prun->log, LOG_INFO,
            "%%MAXPFX: No. of %s prefix received from %s reaches %u, max %u",
            get_qafx_name(prib->qafx), prib->prun->name, prib->pcount_recv,
                                                            prib->pmax.limit);

          /* Set the trigger for limit.
           */
          prib->pmax.trigger = prib->pmax.limit ;
        } ;
    } ;

  return true ;                 /* OK to continue       */
} ;

/*------------------------------------------------------------------------------
 * Clear the max-prefix stuff -- part of stopping or restarting peer.
 */
extern void
bgp_peer_pmax_clear(bgp_prib prib)
{
  if (prib->pmax.set)
    prib->pmax.trigger = prib->pmax.threshold ;
  else
    bgp_prib_pmax_reset(prib) ;
} ;
















/*==============================================================================
 * Finding peer objects and state of same
 */



/*------------------------------------------------------------------------------
 * Fill given buffer with the given "uptime".
 *
 * Note that this is a time period -- not an actual time.
 */
extern qfb_time_t
peer_uptime (time_t uptime)
{
  qfb_time_t QFB_QFS(ipa, qfs) ;

  /* If there is no connection has been done before print `never'.
   */
  if (uptime == 0)
    qfs_put_str(qfs, "never") ;
  else
    {
      time_t period;
      struct tm *tm;

      enum
        {
          ONE_DAY_SECOND   =     24 * 60 * 60,
          ONE_WEEK_SECOND  = 7 * 24 * 60 * 60,
        } ;

      period = bgp_clock () - uptime;
      tm = gmtime (&period);

      if (period < ONE_DAY_SECOND)
        qfs_printf (qfs, "%d:%02d:%02d",        /* 7..8 characters      */
              tm->tm_hour, tm->tm_min, tm->tm_sec);
      else if (period < ONE_WEEK_SECOND)
        qfs_printf (qfs, "%dd%02dh%02dm",       /* 8 characters         */
              tm->tm_yday, tm->tm_hour, tm->tm_min);
      else
        qfs_printf (qfs, "%dw%dd%02dh",         /* 7 or more characters */
              tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);
    } ;

  qfs_term(qfs) ;
  return ipa ;
} ;

/*==============================================================================
 * Clearing
 *
  */


/*------------------------------------------------------------------------------
 * Perform 'hard' clear of given peer -- reset it !
 */
extern void
peer_clear (bgp_prun prun)
{
  /* Overrides any Max Prefix issues.
   */
  bgp_peer_restart_timer_cancel (prun) ;

  /* Overrides any idle hold timer
   */
  prun->idle_hold_time = QTIME(prun->bgp_args_r.idle_hold_min_secs) ;

  bgp_peer_down(prun, PEER_DOWN_USER_RESET) ;
} ;

/*------------------------------------------------------------------------------
 * Perform some sort of 'soft' clear for the given peer.
 *
 * For the given AFI/SAFI, the stype means:
 *
 *   BGP_CLEAR_HARD
 *
 *     Do nothing -- should NOT be here !
 *
 *   BGP_CLEAR_SOFT_OUT
 *
 *     Re-announce everything in the given AFI/SAFI to the peer.
 *
 *   BGP_CLEAR_SOFT_IN
 *
 *     If we have adj_in stuff, refresh from it.
 *
 *     Otherwise, if we can send a refresh request, do so.
 *
 *     Otherwise, error
 *
 *   BGP_CLEAR_SOFT_BOTH
 *
 *     Do BGP_CLEAR_SOFT_IN and BGP_CLEAR_SOFT_OUT.
 *
 *   BGP_CLEAR_SOFT_IN_ORF_PREFIX
 *
 *     If we are configured for ORF, send a refresh request, updating the ORF
 *     (if any).
 *
 *   BGP_CLEAR_SOFT_RSCLIENT
 *
 *     If the given peer is a RS Client (in the given AFI/SAFI):
 *
 *       announce all static routes to the RS Client
 *
 *       announce contents if the RS Client's RIB to the RS Client
 */
extern bgp_ret_t
peer_clear_soft (bgp_prun prun, qafx_t qafx, bgp_clear_type_t stype)
{
  bgp_prib prib ;

  if (prun->state != bgp_pEstablished)
    return BGP_SUCCESS ;                /* Nothing to do        */

  prib = prun->prib[qafx] ;

  if (prib == NULL)
    return BGP_ERR_AF_NOT_CONFIGURED;

  /* Do the Out-Bound soft reconfigurations -- ie. re-announce stuff.
   */
  switch (stype)
    {
      case BGP_CLEAR_HARD:
      default:
        qassert(false) ;
        return BGP_SUCCESS ;

      case BGP_CLEAR_SOFT_IN:
      case BGP_CLEAR_SOFT_IN_ORF_PREFIX:
        break ;                         /* nothing to do        */

      case BGP_CLEAR_SOFT_RSCLIENT:
        if (prib->route_server_client)
          {
#if 0
            bgp_check_local_routes_rsclient (prun, qafx);
            bgp_soft_reconfig_rsclient_in (prun, qafx);
#endif
          } ;
        break ;

      case BGP_CLEAR_SOFT_OUT:
      case BGP_CLEAR_SOFT_BOTH:
        bgp_announce_family (prun, qafx, 10);
        break ;
    } ;

  /* Do the In-Bound soft reconfigurations -- ie. request refresh.
   */
  switch (stype)
    {
      case BGP_CLEAR_HARD:
      case BGP_CLEAR_SOFT_OUT:
      case BGP_CLEAR_SOFT_RSCLIENT:
      default:
        break ;                         /* nothing to do        */

      case BGP_CLEAR_SOFT_IN_ORF_PREFIX:
        /* If we can send ORF, then send a refresh request, updating the
         * ORF as required.
         */
        if (prib->orf_pfx_can_send)
          {
            if (prib->plist[FILTER_IN] != NULL)
              {
                /* If have sent ORF, send 'remove' previous ORF, but 'defer'
                 * refresh.  Then send current state of ORF and ask for
                 * 'immediate' refresh.
                 */
                if (prib->orf_pfx_sent)
                  bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                         BGP_ORF_WTR_DEFER, true /* remove */) ;
                bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                BGP_ORF_WTR_IMMEDIATE, false /* not remove */) ;
              }
            else
              {
                /* If have sent ORF, send 'remove' previous and ask for
                 * 'immediate' refresh, otherwise ask for a refresh.
                 */
                if (prib->orf_pfx_sent)
                  bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                     BGP_ORF_WTR_IMMEDIATE, true /* remove */) ;
                else
                  bgp_route_refresh_send (prib, 0, 0, 0);
              } ;

            break ;                     /* <-<-<- done          */
          } ;

        /* Otherwise, treat as simple inbound soft reconfig.
         */
        fall_through ;

      case BGP_CLEAR_SOFT_IN:
      case BGP_CLEAR_SOFT_BOTH:
        /* If neighbor has soft reconfiguration inbound flag, use the
         * Adj-RIB-In database.
         *
         * If neighbor has route refresh capability, send route refresh
         * message to the peer.
         */
        if      (prib->soft_reconfig)
          bgp_soft_reconfig_in (prun, qafx);
        else if (prun->session->args->can_rr != bgp_form_none)
          bgp_route_refresh_send (prib, 0, 0, 0);
        else
          return BGP_ERR_SOFT_RECONFIG_UNCONFIGURED;

        break ;
    } ;

  return BGP_SUCCESS ;
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
 * Enabling and disabling a peer.
 */
static void bgp_peer_stop (bgp_prun prun, bool nsf) ;
static void bgp_peer_reset_enable(bgp_prun prun) ;
static void bgp_peer_down_notify(bgp_prun prun, peer_down_t why_down,
                                                                bgp_note note) ;
static void bgp_peer_shutdown(bgp_prun prun) ;
static bgp_note bgp_peer_map_peer_down(peer_down_t why_down) ;
static peer_down_t bgp_peer_map_notification(bgp_note noten) ;


static int bgp_graceful_restart_timer_expire (struct thread *thread);
static int bgp_graceful_stale_timer_expire (struct thread *thread);


/*------------------------------------------------------------------------------
 * Enable Peer
 *
 * This means that something has changed, and session can be started, if no
 * session has already started.
 *
 * So does nothing unless in pIdle, and expects the peer session state to be:
 *
 *   - pssStopped XXX
 *
 *   - pssRunning XXX
 *
 *   - pssLimping XXX -- cannot, yet, start a new session -- that will happen in
 *                      due course.
 *
 * This means that any change which requires the session to be taken down and
 * restarted needs to call bgp_peer_disable().
 *
 * The other peer states:
 *
 *   - pEstablished
 *
 *   - pResetting -- cannot restart the peer yet, that will happen in due course.
 *
 *   - pDeleted   -- Enable peer makes no sense...  asserts invalid.
 *
 * TODO: assert !pEstablished in bgp_peer_enable ?
 */
extern void
bgp_peer_enable(bgp_prun prun)
{
#if 0
  switch (prun->state)
    {
      case bgp_pDown:
        if (prun->args.can_af == qafx_empty_set)
          {
            break ;
          } ;

        fall_through ;

      case bgp_pDown:
        /* The peer is disabled when no address family is enabled.
         *
         * An address family is enabled when it is (a) activated and (b) it is
         * not PEER_FLAG_SHUTDOWN or PEER_STATUS_PREFIX_OVERFLOW or
         * PEER_AFS_DISABLED or otherwise disabled.
         *
         * If no address family is enabled, will do nothing and will remain
         * pDown.
         */
        if (prun->args.can_af == qafx_empty_set)
          break ;

        qassert(!peer_is_disabled(prun)) ;
        qassert(prun->session->peer_state == bgp_pssStopped) ;

        prun->state = bgp_pStarted ;
        fall_through ;

      case bgp_pStarted:
        /* The peer is already enabled... so we
         *
         *
         *
         */
        if (prun->af_configured == qafx_empty_set)
          {
            break ;
          } ;

        qassert(   !(prun->c_flags  & PEER_FLAG_SHUTDOWN)
                && !(prun->sflags & PEER_STATUS_PREFIX_OVERFLOW) ) ;

        qassert(prun->session->peer_state == bgp_pssStopped) ;

        bgp_peer_reset_enable(prun) ;   /* tidy up      */
        bgp_session_config(prun) ;
        bgp_peer_change_status (prun, bgp_pStarted) ;

        break ;




        if (bgp_session_is_active(prun->session))
          assert(prun->session_state != bgp_psEstablished) ;
        else
          {
            if ( (prun->af_configured != qafx_empty_set)
                && !(prun->c_flags  & PEER_FLAG_SHUTDOWN)
                && !(prun->sflags & PEER_STATUS_PREFIX_OVERFLOW) )
              {
                /* enable the session
                 */
                bgp_peer_reset_enable(prun) ;   /* tidy up      */
                bgp_session_config(prun) ;
                bgp_peer_change_status (prun, bgp_pStarted) ;
              } ;
          } ;
        break ;

      case bgp_pEstablished:
        break ;

      case bgp_pDeleting:
        zabort("cannot enable a pDeleting peer") ;
        break ;

      default:
        zabort("unknown prun->state") ;
        break ;
    } ;

#endif
} ;

/*------------------------------------------------------------------------------
 * Update "open_state", if possible, for given peer -- in pStarted state.
 *
 * This is used when the peer is pStarted, but an address family has been
 * enabled or disabled, or any of the bgp_open_state has been changed.
 *
 * pStarted means that a session enable message has been sent to the BGP
 * Engine, but the session is not known (to the Peering Engine) to have
 * established, yet.  There are two cases:
 *
 *   1) the OPEN message has not, yet been sent.
 *
 *      in this case, the session->open_send can be updated, so the change in
 *      the enabled address families does not require the session to be
 *      disabled and re-enabled.
 *
 *   2) the OPEN message has been sent.
 *
 *      so there is no alternative, the session must be disabled and later
 *      automatically re-enabled.
 *
 * NB: does nothing for peers which are not pStarted.
 */
extern void
bgp_peer_update_open_state(bgp_prun prun, peer_down_t why_down)
{
  bgp_open_state open_send_new, open_send_was ;

  if (prun->state != bgp_pStarted)
    return ;


} ;

/*------------------------------------------------------------------------------
 * Down Peer -- bring down any existing session and restart if possible.
 *
 * The following "why_down" values are special:
 *
 *   - PEER_DOWN_NSF_CLOSE_SESSION
 *
 *     causes NSF to be turned on as the peer is stopped and routes are cleared.
 *
 *   - PEER_DOWN_USER_SHUTDOWN
 *
 *     causes the peer to be shutdown -- so won't restart.
 *
 *   - PEER_DOWN_NEIGHBOR_DELETE
 *
 *     causes PEER_DOWN_USER_SHUTDOWN prior to deleting the peer completely.
 *
 * If there is an active session, then it must be disabled, sending the given
 * notification, or one based on the reason for downing the peer.
 *
 * If there is no active session, any stale NSF routes will be cleared.
 *
 * So any session ends up as:
 *
 *   pssStopped  XXX -- wasn't active and still isn't
 *
 *   pssLimping  XXX -- was pssRunning, we now wait for BGP Engine
 *                      to complete the disable action and signal when done.
 *
 * The result depends on the initial peer state:
 *
 *   0. pDown
 *
 *
 *
 *   1. pStarted or pEstablished
 *
 *      The session will have been disabled -- and will now be sLimping.
 *
 *      When the .
 *
 *      Noting that PEER_DOWN_USER_SHUTDOWN and PEER_DOWN_NEIGHBOR_DELETE both
 *      prevent any restart -- by setting PEER_FLAG_SHUTDOWN.
 *
 *   2. pEstablished
 *
 *      The session will have been disabled -- and will now be sLimping.
 *
 *      See bgp_peer_stop() for the state of the peer.
 *
 *   3. bgp_peer_pClearing
 *
 *      In this state the session can only be:
 *
 *        sLimping    -- session disable has been sent to the BGP Engine.
 *        sDisabled   -- session has been disabled by the BGP Engine
 *
 *      because peer must have been pEstablished immediately before.
 *
 *      Do nothing -- will proceed to pIdle in due course.
 *
 *   4. bgp_peer_pDeleting
 *
 *      In this state there may be no session at all, or the session can
 *      only be:
 *
 *        sIdle       -- session never got going
 *        sLimping    -- session disable has been sent to the BGP Engine.
 *        sDisabled   -- session has been disabled by the BGP Engine
 *
 *      Do nothing -- peer will be deleted in due course.
 */
extern void
bgp_peer_down(bgp_prun prun, peer_down_t why_down)
{
  bgp_peer_down_notify(prun, why_down, NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Notify the far end that an error has been detected, and close down the
 * session.
 *
 * The session will have been established, so the IdleHoldTime will be extended.
 *
 * Because it knows no better, the session will be restarted.
 */
extern void
bgp_peer_down_error(bgp_prun prun,
                                bgp_nom_code_t code, bgp_nom_subcode_t subcode)
{
  bgp_peer_down_error_with_data (prun, code, subcode, NULL, 0);
}

/*------------------------------------------------------------------------------
 * Notify the far end that an error has been detected, and close down the
 * session.
 *
 * Same as above, except that this accepts a data part for the notification
 * message -- but len may be 0 (and data may be null iff len == 0).
 */
extern void
bgp_peer_down_error_with_data (bgp_prun prun,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                               const byte* data, size_t datalen)
{
  bgp_note note ;
  note = bgp_note_new_with_data(code, subcode, data, datalen);

  bgp_peer_down_notify(prun, bgp_peer_map_notification(note), note) ;
} ;

/*------------------------------------------------------------------------------
 * Down Peer for the given reason, with the given notification, if any.
 *
 * See bgp_peer_down() above.
 *
 * If the session is active and has not been downed already, then we now down
 * it and with suitable notification.
 *
 * If the notification is NULL and need to send a notification, make one up
 * from the given reason for downing the peer.
 *
 * NB: once the session has been sent one notification, all further
 *     notifications are ignored (and discarded, here).
 *
 *     If the session is not in a state to receive a notification, we ignore
 *     this one (and discard it, here).
 *
 * NB: takes responsibility for the notification.
 */
static void
bgp_peer_down_notify(bgp_prun prun, peer_down_t why_down, bgp_note note)
{
  /* Deal with session (if any)
   */
  if (note == NULL)
    note = bgp_peer_map_peer_down(why_down) ;

#if 0
  if (bgp_session_disable(peer, note))
    prun->session->note = bgp_note_copy(prun->session->note, note) ;
  else
    bgp_note_free(note) ;

  /* This logging is (more or less) part of commit 1212dc1961...
   *
   * TODO worry how useful this is and whether is not already done elsewhere.
   */

  /* Log some                                                           */
  switch (why_down)
    {
      case PEER_DOWN_USER_RESET:
        zlog_info ("Notification sent to neighbor %s: User reset", prun->host);
        break ;

      case PEER_DOWN_USER_SHUTDOWN:
        zlog_info ("Notification sent to neighbor %s: shutdown", prun->host);
        break ;

      case PEER_DOWN_NOTIFY_SEND:
        zlog_info ("Notification sent to neighbor %s: type %u/%u",
                   prun->host, code, sub_code);
        break ;

      default:
        zlog_info ("Notification sent to neighbor %s: configuration change",
                prun->host);
        break ;
    } ;
#endif

  /* Now worry about the state of the peer
   */
  if ((why_down == PEER_DOWN_USER_SHUTDOWN)
                                     || (why_down == PEER_DOWN_NEIGHBOR_DELETE))
    bgp_peer_shutdown(prun) ;

  if (why_down != PEER_DOWN_NULL)
    prun->last_reset = why_down ;
#if 0
  switch (prun->state)
    {
      case bgp_pDown:

      case bgp_pStarted:
        assert(!bgp_session_is_active(prun->session)
                  || (prun->session->peer_state == bgp_session_psLimping)) ;

        bgp_peer_nsf_stop (prun) ;        /* flush stale routes, if any   */

        bgp_peer_enable(prun) ;           /* Restart if possible.         */

        break ;

      case bgp_pEstablished:
        assert(prun->session->peer_state == bgp_session_psLimping) ;

        bgp_peer_stop(prun, why_down == PEER_DOWN_NSF_CLOSE_SESSION) ;

        break ;

      case bgp_pDown:
        assert(   (prun->session->peer_state == bgp_session_psLimping)
               || (prun->session->peer_state == bgp_session_psStopped) ) ;

        bgp_peer_nsf_stop (prun) ;        /* flush stale routes, if any   */

        break ;

      case bgp_pDeleting:
        assert(   (prun->session == NULL)
               || (prun->session->peer_state == bgp_session_psStopped)
               || (prun->session->peer_state == bgp_session_psLimping) ) ;
        break ;

      default:
        zabort("unknown prun->state") ;
        break ;
    } ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Administrative BGP peer stop event -- stop pEstablished peer.
 *
 * MUST be pEstablished.
 *
 * Sets pDown and clears down all routes etc, subject to the required NSF.
 *
 * NB: Leaves any Max Prefix Timer running.
 *
 *     Starts Graceful Restart and Stale Route timers iff NSF and at least one
 *     afi/safi is enabled for NSF.
 */
static void
bgp_peer_stop (bgp_prun prun, bool nsf)
{
  assert( (prun->state == bgp_pStarted) ||
          (prun->state == bgp_pEstablished) ) ;

  /* bgp log-neighbor-changes of neighbor Down
   */
  if (prun->state == bgp_pEstablished)
    if (prun->do_log_neighbor_changes_r)
      zlog_info ("%%ADJCHANGE: neighbor %s Down %s", prun->name,
                          map_direct(bgp_peer_down_map, prun->last_reset).str) ;

  /* Change state to pDown -- turns off all timers.
   */
  bgp_peer_change_status(prun, bgp_pDown) ;

  prun->dropped++ ;
  prun->resettime = bgp_clock () ;

  /* Clear out routes, with NSF if required.
   *
   * Sets PEER_STATUS_NSF_WAIT iff NSF and at least one afi/safi is enabled
   * for NSF.  Clears PEER_STATUS_NSF_WAIT otherwise.
   */
  bgp_clear_routes(prun, nsf) ;

  /* graceful restart
   */
  if (prun->nsf_restarting)
    {
      if (BGP_DEBUG (events, EVENTS))
        {
          zlog_debug ("%s graceful restart timer started for %d sec",
                      prun->name, prun->v_gr_restart);
          zlog_debug ("%s graceful restart stalepath timer started for %d sec",
                      prun->name, prun->bgp_args_r.stalepath_time_secs);
        } ;

      BGP_TIMER_ON (prun->t_gr_restart, bgp_graceful_restart_timer_expire,
                    prun->v_gr_restart) ;

      if (nsf)
        BGP_TIMER_ON (prun->t_gr_stale, bgp_graceful_stale_timer_expire,
                                         prun->bgp_args_r.stalepath_time_secs) ;
    } ;

  /* Reset uptime.
   */
  prun->uptime = bgp_clock ();

#ifdef HAVE_SNMP
  bgpTrapBackwardTransition (prun);
#endif /* HAVE_SNMP */
} ;

/*------------------------------------------------------------------------------
 * Clear out any stale routes, cancel any Graceful Restart timers.
 *
 * NB: may still be pResetting from when peer went down leaving these stale
 *     routes.
 *
 * NB: assumes clearing stale routes will complete immediately !
 */
static void
bgp_peer_clear_all_stale_routes (bgp_prun prun)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_prib prib ;

      prib = prun->prib[qafx] ;

      if ((prib != NULL) && prib->nsf_mode)
        bgp_clear_stale_route (prun, qafx);
    } ;

  bgp_graceful_restart_timer_cancel(prun) ;
  bgp_graceful_stale_timer_cancel(prun) ;

  prun->nsf_restarting = false ;
} ;

/*------------------------------------------------------------------------------
 * If waiting for NSF peer to come back, stop now.
 *
 * When a session stops -- see bgp_peer_stop(), above -- the peer is set
 * PEER_STATUS_NSF_WAIT iff there are now stale routes in the table, waiting
 * for peer to come back.
 *
 * This function terminates that wait and clears out any stale routes, and
 * cancels any timers.
 *
 * Also clears down all NSF c_flags.
 *
 * If is PEER_STATUS_NSF_WAIT, MUST be pIdle or pResetting.
 *
 * NB: may still be pResetting from when peer went down leaving these stale
 *     routes.
 *
 * NB: assumes clearing stale routes will complete immediately !
 */
static void
bgp_peer_nsf_stop (bgp_prun prun)
{
  qafx_t qafx ;

  if (prun->nsf_restarting)
    {
      assert( (prun->state == bgp_pStarted)
           || (prun->state == bgp_pDown) ) ;

      bgp_peer_clear_all_stale_routes (prun) ;
    } ;

  prun->nsf_enabled = false ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_prib prib ;

      prib = prun->prib[qafx] ;

      if (prib != NULL)
        prib->nsf_mode = false ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set the PEER_FLAG_SHUTDOWN flag and also:
 *
 *   - turn off any NSF and related timers.
 *
 *   - turn off any Max Prefix overflow and related timers.
 */
static void
bgp_peer_shutdown(bgp_prun prun)
{
  peer_flag_modify(prun, cgs_SHUTDOWN, true) ;
  bgp_peer_restart_timer_cancel(prun) ;

  bgp_peer_nsf_stop (prun) ;
} ;

/*------------------------------------------------------------------------------
 * Reset peer "active" state -- tidies things up, ready for peer to be enabled.
 *
 * NB: can be called any number of times.
 */
static void
bgp_peer_reset_enable(bgp_prun prun)
{
  qafx_t qafx ;

  assert(prun->state != bgp_pEstablished) ;

  prun->nsf_enabled = false ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_prib     prib ;

      /* Reset all negotiated variables
       */
      /* peer address family c_flags
       */
      prib = prun->prib[qafx] ;

      if (prib != NULL)
        {
          prib->nsf_mode          = false ;
          prib->af_status_r    = 0 ;
        } ;

      /* Received ORF prefix-filter
       */
      prib->orf_plist = prefix_bgp_orf_delete(prib->orf_plist) ;
    } ;
} ;


/*==============================================================================
 * Session state changes and their effect on the peer state.
 */
static void bgp_session_has_disabled(bgp_session session);


/*------------------------------------------------------------------------------
 * BGP Session has been Established.
 */
extern void
bgp_session_has_established(bgp_session session)
{
  bgp_prun         prun ;
  bgp_session_args args ;
  qafx_t           qafx ;
  int  nsf_af_count ;

  prun = session->prun ;
  assert(prun->session == session) ;            /* Safety first         */

  /* Peer state change.
   *
   * This stops all timers other than the Graceful Stale Timer.
   */
  bgp_peer_change_status (prun, bgp_pEstablished);

  /* The session->args now belong to the peer, as do the open_sent and
   * open_recv.
   *
   * Extract a few things that affect the state of the peer or address
   * families.
   *
   * We walk through the atomic load once, so that everything protected by the
   * spin-lock should now be visible in this pthread.  [This may not be
   * essential, but does not hurt.]
   */
  args = qa_get_ptr((void**)&session->args) ;

  prun->args_r.remote_id = session->open_recv->args->remote_id;
  prun->af_running = args->can_af ;

  /* Clear down the state of all known address families, and set anything
   * we now know.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_prib   prib ;
      qafx_bit_t qb ;

      prib = prun->prib[qafx] ;
      qb   = qafx_bit(qafx) ;

      qassert((prib != NULL) == (prun->af_set_up & qb)) ;

      if (prib == NULL)
        continue ;              /* not configured       */

      if (!(prun->af_running & qb))
        continue ;              /* not running          */

      prib->session_up ;

      if (args->gr.can_preserve & qb)
        {
          prib->gr_can_preserve  = true ;
          prib->gr_has_preserved = (args->gr.has_preserved & qb) ;
        }
      else
        {
          prib->gr_can_preserve  = false ;
          prib->gr_has_preserved = false ;
        }

      prib->orf_pfx_can_send = (args->can_orf_pfx.af[qafx]
                                                      & (ORF_SM | ORF_SM_pre)) ;
      prib->orf_pfx_may_recv = (args->can_orf_pfx.af[qafx]
                                                      & (ORF_RM | ORF_RM_pre)) ;
    } ;

    prun->v_gr_restart = args->gr.restart_time;

    /* TODO: should we do anything with this? */
  #if 0
    int         restarting ;            /* Restart State flag                 */
  #endif

  /* Install next hop, as required.
   */
  bgp_nexthop_set(&session->cops->su_local,
                  &session->cops->su_remote, &prun->nexthop, prun) ;

  /* Clear last notification data -- Routing Engine private field
   *
   * This is done because XXX XXX XXX XXX
   */
  prun->session->note = bgp_note_free(prun->session->note);

  /* Increment established count.
   */
  prun->established++;

  /* bgp log-neighbor-changes of neighbor Up
   */
  if (prun->do_log_neighbor_changes_r)
    zlog_info ("%%ADJCHANGE: neighbor %s Up", prun->name);

  /* graceful restart
   */
  prun->nsf_restarting = false ;

  nsf_af_count = 0 ;
  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_prib prib ;

      /* If the afi/safi has been negotiated, and have received Graceful
       * Restart capability, and is Restarting, and will Gracefully Restart
       * the afi/safi, then....
       */
      if (get_qSAFI(qafx) == qSAFI_MPLS_VPN)
        continue ;              /* Don't do graceful restart for MPLS VPN  */

      prib = prun->prib[qafx] ;
      if (prib == NULL)
        {
          qassert(!(prun->af_set_up & qafx_bit(qafx))) ;
          continue ;
        } ;

      qassert(prun->af_set_up & qafx_bit(qafx)) ;

      if (prib->gr_can_preserve)
        {
          /* If have held onto routes for this afi/safi but forwarding has
           * not been preserved, then clean out the stale routes.
           *
           * Set NSF for this address family for next time.
           */
          if (prib->nsf_mode && !prib->gr_has_preserved)
            bgp_clear_stale_route (prun, qafx);

          prib->nsf_mode = true ;
          nsf_af_count++;
        }
      else
        {
          /* Remove stale routes, if any for this afi/safi
           */
          if (prib->nsf_mode)
            bgp_clear_stale_route (prun, qafx);

          prib->nsf_mode = false ;
        }
    }

  if (nsf_af_count)
    prun->nsf_enabled = true ;
  else
    {
      prun->nsf_enabled = false ;
      bgp_graceful_stale_timer_cancel(prun) ;
    }

  /* Send route-refresh when ORF is enabled
   *
   * First update is deferred until ORF or ROUTE-REFRESH is received
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_prib prib ;

      prib = prun->prib[qafx] ;
      if (prib == NULL)
        continue ;

      if (prib->orf_pfx_can_send)
        bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                BGP_ORF_WTR_IMMEDIATE, false /* not remove */) ;

      if (prib->orf_pfx_can_send)
         prib->orf_pfx_wait = true ;
    } ;

  /* Reset uptime, send current table.
   */
  prun->uptime = bgp_clock ();

  bgp_announce_all_families (prun, 10);

#ifdef HAVE_SNMP
  bgpTrapEstablished (prun);
#endif /* HAVE_SNMP */
}

/*------------------------------------------------------------------------------
 * BGP Engine has signalled that it has stopped the session, while .
 *
 * The session->event:
 *
 *   bgp_session_eDisabled
 *
 *     This is the expected response to a bgp_session_disable()
 *
 *     args->notification   -- the notification sent, if any.
 *     args->stopped        -- true
 *
 *     If a notification message is sent to the BGP Engine, then if it is
 *     actually sent, then that is signalled by returning it here.  If, for
 *     whatever reason, no notification is sent, then NULL is returned.
 *
 *   bgp_session_eInvalid_msg
 *
 *     This tells the Routeing Engine that an invalid message has been received,
 *     on one connection or another.
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true
 *
 *   bgp_session_eFSM_error
 *
 *     This tells the Routeing Engine that something has gone wrong in the FSM
 *     sequencing... possibly an unexpected message from the other end.
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eNOM_recv
 *
 *     This tells the Routeing Engine that a NOTIFICATION has been received
 *     from the other end.
 *
 *     args->notification   -- the notification that was *received*
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eExpired
 *
 *     args->notification   -- the notification that was sent
 *     args->err            -- X  (0)
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_dropped
 *
 *     This tells the Routeing Engine that some TCP event has caused the
 *     connection to drop (eg ECONNRESET).
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_failed
 *
 *     This tells the Routeing Engine that a connect() or an accept() operation
 *     have failed to establish connection.
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- false    -- FSM gone idle and will restart
 *
 *   bgp_session_eTCP_error
 *
 *     This tells the Routeing Engine that I/O error (which does not count
 *     as either bgp_session_eTCP_dropped or bgp_session_eTCP_failed) has
 *     occurred.
 *
 *     args->notification   -- NULL
 *     args->err            -- the error in question
 *     args->ordinal        -- primary/secondary
 *     args->stopped        -- true, iff was Established
 *                             false    -- FSM gone idle and will restart
 *
 *   bgp_session_eInvalid
 *
 *     Something has gone badly wrong.
 *
 *     args->notification   -- NULL
 *     args->err            -- X  (0)
 *     args->ordinal        -- X  (0)
 *     args->stopped        -- true
 *
 *
 *
 *
 *
 * NB: takes responsibility for the notification.
 *
 * TODO: session stopped because we stopped it or because the other end did ?
 * TODO: restore NSF !!
 */
extern void
bgp_session_has_stopped(bgp_session session, bgp_note note)
{
#if 0
  peer_down_t why_down ;
#endif

  bgp_prun prun ;

  prun = session->prun ;

  /* If the peer is NULL that means that the peer to whom this session
   * once belonged has been dismantled.... this is
   */










  assert(prun->session == session) ;            /* Safety first         */










  if (prun->state == bgp_pEstablished)
    {
      time_t  t ;
      qtime_t m, n, h ;

      /* We double the IdleHoldTime and then apply a maximum value, where that
       * maximum depends on how long has been up for:
       *
       * Let 'm' be our maximum allowed, and 't' be the time was up.  Then
       * we calculate 'n' as:
       *
       *   n = (t + m) * 2 / m
       *
       * Which for m = 120 (historical maximum) gives, for various 't':
       *
       *   <  60  -- n = 2   => max = 120 -- special
       *   < 120  -- n = 3   => max = 120
       *   < 180  -- n = 4   => max =  60
       *   < 240  -- n = 5   => max =  30
       *   ... etc.          -> etc.
       *
       * The maximum allowed IdleHoldTime is then:
       *
       *   m = m / (2^(n - 3))  -- if n > 3
       *
       * As shown above.
       *
       * NB: setting bgp->default_idle_hold_max_secs to zero turns off this
       *     process altogether !
       */
      t = QTIME(bgp_clock() - prun->uptime) ;
      m = QTIME(prun->bgp_args_r.idle_hold_max_secs) ;

      n = (t + m) * 2 / m ;
      if (n > 3)
        m = m / (1 << (n - 3)) ;

      h = prun->idle_hold_time * 2 ;

      if (h > m)
        h = m ;

      if (h < QTIME(prun->bgp_args_r.idle_hold_min_secs))
        h = QTIME(prun->bgp_args_r.idle_hold_min_secs) ;

      prun->idle_hold_time = h ;
    } ;





    prun = session->prun ;
    assert(prun->session == session) ;    /* Safety first         */

   prun->session_state = bgp_pssStopped ;

    /* Immediately discard any other messages for this session.
     */
    mqueue_revoke(re_nexus->queue, session, 0) ;

#if 0
    /* If the session is marked "delete_me", do that.
     *
     * Otherwise, Old session now gone, so re-enable peer if now possible.
     */
    if (session->delete_me)
      bgp_session_delete(prun) ;  /* NB: this may also delete the peer.   */
    else
      bgp_peer_enable(prun);



  if (note == NULL)
    why_down = PEER_DOWN_CLOSE_SESSION ;
  else
    {
      if (note->received)
        why_down = PEER_DOWN_NOTIFY_RECEIVED ;
      else
        why_down = bgp_peer_map_notification(note) ;
    } ;

  bgp_peer_down_notify(prun, why_down, note) ;
#endif

} ;

/*==============================================================================
 *
 */


/*------------------------------------------------------------------------------
 * Graceful Restart timer has expired.
 *
 * MUST be pIdle or pResetting -- transition to pEstablished cancels this timer.
 *
 * Clears out stale routes and stops the Graceful Restart Stale timer.
 *
 * Clears down PEER_STATUS_NSF_MODE & PEER_STATUS_NSF_WAIT.
 */
static int
bgp_graceful_restart_timer_expire (struct thread *thread)
{
  bgp_prun prun;

  prun = THREAD_ARG (thread);
  prun->t_gr_restart = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s graceful restart timer expired", prun->name) ;

  bgp_peer_nsf_stop (prun) ;

  return 0;
}

/*------------------------------------------------------------------------------
 * Cancel any Graceful Restart timer
 *
 * NB: does NOT do anything about any stale routes or about any stale timer !
 */
static void
bgp_graceful_restart_timer_cancel (bgp_prun prun)
{
  if (prun->t_gr_restart)
    {
      BGP_TIMER_OFF (prun->t_gr_restart);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s graceful restart timer stopped", prun->name);
    }
} ;

/*------------------------------------------------------------------------------
 * Graceful Restart Stale timer has expired.
 *
 * SHOULD be pEstablished, because otherwise the Graceful Restart timer should
 * have gone off before this does, and cancelled this.
 *
 * To be safe, if not pEstablished, then MUST be pIdle or pResetting, so can do
 * bgp_peer_nsf_stop (peer).
 *
 * Clears out stale routes and stops the Graceful Restart Stale timer.
 *
 * Clears down PEER_STATUS_NSF_MODE & PEER_STATUS_NSF_WAIT.
 */
static int
bgp_graceful_stale_timer_expire (struct thread *thread)
{
  bgp_prun prun;

  prun = THREAD_ARG (thread);
  prun->t_gr_stale = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s graceful restart stalepath timer expired", prun->name);

  if (prun->state == bgp_pEstablished)
    bgp_peer_clear_all_stale_routes(prun) ;
  else
    bgp_peer_nsf_stop(prun) ;

  return 0;
}

/*------------------------------------------------------------------------------
 * Cancel any Graceful Restart Stale timer
 *
 * NB: does NOT do anything about any stale routes !
 */
static void
bgp_graceful_stale_timer_cancel (bgp_prun prun)
{
  if (prun->t_gr_stale)
    {
      BGP_TIMER_OFF (prun->t_gr_stale);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s graceful restart stalepath timer stopped", prun->name);
    }
} ;

#if 0
/* BGP peer is stopped by the error. */
static int
bgp_stop_with_error (bgp_prun prun)
{
  /* Double start timer. */
  prun->idle_hold_time_secs  *= 2;

  /* Overflow check. */
  if (prun->idle_hold_time_secs  >= (60 * 2))
    prun->idle_hold_time_secs  = (60 * 2);

  bgp_stop (prun);

  return 0;
}
#endif


/*==============================================================================
 * For the given interface name, get a suitable address so can bind() before
 * connect() so that we use the required interface.
 *
 * If has a choice, uses address that best matches the peer's address.
 */
extern sockunion
bgp_peer_get_ifaddress(bgp_prun prun, const char* ifname, sa_family_t af)
{
  struct interface* ifp ;
  struct connected* connected;
  struct listnode*  node;
  prefix   best_prefix ;
  prefix_t peer_prefix[1] ;
  int   best, this ;

  if (prun->cops_r.ifname[0] == '\0')
    return NULL ;

  ifp = if_lookup_by_name (prun->cops_r.ifname) ;
  if (ifp == NULL)
    {
      zlog_err("Peer %s interface %s is not known", prun->name, ifname) ;
      return NULL ;
    } ;

  prefix_from_sockunion(peer_prefix, prun->su_name) ;
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

  zlog_err("Peer %s interface %s has no suitable address", prun->name, ifname);

  return NULL ;
} ;

