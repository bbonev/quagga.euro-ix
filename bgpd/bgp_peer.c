/* BGP Peer Handling
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
#include <zebra.h>

#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"

#include "bgpd/bgp_session.h"
#include "bgpd/bgp_connection.h"
#include "bgpd/bgp_engine.h"
#include "bgpd/bgp_peer_index.h"
#include "bgpd/bgpd.h"
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
 * Creation and destruction of peer objects
 */
static bgp_peer bgp_peer_free(bgp_peer peer) ;

/*------------------------------------------------------------------------------
 * Allocate new peer object, implicitly locked.
 *
 * Points new peer object at owning bgp instance -- that pointer owns a lock
 * on that bgp instance.
 *
 * Note that this does not add the structure to any list.
 *
 * Returns:  address of new peer object.
 *
 * NB: the peer object owns a lock on itself.
 *
 *     That lock is cleared by bgp_peer_delete().
 */
extern bgp_peer
bgp_peer_new (bgp_inst bgp, peer_type_t type)
{
  bgp_peer peer;
  struct servent *sp;

  /* bgp argument is absolutely required
   */
  assert (bgp != NULL) ;

  /* Allocate new peer: point it at owning bgp instance and take a lock on that.
   *
   * All types of peer have a bgp parent.
   */
  peer = XCALLOC (MTYPE_BGP_PEER, sizeof (bgp_peer));

  peer->bgp  = bgp_lock (bgp) ;
  peer->type = type ;

  /*
  bgp_inst      bgp;
  peer_type_t   type ;
  qafx_set_t    group_membership ;
  bgp_peer_state_t  state ;
  bgp_peer_config_t config ;
  bgp_peer_index_entry  peer_ie ;
  bgp_session           session ;
  bgp_peer_session_state_t session_state ;
  uint          lock;
  peer_group group ;
  bgp_peer_sort_t  sort ;
  sockunion su_name ;
  char*     host ;
  char*     desc ;
  time_t uptime;
  time_t readtime;
  time_t resettime;
  struct zlog *log;
  bool       shared_network;
  bgp_nexthop_t nexthop;
  peer_down_t   last_reset;
  bgp_note      note ;
  qafx_set_t af_configured ;
  qafx_set_t af_running ;
  peer_rib      prib[qafx_count] ;
  uint          af_running_count ;
  peer_rib      prib_running[qafx_count] ;
  struct dl_base_pair(bgp_route_refresh) rr_pending ;
  bgp_session_args_t  args
  as_t          change_local_as ;
  bool          change_local_as_prepend ;
  bool          disable_connected_check ;
  uint16_t      weight ;
  uint          config_mrai ;
  peer_status_bits_t    sflags;
  bgp_peer_idle_state_t idle ;
  bgp_cops_t    cops ;
  qtimer        qt_restart ;
  qtime_t       idle_hold_time ;
  uint          v_asorig;
  uint          v_gr_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;
  uint32_t established;
  uint32_t dropped;
  uint16_t table_dump_index;
  */

  /* Set some default values -- common to all types of peer object
   */
  peer->idle_hold_time = QTIME(peer->bgp->default_idle_hold_min_secs) ;

  peer->v_asorig  = BGP_DEFAULT_ASORIGINATE;
  peer->state     = bgp_pDown;

  qassert(peer->weight   == 0) ;

  /* The cops object is embedded,
   *
   */






  /* Get service port number
   */
  sp = getservbyname ("bgp", "tcp");
  peer->cops.port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);

  return bgp_peer_lock (peer) ;         /* initial, self reference      */
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

  /* Creating a new peer sets:
   *
   * Since we are creating a real peer, set that and add self to the bgp
   * instance's list of peer.  Note that this counts as a reference to the
   * peer.
   */
  peer = bgp_peer_new (bgp, PEER_TYPE_REAL);
  listnode_add_sort (bgp->peer, bgp_peer_lock (peer));

  qassert(peer->state == bgp_pDown) ;

  /* Set basic properties of peer -- evaluate and set the peer sort.
   *
   * Evaluation of the peer sort depends on the peer->args.remote_as, the
   * peer->bgp->my_as,  and the confederation state.
   *
   * Setting the sort also sets values which depend on the sort:
   *
   *   * peer->args.local_as  -- set to bgp->my_as, except...
   *                             ...if eBGP and CONFED is enabled, when must be
   *                                bgp->confed_id
   *
   *   * peer->v_routeadv     -- if the sort changes, then we set the default
   *                             value for the new sort.
   *
   *   * peer->ttl and        -- if the sort changes, then we set the default
   *       peer->gtsm            values for the new sort.
   */
  peer->su_name         = sockunion_dup(su) ;
  peer->host            = sockunion_su2str (su, MTYPE_BGP_PEER_HOST) ;
  peer->args.remote_as  = remote_as;
  peer->args.local_id   = bgp->router_id;

  qassert(peer->sort            == BGP_PEER_UNSPECIFIED) ;
  qassert(peer->args.remote_as  != BGP_ASN_NULL) ;
  qassert(peer->args.local_as   == BGP_ASN_NULL) ;
  qassert(peer->change_local_as == BGP_ASN_NULL) ;

  peer_sort_set(peer, peer_sort(peer)) ;

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
}

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

  bgp = peer->bgp ;

  /* Once peer is pDeleting it should be impossible to find in order to
   * bgp_peer_delete() it !
   */
  assert (peer->state != bgp_pDeleting);

  if (peer->type == PEER_TYPE_REAL)
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
          struct listnode *pn;
          pn = listnode_lookup (peer->group->peer, peer) ;

          assert(pn != NULL) ;

          bgp_peer_unlock (peer);       /* group->peer list reference   */
          list_delete_node (peer->group->peer, pn);

          peer->group = NULL;
        } ;
    } ;

  /*
  bgp_inst      bgp;
  peer_type_t   type ;
  qafx_set_t    group_membership ;
  bgp_peer_state_t  state ;
  bgp_peer_config_t config ;
  bgp_peer_index_entry  peer_ie ;
  bgp_session           session ;
  bgp_peer_session_state_t session_state ;
  uint          lock;
  peer_group group ;
  bgp_peer_sort_t  sort ;
  sockunion su_name ;
  char*     host ;
  char*     desc ;
  time_t uptime;
  time_t readtime;
  time_t resettime;
  struct zlog *log;
  bool       shared_network;
  bgp_nexthop_t nexthop;
  peer_down_t   last_reset;
  bgp_note      note ;
  qafx_set_t af_configured ;
  qafx_set_t af_running ;
  peer_rib      prib[qafx_count] ;
  uint          af_running_count ;
  peer_rib      prib_running[qafx_count] ;
  struct dl_base_pair(bgp_route_refresh) rr_pending ;
  bgp_session_args_t  args
  as_t          change_local_as ;
  bool          change_local_as_prepend ;
  bool          disable_connected_check ;
  uint16_t      weight ;
  uint          config_mrai ;
  peer_status_bits_t    sflags;
  bgp_peer_idle_state_t idle ;
  bgp_cops_t    cops ;
  qtimer        qt_restart ;
  qtime_t       idle_hold_time ;
  uint          v_asorig;
  uint          v_gr_restart;
  struct thread *t_gr_restart;
  struct thread *t_gr_stale;
  uint32_t established;
  uint32_t dropped;
  uint16_t table_dump_index;
  */








  /* Password configuration
   */
  if (peer->password)
    {
      XFREE (MTYPE_PEER_PASSWORD, peer->password);
      peer->password = NULL;
    }

  /* Delete from bgp->peer list, if required.
   */
  if (peer->type == PEER_TYPE_REAL)
    {
      struct listnode *pn;
      pn = listnode_lookup (bgp->peer, peer) ;

      assert(pn != NULL) ;

      bgp_peer_unlock (peer);   /* bgp peer list reference      */
      list_delete_node (bgp->peer, pn);
    } ;

  /* Discard rsclient ribs which are owned by group
   * and cross-check rib pointer and PEER_FLAG_RSERVER_CLIENT.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib prib ;

      prib = peer->prib[qafx] ;
      if (prib == NULL)
        continue ;

      if (peer->config.af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)
        {
          if (prib->af_group_member)
            peer->config.af_flags[qafx] &= ~PEER_AFF_RSERVER_CLIENT ;
        } ;
    } ;

  /* Can now clear any rsclient ribs.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib prib ;

      prib = peer->prib[qafx] ;
      if (prib == NULL)
        continue ;

      bgp_clear_rsclient_rib(peer, qafx) ;

      peer->config.af_flags[qafx] &= ~PEER_AFF_RSERVER_CLIENT ;
    } ;

  /* Have now finished with any rsclient ribs
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    peer->prib[qafx] = bgp_table_finish (peer->prib[qafx]) ;

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
 * increase reference count on a struct peer
 */
extern bgp_peer
bgp_peer_lock (bgp_peer peer)
{
  ++peer->lock ;
  return peer;
}

/*------------------------------------------------------------------------------
 * decrease reference count on a struct peer
 *
 * If is last reference, the structure is freed and NULL returned
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

  if (peer->type == PEER_TYPE_REAL)
    --bm->peer_linger_count ;

  bgp = peer->bgp ;

  if (peer->desc)
    XFREE (MTYPE_PEER_DESC, peer->desc);

  /* Discard name and text form thereof
   */
  peer->su_name = sockunion_free(peer->su_name);

  if (peer->host != NULL)
    XFREE (MTYPE_BGP_PEER_HOST, peer->host) ;   /* sets peer->host NULL */

  bgp_sync_delete (peer);

  memset (peer, 0, sizeof (struct peer));
  peer->lock = -54321 ;
  XFREE (MTYPE_BGP_PEER, peer);

  bgp_unlock(bgp);

  return NULL ;
} ;

/*==============================================================================
 * Finding peer objects and state of same
 */



/*------------------------------------------------------------------------------
 * Look-up peer by its address in the given bgp instance or all instances.
 *
 * If the given 'bgp' is NULL, try all bgp instances.
 *
 * Returns:  peer address (of *real* peer) if found -- NULL if not found
 */
extern bgp_peer
peer_lookup (bgp_inst bgp, sockunion su)
{
  bgp_peer peer;

  if (bgp != NULL)
    {
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          if (sockunion_same (peer->su_name, su))
            return peer;
        } ;
    }
  else
    {
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
        {
          if (bgp != NULL)
            {
              peer = peer_lookup (bgp, su) ;
              if (peer != NULL)
                return peer ;
            } ;
        } ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Look-up peer by its address in the given bgp instance or all instances.
 *
 * If the given 'bgp' is NULL, try *all* bgp instances.
 *
 * Returns:  peer address (of *real* peer) if found -- NULL if not found
 */
extern bgp_peer
peer_lookup_vty (vty vty, bgp_inst bgp, const char* peer_str, qafx_t qafx)
{
  sockunion_t su[1] ;
  bgp_peer    peer;

  if (! sockunion_str2su (su, peer_str))
    {
      vty_out (vty, "Malformed neighbor address: %s\n", peer_str);
      return NULL ;
    }

  peer = peer_lookup (NULL, su);
  if (peer == NULL)
    {
      vty_out (vty, "%% No such neighbor\n");
      return NULL;
    } ;

  if ((qafx != qafx_undef) && !peer_family_is_active(peer, qafx))
    {
      vty_out (vty, "%% Neighbor not activated in address family\n");
      return NULL;
    } ;

  return peer ;
} ;

/*------------------------------------------------------------------------------
 * Peer comparison function for sorting.
 *
 * The list of peers hung from the parent bgp instance uses this to keep the
 * list in peer "name" order.
 */
extern int
peer_cmp (bgp_peer p1, bgp_peer p2)
{
  return sockunion_cmp (p1->su_name, p2->su_name);
}

/*------------------------------------------------------------------------------
 * Fill given buffer with the given "uptime".
 *
 * Note that this is a time period -- not an actual time.
 */
extern char*
peer_uptime (time_t uptime, char *buf, size_t len)
{
  time_t period;
  struct tm *tm;

  /* Check buffer length.
   */
  if (len < BGP_UPTIME_LEN)
    {
      zlog_warn ("peer_uptime (): buffer shortage %lu", (u_long)len);
      /* XXX: should return status instead of buf... */
      snprintf (buf, len, "<error>");
      return buf;
    }

  /* If there is no connection has been done before print `never'.
   */
  if (uptime == 0)
    {
      snprintf (buf, len, "never");
      return buf;
    }

  /* Get current time.
   */
  period = bgp_clock () - uptime;
  tm = gmtime (&period);

  /* Making formatted timer strings.
   */
#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND 60*60*24*7

  if (period < ONE_DAY_SECOND)
    snprintf (buf, len, "%d:%02d:%02d",         /* 7..8 characters      */
              tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (period < ONE_WEEK_SECOND)
    snprintf (buf, len, "%dd%02dh%02dm",        /* 8 characters         */
              tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    snprintf (buf, len, "%dw%dd%02dh",          /* 7 or more characters */
              tm->tm_yday/7, tm->tm_yday - ((tm->tm_yday/7) * 7), tm->tm_hour);

  return buf;
} ;

/*==============================================================================
 * Address Family activation and deactivation.
 *
  */
static void peer_deactivate_family (bgp_peer peer, qafx_t qafx) ;
static bool peer_is_disabled(bgp_peer peer) ;

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
  peer_rib   prib ;
  qafx_bit_t qb ;

  qb = qafx_bit(qafx) ;

  prib = peer_family_prib(peer, qafx) ;

  if (prib == NULL)
    {
      /* Create address family configuration.
       */
      qassert(!(peer->af_configured & qb)) ;

      prib = peer_rib_new(peer, qafx) ;
      peer->af_configured |= qb ;
    } ;

  if ((qafx != qafx_ipv4_unicast) && !peer->args.can_capability
                                  && !peer->args.cap_af_override)
    enable = false ;

  if (peer->type == PEER_TYPE_REAL)
    {
      qafx_set_t af_was_enabled ;       /* old value    */

      if (enable)
        prib->af_status &= ~PEER_AFS_DISABLED ;
      else
        prib->af_status |=  PEER_AFS_DISABLED ;

      af_was_enabled = peer->args.can_af ;

      if (enable && !peer_is_disabled(peer) && !bm->reading_config)
        peer->args.can_af = af_was_enabled |  qb ;
      else
        peer->args.can_af = af_was_enabled & ~qb ;

      if (peer->args.can_af != af_was_enabled)
        {
          /* The enabled state of one or more address families has changed.
           *
           * For address families which have been disabled, we withdraw all
           * routes and discard the adj-out.
           *
           * For address families which have been enabled:
           */
          switch (peer->state)
            {
              case bgp_pDown:
                qassert(af_was_enabled == qafx_set_empty) ;
                bgp_peer_enable(peer) ;
                break ;

              case bgp_pStarted:
                qassert(af_was_enabled != qafx_set_empty) ;
                bgp_peer_enable(peer) ;
                break ;

              case bgp_pEstablished:
                qassert(af_was_enabled != qafx_set_empty) ;
                bgp_peer_down(peer, PEER_DOWN_AF_ACTIVATE) ;
                break ;

              case bgp_pDown:
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
  peer_rib  prib ;

  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_SUCCESS ;

  if (peer->type == PEER_TYPE_GROUP_CONF)
    {
      struct peer_group *group;
      struct listnode *node, *nnode;
      struct peer* group_member ;

      group = peer->group;

      for (ALL_LIST_ELEMENTS (peer->group->peer, node, nnode, group_member))
        {
          peer_rib  m_prib ;

          m_prib = peer_family_prib(group_member, qafx) ;

          if ((m_prib != NULL) && m_prib->af_group_member)
            return BGP_ERR_PEER_GROUP_MEMBER_EXISTS;
        }
    }
  else
    {
      if (prib->af_group_member)
        return BGP_ERR_PEER_BELONGS_TO_GROUP;
    }
  /* If we arrive here, the peer is either:
   *
   *   - a real peer which is not a group member for this afi/safi
   *
   *   - a group.
   *
   * De-activate the address family configuration.
   */
  peer_deactivate_family (peer, qafx);

  /* Deal with knock on effect on real peer
   */
  if (peer->type == PEER_TYPE_REAL)
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
  peer_rib prib ;
  int i;
  bgp_orf_name orf_name ;

  prib = peer->prib[qafx] ;
  if (prib != NULL)
    return ;

  peer->prib[qafx] = prib = peer_rib_new(peer, qafx) ;

  /* Set default neighbor send-community.
   */
  if (! bgp_option_check (BGP_OPT_CONFIG_CISCO))
    peer->config.af_flags[qafx] |= (PEER_AFF_SEND_COMMUNITY |
                                    PEER_AFF_SEND_EXT_COMMUNITY) ;

  /* Set defaults for neighbor maximum-prefix -- unset
   */
  bgp_peer_pmax_reset(prib) ;
} ;

/*------------------------------------------------------------------------------
 * Reset the given prib's pmax settings.
 */
extern prefix_max
bgp_peer_pmax_reset(peer_rib prib)
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
 * Deactivate the given address family for the given peer.
 *
 * Dismantles all address-family specific configuration, which means that
 * dismantles the peer_rib for the address family.
 */
static void
peer_deactivate_family (bgp_peer peer, qafx_t qafx)
{
  peer_rib prib ;
  int i;

  prib = peer->prib[qafx] ;
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

  /* Clear all neighbor's address family flags.
   */
  peer->config.af_flags[qafx] = 0 ;
  prib->af_status             = 0 ;

  /* Clear ORF info
   */
  prib->orf_plist = prefix_bgp_orf_delete(prib->orf_plist) ;

  /* Can now free the peer_rib structure.
   */
  peer->prib[qafx] = peer_rib_free(prib) ;
} ;

/*------------------------------------------------------------------------------
 * Is the peer currently disabled ?
 */
static bool
peer_is_disabled(bgp_peer peer)
{
  return (peer->cops.conn_state == bc_is_shutdown) ||
         (peer->sflags & PEER_STATUS_PREFIX_OVERFLOW) ;
} ;

/*==============================================================================
 *
 */

/*------------------------------------------------------------------------------
 * Peer Group comparison function for sorting.
 *
 * The list of groups hung from the parent bgp instance uses this to keep the
 * list in group "name" order.
 */
extern int
peer_group_cmp (peer_group g1, peer_group g2)
{
  return strcmp (g1->name, g2->name);
} ;

/*------------------------------------------------------------------------------
 * Create a Peer Group stucture
 */
static struct peer_group *
peer_group_new (void)
{
  return (struct peer_group *) XCALLOC (MTYPE_PEER_GROUP,
                                        sizeof (struct peer_group));
}

/*------------------------------------------------------------------------------
 * Destroy a Peer Group stucture
 */
static void
peer_group_free (struct peer_group *group)
{
  XFREE (MTYPE_PEER_GROUP, group);
}

/*------------------------------------------------------------------------------
 * Lookup group in given bgp instance.
 *
 * NB: unlike peer_lookup(), this will NOT scan all bgp instances if bgp is
 *     NULL -- will CRASH instead.
 */
extern peer_group
peer_group_lookup (bgp_inst bgp, const char* name)
{
  struct peer_group *group;
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
extern peer_group
peer_group_get (bgp_inst bgp, const char* name)
{
  peer_group group;

  group = peer_group_lookup (bgp, name);
  if (group == NULL)
    {
      bgp_peer  conf ;

      group = peer_group_new ();
      conf  = bgp_peer_new(bgp, PEER_TYPE_GROUP_CONF) ;
      conf->group = group;

      group->bgp  = bgp;                /* the conf owns a lock */
      group->name = strdup (name);
      group->peer = list_new ();
      group->conf = bgp_peer_lock (conf);

      listnode_add_sort (bgp->group, group);

      if (! bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4))
        conf->afc[qafx_ipv4_unicast] = true ;

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
peer_group_delete (peer_group group)
{
  bgp_inst bgp;
  bgp_peer peer;
  struct listnode *node, *nnode;

  bgp = group->bgp;

  for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
    {
      /* Deleting a peer-group deletes all the peers which are bound to it.
       *
       * Note that the pointer to the group structure is cleared first, to
       * stop bgp_peer_delete() from deleting the peer from the list !!
       *
       * TODO ... seems not to decrement the lock which the list has on the
       *          peer object ?
       */
      peer->group = NULL;
      bgp_peer_delete (peer);
    } ;

  list_delete (group->peer) ;

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
  peer_rib prib ;

  prib = peer->prib[qafx] ;

  assert(prib != NULL) ;

  /* Discard the rsclient prib
   */
  bgp_clear_rsclient_rib (peer, qafx);
  peer->prib[qafx] = bgp_table_finish (peer->prib[qafx]);

  /* Discard import policy unconditionally
   */
  prib->rmap[RMAP_IMPORT] = route_map_clear_ref(prib->rmap[RMAP_IMPORT]) ;

  /* Discard export policy unless should be kept.
   */
  if (!keep_export)
    prib->rmap[RMAP_EXPORT] = route_map_clear_ref(prib->rmap[RMAP_EXPORT]) ;
} ;

/*------------------------------------------------------------------------------
 * Perform 'hard' clear of given peer -- reset it !
 */
extern void
peer_clear (bgp_peer peer)
{
  /* Overrides any Max Prefix issues.
   */
  bgp_peer_restart_timer_cancel (peer) ;

  /* Overrides any idle hold timer
   */
  peer->idle_hold_time = QTIME(peer->bgp->default_idle_hold_min_secs) ;

  bgp_peer_down(peer, PEER_DOWN_USER_RESET) ;
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
peer_clear_soft (bgp_peer peer, qafx_t qafx, bgp_clear_type_t stype)
{
  peer_rib prib ;

  if (peer->state != bgp_pEstablished)
    return BGP_SUCCESS ;                /* Nothing to do        */

  prib = peer_family_prib(peer, qafx) ;

  if (prib == NULL)
    return BGP_ERR_AF_UNCONFIGURED;

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
            bgp_check_local_routes_rsclient (peer, qafx);
            bgp_soft_reconfig_rsclient_in (peer, qafx);
          } ;
        break ;

      case BGP_CLEAR_SOFT_OUT:
      case BGP_CLEAR_SOFT_BOTH:
        bgp_announce_family (peer, qafx);
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
        if (prib->af_status & PEER_AFS_ORF_PFX_CAN_SEND)
          {
            if (prib->plist[FILTER_IN] != NULL)
              {
                /* If have sent ORF, send 'remove' previous ORF, but 'defer'
                 * refresh.  Then send current state of ORF and ask for
                 * 'immediate' refresh.
                 */
                if (prib->af_status & PEER_AFS_ORF_PFX_SENT)
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
                if (prib->af_status & PEER_AFS_ORF_PFX_SENT)
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
          bgp_soft_reconfig_in (peer, qafx);
        else if (peer->session->args->can_rr != bgp_form_none)
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
peer_sort (bgp_peer peer)
{
  bgp_peer_sort_t sort ;
  bgp_inst bgp;

  bgp = peer->bgp ;
  assert(bgp != NULL) ;         /* absolutely impossible        */

  if (peer->type == PEER_TYPE_GROUP_CONF)
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
          if (peer->args.remote_as == bgp->my_as)
            sort = BGP_PEER_IBGP ;
          else
            sort = BGP_PEER_EBGP ;
        }
      else
        {
          struct peer *peer1;

          peer1 = listnode_head (peer->group->peer);
          if (peer1 != NULL)
            {
              if (peer1->args.remote_as == bgp->my_as)
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
      if (peer->args.remote_as == bgp->my_as)
        sort = BGP_PEER_IBGP ;
      else if (bgp_confederation_peers_check (bgp, peer->args.remote_as))
        sort = BGP_PEER_CBGP ;
      else
        sort = BGP_PEER_EBGP ;

      qassert((peer->sort == BGP_PEER_UNSPECIFIED) || (peer->sort == sort)) ;
    } ;

  return sort ;
}

/*------------------------------------------------------------------------------
 * Set the given peer->sort and set/update things which depend on that:
 *
 *   * peer->args.local_as  -- set to bgp->my_as, except...
 *                             ...if eBGP and CONFED is enabled, when must be
 *                                bgp->confed_id, except...
 *                             ...if eBGP and change_local_as is enabled, when
 *                                must be peer->change_local_as
 *
 *   * peer->config_mrai    -- if the sort changes, then we discard any
 *                             explicit MRAI, reverting to the default.
 *
 *   * peer->ttl and        -- if the sort changes, then we set the default
 *       peer->gtsm            values for the new sort.
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
      peer->config.set  &= ~PEER_CONFIG_MRAI ;
      peer->config_mrai  = 0 ;          /* for completeness     */
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

      if ( (old_ttl != peer->cops.ttl) ||
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
          peer_rib prib ;

          prib = peer_family_prib(peer, qafx) ;
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
 * peer global config reset, after unbinding from group !
 */
static void
peer_global_config_reset (bgp_peer peer)
{
  qassert(peer->type == PEER_TYPE_REAL) ;

  peer->weight = 0;
  peer->change_local_as = BGP_ASN_NULL ; /* PEER_FLAG_LOCAL_AS_NO_PREPEND...
                                          * ...cleared below.
                                          * Unset *before* setting local_as */
  peer_sort_init_local_as(peer, peer->sort) ;
  peer_sort_init_ttl_gtsm(peer, peer->sort) ;

  sockunion_clear(&peer->cops.su_local) ;
  if (!(peer->config.set & PEER_CONFIG_INTERFACE))
    memset(peer->cops.ifname, 0, IF_NAMESIZE) ;
  confirm(sizeof(peer->cops.ifname) == IF_NAMESIZE) ;

  peer->config.flags    = 0 ;
  peer->config.set     &= ~PEER_CONFIG_GROUP_OVERRIDE ;

  peer->args.holdtime_secs  = peer->bgp->default_holdtime ;
  peer->args.keepalive_secs = peer->bgp->default_keepalive ;
  peer->config_mrai         = peer_get_mrai(peer) ; /* ~PEER_CONFIG_MRAI */

  peer->cops.idle_hold_max_secs  = peer->bgp->default_idle_hold_max_secs ;
  peer->cops.connect_retry_secs  = peer->bgp->default_connect_retry_secs ;
  peer->cops.accept_retry_secs   = peer->bgp->default_accept_retry_secs ;
  peer->cops.open_hold_secs      = peer->bgp->default_open_hold_secs ;
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
    peer->args.local_as = peer->bgp->my_as ;
  else if (peer->change_local_as != BGP_ASN_NULL)
    peer->args.local_as = peer->change_local_as ;
  else
    peer->args.local_as = peer->bgp->ebgp_as ;
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

  if      (peer->args.remote_as == peer->bgp->my_as)
    sort = BGP_PEER_IBGP ;
  else if (bgp_confederation_peers_check (peer->bgp, peer->args.remote_as))
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

  if (change && (peer->type == PEER_TYPE_REAL))
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

  peer = peer_lookup (bgp, su);

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
              if (*p_as != bgp->my_as)
                {
                  *p_as = peer->args.remote_as;
                  return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
          else
            {
              if (*p_as == bgp->my_as)
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
      if (peer_lookup (NULL, su) != NULL)
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

/*==============================================================================
 * Side effect handling for changing of peer flags
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

/* Structure which defines the side effect of one or more flags.
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
  peer_change_type_t type;

  /* Peer down cause
   */
  peer_down_t peer_down;
};

/*------------------------------------------------------------------------------
 * Look up action for given flags.
 *
 * Returns: address of required peer_flag_action structure,
 *      or: NULL if no action found for the given combination of flags.
 *
 * This mechanism is generally used when setting/clearing one flag at a time.
 *
 * The table may contain entries with more than one flag.  In these cases,
 * any combination of those flags may be set/cleared together -- any flags
 * which are not mentioned are not affected.
 *
 * The given flags value must either exactly match a single flag entry, or be
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



/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * Change specified peer "flag".
 *
 * These are states of a peer or peer-group which are conceptually "flags", the
 * setting/clearing of which have a variety of side effects.
 *
 * The setting/clearing of a state for a peer-group, forces the new peer-group
 * state onto all peer-group members -- whether or not the state of the
 * peer-group changes.
 *
 * NB: this only sets the configuration.... XXX XXX XXX XXX XXX
 */
extern bgp_ret_t
bgp_peer_flag_modify(bgp_peer peer, peer_flag_t flag, bool set)
{
  peer_group group;
  bool group_conf, group_member ;
  peer_flag_t gflags, mask ;

  group = peer->group ;

  group_conf   = (peer->type == PEER_TYPE_GROUP_CONF) ;
  group_member = !group_conf && (group != NULL) ;

  /* First step, discover if we are about to change the setting, and
   * do any validity checking required.
   */
  if (group_member)
    gflags = group->conf->config.flags ;
  else
    gflags = 0 ;

  mask = flag ;
  switch (flag)
    {
      /* Cannot clear shutdown on group members if is set at group level.
       */
      case PEER_FLAG_SHUTDOWN:
        if (!set && (gflags & flag))
          return BGP_ERR_PEER_GROUP_SHUTDOWN ;

        if (set)
          peer->config.was_shutdown = true ;
        break ;

      /* Limitations on group member passive/active if:
       *
       *   * no limitations if the group has no setting.
       *
       *   * cannot clear either flag if the group has a setting.
       *
       *   * cannot set something different if the group has a setting.
       */
      case PEER_FLAG_PASSIVE:
      case PEER_FLAG_ACTIVE:
        mask = PEER_FLAG_PASSIVE | PEER_FLAG_ACTIVE ;

        if (gflags & mask)
          {
            if (!set || ((gflags & mask) != flag))
              return BGP_ERR_PEER_GROUP_HAS_THE_FLAG ;
          } ;

        qassert(!(gflags & mask) || set) ;

        break ;

      /* Cannot clear PEER_FLAG_DISABLE_CONNECTED_CHECK if group has it.
       */
      case PEER_FLAG_DISABLE_CONNECTED_CHECK:
        break ;

      /* Strict Capability checking
       *
       * Cannot be strict and either disable capabilities or override address
       * families.
       *
       * This test works for peer, group or group-member.  For group-member
       * it works because if the group has one or both disable/override, then
       * the member will have at least those.
       *
       * The usual check, below, will prevent the clearing of strict on a member
       * if the group has it set.
       */
      case PEER_FLAG_STRICT_CAP_MATCH:
        if (set && (peer->config.flags & (PEER_FLAG_OVERRIDE_CAPABILITY |
                                          PEER_FLAG_DONT_CAPABILITY)))
          return BGP_ERR_PEER_FLAG_CONFLICT_1 ;

        if (set)
          mask |= (PEER_FLAG_OVERRIDE_CAPABILITY | PEER_FLAG_DONT_CAPABILITY) ;
        break ;

      /* Overriding Address Family Capabilities -- cannot while strict.
       *
       * A group member will have strict set if it is set in the group.
       */
      case PEER_FLAG_OVERRIDE_CAPABILITY:
        if (set && (peer->config.flags & PEER_FLAG_STRICT_CAP_MATCH))
          return BGP_ERR_PEER_FLAG_CONFLICT_2 ;

        if (set)
          mask |= PEER_FLAG_STRICT_CAP_MATCH ;

        break ;

      /* Disabling Capabilities -- cannot disable while have Strict !
       */
      case PEER_FLAG_DONT_CAPABILITY:
        if (set && (peer->config.flags & PEER_FLAG_STRICT_CAP_MATCH))
          return BGP_ERR_PEER_FLAG_CONFLICT_3 ;

        if (set)
          mask |= PEER_FLAG_STRICT_CAP_MATCH ;

        break ;

      /* Dynamic Capability support
       *
       * Similar to passive/active -- cannot set something different in a
       * member.
       */
      case PEER_FLAG_DYNAMIC_CAPABILITY:
      case PEER_FLAG_DYNAMIC_CAPABILITY_DEP:
        if (set)
          return BGP_ERR_INVALID_VALUE ;

        mask = PEER_FLAG_DYNAMIC_CAPABILITY | PEER_FLAG_DYNAMIC_CAPABILITY_DEP ;

        if (gflags & mask)
          {
            if (!set || ((gflags & mask) != flag))
              return BGP_ERR_PEER_GROUP_HAS_THE_FLAG ;
          } ;

        qassert(!(gflags & mask) || set) ;

        break ;

      /* Anything else is not valid.
       */
      case PEER_FLAG_LOCAL_AS_NO_PREPEND:       /* not handled here !   */
      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
  } ;

  /* General purpose reject attempt to clear a flag which is set by the group,
   * and reject setting of a flag which is cleared by the group.
   */
  if (set)
    {
      if ((~gflags & PEER_FLAG_GROUP_CLEAR) & flag)
        return BGP_ERR_PEER_GROUP_HAS_THE_FLAG ;
    }
  else
    {
      if (( gflags & PEER_FLAG_GROUP_SET) & flag)
        return BGP_ERR_PEER_GROUP_HAS_THE_FLAG ;
    } ;

  /* Apply the change to the peer/peer-group, if any.
   *
   * Knock down all the bits in the mask, then if is set, set the given flag.
   */
  peer->config.flags = (peer->config.flags & ~mask) | (set ? flag : 0) ;

  /* And if is group, apply the change to all the group members.
   *
   * Note that this imprints the group state onto the peer state, for this
   * collection of flags.
   */
  if (group_conf)
    {
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        peer->config.flags = (peer->config.flags & ~mask) | (set ? flag : 0) ;
    } ;

  return BGP_SUCCESS ;
} ;

/*==============================================================================
 * peer->af_flags setting/clearing -- complete with side-effects.
 *
 * Table of actions for changing peer->af_flags
 *
 * NB: some flags may be set/cleared together, in any combination.
 */
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
    {  PEER_AFF_ORF_PFX_SM
     | PEER_AFF_ORF_PFX_RM,
                 true, peer_change_reset,      PEER_DOWN_CONFIG_CHANGE },
    {  PEER_AFF_NEXTHOP_LOCAL_UNCHANGED,
                false, peer_change_reset_out,  PEER_DOWN_NULL },
    { 0, false, peer_change_none, PEER_DOWN_NULL }
  };

static void peer_af_flag_modify_action (peer_rib prib, peer_flag_action action,
                              qafx_t qafx, peer_af_flag_bits_t flag, bool set) ;

/*------------------------------------------------------------------------------
 * Set specified peer->af_flags flag.
 */
extern bgp_ret_t
peer_af_flag_set (bgp_peer peer, qafx_t qafx, peer_af_flag_bits_t flag)
{
  return peer_af_flag_modify (peer, qafx, flag, true);
}

/*------------------------------------------------------------------------------
 * Clear specified peer->af_flags flag.
 */
extern bgp_ret_t
peer_af_flag_unset (bgp_peer peer, qafx_t qafx, peer_af_flag_bits_t flag)
{
  return peer_af_flag_modify (peer, qafx, flag, false);
}

/*------------------------------------------------------------------------------
 * Change specified peer->af_flags flag.
 *
 * See: peer_af_flag_action_list above.
 */
extern bgp_ret_t
peer_af_flag_modify (bgp_peer peer, qafx_t qafx, peer_af_flag_bits_t flag,
                                                                       bool set)
{
  struct listnode *node, *nnode;
  peer_group  group;
  peer_flag_action action;
  bool  group_conf ;
  bool  group_member ;
  peer_rib prib ;

  action = peer_flag_action_find (peer_af_flag_action_list, flag);

  /* No flag action is found.
   */
  if (action == NULL)
    return BGP_ERR_INVALID_FLAG;

  /* Address family must be activated.
   */
  prib = peer_family_prib(peer, qafx) ;
  if (prib == NULL)
    return BGP_ERR_PEER_INACTIVE;

  group = peer->group;

  group_conf   = (peer->type == PEER_TYPE_GROUP_CONF) ;
  group_member = !group_conf && prib->af_group_member ;

  /* Not for peer-group member.
   */
  if (action->not_for_member && prib->af_group_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

 /* Special check for reflector client.
  */
  if ((flag & PEER_AFF_REFLECTOR_CLIENT) && (peer_sort(peer) != BGP_PEER_IBGP))
    return BGP_ERR_NOT_INTERNAL_PEER;

  /* Special check for remove-private-AS.
   */
  if ((flag & PEER_AFF_REMOVE_PRIVATE_AS) && (peer_sort(peer) == BGP_PEER_IBGP))
    return BGP_ERR_REMOVE_PRIVATE_AS;

  /* When unset a peer-group member's flag we have to check peer-group
   * configuration.
   *
   * What this means is that a peer-group member may set a flag for itself,
   * which may override the group's value for the flag.  But a peer-group
   * member may NOT clear a flag for itself if the flag is set in the group.
   *
   * NB: if is attempting to clear more than one flag, then will be blocked if
   *     the group has any one of them set.
   */
  if (! set && group_member)
    if (group->conf->config.af_flags[qafx] & flag)
      return BGP_ERR_PEER_GROUP_HAS_THE_FLAG;

  /* Execute action for real peer or for group.
   */
  peer_af_flag_modify_action (prib, action, qafx, flag, set) ;

  /* Peer group member updates.
   */
  if (group_conf)
    {
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          prib = peer_family_prib(peer, qafx) ;
          if (prib == NULL)
            continue ;

          if (! prib->af_group_member)
            continue;

          peer_af_flag_modify_action(prib, action, qafx, flag, set) ;
        } ;
    } ;

  return BGP_SUCCESS ;
}

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
peer_af_flag_modify_action (peer_rib prib, peer_flag_action action,
                                qafx_t qafx, peer_af_flag_bits_t flag, bool set)
{
  peer_af_flag_bits_t* p_aff ;
  peer_af_flag_bits_t  now ;

  p_aff = &prib->peer->config.af_flags[qafx] ;
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

  if (prib->peer->type != PEER_TYPE_REAL)
    return;

  if ((action->flag == PEER_AFF_SOFT_RECONFIG) && !set)
    {
      if (prib->peer->state == bgp_pEstablished)
        bgp_clear_adj_in (prib);
    }
  else
    {
      /* Perform action after change of state of a peer for the given afi/safi.
       *
       * If has to down the peer (drop any existing session and restart), then
       * requires a peer_down_t to record why.
       */
      switch (action->type)
        {
          case  peer_change_none:
            break ;

          case peer_change_reset:
            bgp_peer_down(prib->peer, action->peer_down) ;
            break ;

          case peer_change_reset_in:
            if (peer->state == bgp_pEstablished)
              {
                if (prib->peer->session->args->can_rr != bgp_form_none)
                  bgp_route_refresh_send (prib, 0, 0, 0);
                else
                  bgp_peer_down(prib->peer, action->peer_down);
              } ;
            break ;

          case peer_change_reset_out:
            bgp_announce_family (prib->peer, qafx) ;
                                /* Does nothing if !pEstablished        */
          break ;

          default:
            zabort("unknown peer_change_type") ;
            break ;
        } ;
    } ;
} ;

/*==============================================================================
 * Peer Group and Peer related functions
 */
static void peer_group2peer_config_copy (bgp_peer peer, peer_group group,
                                                                  qafx_t qafx) ;

/*------------------------------------------------------------------------------
 * Unset peer-group's remote-as
 */
extern bgp_ret_t
peer_group_remote_as_delete (peer_group group)
{
  struct peer *peer;
  struct listnode *node, *nnode;

  if (group->conf->args.remote_as == BGP_ASN_NULL)
    return BGP_SUCCESS ;

  for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
    {
      /* Unsetting a peer-group remote-as deletes all the peers which are bound
       * to it.
       *
       * Note that the pointer to the group structure is cleared first, to
       * stop bgp_peer_delete() from deleting the peer from the list !!
       *
       * TODO ... seems not to decrement the lock which the list has on the
       *          peer object ?
       */
      peer->group = NULL;
      bgp_peer_delete (peer);
    } ;

  list_delete_all_node (group->peer);

  group->conf->args.remote_as = BGP_ASN_NULL ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set peer-group's remote-as
 */
extern bgp_ret_t
peer_group_remote_as (bgp_inst bgp, const char* group_name, as_t* p_as)
{
  peer_group group;
  bgp_peer   peer;
  struct listnode *node, *nnode;

  group = peer_group_lookup (bgp, group_name);
  if (group == NULL)
    return BGP_ERR_INVALID_VALUE ;

  if (group->conf->args.remote_as == *p_as)
    return BGP_SUCCESS ;

  /* When we setup peer-group AS number all peer group member's AS
   * number must be updated to same number.
   */
  peer_as_change (group->conf, *p_as);

  for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
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
                                     peer_group group, qafx_t qafx, as_t* p_asn)
{
  bgp_peer        peer ;
  peer_rib        prib ;
  bgp_peer_sort_t group_sort ;
  bool first_member ;

  /* Check peer group's address family.
   */
  if (! peer_family_is_active(group->conf, qafx))
    return BGP_ERR_PEER_GROUP_AF_UNCONFIGURED;

  /* Lookup the peer in the given bgp instance.
   */
  peer = peer_lookup (bgp, su) ;

  /* Create a new peer -- iff is unique and group specifies a remote-as.
   */
  if (peer == NULL)
    {
      if (group->conf->args.remote_as == BGP_ASN_NULL)
        return BGP_ERR_PEER_GROUP_NO_REMOTE_AS ;

      if (peer_lookup (NULL, su) != NULL)
        return BGP_ERR_PEER_EXISTS ;

      peer = bgp_peer_create (su, bgp, group->conf->args.remote_as, qafx);
      peer->group = group;
      peer->group_membership |= qafx_bit(qafx) ;

      peer = bgp_peer_lock (peer); /* group->peer list reference */
      listnode_add (group->peer, peer);

      peer_group2peer_config_copy(peer, group, qafx);

      return BGP_SUCCESS ;      /* Done         */
    } ;

  qassert(peer->type == PEER_TYPE_REAL) ;
  qassert(bgp == peer->bgp) ;

  prib = peer->prib[qafx] ;

  /* When the peer already belongs to peer group, check the consistency.
   */
  if ((peer->group != NULL) && (prib != NULL))
    {
      if (peer->group == group)
        {
          /* Already in the given group -- done if already in the group for
           * the given AFI/SAFI.
           */
          if (peer->group_membership & qafx_bit(qafx))
            {
              qassert(prib->af_group_member) ;
              return BGP_SUCCESS ;      /* AFI/SAFI already bound       */
            } ;
        }
      else
        {
          /* Cannot change which group an AFI/SAFI is bound to, nor can
           * we bind an AFI/SAFI to a different group to the one we are
           * already a member of.
           */
          qassert(strcmp (peer->group->name, group->name) != 0) ;

          if (prib->af_group_member)
            return BGP_ERR_PEER_GROUP_CANT_CHANGE;
          else
            return BGP_ERR_PEER_GROUP_MISMATCH;
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
  if (peer->group == NULL)
    {
      peer->group = group;

      peer = bgp_peer_lock (peer); /* group->peer list reference */
      listnode_add (group->peer, peer);
    }
  else
    assert (peer->group == group) ;

  peer->group_membership &= ~qafx_bit(qafx) ;

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
  if (peer->config.af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)
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
      peer->config.af_flags[qafx] &= ~PEER_AFF_RSERVER_CLIENT ;

      peer_rsclient_unset(peer, qafx,
               (group->conf->config.af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)) ;
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
peer_group_unbind (bgp_peer peer, peer_group group, qafx_t qafx)
{
  qassert(peer->type == PEER_TYPE_REAL) ;

  if (!(peer->group_membership & qafx_bit(qafx)))
    return BGP_SUCCESS ;                /* not in this afi/safi         */

  if (group != peer->group)
    return BGP_ERR_PEER_GROUP_MISMATCH; /* quit if not member of this group */

  /* So is a member of this group for this afi/safi.
   *
   * This is an implied deactivation for this peer.  That is taken care of in
   * bgp_peer_down().
   */
  peer->group_membership &= ~qafx_bit(qafx) ;
  peer_deactivate_family (peer, qafx) ;

  /* If is now no longer a member of this group in any afi/safi at all,
   * then remove the group setting and remove from the list of peers attached
   * to the group.
   *
   * If the group has a 'remote-as' set, then we can delete the peer altogether.
   */
  if (peer->group_membership == qafx_set_empty)
    {
      assert (listnode_lookup (group->peer, peer));

      bgp_peer_unlock (peer);   /* peer group list reference    */
      listnode_delete (group->peer, peer);
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
peer_group2peer_config_copy (bgp_peer peer, peer_group group, qafx_t qafx)
{
  enum
    {
      in  = FILTER_IN,
      out = FILTER_OUT,
    } ;

  bgp_peer   conf;
  peer_rib   prib, g_prib ;

  conf    = group->conf;

  prib   = peer->prib[qafx] ;
  g_prib = conf->prib[qafx] ;

  /* Various sets of flags apply
   */
  peer->config.flags          = conf->config.flags;
  peer->config.af_flags[qafx] = conf->config.af_flags[qafx] ;

  /* remote-as, local-as & allowas-in
   *
   * For completeness we set the sort after
   */
  if (conf->args.remote_as != BGP_ASN_NULL)
    peer->args.remote_as = conf->args.remote_as;

  peer_sort_set(peer, peer_sort(peer)) ;

  if (conf->change_local_as != BGP_ASN_NULL)
    peer->change_local_as = conf->change_local_as;

  prib->allowas_in = g_prib->allowas_in ;

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
  peer->config.set = (peer->config.set & ~PEER_CONFIG_GROUP_OVERRIDE) |
                     (conf->config.set &  PEER_CONFIG_GROUP_OVERRIDE) ;

  peer->weight              = conf->weight;
  peer->args.holdtime_secs  = conf->args.holdtime_secs ;
  peer->args.keepalive_secs = conf->args.keepalive_secs ;
  peer->config_mrai         = conf->config_mrai ;

  peer->cops.connect_retry_secs = conf->cops.connect_retry_secs ;
  peer->cops.accept_retry_secs  = conf->cops.accept_retry_secs ;
  peer->cops.open_hold_secs     = conf->cops.open_hold_secs ;

  /* password apply
   */
  strncpy(peer->cops.password, conf->cops.password, BGP_PASSWORD_SIZE) ;
  confirm(sizeof(peer->cops.password) == BGP_PASSWORD_SIZE) ;

  /* maximum-prefix
   */
  prib->pmax = g_prib->pmax;

  /* route-server-client
   */
  if (group->conf->config.af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)
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

  /* update-source apply -- ifname takes precedence.
   */
  if (!(peer->config.set & PEER_CONFIG_INTERFACE))
    {
      if      (conf->cops.ifname[0] != '\0')
        sockunion_clear(&peer->cops.su_local) ;
      else if (sockunion_family(&conf->cops.su_local) != AF_UNSPEC)
        sockunion_copy(&peer->cops.su_local, &conf->cops.su_local) ;

      strncpy(peer->cops.ifname, conf->cops.ifname, IF_NAMESIZE) ;
      confirm(sizeof(peer->cops.ifname) == IF_NAMESIZE) ;
    } ;

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

  if (prib->rmap[RMAP_RS_IN] == NULL)
    prib->rmap[RMAP_RS_IN] = route_map_set_ref(g_prib->rmap[RMAP_RS_IN]) ;

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


/*==============================================================================
 * Enabling and disabling a peer.
 */
static void bgp_peer_stop (bgp_peer peer, bool nsf) ;
static void bgp_peer_reset_enable(bgp_peer peer) ;
static void bgp_peer_down_notify(bgp_peer peer, peer_down_t why_down,
                                                                bgp_note note) ;
static void bgp_peer_shutdown(bgp_peer peer) ;
static bgp_note bgp_peer_map_peer_down(peer_down_t why_down) ;
static peer_down_t bgp_peer_map_notification(bgp_note noten) ;

static void bgp_peer_change_status (bgp_peer peer, bgp_peer_state_t new_state);
static void bgp_peer_timers_set (bgp_peer peer) ;



static int bgp_graceful_restart_timer_expire (struct thread *thread);
static void bgp_graceful_restart_timer_cancel (struct peer* peer) ;
static int bgp_graceful_stale_timer_expire (struct thread *thread);
static void bgp_graceful_stale_timer_cancel (struct peer* peer) ;


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
 *   - pClearing -- cannot restart the peer yet, that will happen in due course.
 *
 *   - pDeleted  -- Enable peer makes no sense...  asserts invalid.
 *
 * TODO: assert !pEstablished in bgp_peer_enable ?
 */
extern void
bgp_peer_enable(bgp_peer peer)
{
  switch (peer->state)
    {
      case bgp_pDown:
        if (peer->args.can_af == qafx_set_empty)
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
        if (peer->args.can_af == qafx_set_empty)
          break ;

        qassert(!peer_is_disabled(peer)) ;
        qassert(peer->session->peer_state == bgp_pssStopped) ;

        peer->state = bgp_pStarted ;
        fall_through ;

      case bgp_pStarted:
        /* The peer is already enabled... so we
         *
         *
         *
         */
        if (peer->af_configured == qafx_set_empty)
          {
            break ;
          } ;

        qassert(   !(peer->flags  & PEER_FLAG_SHUTDOWN)
                && !(peer->sflags & PEER_STATUS_PREFIX_OVERFLOW) ) ;

        qassert(peer->session->peer_state == bgp_pssStopped) ;

        bgp_peer_reset_enable(peer) ;   /* tidy up      */
        bgp_session_config(peer) ;
        bgp_peer_change_status (peer, bgp_pStarted) ;

        break ;




        if (bgp_session_is_active(peer->session))
          assert(peer->session_state != bgp_psEstablished) ;
        else
          {
            if ( (peer->af_configured != qafx_set_empty)
                && !(peer->flags  & PEER_FLAG_SHUTDOWN)
                && !(peer->sflags & PEER_STATUS_PREFIX_OVERFLOW) )
              {
                /* enable the session
                 */
                bgp_peer_reset_enable(peer) ;   /* tidy up      */
                bgp_session_config(peer) ;
                bgp_peer_change_status (peer, bgp_pStarted) ;
              } ;
          } ;
        break ;

      case bgp_pEstablished:
        break ;

      case bgp_pDeleting:
        zabort("cannot enable a pDeleting peer") ;
        break ;

      default:
        zabort("unknown peer->state") ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Update "open_state", if possible, for given peer -- in pUp state.
 *
 * This is used when the peer is pUp, but an address family has been
 * enabled or disabled, or any of the bgp_open_state has been changed.
 *
 * pUp means that a session enable message has been sent to the BGP
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
 * NB: does nothing for peers which are not pUp.
 */
extern void
bgp_peer_update_open_state(bgp_peer peer, peer_down_t why_down)
{
  bgp_open_state open_send_new, open_send_was ;

  if (peer->state != bgp_pStarted)
    return ;

  /* Make a new bgp_open_state to be used and swap that in, if possible.
   */
  open_send_new = bgp_peer_open_state_init_new(NULL, peer) ;
  open_send_was = NULL ;

  BGP_SESSION_LOCK(peer->session) ;     /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  if (peer->session->start_state < open_sent)
    {
      open_send_was            = peer->session->open_send ;
      peer->session->open_send = open_send_new ;
    } ;

  BGP_SESSION_UNLOCK(peer->session) ;   /*->->->->->->->->->->->->->->->*/

  /* If we could not swap in the new open state, then we have to down the
   * peer -- it will come up again automatically in the new state.
   */
  if (open_send_was == NULL)
    {
      bgp_peer_down(peer, why) ;

      open_send_was = open_send_new ;
    }

  /* Discard the now unwanted bgp_open_state.
   */
  bgp_open_state_free(open_send_was) ;
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
 *   1. pUp or pEstablished
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
bgp_peer_down(bgp_peer peer, peer_down_t why_down)
{
  bgp_peer_down_notify(peer, why_down, NULL) ;
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
bgp_peer_down_error(bgp_peer peer,
                                bgp_nom_code_t code, bgp_nom_subcode_t subcode)
{
  bgp_peer_down_error_with_data (peer, code, subcode, NULL, 0);
}

/*------------------------------------------------------------------------------
 * Notify the far end that an error has been detected, and close down the
 * session.
 *
 * Same as above, except that this accepts a data part for the notification
 * message -- but len may be 0 (and data may be null iff len == 0).
 */
extern void
bgp_peer_down_error_with_data (bgp_peer peer,
                               bgp_nom_code_t code, bgp_nom_subcode_t subcode,
                                               const byte* data, size_t datalen)
{
  bgp_note note ;
  note = bgp_note_new_with_data(code, subcode, data, datalen);

  bgp_peer_down_notify(peer, bgp_peer_map_notification(note), note) ;
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
bgp_peer_down_notify(bgp_peer peer, peer_down_t why_down, bgp_note note)
{
  /* Deal with session (if any)
   */
  if (note == NULL)
    note = bgp_peer_map_peer_down(why_down) ;

  if (bgp_session_disable(peer, note))
    peer->session->note = bgp_note_copy(peer->session->note, note) ;
  else
    bgp_note_free(note) ;

#if 0
  /* This logging is (more or less) part of commit 1212dc1961...
   *
   * TODO worry how useful this is and whether is not already done elsewhere.
   */

  /* Log some                                                           */
  switch (why_down)
    {
      case PEER_DOWN_USER_RESET:
        zlog_info ("Notification sent to neighbor %s: User reset", peer->host);
        break ;

      case PEER_DOWN_USER_SHUTDOWN:
        zlog_info ("Notification sent to neighbor %s: shutdown", peer->host);
        break ;

      case PEER_DOWN_NOTIFY_SEND:
        zlog_info ("Notification sent to neighbor %s: type %u/%u",
                   peer->host, code, sub_code);
        break ;

      default:
        zlog_info ("Notification sent to neighbor %s: configuration change",
                peer->host);
        break ;
    } ;
#endif

  /* Now worry about the state of the peer
   */
  if ((why_down == PEER_DOWN_USER_SHUTDOWN)
                                     || (why_down == PEER_DOWN_NEIGHBOR_DELETE))
    bgp_peer_shutdown(peer) ;

  if (why_down != PEER_DOWN_NULL)
    peer->last_reset = why_down ;

  switch (peer->state)
    {
      case bgp_pDown:

      case bgp_pStarted:
        assert(!bgp_session_is_active(peer->session)
                  || (peer->session->peer_state == bgp_session_psLimping)) ;

        bgp_peer_nsf_stop (peer) ;        /* flush stale routes, if any   */

        bgp_peer_enable(peer) ;           /* Restart if possible.         */

        break ;

      case bgp_pEstablished:
        assert(peer->session->peer_state == bgp_session_psLimping) ;

        bgp_peer_stop(peer, why_down == PEER_DOWN_NSF_CLOSE_SESSION) ;

        break ;

      case bgp_pDown:
        assert(   (peer->session->peer_state == bgp_session_psLimping)
               || (peer->session->peer_state == bgp_session_psStopped) ) ;

        bgp_peer_nsf_stop (peer) ;        /* flush stale routes, if any   */

        break ;

      case bgp_pDeleting:
        assert(   (peer->session == NULL)
               || (peer->session->peer_state == bgp_session_psStopped)
               || (peer->session->peer_state == bgp_session_psLimping) ) ;
        break ;

      default:
        zabort("unknown peer->state") ;
        break ;
    } ;
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
bgp_peer_stop (bgp_peer peer, bool nsf)
{
  assert( (peer->state == bgp_pStarted) ||
          (peer->state == bgp_pEstablished) ) ;

  /* bgp log-neighbor-changes of neighbor Down
   */
  if (peer->state == bgp_pEstablished)
    if (bgp_flag_check (peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
      zlog_info ("%%ADJCHANGE: neighbor %s Down %s", peer->host,
                                       peer_down_str [(int) peer->last_reset]) ;

  /* Change state to pDown -- turns off all timers.
   */
  bgp_peer_change_status(peer, bgp_pDown) ;

  peer->dropped++ ;
  peer->resettime = bgp_clock () ;

  /* Clear out routes, with NSF if required.
   *
   * Sets PEER_STATUS_NSF_WAIT iff NSF and at least one afi/safi is enabled
   * for NSF.  Clears PEER_STATUS_NSF_WAIT otherwise.
   */
  bgp_clear_all_routes (peer, nsf) ;

  /* graceful restart
   */
  if (CHECK_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT))
    {
      if (BGP_DEBUG (events, EVENTS))
        {
          zlog_debug ("%s graceful restart timer started for %d sec",
                      peer->host, peer->v_gr_restart);
          zlog_debug ("%s graceful restart stalepath timer started for %d sec",
                      peer->host, peer->bgp->stalepath_time);
        } ;

      BGP_TIMER_ON (peer->t_gr_restart, bgp_graceful_restart_timer_expire,
                    peer->v_gr_restart) ;

      if (nsf)
        BGP_TIMER_ON (peer->t_gr_stale, bgp_graceful_stale_timer_expire,
                                                    peer->bgp->stalepath_time) ;
    } ;

  /* Reset uptime.
   */
  peer->uptime = bgp_clock ();

#ifdef HAVE_SNMP
  bgpTrapBackwardTransition (peer);
#endif /* HAVE_SNMP */
} ;

/*------------------------------------------------------------------------------
 * Clear out any stale routes, cancel any Graceful Restart timers.
 *
 * NB: may still be pClearing from when peer went down leaving these stale
 *     routes.
 *
 * NB: assumes clearing stale routes will complete immediately !
 */
static void
bgp_peer_clear_all_stale_routes (struct peer *peer)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;

      if ((prib != NULL) && prib->nsf)
        bgp_clear_stale_route (peer, qafx);
    } ;

  bgp_graceful_restart_timer_cancel(peer) ;
  bgp_graceful_stale_timer_cancel(peer) ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT);
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
 * Also clears down all NSF flags.
 *
 * If is PEER_STATUS_NSF_WAIT, MUST be pIdle or pClearing.
 *
 * NB: may still be pClearing from when peer went down leaving these stale
 *     routes.
 *
 * NB: assumes clearing stale routes will complete immediately !
 */
static void
bgp_peer_nsf_stop (struct peer *peer)
{
  qafx_t qafx ;

  if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_WAIT))
    {
      assert( (peer->state == bgp_pStarted)
           || (peer->state == bgp_pDown) ) ;

      bgp_peer_clear_all_stale_routes (peer) ;
    } ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;

      if (prib != NULL)
        prib->nsf = false ;
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
bgp_peer_shutdown(struct peer *peer)
{
  bgp_peer_flag_modify(peer, PEER_FLAG_SHUTDOWN, true) ;
  bgp_peer_restart_timer_cancel(peer) ;

  bgp_peer_nsf_stop (peer) ;
} ;

/*------------------------------------------------------------------------------
 * Reset peer "active" state -- tidies things up, ready for peer to be enabled.
 *
 * NB: can be called any number of times.
 */
static void
bgp_peer_reset_enable(bgp_peer peer)
{
  qafx_t qafx ;

  assert(peer->state != bgp_pEstablished) ;

  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE) ;

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp_orf_name orf_name ;
      peer_rib     prib ;

      /* Reset all negotiated variables
       */
      /* peer address family flags
       */
      prib = peer->prib[qafx] ;

      if (prib != NULL)
        {
          prib->nsf            = false ;
          prib->af_status      = 0 ;
        } ;

      /* Received ORF prefix-filter
       */
      prib->orf_plist = prefix_bgp_orf_delete(prib->orf_plist) ;
    } ;
} ;


/*==============================================================================
 * Session state changes and their effect on the peer state.
 */
static void bgp_session_has_established(bgp_session session);
static void bgp_session_has_stopped(bgp_session session, bgp_note note) ;
static void bgp_session_has_disabled(bgp_session session);


/*------------------------------------------------------------------------------
 * BGP Session has been Established.
 */
static void
bgp_session_has_established(bgp_session session)
{
  bgp_peer         peer ;
  bgp_session_args args ;
  qafx_t           qafx ;
  int  nsf_af_count ;

  peer = session->peer ;
  assert(peer->session == session) ;            /* Safety first         */

  /* Peer state change.
   *
   * This stops all timers other than the Graceful Stale Timer.
   */
  bgp_peer_change_status (peer, bgp_pEstablished);

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

  peer->args->remote_id = session->open_recv->args->remote_id;
  peer->af_running = args->can_af ;

  /* Clear down the state of all known address families, and set anything
   * we now know.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      peer_rib   prib ;
      qafx_bit_t qb ;

      prib = peer->prib[qafx] ;
      qb   = qafx_bit(qafx) ;

      qassert((prib != NULL) == (peer->af_configured & qb)) ;

      if (prib == NULL)
        continue ;              /* not configured       */

      prib->af_status &= (PEER_AFS_DISABLED) ;

      if (!(peer->af_running & qb))
        continue ;              /* not running          */

      prib->af_status |= PEER_AFS_RUNNING ;

      if (args->gr.can_preserve & qb)
        {
          prib->af_status |= PEER_AFS_GR_CAN_PRESERVE ;
          if (args->gr.has_preserved & qb)
            prib->af_status |= PEER_AFS_GR_HAS_PRESERVED ;
        } ;

      if (args->can_orf_pfx[qafx] & (ORF_SM | ORF_SM_pre))
        prib->af_status |= PEER_AFS_ORF_PFX_CAN_SEND ;

      if (args->can_orf_pfx[qafx] & (ORF_RM | ORF_RM_pre))
        prib->af_status |= PEER_AFS_ORF_PFX_MAY_RECV ;
    } ;

    peer->v_gr_restart = args->gr.restart_time;

    /* TODO: should we do anything with this? */
  #if 0
    int         restarting ;            /* Restart State flag                 */
  #endif

  /* Install next hop, as required.
   */
  bgp_nexthop_set(session->cops->su_local,
                  session->cops->su_remote, &peer->nexthop, peer) ;

  /* Clear last notification data -- Routing Engine private field
   *
   * This is done because XXX XXX XXX XXX
   */
  peer->session->note = bgp_note_free(peer->session->note);

  /* Increment established count.
   */
  peer->established++;

  /* bgp log-neighbor-changes of neighbor Up
   */
  if (bgp_flag_check (peer->bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
    zlog_info ("%%ADJCHANGE: neighbor %s Up", peer->host);

  /* graceful restart
   */
  UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_WAIT) ;

  nsf_af_count = 0 ;
  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      peer_rib prib ;

      /* If the afi/safi has been negotiated, and have received Graceful
       * Restart capability, and is Restarting, and will Gracefully Restart
       * the afi/safi, then....
       */
      if (get_qSAFI(qafx) == qSAFI_MPLS_VPN)
        continue ;              /* Don't do graceful restart for MPLS VPN  */

      prib = peer_family_prib(peer, qafx) ;
      if (prib == NULL)
        {
          qassert(!(peer->af_configured & qafx_bit(qafx))) ;
          continue ;
        } ;

      qassert(peer->af_configured & qafx_bit(qafx)) ;

      if (prib->af_status & PEER_AFS_GR_CAN_PRESERVE)
        {
          /* If have held onto routes for this afi/safi but forwarding has
           * not been preserved, then clean out the stale routes.
           *
           * Set NSF for this address family for next time.
           */
          if (prib->nsf && ! (prib->af_status & PEER_AFS_GR_HAS_PRESERVED))
            bgp_clear_stale_route (peer, qafx);

          prib->nsf = true ;
          nsf_af_count++;
        }
      else
        {
          /* Remove stale routes, if any for this afi/safi            */
          if (prib->nsf)
            bgp_clear_stale_route (peer, qafx);

          prib->nsf = false ;
        }
    }

  if (nsf_af_count)
    SET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);
  else
    {
      UNSET_FLAG (peer->sflags, PEER_STATUS_NSF_MODE);
      bgp_graceful_stale_timer_cancel(peer) ;
    }

  /* Send route-refresh when ORF is enabled
   *
   * First update is deferred until ORF or ROUTE-REFRESH is received
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      peer_rib prib ;

      prib = peer_family_prib(peer, qafx) ;
      if (prib == NULL)
        continue ;

      if (prib->af_status & PEER_AFS_ORF_PFX_CAN_SEND)
        bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                BGP_ORF_WTR_IMMEDIATE, false /* not remove */) ;

      if (prib->af_status & PEER_AFS_ORF_PFX_MAY_RECV)
         prib->af_status |= PEER_AFS_ORF_PFX_WAIT ;
    } ;

  /* Reset uptime, send current table.
   */
  peer->uptime = bgp_clock ();

  bgp_announce_all_families (peer);

#ifdef HAVE_SNMP
  bgpTrapEstablished (peer);
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
static void
bgp_session_has_stopped(bgp_session session, bgp_note note)
{
#if 0
  peer_down_t why_down ;
#endif

  bgp_peer peer ;

  peer = session->peer ;

  /* If the peer is NULL that means that the peer to whom this session
   * once belonged has been dismantled.... this is
   */










  assert(peer->session == session) ;            /* Safety first         */

  assert(bgp_session_is_active(session)) ;      /* "confused" if not    */









  if (peer->state == bgp_pEstablished)
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
      t = QTIME(bgp_clock() - peer->uptime) ;
      m = QTIME(peer->bgp->default_idle_hold_max_secs) ;

      n = (t + m) * 2 / m ;
      if (n > 3)
        m = m / (1 << (n - 3)) ;

      h = peer->idle_hold_time * 2 ;

      if (h > m)
        h = m ;

      if (h < QTIME(peer->bgp->default_idle_hold_min_secs))
        h = QTIME(peer->bgp->default_idle_hold_min_secs) ;

      peer->idle_hold_time = h ;
    } ;





    peer = session->peer ;
    assert(peer->session == session) ;    /* Safety first         */

    session->peer_state = bgp_session_psDown ;

    /* Immediately discard any other messages for this session.
     */
    mqueue_revoke(re_nexus->queue, session, 0) ;

    /* If the session is marked "delete_me", do that.
     *
     * Otherwise, Old session now gone, so re-enable peer if now possible.
     */
    if (session->delete_me)
      bgp_session_delete(peer) ;  /* NB: this may also delete the peer.   */
    else
      bgp_peer_enable(peer);



#if 0
  if (note == NULL)
    why_down = PEER_DOWN_CLOSE_SESSION ;
  else
    {
      if (note->received)
        why_down = PEER_DOWN_NOTIFY_RECEIVED ;
      else
        why_down = bgp_peer_map_notification(note) ;
    } ;

  bgp_peer_down_notify(peer, why_down, note) ;
#endif

} ;

/*==============================================================================
 *
 */


/*------------------------------------------------------------------------------
 * Graceful Restart timer has expired.
 *
 * MUST be pIdle or pClearing -- transition to pEstablished cancels this timer.
 *
 * Clears out stale routes and stops the Graceful Restart Stale timer.
 *
 * Clears down PEER_STATUS_NSF_MODE & PEER_STATUS_NSF_WAIT.
 */
static int
bgp_graceful_restart_timer_expire (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_gr_restart = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s graceful restart timer expired", peer->host) ;

  bgp_peer_nsf_stop (peer) ;

  return 0;
}

/*------------------------------------------------------------------------------
 * Cancel any Graceful Restart timer
 *
 * NB: does NOT do anything about any stale routes or about any stale timer !
 */
static void
bgp_graceful_restart_timer_cancel (struct peer* peer)
{
  if (peer->t_gr_restart)
    {
      BGP_TIMER_OFF (peer->t_gr_restart);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s graceful restart timer stopped", peer->host);
    }
} ;

/*------------------------------------------------------------------------------
 * Graceful Restart Stale timer has expired.
 *
 * SHOULD be pEstablished, because otherwise the Graceful Restart timer should
 * have gone off before this does, and cancelled this.
 *
 * To be safe, if not pEstablished, then MUST be pIdle or pClearing, so can do
 * bgp_peer_nsf_stop (peer).
 *
 * Clears out stale routes and stops the Graceful Restart Stale timer.
 *
 * Clears down PEER_STATUS_NSF_MODE & PEER_STATUS_NSF_WAIT.
 */
static int
bgp_graceful_stale_timer_expire (struct thread *thread)
{
  struct peer *peer;

  peer = THREAD_ARG (thread);
  peer->t_gr_stale = NULL;

  if (BGP_DEBUG (events, EVENTS))
    zlog_debug ("%s graceful restart stalepath timer expired", peer->host);

  if (peer->state == bgp_pEstablished)
    bgp_peer_clear_all_stale_routes(peer) ;
  else
    bgp_peer_nsf_stop(peer) ;

  return 0;
}

/*------------------------------------------------------------------------------
 * Cancel any Graceful Restart Stale timer
 *
 * NB: does NOT do anything about any stale routes !
 */
static void
bgp_graceful_stale_timer_cancel (struct peer* peer)
{
  if (peer->t_gr_stale)
    {
      BGP_TIMER_OFF (peer->t_gr_stale);
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s graceful restart stalepath timer stopped", peer->host);
    }
} ;

#if 0
/* BGP peer is stopped by the error. */
static int
bgp_stop_with_error (struct peer *peer)
{
  /* Double start timer. */
  peer->idle_hold_time_secs  *= 2;

  /* Overflow check. */
  if (peer->idle_hold_time_secs  >= (60 * 2))
    peer->idle_hold_time_secs  = (60 * 2);

  bgp_stop (peer);

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
bgp_peer_get_ifaddress(bgp_peer peer, const char* ifname, sa_family_t af)
{
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

  return NULL ;
} ;

/*==============================================================================
 * Peer state values.
 *
 * These are functions to return the value of some peer state, where that may
 * depend on how the state is configured and/or what state the peer is in.
 *
 */

/*------------------------------------------------------------------------------
 * Get the AcceptRetryTime for the peer.
 *
 * The "AcceptRetryTime" is not an RFC value... it is invented here as the
 * time for which the connection accept logic will hold on to an incoming
 * connection waiting for a session to come up and claim it.
 *
 * During this time the other end should send an OPEN and sit in OpenSent
 * state -- where it will remain for the "OpenHoldTime", see below.
 *
 *   * TODO ... configuration for "AcceptRetryTime" ??
 *
 *   * otherwise, return peer->bgp->default_connect
 *
 * Returns: current effective value -- seconds
 */
extern uint
peer_get_accept_retry_time(bgp_peer peer)
{
  return peer->bgp->default_accept_retry_secs ;
} ;

/*------------------------------------------------------------------------------
 * Get the OpenHoldTime for the peer.
 *
 * The "OpenHoldTime" is not given that name in RFC4271, but is the "large"
 * value that the HoldTimer is set to on entry to OpenSent state.  Suggested
 * default value is 4 *minutes*.
 *
 *   * TODO ... configuration for OpenHoldTime ???
 *
 *   * otherwise, return peer->bgp->default_open_hold_secs
 *
 * Returns: current effective value -- seconds
 */
extern uint
peer_get_open_hold_time(bgp_peer peer)
{
  return peer->bgp->default_open_hold_secs ;
} ;

/*------------------------------------------------------------------------------
 * Get the MRAI for the peer.
 *
 *   * if is PEER_CONFIG_MRAI, return the peer->config_mrai
 *
 *   * otherwise, return peer->bgp->default_xbgp_mrai -- depending on the
 *     peer->sort (setting the peer->config_mrai).
 *
 * Returns: current effective value
 */
extern uint
peer_get_mrai(bgp_peer peer)
{
  if (CHECK_FLAG (peer->config.set, PEER_CONFIG_MRAI))
    return peer->config_mrai ;
  else
    {
      switch (peer->sort)
        {
          case BGP_PEER_IBGP:
            return peer->config_mrai = peer->bgp->default_ibgp_mrai ;

          case BGP_PEER_CBGP:
            return peer->config_mrai = peer->bgp->default_cbgp_mrai ;

          case BGP_PEER_EBGP:
          default:
            return peer->config_mrai = peer->bgp->default_ebgp_mrai ;
        } ;
    } ;
} ;

/*==============================================================================
 *
 */
static void bgp_peer_stop_running(bgp_peer peer, bgp_note note,
                                                         peer_down_t why_down) ;
static void bgp_peer_restart_timer_cancel (bgp_peer peer) ;

/*------------------------------------------------------------------------------
 * Something has changed in the peer->cops...
 */
extern void
bgp_peer_cops_changed()
{

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
bgp_peer_set_down(bgp_peer peer, bgp_peer_idle_state_t new_idle,
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

  /* The various forms of bc_is_down can escalate,
   */
  old_idle = peer->idle ;

  if (old_idle & bgp_pisDown)
    {
      /* Is already down, this may escalate, but has no effect on cops.
       */
      if ((old_idle & bgp_pisDown) < new_idle)
        peer->idle = new_idle | (old_idle & ~bgp_pisDown) ;

      confirm(bgp_pisDeconfigured > bgp_pisShutdown) ;
      confirm(bgp_pisShutdown     > bgp_pisNoAF) ;
      confirm(bgp_pisNoAF         > bgp_pisMaxPrefixStop) ;

      qassert( (peer->state != bgp_pStarted) &&
               (peer->state != bgp_pEstablished) ) ;
      qassert(peer->session_state != bgp_pssRunning) ;

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

  bgp_peer_restart_timer_cancel(peer) ;

  new_idle |= (old_idle & ~bgp_pisMaxPrefixWait) ;

  peer->idle = new_idle ;

  /* At this point: is now pisDown, but was not previously, so this is the
   *                                                      transition to pisDown.
   * Reflect the state into the peer->cops.
   */
  peer->cops.conn_state &= ~(bgp_csTrack | bgp_csRun) ;

  /* If the session is bgp_pssRunning then we need down the session and
   * acceptor.  Otherwise, we need to down just the acceptor.
   */
  switch (peer->session_state)
    {
      /* Make the transition to pResetting/pssLimping.  If was pEstablished,
       * then start the clearing process running.
       *
       * When the session responds with a session-has-stopped message, can make
       * the transition out of pResetting, if is ready to do so.
       */
      case bgp_pssRunning:
        qassert((peer->state == bgp_pStarted) ||
                (peer->state == bgp_pEstablished)) ;

        bgp_peer_stop_running(peer, note, why_down) ;
        break ;

      /* These states are unchanged by going pisDown.
       */
      case bgp_pssInitial:
      case bgp_pssDeleted:
        break ;

      /* Going pisDown will affect the acceptor.
       */
      case bgp_pssLimping:
      case bgp_pssStopped:
        bgp_session_new_cops(peer->session, &peer->cops) ;
        break ;
    } ;

  bgp_note_free(note) ;       /* done with (if any)   */
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
extern void
bgp_peer_set_idle(bgp_peer peer, bgp_peer_idle_state_t new_idle,
                                            bgp_note note, peer_down_t why_down)
{
  qassert((peer->state          == bgp_pStarted) ||
          (peer->state          == bgp_pEstablished) );
  qassert(peer->session_state   == bgp_pssRunning) ;
  qassert(peer->idle            == bgp_pisRunnable) ;
  qassert(peer->cops.conn_state &  bgp_csRun) ;

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

  peer->idle            |= new_idle ;
  peer->cops.conn_state &= ~bgp_csRun ;

  bgp_peer_stop_running(peer, note, why_down) ;
} ;

/*------------------------------------------------------------------------------
 * Stop the current pssRunning session session.
 *
 * If is pStarted, will stop the session -- unconditionally.
 *
 * If is pEstablished, will start the clearing process and set pisClearing.
 *
 * Expects: peer->idle            to not be pisRunnable, any more.
 *          peer->cops.conn_state to not be csRun, any more.
 *
 * NB: takes responsibility for the notification
 */
static void
bgp_peer_stop_running(bgp_peer peer, bgp_note note, peer_down_t why_down)
{
  qassert(peer->session_state   == bgp_pssRunning) ;
  qassert((peer->state          == bgp_pStarted) ||
          (peer->state          == bgp_pEstablished) );
  qassert(peer->idle            != bgp_pisRunnable) ;
  qassert(!(peer->cops.conn_state &  bgp_csRun)) ;

  if (note == NULL)
    note = bgp_peer_map_peer_down(why_down) ;

  bgp_session_stop(peer->session, note) ;
                                /* takes charge of the notification     */

  peer->session_state = bgp_pssLimping ;
  if (peer->state == bgp_pEstablished)
    bgp_peer_start_clearing(peer) ;             /* sets pisClearing     */

  // set the why_down state XXX XXX XXX

  bgp_peer_change_status(peer, bgp_pResetting) ;
} ;

/*------------------------------------------------------------------------------
 * Something in the connection options has changed, so may need to prod the
 * session.
 *
 *
 *
 */
extern void
bgp_peer_cops_change(bgp_peer peer)
{
  bgp_conn_state_t state ;
  bgp_cops         new_cops, cops_tx ;

  /* If we are reading the configuration file, we don't need to do anything at
   * all here.
   */
  if (bm->reading_config)
    return ;

  /* Worry...
   */
  state = peer->cops.conn_state ;

  if (state & bc_is_down)
    return ;                    /* nothing to do if (still down)        */

  new_cops = bgp_session_cops_make(peer) ;

  if (new_cops == NULL)
    return ;                    /* unchanged !                          */

  /* We have a changed set of cops...
   *
   */
  if (state == bc_is_up)
    {
      qassert(peer->session_state != bgp_pssLimping) ;

      if ( (peer->session_state == bgp_pssStopped) ||
           (peer->session_state == bgp_pssInitial) )
        {
          bgp_session_config(peer) ;
          peer->session_state = bgp_pssRunning ;
        } ;
    } ;

  cops_tx = bgp_cops_copy(NULL, new_cops) ;
  cops_tx = qa_swap_ptrs((void**)&peer->session->cops_tx, cops_tx) ;
  if (cops_tx != NULL)
    bgp_cops_free(cops_tx) ;

  // Boot Woot Woot
} ;


/*------------------------------------------------------------------------------
 * Something in the session arguments has changed, so may need to prod the
 * session.
 *
 */
extern void
peer_args_prod(bgp_peer peer)
{
  bgp_session_args  new_args, args_tx ;

  /* If the session is not up, then any change in arguments is moot.
   */
  if (peer->session_state != bgp_pssRunning)
    return ;

  new_args = bgp_session_cops_make(peer) ;

  if (new_args == NULL)
    return ;                    /* unchanged !                          */

  args_tx = bgp_session_args_copy(NULL, new_args) ;
  args_tx = qa_swap_ptrs((void**)&peer->session->args_tx, args_tx) ;
  if (args_tx != NULL)
    bgp_cops_free(args_tx) ;


  // Boot Woot Woot

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
 * Set new peer state.
 *
 * If state changes log state change if required and deal with dropping back to
 * pIdle.
 *
 * In any case, set timers for the new state -- so if state hasn't changed,
 * will restart those timers.
 */
static void
bgp_peer_change_status (bgp_peer peer, bgp_peer_state_t new_state)
{
  bgp_peer_state_t old_state ;

  old_state = peer->state ;

  if (old_state == new_state)
    return ;

  peer->state = new_state ;

  if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("peer %s went from %s to %s", peer->host,
                           map_direct(bgp_peer_status_map, old_state).str,
                           map_direct(bgp_peer_status_map, new_state).str) ;

  /* Tidying up on entry to new state.
   */
  switch (peer->state)
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
        bgp_graceful_restart_timer_cancel(peer) ;
        break;

      /* On entry to pResetting...
       */
      case bgp_pResetting:
        BGP_TIMER_OFF (peer->t_gr_restart);

        bgp_graceful_stale_timer_cancel(peer) ;
        break ;

      /* Take a rubust vuew of unknown states...
       */
      default:
        qassert(false) ;
        fall_through ;                  /* treat as pDeleting   */

      /* On entry to pDeleting, turn off all timers.
       */
      case bgp_pDeleting:
        BGP_TIMER_OFF (peer->t_gr_restart);
        BGP_TIMER_OFF (peer->t_gr_stale);
        break;
    } ;
} ;

/*==============================================================================
 * Peer Restart Timer Handling.
 */
static void bgp_peer_restart_timer_start(bgp_peer peer, qtime_t interval) ;
static void bgp_peer_restart_timer_expired (qtimer qtr, void* timer_info,
                                                            qtime_mono_t when) ;

/*------------------------------------------------------------------------------
 * Something has changed such that the peer may restart, if it can.
 *
 *
 *
 */
extern void
bgp_peer_may_restart(bgp_peer peer)
{
  /* If we are reading the configuration file, we don't need to do anything at
   * all here.
   *
   * If we are not runnable, then we need not restart.
   */
  if (bm->reading_config || (peer->idle != bgp_pisRunnable))
    return ;

  /* Keep bgp_pisReset, until timer expires and everything kicks off.
   */
  peer->idle = bgp_pisReset ;

  if ((peer->state == bgp_pDown) || (peer->session_state == bgp_pssStopped))
    bgp_peer_restart_timer_start(peer, QTIME(1)) ;
} ;



/*------------------------------------------------------------------------------
 * Check for maximum prefix ...
 */
extern bool
bgp_peer_pmax_check(peer_rib prib)
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
          zlog (prib->peer->log, LOG_INFO,
              "%%MAXPFXEXCEED: No. of %s prefix received from %s %u exceed, "
                "limit %u", get_qafx_name(prib->qafx), prib->peer->host,
                                         prib->pcount_recv, prib->pmax.limit) ;

          /* Set the trigger so we don't come back !
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

      qassert((prib->peer->state == bgp_pEstablished) &&
                                (prib->peer->session_state == bgp_pssRunning)) ;

      if (prib->pmax.restart == 0)
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix stop.", prib->peer->host) ;

          bgp_peer_set_down(prib->peer, bgp_pisMaxPrefixStop, note,
                                                         PEER_DOWN_MAX_PREFIX) ;
        }
      else
        {
          if (BGP_DEBUG (events, EVENTS))
            zlog_debug ("%s Maximum-prefix restart timer started for %d secs",
                                         prib->peer->host, prib->pmax.restart) ;
          bgp_peer_restart_timer_start(prib->peer, QTIME(prib->pmax.restart)) ;

          bgp_peer_set_idle(prib->peer, bgp_pisMaxPrefixWait, note,
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
          zlog (prib->peer->log, LOG_INFO,
            "%%MAXPFX: No. of %s prefix received from %s reaches %u, max %u",
            get_qafx_name(prib->qafx), prib->peer->host, prib->pcount_recv,
                                                             prib->pmax.limit);

          /* Set the trigger for limit.
           */
          prib->pmax.trigger = prib->pmax.limit ;
        } ;
    } ;

  return true ;                 /* OK to continue       */
} ;

/*------------------------------------------------------------------------------
 * Set the restart timer running.
 */
static void
bgp_peer_restart_timer_start(bgp_peer peer, qtime_t interval)
{
  static qrand_seq_t seed ;

  if (peer->qt_restart == NULL)
     peer->qt_restart = qtimer_init_new(NULL, re_nexus->pile, NULL, peer) ;

  qtimer_set_interval(peer->qt_restart, interval + qrand(seed, QTIME(0.25)),
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
bgp_peer_restart_timer_cancel (bgp_peer peer)
{
  if (peer->idle & bgp_pisMaxPrefixWait)
    {
      if (BGP_DEBUG (events, EVENTS))
        zlog_debug ("%s Maximum-prefix restart timer cancelled", peer->host) ;

      peer->idle &= ~bgp_pisMaxPrefixWait ;

      qassert(peer->qt_restart != NULL) ;
    } ;

  if (peer->qt_restart != NULL)
    qtimer_unset(peer->qt_restart) ;
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
  bgp_peer              peer;
  bgp_peer_idle_state_t idle ;

  peer = timer_info ;
  qassert(peer->qt_restart == qtr) ;

  idle = peer->idle ;

  /* If peer was down because of a max-prefix overflow, then clear that state,
   * and see if is now ready to restart.
   */
  if (BGP_DEBUG (events, EVENTS) && (idle & bgp_pisMaxPrefixWait))
    zlog_debug ("%s Maximum-prefix restart timer expired, restore peering",
                                                                   peer->host) ;

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

  if ( (idle != bgp_pisRunnable) || (peer->state != bgp_pDown)
                                 || (peer->session_state != bgp_pssStopped) )
    {
      peer->idle = idle | bgp_pisReset ;
      return ;
    }

  /* Set pisRunnable and proceed to start the session.
   */
  peer->idle             = bgp_pisRunnable ;
  peer->state            = bgp_pStarted ;
  peer->cops.conn_state |= bgp_csRun | bgp_csTrack ;

  bgp_session_start(peer->session);
} ;

