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
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_names.h"

#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "sockunion.h"
#include "prefix.h"
#include "thread.h"
#include "log.h"
#include "stream.h"
#include "memory.h"
#include "plist.h"
#include "mqueue.h"
#include "workqueue.h"
#include "if.h"

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
   */
  peer = XCALLOC (MTYPE_BGP_PEER, sizeof (bgp_peer));

  peer->bgp  = bgp_lock (bgp) ;
  peer->type = type ;

  /* Set some default values -- common to all types of peer object
   */
  peer->v_start   = BGP_INIT_START_TIMER;
  peer->v_asorig  = BGP_DEFAULT_ASORIGINATE;
  peer->state     = bgp_pDisabled;

  qassert(peer->weight   == 0) ;
  qassert(peer->password == NULL) ;

  /* Create buffers for a real peer.
   */
  if (peer->type == PEER_TYPE_REAL)
    {
      peer->ibuf = stream_new (BGP_STREAM_SIZE);
      peer->obuf_fifo = stream_fifo_new ();
      peer->work = stream_new (BGP_STREAM_SIZE);
    } ;

  /* Get service port number
   */
  sp = getservbyname ("bgp", "tcp");
  peer->port = (sp == NULL) ? BGP_PORT_DEFAULT : ntohs (sp->s_port);

  return bgp_peer_lock (peer) ;         /* initial, self reference      */
} ;

/*------------------------------------------------------------------------------
 * Create new BGP peer -- if an AFI/SAFI is given, activate & enable for that.
 *
 * Peer starts in pDisabled state.
 *
 * This is creating a PEER_TYPE_REAL, which is placed on the bgp->peer list.
 * (This is NOT creating a peer-group config object, or a "self" peer object.)
 *
 * The 'local_as' will be: bgp->as        unless...
 *                         bgp->confed_id ...we are a CONFED and the peer is
 *                                           external to the CONFED.
 *
 * Returns:  address of new peer
 *
 * NB: the peer is locked once, by virtue of having been added to the bgp->peer
 *     list.
 */
extern bgp_peer
bgp_peer_create (sockunion su, bgp_inst bgp, as_t remote_as, qafx_t qafx)
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

  qassert(peer->state == bgp_pDisabled) ;

  /* Set basic properties of peer -- evaluate and set the peer sort.
   *
   * Evaluation of the peer sort depends on the peer->as, the peer->bgp->as,
   * and the confederation state.
   *
   * Setting the sort also sets values which depend on the sort:
   *
   *   * peer->local_as       -- set to bgp->as, except...
   *                             ...if eBGP and CONFED is enabled, when must be
   *                                bgp->confed_id
   *
   *   * peer->v_routeadv     -- if the sort changes, then we set the default
   *                             value for the new sort.
   *
   *   * peer->ttl and        -- if the sort changes, then we set the default
   *       peer->gtsm            values for the new sort.
   */
  peer->su_name     = *su;
  peer->as          = remote_as;
  peer->local_id    = bgp->router_id;

  qassert(peer->sort            == BGP_PEER_UNSPECIFIED) ;
  qassert(peer->as              != BGP_ASN_NULL) ;
  qassert(peer->local_as        == BGP_ASN_NULL) ;
  qassert(peer->change_local_as == BGP_ASN_NULL) ;

  peer_sort_set(peer, peer_sort(peer)) ;

  /* If required, activate given AFI/SAFI -- eg "default ipv4-unicast"
   */
  if (qafx != qafx_undef)
    peer->afc[qafx] = true ;

  /* Last read time and reset time set
   */
  peer->readtime = peer->resettime = bgp_clock ();

  /* Make peer's address string.
   */
  peer->host = sockunion_su2str (su, MTYPE_BGP_PEER_HOST) ;

  /* session -- NB: *before* peer is registered, so before any possible
   *                lookup up by accept() in the BGP Engine
   */
  bgp_session_init_new(peer);

  /* register -- NB: *after* peer->session set, so safe
   */
  bgp_peer_index_register(peer);

  /* If require, enable now all is ready
   */
  if (qafx != qafx_undef)
    bgp_peer_enable(peer) ;

  return peer;
}

/*------------------------------------------------------------------------------
 * Delete peer from configuration.
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

      if (prib->af_flags & PEER_AFF_RSERVER_CLIENT)
        {
          if (prib->af_group_member)
            {
              prib->af_flags &= ~PEER_AFF_RSERVER_CLIENT ;
            } ;
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

      prib->af_flags &= ~PEER_AFF_RSERVER_CLIENT ;
    } ;

  /* Have now finished with any rsclient ribs
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    peer->prib[qafx] = bgp_table_finish (peer->prib[qafx]) ;

  /* Buffers.
   */
  peer->ibuf = stream_free (peer->ibuf) ;
  peer->obuf_fifo = stream_fifo_free (peer->obuf_fifo);
  peer->work = stream_free (peer->work) ;

  /* Local and remote addresses.
   */
  peer->su_local  = sockunion_free (peer->su_local);
  peer->su_remote = sockunion_free (peer->su_remote);

  /* Shut down and release all pribs.
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    peer_deactivate_family (peer, qafx) ;

  /* Unregister the peer.
   *
   * NB: the peer can no longer be looked up by its 'name'.
   *
   *     In particular this means that the accept() logic in the BGP Engine
   *     will conclude that the session should not be accepting connections.
   *
   * NB: also (currently) releases the peer_id -- which may not be so clever ?
   */
  bgp_peer_index_deregister_peer(peer);

  /* Tear down session, if any and if possible.
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

  /* Free allocated host character.
   */
  if (peer->host)
    XFREE (MTYPE_BGP_PEER_HOST, peer->host);

  /* Update source configuration.
   */
  if (peer->update_source != NULL)
    sockunion_free (peer->update_source);

  if (peer->update_if != NULL)
    XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);

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
      snprintf (buf, len, "<error> ");
      return buf;
    }

  /* If there is no connection has been done before print `never'.
   */
  if (uptime == 0)
    {
      snprintf (buf, len, "never   ");
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
    snprintf (buf, len, "%02d:%02d:%02d",
              tm->tm_hour, tm->tm_min, tm->tm_sec);
  else if (period < ONE_WEEK_SECOND)
    snprintf (buf, len, "%dd%02dh%02dm",
              tm->tm_yday, tm->tm_hour, tm->tm_min);
  else
    snprintf (buf, len, "%02dw%dd%02dh",
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
 * Activate the peer or peer group for specified AFI/SAFI.
 *
 * Activation means that the the peer or peer-group has configuration for the
 * address family.
 *
 * For a real peer, activating an address family which is not already active
 * implicitly enables it -- which has a knock on effect on the peer and any
 * session.
 *
 */
extern bgp_ret_t
peer_activate (bgp_peer peer, qafx_t qafx, bool enable)
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

  if (peer->type == PEER_TYPE_REAL)
    {
      qafx_set_t af_enabled ;

      /* If we are enabling the address family, we clear the af_disabled bit,
       * otherwise we set it.
       *
       * If the peer is disabled, then nothing is enabled, otherwise all
       * activated peers which are not disabled are enabled.
       */
      if (enable)
        peer->af_disabled &= ~qb ;
      else
        peer->af_disabled |=  qb ;

      if (peer_is_disabled(peer))
        af_enabled = qafx_set_empty ;
      else
        af_enabled = peer->af_configured & ~peer->af_disabled ;

      if (af_enabled != peer->af_enabled)
        {
          /* The enabled state of one or more address families has changed.
           *
           * For address families which have been disabled, we withdraw all
           * routes and discard the adj-out.
           *
           * For address families which have been enabled:
           */
          qafx_bit_t af_to_disable ;
          qafx_bit_t af_to_enable ;

          af_to_disable =  peer->af_enabled & ~af_enabled ;
          af_to_enable  = ~peer->af_enabled &  af_enabled ;

          switch (peer->state)
            {
              case bgp_pDisabled:
                peer->af_enabled = af_enabled ;

                if (af_enabled != qafx_set_empty)
                  {
                    // start things going... change up to pEnabled;
                  } ;

                break ;

              case bgp_pEnabled:
                peer->af_enabled = af_enabled ;

                if (af_enabled != qafx_set_empty)
                  {


                  } ;

              case bgp_pEstablished:
                if (af_enabled != qafx_set_empty)



              case bgp_pDown:
              case bgp_pDeleting:

              default:
            } ;


      was_active = (peer->af_configured != qafx_empty_set);
      peer->af_configured |= qafx_bit(qafx) ;

          /* If wasn't active, can now enable since now is.
           *
           * Otherwise, to enable an extra AFI/SAFI need either to use Dynamic
           * Capabilities or restart the session.
           */
          if (! was_active)
            bgp_peer_enable (peer);
          else
            /* TODO: Dynamic capability */
    #if 0
            {
              if (peer->status == Established)
                {
                  if ((peer->cap & PEER_CAP_DYNAMIC_RCV))
                    {
                      peer->af_adv[afi][safi] = 1;
                      bgp_capability_send (peer, afi, safi,
                                           BGP_CAN_MP_EXT,
                                           CAPABILITY_ACTION_SET);
                      if (peer->af_rcv[afi][safi])
                        {
                          peer->af_use[afi][safi] = 1;
                          bgp_announce_family (peer, afi, safi);
                        }
                    }
                  else
    #endif
                   {
                     bgp_peer_down(peer, PEER_DOWN_AF_ACTIVATE) ;
                   }
    #if 0
                }
            }
    #endif

    }

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

      if ( (peer->state == bgp_pEstablished)
             && (peer->caps_rcv & (PEER_CAP_DYNAMIC | PEER_CAP_DYNAMIC_dep)) )
        {
          /* If can dynamically reconfigure can avoid restarting the session.
           */
          qafx_bit_t qb ;

          qb = qafx_bit(qafx) ;

          peer->af_adv  &= ~qb ;
          peer->af_use &= ~qb ;

          if (peer->af_use != qafx_set_empty)
            {
              bgp_capability_send (peer, qafx, BGP_CAN_MP_EXT,
                                                    CAPABILITY_ACTION_UNSET);
              bgp_clear_routes(peer, qafx, false);

              down = false ;    /* don't need to down the peer          */
            } ;
        } ;

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
    prib->af_flags |= (PEER_AFF_SEND_COMMUNITY | PEER_AFF_SEND_EXT_COMMUNITY) ;

  /* Set defaults for neighbor maximum-prefix
   */
  prib->pmax.limit     = 0;
  prib->pmax.threshold = 0;
  prib->pmax.thresh_pc = MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
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
  prib->af_flags       = 0;
  prib->af_status      = 0;
  prib->af_caps_adv    = 0;
  prib->af_caps_rcv    = 0;
  prib->af_caps_use    = 0;
  prib->af_orf_pfx_adv = 0 ;
  prib->af_orf_pfx_rcv = 0 ;
  prib->af_orf_pfx_use = 0 ;

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
  return (peer->flags & PEER_FLAG_SHUTDOWN) ||
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

      conf->host  = XSTRDUP (MTYPE_BGP_PEER_HOST, name);
      conf->as    = 0;
      conf->ttl   = 1;
      conf->gtsm  = false ;
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
  assert(peer->prib[qafx] != NULL) ;

  /* Discard the rsclient prib
   */
  bgp_clear_rsclient_rib (peer, qafx);
  peer->prib[qafx] = bgp_table_finish (peer->prib[qafx]);

  /* Discard import policy unconditionally
   */
  peer->filter[qafx].rmap[RMAP_IMPORT] =
                     route_map_clear_ref(peer->filter[qafx].rmap[RMAP_IMPORT]) ;

  /* Discard export policy unless should be kept.
   */
  if (!keep_export)
    peer->filter[qafx].rmap[RMAP_EXPORT] =
                     route_map_clear_ref(peer->filter[qafx].rmap[RMAP_EXPORT]) ;
} ;

/*------------------------------------------------------------------------------
 * Perform 'hard' clear of given peer -- reset it !
 */
extern void
peer_clear (bgp_peer peer)
{
  /* Overrides any Max Prefix issues.
   */
  bgp_maximum_prefix_cancel_timer (peer) ;

  /* Overrides any idle hold timer
   */
  peer->v_start = BGP_INIT_START_TIMER;

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
        if (prib->af_flags & PEER_AFF_RSERVER_CLIENT)
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
        if (prib->af_caps_use & PEER_AF_CAP_ORF_PFX_SEND)
          {
            if (prib->plist[FILTER_IN] != NULL)
              {
                /* If have sent ORF, send 'remove' previous ORF, but 'defer'
                 * refresh.  Then send current state of ORF and ask for
                 * 'immediate' refresh.
                 */
                if (prib->af_status & PEER_STATUS_ORF_PREFIX_SENT)
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
                if (prib->af_status & PEER_STATUS_ORF_PREFIX_SENT)
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
        if      (prib->af_flags & PEER_AFF_SOFT_RECONFIG)
          bgp_soft_reconfig_in (peer, qafx);
        else if (peer->caps_use & PEER_CAP_RR)
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
    if ((peer->af_flags[qafx] & PEER_AFF_RSERVER_CLIENT)
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
 *   bgp->as            -- our ASN -- per router BGP <ASN>
 *
 *                         If we are in a CONFED, this is our CONFED Member AS.
 *
 *                         NB: once a bgp instance has been created, it is not
 *                             possible to change the bgp->as.
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
 *   peer->as           -- the peer's ASN -- per neighbor remote-as <ASN>
 *
 * The peer->local_as will be bgp->as, unless we are in a CONFED and the
 * peer->sort is BGP_PEER_EBGP, in which case peer->local_as is bgp->as.
 */
static void peer_sort_init_local_as(bgp_peer peer, bgp_peer_sort_t sort) ;
static void peer_sort_init_ttl_gtsm(bgp_peer peer, bgp_peer_sort_t sort) ;

/*------------------------------------------------------------------------------
 * Establish sort of peer or peer-group from first principles.
 *
 * For peer, this depends on the peer->as, bgp->as and confederation state.
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
 * NB: bgp->as cannot be changed once set.  So a peer or peer-group which is
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
      if (peer->as != BGP_ASN_NULL)
        {
          if (bgp->as == peer->as)
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
              if (peer1->as == bgp->as)
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
      if (peer->as == bgp->as)
        sort = BGP_PEER_IBGP ;
      else if (bgp_confederation_peers_check (bgp, peer->as))
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
 *   * peer->local_as       -- set to bgp->as, except...
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

  /* Update peer->local_as as required
   */
  old_local_as = peer->local_as ;

  peer_sort_init_local_as(peer, peer->sort) ;
  if (old_local_as != peer->local_as)
    changed = true ;

  /* If the sort has changed, set default MRAI  TODO really ??
   */
  if (old_sort != peer->sort)
    {
      peer->config     &= ~PEER_CONFIG_MRAI ;
      peer->config_mrai = 0 ;           /* for completeness     */
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

      old_ttl  = peer->ttl ;
      old_gtsm = peer->gtsm ;

      peer_sort_init_ttl_gtsm(peer, peer->sort) ;

      if ((old_ttl != peer->ttl) || (old_gtsm != peer->gtsm))
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

          if (prib->af_flags & PEER_AFF_REFLECTOR_CLIENT)
            {
              prib->af_flags ^= PEER_AFF_REFLECTOR_CLIENT ;
              changed = true ;
            } ;
        } ;
    } ;

  return changed ;
} ;

/*------------------------------------------------------------------------------
 * peer global config reset
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

  peer->update_source = sockunion_free (peer->update_source) ;

  if (peer->update_if != NULL)
    XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
                                         /* sets peer->update_if = NULL */

  peer->flags     = 0;
  peer->config    = 0;
  peer->config_holdtime  = 0;   /* for completeness     */
  peer->config_keepalive = 0;   /* for completeness     */
  peer->config_connect   = 0;   /* for completeness     */
  peer->config_mrai      = 0;   /* for completeness     */
} ;

/*------------------------------------------------------------------------------
 * Set the peer->local_as given the sort, peer->bgp and peer->change_local_as
 *
 * Sets according to the given sort:
 *
 *   * BGP_PEER_IBGP:  peer->bgp->as
 *
 *   * BGP_PEER_CBGP:  peer->bgp->as
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
    peer->local_as = peer->bgp->as ;
  else if (peer->change_local_as != BGP_ASN_NULL)
    peer->local_as = peer->change_local_as ;
  else
    peer->local_as = peer->bgp->ebgp_as ;
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
      peer->ttl  = MAXTTL ;
      peer->gtsm = false ;
    }
  else
    {
      if (peer->group == NULL)
        {
          peer->ttl  = 1;
          peer->gtsm = false ;
        }
      else
        {
          peer->ttl  = peer->group->conf->ttl ;
          peer->gtsm = peer->group->conf->gtsm ;
        }
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set the given peer's 'remote-as' -- ie peer->as
 *
 * Updates peer->sort etc. as required -- see peer_sort_set().
 *
 * Returns:  true <=> peer->as or anything else changes.
 */
static bool
peer_as_set(bgp_peer peer, as_t asn)
{
  bgp_peer_sort_t sort ;
  as_t            old_asn ;

  old_asn  = peer->as ;
  peer->as = asn ;

  if (peer->bgp->as == peer->as)
    sort = BGP_PEER_IBGP ;
  else if (bgp_confederation_peers_check (peer->bgp, peer->as))
    sort = BGP_PEER_CBGP ;
  else
    sort = BGP_PEER_EBGP ;

  return peer_sort_set(peer, sort) || (old_asn != peer->as) ;
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
          if (peer->group->conf->as != BGP_ASN_NULL)
            {
              /* Return peer group's AS number.
               */
              *p_as = peer->group->conf->as;
              return BGP_ERR_PEER_GROUP_MEMBER;
            } ;

          if (peer_sort(peer->group->conf) == BGP_PEER_IBGP)
            {
              if (bgp->as != *p_as)
                {
                  *p_as = peer->as;
                  return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
          else
            {
              if (bgp->as == *p_as)
                {
                  *p_as = peer->as;
                  return BGP_ERR_PEER_GROUP_PEER_TYPE_DIFFERENT;
                }
            }
        }

      /* Existing peer's AS number change.
       */
      if (peer->as != *p_as)
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
 * peer->flags setting/clearing -- complete with side-effects.
 *
 * Table of actions for changing peer->flags
 *
 * NB: change actions are peer_change_none or peer_change_reset ONLY.
 *     (The peer->flags apply to all afi/safi.)
 *
 * NB: PEER_FLAG_LOCAL_AS_NO_PREPEND is dealt with elsewhere.
 *
 * NB: all flags are set/cleared individually.
 */
static const struct peer_flag_action peer_flag_action_list[] =
  {
    {  PEER_FLAG_PASSIVE,
                false, peer_change_reset,     PEER_DOWN_PASSIVE_CHANGE},
    {  PEER_FLAG_SHUTDOWN,
                false, peer_change_reset,     PEER_DOWN_USER_SHUTDOWN },
    {  PEER_FLAG_DONT_CAPABILITY,
                false, peer_change_reset,     PEER_DOWN_DONT_CAPABILITY },
    {  PEER_FLAG_OVERRIDE_CAPABILITY,
                false, peer_change_reset,     PEER_DOWN_OVERRIDE_CAPABILITY },
    {  PEER_FLAG_STRICT_CAP_MATCH,
                false, peer_change_reset,     PEER_DOWN_STRICT_CAP_MATCH },
    {  PEER_FLAG_DYNAMIC_CAPABILITY,
                false, peer_change_reset,     PEER_DOWN_CAPABILITY_CHANGE },
    {  PEER_FLAG_DISABLE_CONNECTED_CHECK,
                false, peer_change_reset,     PEER_DOWN_CONFIG_CHANGE },
    { 0, false, peer_change_none, PEER_DOWN_NULL }
  };

static bgp_ret_t peer_flag_modify (bgp_peer peer, peer_flag_bits_t flag,
                                                                     bool set) ;
static void peer_flag_modify_action (bgp_peer peer, peer_flag_action action,
                                              peer_flag_bits_t flag, bool set) ;

/*------------------------------------------------------------------------------
 * Set specified peer->flags flag.
 */
extern bgp_ret_t
peer_flag_set (bgp_peer peer, peer_flag_bits_t flag)
{
  return peer_flag_modify (peer, flag, true);
}

/*------------------------------------------------------------------------------
 * Clear specified peer->flags flag.
 */
extern bgp_ret_t
peer_flag_unset (bgp_peer peer, peer_flag_bits_t flag)
{
  return peer_flag_modify (peer, flag, false);
}

/*------------------------------------------------------------------------------
 * Change specified peer->flags flag.
 *
 * See: peer_flag_action_list above.
 */
static bgp_ret_t
peer_flag_modify (bgp_peer peer, peer_flag_bits_t flag, bool set)
{
  peer_group group;
  peer_flag_action action;
  bool group_conf ;
  bool group_member ;

  group = peer->group ;

  group_conf   = (peer->type == PEER_TYPE_GROUP_CONF) ;
  group_member = !group_conf && (group != NULL) ;

  /* Find flag action -- quit of none known.
   */
  action = peer_flag_action_find(peer_flag_action_list, flag) ;

  if (action == NULL)
    return BGP_ERR_INVALID_FLAG;

  /* This is for flags which may neither be set nor cleared on a group member.
   */
  if (group_member && action->not_for_member)
    return BGP_ERR_INVALID_FOR_PEER_GROUP_MEMBER;

  /* Flags may be set on a group member, but may not be cleared on a group
   * member.
   *
   * That is: if the flag is set in the group, that takes precedence.
   */
  if (group_member && ! set)
    {
      if (group->conf->flags & flag)
        {
          if (flag == PEER_FLAG_SHUTDOWN)
            return BGP_ERR_PEER_GROUP_SHUTDOWN;
          else
            return BGP_ERR_PEER_GROUP_HAS_THE_FLAG;
        }
    } ;

  /* Flag conflict check.
   *
   * Cannot set PEER_FLAG_STRICT_CAP_MATCH & PEER_FLAG_OVERRIDE_CAPABILITY
   * together.
   */
  if (set)
    {
      if      (flag & PEER_FLAG_STRICT_CAP_MATCH)
        {
          if (peer->flags & (PEER_FLAG_DONT_CAPABILITY |
                             PEER_FLAG_OVERRIDE_CAPABILITY))
            return BGP_ERR_PEER_FLAG_CONFLICT_1 ;
        }
      else if (flag & PEER_FLAG_OVERRIDE_CAPABILITY)
        {
          if (peer->flags & PEER_FLAG_STRICT_CAP_MATCH)
            return BGP_ERR_PEER_FLAG_CONFLICT_2 ;
        }
      else if (flag & PEER_FLAG_DONT_CAPABILITY)
        {
          if (peer->flags & PEER_FLAG_STRICT_CAP_MATCH)
            return BGP_ERR_PEER_FLAG_CONFLICT_3 ;
        } ;
    } ;

  /* Execute action for real peer or for group.
   */
  peer_flag_modify_action (peer, action, flag, set) ;

  /* Peer group member updates.
   */
  if (group_conf)
    {
      struct listnode *node, *nnode;

      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        peer_flag_modify_action (peer, action, flag, set);
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Set or clear something in peer->flags.
 *
 * If any flag changes, implement any implied changes.
 *
 * NB: side effects only apply to PEER_TYPE_REAL peers.
 *
 * NB: Clearing PEER_FLAG_SHUTDOWN is a special case
 *
 * NB: Setting PEER_FLAG_SHUTDOWN -> PEER_DOWN_USER_SHUTDOWN, which is a
 *     special case in bgp_peer_down.
 */
static void
peer_flag_modify_action (bgp_peer peer, peer_flag_action action,
                                                peer_flag_bits_t flag, bool set)
{
  peer_flag_bits_t now ;

  now = peer->flags & flag ;

  if (set)
    {
      if (now != flag)
        peer->flags |= flag ;
      else
        return ;                /* no change            */
    }
  else
    {
      if (now != 0)
        peer->flags ^= now ;
      else
        return ;                /* no change            */
    } ;

  if (peer->type != PEER_TYPE_REAL)
    return;

  switch (action->type)
    {
      case peer_change_none:
        break ;

      default:
        qassert(false) ;
        fall_through ;

      case peer_change_reset:
        if ((action->flag & PEER_FLAG_SHUTDOWN) && !set)
          {
            /* Clearing PEER_FLAG_SHUTDOWN
             */
            peer->v_start = BGP_INIT_START_TIMER;
            bgp_peer_enable(peer);
          }
        else
          bgp_peer_down(peer, action->peer_down) ;

        break ;
    } ;
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
    if (group->conf->prib[qafx]->af_flags & flag)
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
  peer_af_flag_bits_t now ;

  now = prib->af_flags & flag ;

  if (set)
    {
      if (now != flag)
        prib->af_flags |= flag ;
      else
        return ;                /* no change            */
    }
  else
    {
      if (now != 0)
        prib->af_flags ^= now ;
      else
        return ;                /* no change            */
    } ;

  if (prib->peer->type != PEER_TYPE_REAL)
    return;

  if ((action->flag == PEER_AFF_SOFT_RECONFIG) && !set)
    {
      if (peer->state == bgp_pEstablished)
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
                if (prib->peer->caps_use & PEER_CAP_RR)
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

  if (group->conf->as == BGP_ASN_NULL)
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

  group->conf->as = BGP_ASN_NULL ;

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

  if (group->conf->as == *p_as)
    return BGP_SUCCESS ;

  /* When we setup peer-group AS number all peer group member's AS
   * number must be updated to same number.
   */
  peer_as_change (group->conf, *p_as);

  for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
    {
      if (peer->as != *p_as)
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
      if (group->conf->as == BGP_ASN_NULL)
        return BGP_ERR_PEER_GROUP_NO_REMOTE_AS ;

      if (peer_lookup (NULL, su) != NULL)
        return BGP_ERR_PEER_EXISTS ;

      peer = bgp_peer_create (su, bgp, group->conf->as, qafx);
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
            *p_asn = peer->as ;

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
          group->conf->change_local_as = BGP_ASN_NULL ;
          UNSET_FLAG (group->conf->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND);
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
  if (prib->af_flags & PEER_AFF_RSERVER_CLIENT)
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
      UNSET_FLAG(prib->af_flags, PEER_AFF_RSERVER_CLIENT) ;

      peer_rsclient_unset(peer, qafx,
                (group->conf->prib[qafx]->af_flags & PEER_AFF_RSERVER_CLIENT)) ;
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

      if (group->conf->as != BGP_ASN_NULL)
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
  peer->flags     = conf->flags;
  prib->af_flags  = g_prib->af_flags ;

  /* remote-as, local-as & allowas-in
   *
   * For completeness we set the sort after
   */
  if (conf->as != BGP_ASN_NULL)
    peer->as = conf->as;

  peer_sort_set(peer, peer_sort(peer)) ;

  if (conf->change_local_as != BGP_ASN_NULL)
    peer->change_local_as = conf->change_local_as;

  prib->allowas_in = g_prib->allowas_in ;

  /* TTL & GTSM
   */
  if (peer->sort != BGP_PEER_IBGP)
    {
      peer->ttl  = conf->ttl;
      peer->gtsm = conf->gtsm;
    } ;

  /* The group's configuration for:
   *
   *   PEER_CONFIG_WEIGHT
   *   PEER_CONFIG_TIMER
   *   PEER_CONFIG_CONNECT
   *   PEER_CONFIG_MRAI
   *
   * take precedence over the peer's settings, and wipe out those settings.
   *
   * NB: when the given peer is removed from the group, any previous
   *     configuration is lost, and reverts to the default.)
   */
  if (conf->config & PEER_CONFIG_WEIGHT)
    {
      peer->config |= PEER_CONFIG_WEIGHT ;
      peer->weight  = conf->weight;
    }
  else
    {
      peer->config &= ~PEER_CONFIG_WEIGHT ;
      peer->weight  = 0 ;
    } ;

  if (conf->config & PEER_CONFIG_TIMER)
    {
      peer->config          |= PEER_CONFIG_TIMER ;
      peer->config_holdtime  = conf->config_holdtime;
      peer->config_keepalive = conf->config_keepalive;
    }
  else
    {
      peer->config &= ~PEER_CONFIG_TIMER ;
      peer->config_holdtime  = 0 ;
      peer->config_keepalive = 0 ;
    } ;

  if (conf->config & PEER_CONFIG_CONNECT)
    {
      peer->config          |= PEER_CONFIG_CONNECT;
      peer->config_connect   = conf->config_connect;
    }
  else
    {
      peer->config          &= ~PEER_CONFIG_CONNECT;
      peer->config_connect   = 0 ;
    } ;

  if (conf->config & PEER_CONFIG_MRAI)
    {
      peer->config          |= PEER_CONFIG_MRAI ;
      peer->config_mrai      = conf->config_mrai ;
    }
  else
    {
      peer->config          &= ~PEER_CONFIG_MRAI;
      peer->config_mrai      = 0 ;
    } ;

  /* password apply
   */
  if (peer->password != NULL)
    XFREE (MTYPE_PEER_PASSWORD, peer->password);

  if (conf->password)
    peer->password =  XSTRDUP (MTYPE_PEER_PASSWORD, conf->password);
  else
    peer->password = NULL;

  /* maximum-prefix
   */
  prib->pmax = g_prib->pmax;

  /* route-server-client
   */
  if (g_prib->af_flags & PEER_AFF_RSERVER_CLIENT)
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
  if (conf->update_source != NULL)
    {
      if (peer->update_source != NULL)
        sockunion_free (peer->update_source);
      if (peer->update_if != NULL)
        {
          XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
          peer->update_if = NULL;
        } ;

      peer->update_source = sockunion_dup (conf->update_source);
    }
  else if (conf->update_if != NULL)
    {
      if (peer->update_source != NULL)
        peer->update_source = sockunion_free (peer->update_source);

      if (peer->update_if != NULL)
        XFREE (MTYPE_PEER_UPDATE_SOURCE, peer->update_if);
      peer->update_if = XSTRDUP (MTYPE_PEER_UPDATE_SOURCE, conf->update_if);
    }

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
                                                      bgp_notify notification) ;
static void bgp_peer_shutdown(bgp_peer peer) ;
static bgp_notify bgp_peer_map_peer_down(peer_down_t why_down) ;
static peer_down_t bgp_peer_map_notification(bgp_notify notification) ;

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
 *   - psDown    XXX
 *
 *   - psUp      XXX
 *
 *   - psLimping XXX -- cannot, yet, start a new session -- that will happen in
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
        if (peer->af_enabled == qafx_set_empty)
          {
            break ;
          } ;

        fall_through ;

      case bgp_pDisabled:
        /* The peer is disabled when no address family is enabled.
         *
         * An address family is enabled when it is (a) activated and (b) it is
         * not PEER_FLAG_SHUTDOWN or PEER_STATUS_PREFIX_OVERFLOW or otherwise
         * disabled.
         *
         * If no address family is enabled, will do nothing and will remain
         * pDisabled.
         */
        if (peer->af_enabled == qafx_set_empty)
          break ;

        qassert(!peer_is_disabled(peer)) ;
        qassert(peer->session->peer_state == bgp_psDown) ;

        peer->state = bgp_pEnabled ;
        fall_through ;

      case bgp_pEnabled:
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

        qassert(peer->session->peer_state == bgp_psDown) ;

        bgp_peer_reset_enable(peer) ;   /* tidy up      */
        bgp_session_enable(peer) ;
        bgp_peer_change_status (peer, bgp_pEnabled) ;

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
                bgp_session_enable(peer) ;
                bgp_peer_change_status (peer, bgp_pEnabled) ;
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
 * Update "open_state", if possible, for given peer -- in pEnabled state.
 *
 * This is used when the peer is pEnabled, but an address family has been
 * enabled or disabled, or any of the bgp_open_state has been changed.
 *
 * pEnabled means that a session enable message has been sent to the BGP
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
 * NB: does nothing for peers which are not pEnabled.
 */
extern void
bgp_peer_update_open_state(bgp_peer peer, peer_down_t why_down)
{
  bgp_open_state open_send_new, open_send_was ;

  if (peer->state != bgp_pEnabled)
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
 *   psDown     XXX -- wasn't active and still isn't
 *
 *   psLimping  XXX -- was psUp, we now wait for BGP Engine
 *                to complete the disable action and signal when done.
 *
 * The result depends on the initial peer state:
 *
 *   0. pDisabled
 *
 *
 *
 *   1. pEnabled or pEstablished
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
  bgp_notify notification;
  notification = bgp_notify_new_with_data(code, subcode, data, datalen);

  bgp_peer_down_notify(peer, bgp_peer_map_notification(notification),
                                                                 notification) ;
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
bgp_peer_down_notify(bgp_peer peer, peer_down_t why_down,
                                                        bgp_notify notification)
{
  /* Deal with session (if any)
   */
  if (notification == NULL)
    notification = bgp_peer_map_peer_down(why_down) ;

  if (bgp_session_disable(peer, notification))
    bgp_notify_set(&peer->session->notification, notification) ;
  else
    bgp_notify_free(notification) ;

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
      case bgp_pDisabled:

      case bgp_pEnabled:
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
               || (peer->session->peer_state == bgp_session_psDown) ) ;

        bgp_peer_nsf_stop (peer) ;        /* flush stale routes, if any   */

        break ;

      case bgp_pDeleting:
        assert(   (peer->session == NULL)
               || (peer->session->peer_state == bgp_session_psDown)
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
  assert( (peer->state == bgp_pEnabled) ||
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

  /* Reset peer synctime
   */
  peer->synctime = 0;
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
      assert( (peer->state == bgp_pEnabled)
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
  peer->flags |= PEER_FLAG_SHUTDOWN ;

  bgp_maximum_prefix_cancel_timer(peer) ;

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

  peer->caps_adv = 0 ;
  peer->caps_rcv = 0 ;
  peer->caps_use = 0 ;
  peer->af_adv  = qafx_set_empty ;
  peer->af_rcv = qafx_set_empty ;
  peer->af_use = qafx_set_empty ;

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
          prib->af_caps_adv    = 0 ;
          prib->af_caps_rcv    = 0 ;
          prib->af_caps_use    = 0 ;
          prib->af_orf_pfx_adv = 0 ;
          prib->af_orf_pfx_rcv = 0 ;
          prib->af_orf_pfx_use = 0 ;
        } ;

      /* Received ORF prefix-filter
       */
      prib->orf_plist = prefix_bgp_orf_delete(prib->orf_plist) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Construct notification based on the reason for bringing down the session
 *
 * Where the session is brought down by the other end, returns NULL.
 */
static bgp_notify
bgp_peer_map_peer_down(peer_down_t why_down)
{
  bgp_nom_code_t    code ;
  bgp_nom_subcode_t subcode ;

  assert((why_down >= PEER_DOWN_first) && (why_down < PEER_DOWN_count)) ;

  code    = BGP_NOMC_CEASE ;            /* Default values       */
  subcode = BGP_NOMS_UNSPECIFIC ;

  switch(why_down)
  {
    case PEER_DOWN_NULL:
      return NULL ;

    /* Session taken down at this end for some unspecified reason         */

    case PEER_DOWN_UNSPECIFIED:
      break ;

    /* Configuration changes that cause a session to be reset.            */

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

    /* Other actions that cause a session to be reset                     */

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

    /* Errors and problems that cause a session to be reset               */
    /*                                                                    */
    /* SHOULD really have a notification constructed for these, but for   */
    /* completeness construct an "unspecified" for these.                 */

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

    /* Things the far end can do to cause a session to be reset           */

    case PEER_DOWN_NOTIFY_RECEIVED:
      return NULL ;             /* should not get here !                */

    case PEER_DOWN_CLOSE_SESSION:
    case PEER_DOWN_NSF_CLOSE_SESSION:
      return NULL ;             /* nowhere to send a notification !     */

    /* To keep the compiler happy.      */
    case PEER_DOWN_count:
    default:
      break ;                   /* should have asserted already         */
  } ;

  return bgp_notify_new(code, subcode) ;
} ;

/*------------------------------------------------------------------------------
 * Construct reason for bringing down the session based on the notification
 */
static peer_down_t
bgp_peer_map_notification(bgp_notify notification)
{
  if (notification == NULL)
    return PEER_DOWN_UNSPECIFIED ;

  switch (notification->code)
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
        switch (notification->subcode)
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
  if (peer->state != new_state)
    {
      bgp_peer_state_t old_state ;

      old_state   = peer->state ;
      peer->state = new_state ;

      if (BGP_DEBUG (normal, NORMAL))
        zlog_debug ("peer %s went from %s to %s", peer->host,
                           map_direct(bgp_peer_status_map, old_state).str,
                           map_direct(bgp_peer_status_map, new_state).str) ;
    } ;

  /* Timer handling
   */
  switch (peer->state)
    {
      case bgp_pDisabled:
        /* On entry to pIdle the Graceful Restart Timers are left running:
         *
         *   - if no connection is established within the Graceful Restart
         *     time, then things are no longer graceful, and the stale routes
         *     have to be thrown away.
         *
         *   - if routes do not thereafter arrive quickly enough, then the
         *     Graceful Stale time kicks in and stale routes will be thrown away.
         */
        break;

      case bgp_pEstablished:
        /* On entry to pEstablished only the the Graceful Stale Timer is left
         * running.
         *
         * Any Graceful Restart Timer can be cancelled -- have established in
         * time.
         */
        BGP_TIMER_OFF (peer->t_pmax_restart) ;

        bgp_graceful_restart_timer_cancel(peer) ;
        break;

      case bgp_pDown:
        /* On entry to pDown, turn off all timers.
         *
         * The Graceful Restart timer should not be running in any case.
         *
         * If the session is brought down quickly enough, the Graceful Stale
         * timer may be running.
         */
        BGP_TIMER_OFF (peer->t_pmax_restart);
        BGP_TIMER_OFF (peer->t_gr_restart);

        bgp_graceful_stale_timer_cancel(peer) ;
        break ;

      default:
        qassert(false) ;
        fall_through ;                  /* treat as pDeleting   */

      case bgp_pDeleting:
        /* On entry to pDeleting, turn off all timers.
         */
        BGP_TIMER_OFF (peer->t_pmax_restart);
        BGP_TIMER_OFF (peer->t_gr_restart);
        BGP_TIMER_OFF (peer->t_gr_stale);
        break;
    } ;
} ;

/*------------------------------------------------------------------------------
 * BGP Peer Down Causes mapped to strings
 */
const char *peer_down_str[] =
{
  [PEER_DOWN_NULL]                 = "",

  [PEER_DOWN_UNSPECIFIED]          = "Unspecified reason",

  [PEER_DOWN_CONFIG_CHANGE]        = "Unspecified config change",

  [PEER_DOWN_RID_CHANGE]           = "Router ID changed",
  [PEER_DOWN_REMOTE_AS_CHANGE]     = "Remote AS changed",
  [PEER_DOWN_LOCAL_AS_CHANGE]      = "Local AS change",
  [PEER_DOWN_CLID_CHANGE]          = "Cluster ID changed",
  [PEER_DOWN_CONFED_ID_CHANGE]     = "Confederation identifier changed",
  [PEER_DOWN_CONFED_PEER_CHANGE]   = "Confederation peer changed",
  [PEER_DOWN_RR_CLIENT_CHANGE]     = "RR client config change",
  [PEER_DOWN_RS_CLIENT_CHANGE]     = "RS client config change",
  [PEER_DOWN_UPDATE_SOURCE_CHANGE] = "Update source change",
  [PEER_DOWN_AF_ACTIVATE]          = "Address family activated",
  [PEER_DOWN_GROUP_BIND]            = "Peer-group add member",
  [PEER_DOWN_GROUP_UNBIND]          = "Peer-group delete member",
  [PEER_DOWN_DONT_CAPABILITY]      = "dont-capability-negotiate changed",
  [PEER_DOWN_OVERRIDE_CAPABILITY]  = "override-capability changed",
  [PEER_DOWN_STRICT_CAP_MATCH]     = "strict-capability-match changed",
  [PEER_DOWN_CAPABILITY_CHANGE]    = "Capability changed",
  [PEER_DOWN_PASSIVE_CHANGE]       = "Passive config change",
  [PEER_DOWN_MULTIHOP_CHANGE]      = "Multihop config change",
  [PEER_DOWN_AF_DEACTIVATE]        = "Address family deactivated",
  [PEER_DOWN_PASSWORD_CHANGE]      = "MD5 Password changed",
  [PEER_DOWN_ALLOWAS_IN_CHANGE]    = "Allow AS in changed",

  [PEER_DOWN_USER_SHUTDOWN]        = "Admin. shutdown",
  [PEER_DOWN_USER_RESET]           = "User reset",
  [PEER_DOWN_NEIGHBOR_DELETE]      = "Neighbor deleted",

  [PEER_DOWN_INTERFACE_DOWN]       = "Interface down",

  [PEER_DOWN_MAX_PREFIX]           = "Max Prefix Limit exceeded",

  [PEER_DOWN_HEADER_ERROR]         = "Error in message header",
  [PEER_DOWN_OPEN_ERROR]           = "Error in BGP OPEN message",
  [PEER_DOWN_UPDATE_ERROR]         = "Error in BGP UPDATE message",
  [PEER_DOWN_HOLD_TIMER]           = "HoldTimer expired",
  [PEER_DOWN_FSM_ERROR]            = "Error in FSM sequence",
  [PEER_DOWN_DYN_CAP_ERROR]        = "Error in Dynamic Capability",

  [PEER_DOWN_NOTIFY_RECEIVED]      = "Notification received",
  [PEER_DOWN_NSF_CLOSE_SESSION]    = "NSF peer closed the session",
  [PEER_DOWN_CLOSE_SESSION]        = "Peer closed the session",
} ;

CONFIRM(sizeof(peer_down_str) == (PEER_DOWN_count * sizeof(const char*))) ;

/*==============================================================================
 * Session state changes and their effect on the peer state.
 */
static void bgp_session_has_established(bgp_session session);
static void bgp_session_has_stopped(bgp_session session,
                                                      bgp_notify notification) ;
static void bgp_session_has_disabled(bgp_session session);

/*------------------------------------------------------------------------------
 * Deal with change in session state -- mqueue_action function.
 *
 * Receives notifications from the BGP Engine a session event occurs.
 *
 * -- arg0  = session
 *    args  =  bgp_session_event_args
 */
extern void
bgp_session_do_event(mqueue_block mqb, mqb_flag_t flag)
{
  struct bgp_session_event_args* args ;
  bgp_session session ;

  args    = mqb_get_args(mqb) ;
  session = mqb_get_arg0(mqb) ;

  if (flag == mqb_action)
    {
      /* Pull stuff into Routing Engine *private* fields in the session
       */
      session->event   = args->event ;    /* last event                     */
      session->err     = args->err ;      /* errno, if any                  */
      session->ordinal = args->ordinal ;  /* primary/secondary connection   */

      switch(args->event)
        {
          /* If now Established, then the BGP Engine has exchanged BGP Open
           * messages, and received the KeepAlive that acknowledges our Open.
           *
           * The args->ordinal gives which connection it was that became the
           * established one.  The established connection becomes the
           * "primary".
           *
           * Ignore this, however, if the session is sLimping -- which can
           * happen when the session has been disabled, but it became
           * established before the BGP Engine had seen the disable message.
           */
          case bgp_session_eEstablished:
            assert(args->notification == NULL) ;

            session->ordinal_established = session->ordinal ;

            if (session->peer_state == bgp_session_psLimping)
              break ;

            bgp_session_has_established(session);
            break ;

          /* If now Disabled, then the BGP Engine is acknowledging the a
           * session disable, and the session is now disabled.
           *
           * If sent a notification with the disable request, then it is
           * returned iff the notification was actually sent.  Don't really
           * care one way or the other.
           *
           * BEWARE: this may be the last thing that happens to the session
           *         and/or the related peer -- which may be deleted inside
           *         bgp_session_has_disabled().
           */
          case bgp_session_eDisabled:
            bgp_session_has_disabled(session);
            break ;

          /* If now Stopped, then for some reason the BGP Engine has either
           * stopped trying to connect, or the session has been stopped.
           *
           * If the session is "
           *
           *
           *
           * Again we ignore this in sLimping.
           */
          default:
            if (session->peer_state == bgp_session_psLimping)
              break ;

            if (args->stopped)
              bgp_session_has_stopped(session,
                                       bgp_notify_take(&(args->notification))) ;
            break ;
        } ;
    } ;

  bgp_notify_free(args->notification) ;  /* Discard any notification.    */

  mqb_free(mqb) ;
}

/*------------------------------------------------------------------------------
 * BGP Session has been Established.
 */
static void
bgp_session_has_established(bgp_session session)
{
  qafx_t qafx ;
  int nsf_af_count ;

  bgp_peer peer  = session->peer ;
  assert(peer->session == session) ;            /* Safety first         */

  /* Session state change -- Routing Engine private fields
   */
  assert(session->peer_state == bgp_session_psUp) ;

  session->flow_control = BGP_XON_REFRESH; /* updates can be sent */

  /* Peer state change.
   *
   * This stops all timers other than the Graceful Stale Timer.
   */
  bgp_peer_change_status (peer, bgp_pEstablished);

  /* Extracting information from shared fields.
   */
  BGP_SESSION_LOCK(session) ;   /*<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-<-*/

  bgp_peer_open_state_receive(peer);

  sockunion_set_dup(&peer->su_local,  session->su_local) ;
  sockunion_set_dup(&peer->su_remote, session->su_remote) ;

  BGP_SESSION_UNLOCK(session) ; /*->->->->->->->->->->->->->->->->->->->*/

  /* Install next hop, as required.
   */
  bgp_nexthop_set(peer->su_local, peer->su_remote, &peer->nexthop, peer) ;

  /* Clear last notification data -- Routing Engine private field
   *
   * This is done because
   */
  bgp_notify_unset(&(peer->session->notification));

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

      if ((prib->af_status & PEER_STATUS_RUNNING)
          && (peer->caps_adv & PEER_CAP_GR)
          && (prib->af_caps_rcv & PEER_AF_CAP_GR_CAN_PRESERVE))
        {
          /* If have held onto routes for this afi/safi but forwarding has
           * not been preserved, then clean out the stale routes.
           *
           * Set NSF for this address family for next time.
           */
          if (prib->nsf
              && ! (prib->af_caps_rcv & PEER_AF_CAP_GR_HAS_PRESERVED))
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

      if (prib->af_caps_use & PEER_AF_CAP_ORF_PFX_SEND)
        bgp_route_refresh_send (prib, BGP_ORF_T_PFX,
                                BGP_ORF_WTR_IMMEDIATE, false /* not remove */) ;

      if (prib->af_caps_use & PEER_AF_CAP_ORF_PFX_RECV)
         prib->af_status |= PEER_STATUS_ORF_WAIT_REFRESH ;
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
bgp_session_has_stopped(bgp_session session, bgp_notify notification)
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









  if (session->peer_state == bgp_sEstablished)
    {
      time_t  up_for ;
      uint    max_v_start ;

      up_for = bgp_clock() - peer->uptime ;

      /* We double the IdleHoldTime and then apply a maximum value, where that
       * maximum depends on how long has been up for:
       *
       *   < 2 mins -- maximum new IdleHoldTime = 120 secs -- maximum allowed
       *   < 3 mins --                          =  64 secs (2^6)
       *   < 4 mins,                            =  32
       *   < 5 mins,                            =  16
       *   < 6 mins,                            =   8
       *   < 7 mins,                            =   4
       *   < 8 mins                             =   2      (2^1)
       *  >= 8 mins                             =   1 sec
       *
       * NB: setting peer->v_start to zero turns off this process altogether !
       */
      if      (up_for < (2 * 60))
        max_v_start = 120 ;
      else if (up_for < (8 * 60))
        {
          qassert((2 <= (up_for / 60)) && ((up_for / 60) <= 7)) ;

          max_v_start = 1 << (8 - (up_for / 60)) ;
        }
      else
        max_v_start = 1 ;

      peer->v_start *= 2;

      if (peer->v_start > max_v_start)
        peer->v_start = max_v_start ;
    } ;





    peer = session->peer ;
    assert(peer->session == session) ;    /* Safety first         */

    session->peer_state = bgp_session_psDown ;

    /* Immediately discard any other messages for this session.
     */
    mqueue_revoke(routing_nexus->queue, session, 0) ;

    /* If the session is marked "delete_me", do that.
     *
     * Otherwise, Old session now gone, so re-enable peer if now possible.
     */
    if (session->delete_me)
      bgp_session_delete(peer) ;  /* NB: this may also delete the peer.   */
    else
      bgp_peer_enable(peer);



#if 0
  if (notification == NULL)
    why_down = PEER_DOWN_CLOSE_SESSION ;
  else
    {
      if (notification->received)
        why_down = PEER_DOWN_NOTIFY_RECEIVED ;
      else
        why_down = bgp_peer_map_notification(notification) ;
    } ;

  bgp_peer_down_notify(peer, why_down, notification) ;
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
  peer->v_start *= 2;

  /* Overflow check. */
  if (peer->v_start >= (60 * 2))
    peer->v_start = (60 * 2);

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

  if (ifname == NULL)
    return NULL ;

  ifp = if_lookup_by_name (peer->update_if) ;
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
 * Get the KeepaliveTime for the given peer or peer group.
 *
 * If 'current', then for a (real) peer which is pEnabled or pEstablished:
 *
 *   * pEnabled
 *
 *     the value returned is the value which is advertised in any OPEN messages
 *     which will be or have been sent.
 *
 *   * pEstablished
 *
 *     the value returned is the value negotiated for this established session.
 *
 * Otherwise:
 *
 *   * if is PEER_CONFIG_TIMER, return the peer->config_keepalive
 *
 *   * otherwise, return peer->bgp->default_keepalive
 *
 * Returns: peer->keepalive = current effective value
 */
extern uint
peer_get_keepalive(bgp_peer peer, bool current)
{
  if (current && (peer->type == PEER_TYPE_REAL))
    {
      switch (peer->state)
        {
          case bgp_pEnabled:
          case bgp_pEstablished:
            return peer->current_keepalive ;

          default:
            break ;
        } ;
    } ;

  if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
    return peer->config_keepalive ;
  else
    return peer->bgp->default_keepalive ;
} ;

/*------------------------------------------------------------------------------
 * Get the HoldTime for the given peer or peer group.
 *
 * If 'current', then for a (real) peer which is pEnabled or pEstablished:
 *
 *   * pEnabled
 *
 *     the value returned is the value which is advertised in any OPEN messages
 *     which will be or have been sent.
 *
 *   * pEstablished
 *
 *     the value returned is the value negotiated for this established session.
 *
 * Otherwise:
 *
 *   * if is PEER_CONFIG_TIMER, return the peer->config_holdtime
 *
 *   * otherwise, return peer->bgp->default_holdtime
 *
 * Returns: peer->holdtime = current effective value
 */
extern uint
peer_get_holdtime(bgp_peer peer, bool current)
{
  if (current && (peer->type == PEER_TYPE_REAL))
    {
      switch (peer->state)
        {
          case bgp_pEnabled:
          case bgp_pEstablished:
            return peer->current_holdtime ;

          default:
            break ;
        } ;
    } ;

  if (CHECK_FLAG (peer->config, PEER_CONFIG_TIMER))
    return peer->config_holdtime ;
  else
    return peer->bgp->default_holdtime ;
} ;

/*------------------------------------------------------------------------------
 * Get the ConnectRetryTime for the peer.
 *
 *   * if is PEER_CONFIG_CONNECT, return the peer->config_connect
 *
 *   * otherwise, return peer->bgp->default_connect_retry_secs
 *
 * Returns: current effective value -- seconds
 */
extern uint
peer_get_connect_retry_time(bgp_peer peer)
{
  if (CHECK_FLAG (peer->config, PEER_CONFIG_CONNECT))
    return peer->config_connect ;
  else
    return peer->bgp->default_connect_retry_time ;
} ;

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
  return peer->bgp->default_accept_retry_time ;
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
 *   * otherwise, return peer->bgp->default_openholdtime
 *
 * Returns: current effective value -- seconds
 */
extern uint
peer_get_open_hold_time(bgp_peer peer)
{
  return peer->bgp->default_openholdtime ;
} ;

/*------------------------------------------------------------------------------
 * Get the MRAI for the peer.
 *
 *   * if is PEER_CONFIG_MRAI, return the peer->config_mrai
 *
 *   * otherwise, return peer->bgp->default_xbgp_mrai -- depending on the
 *     peer->sort.
 *
 * Returns: current effective value
 */
extern uint
peer_get_mrai(bgp_peer peer)
{
  if (CHECK_FLAG (peer->config, PEER_CONFIG_MRAI))
    return peer->config_mrai ;
  else
    {
      switch (peer->sort)
        {
          case BGP_PEER_IBGP:
            return peer->bgp->default_ibgp_mrai ;

          case BGP_PEER_CBGP:
            return peer->bgp->default_cbgp_mrai ;

          case BGP_PEER_EBGP:
          default:
            return peer->bgp->default_ebgp_mrai ;
        } ;
    } ;
} ;

