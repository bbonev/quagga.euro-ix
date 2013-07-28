/* BGP-4, BGP-4+ daemon program
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

#include <zebra.h>
#include "misc.h"

#include "command.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_peer_vty.h"

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
#ifdef HAVE_SNMP
#include "bgpd/bgp_snmp.h"
#endif /* HAVE_SNMP */

/* BGP process wide configuration.
 */
static struct bgp_master bgp_master;

extern struct in_addr router_id_zebra;

/* BGP process wide configuration pointer to export.
 */
struct bgp_master *bm;

/* BGP process wide nexus.
 */
qpn_nexus cli_nexus     = NULL;
qpn_nexus bgp_nexus     = NULL;
qpn_nexus routing_nexus = NULL;

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

/*==============================================================================
 * BGP global flag manipulation.
 */

extern bgp_ret_t
bgp_option_set (uint flag)
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

extern bgp_ret_t
bgp_option_unset (uint flag)
{
  switch (flag)
    {
      case BGP_OPT_MULTIPLE_INSTANCE:
        if (listcount (bm->bgp) > 1)
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

extern bool
bgp_option_check (uint flag)
{
  return (bm->options & flag);
}

/* BGP flag manipulation.  */
extern void
bgp_flag_set (bgp_inst bgp, uint flag)
{
  bgp->flags |= flag ;
}

extern void
bgp_flag_unset (bgp_inst bgp, uint flag)
{
  bgp->flags &= ~flag ;
}

extern bool
bgp_flag_check (bgp_inst bgp, uint flag)
{
  return (bgp->flags & flag);
}

/*==============================================================================
 * BGP keepalive and holdtime -- defaults for BGP Instance
 *
 * NB: enforces holdtime may not be 1..2
 *
 * NB: the keepalive may be any value... the KeepaliveTime for a given session
 *     is subject to negotiation, and this configured value is part of that.
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_timers_set (bgp_inst bgp, uint32_t keepalive, uint holdtime)
{
  if ((holdtime > 0) && (holdtime < 3))
    holdtime = 3 ;

  bgp->default_keepalive = keepalive ;
  bgp->default_holdtime  = holdtime ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_timers_unset (bgp_inst bgp)
{
  return bgp_timers_set (bgp, BGP_DEFAULT_KEEPALIVE, BGP_DEFAULT_HOLDTIME) ;
}

/*==============================================================================
 * BGP Connect Retry Time -- default for BGP Instance
 *
 * This is generally 120 secs.
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_connect_retry_time_set (bgp_inst bgp, uint connect_retry_time)
{
  bgp->default_connect_retry_time = connect_retry_time ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_connect_retry_time_unset (bgp_inst bgp)
{
  return bgp_connect_retry_time_set (bgp, BGP_DEFAULT_CONNECT_RETRY) ;
}

/*==============================================================================
 * BGP Accept Retry Time -- default for BGP Instance
 *
 * This is generally 240 secs (4 minutes -- same as "OpenHoldTime").
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_accept_retry_time_set (bgp_inst bgp, uint accept_retry_time)
{
  bgp->default_accept_retry_time = accept_retry_time ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_accept_retry_time_unset (bgp_inst bgp)
{
  return bgp_accept_retry_time_set (bgp, BGP_DEFAULT_CONNECT_RETRY) ;
}

/*==============================================================================
 * BGP Open Hold Time -- default for BGP Instance
 *
 * This is generally 240 secs (4 minutes -- RFC4271).
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_open_hold_time_set (bgp_inst bgp, uint openholdtime)
{
  bgp->default_openholdtime = openholdtime ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_open_hold_time_unset (bgp_inst bgp)
{
  return bgp_open_hold_time_set (bgp, BGP_DEFAULT_OPENHOLDTIME) ;
}

/*==============================================================================
 * BGP MRAI -- defaults for BGP Instance
 *
 * These are generally 5 secs for iBGP and 30 secs for eBGP and cBGP.
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_mrai_set (bgp_inst bgp, uint ibgp_mrai, uint cbgp_mrai, uint ebgp_mrai)
{
  bgp->default_ibgp_mrai = ibgp_mrai ;
  bgp->default_cbgp_mrai = cbgp_mrai ;
  bgp->default_ebgp_mrai = ebgp_mrai ;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_mrai_unset (bgp_inst bgp)
{
  return bgp_mrai_set (bgp, BGP_DEFAULT_IBGP_MRAI,
                            BGP_DEFAULT_CBGP_MRAI,
                            BGP_DEFAULT_EBGP_MRAI) ;
} ;

/*==============================================================================
 * CONFEDERATION stuff
 */
static void bgp_check_confed_id_set(bgp_inst bgp) ;
static bgp_ret_t bgp_peer_down_pending(bgp_inst bgp, peer_down_t why) ;

/*------------------------------------------------------------------------------
 * Set BGP router identifier, and update all peers as required.
 *
 * If 'set' is true, set the given router_id -- for "bgp router-id"
 *
 * If 'set' is false, clear the router_id down to the default
 *                                            -- for "no bgp router-id"
 *                                            -- and for initialisation
 *
 * NB: when a bgp instance is created, its router-id is set to the default.
 *
 * NB: if the cluster-id is not set, this also updates the cluster-id.
 */
extern bgp_ret_t
bgp_router_id_set (bgp_inst bgp, in_addr_t router_id, bool set)
{
  bgp_peer peer ;
  struct listnode *node, *nnode;

  if (set)
    bgp->config |= BGP_CONFIG_ROUTER_ID ;
  else
    {
      bgp->config &= ~BGP_CONFIG_ROUTER_ID ;
      router_id = router_id_zebra.s_addr ;
    } ;

  if (bgp->router_id == router_id)
    return BGP_SUCCESS ;

  bgp->router_id = router_id ;

  if (!(bgp->config & BGP_CONFIG_CLUSTER_ID))
    bgp->cluster_id = router_id ;

  /* Set all peer's local identifier with this value.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer->local_id = router_id ;
      bgp_peer_down(peer, PEER_DOWN_RID_CHANGE) ;
    }
  return 0;
}

/*------------------------------------------------------------------------------
 * Set the given bgp instance's cluster-id, and update all peers as required.
 *
 * If 'set' is true, set the given cluster_id -- for "bgp cluster-id"
 *
 * If 'set' is false, clear the cluster_id down to the default
 *                                            -- for "no bgp cluster-id"
 */
extern bgp_ret_t
bgp_cluster_id_set (bgp_inst bgp, in_addr_t cluster_id, bool set)
{
  bgp_peer peer;
  struct listnode *node, *nnode;

  if (set)
    bgp->config |= BGP_CONFIG_CLUSTER_ID ;
  else
    {
      bgp->config &= ~BGP_CONFIG_CLUSTER_ID ;
      cluster_id = bgp->router_id ;
    } ;

  if (bgp->cluster_id == cluster_id)
    return BGP_SUCCESS ;

  bgp->cluster_id = cluster_id ;

  /* Update all IBGP peers.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      qassert(peer->type == PEER_TYPE_REAL) ;

      if (peer->sort != BGP_PEER_IBGP)
        continue;

      bgp_peer_down(peer, PEER_DOWN_CLID_CHANGE) ;
    } ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Set given bgp instance to be a Confederation.
 *
 * If this changes the state of any peer, will set it down_pending.
 * Once has checked all peers, downs any which have changed.  Note that this
 * means that all peers change state "as one", before anything else happens.
.*
 * NB: if not currently a Confederation (ie bgp->confed_id == BGP_ASN_NULL),
 *     then any peers in the confed_peers set will now become confederation
 *     peers.
 *
 * NB: for eBGP sessions, bgp->confed_id and peer->change_local_as both have
 *     an effect on the session.
 *
 *     If bgp->confed_id and peer->change_local_as are both set:
 *
 *       * if they are equal, bgp->confed_id overrides peer->change_local_as.
 *
 *       * if they are not equal, peer->change_local_as takes precedence.
 *
 *     Another way of looking at this is to consider the "true local_as".  The
 *     true local_as is the local_as which would be used (for eBGP) in the
 *     absence of any change_local_as.  So the true local_as is bgp->confed_id
 *     if that is set, or bgp->as
 */
extern bgp_ret_t
bgp_confederation_id_set (bgp_inst bgp, as_t confed_id)
{
  as_t old_confed_id, old_true_local_as ;
  bgp_peer peer ;
  struct listnode *node, *nnode;

  if (confed_id == BGP_ASN_NULL)
    return BGP_ERR_INVALID_AS ;

  if (confed_id == bgp->confed_id)
    return BGP_SUCCESS ;                /* no change !  */

  /* Pick up the old state and update.
   */
  old_confed_id     = bgp->confed_id ;
  old_true_local_as = bgp->ebgp_as ;

  bgp->ebgp_as = bgp->confed_id = confed_id ;

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->local_as as
   * required.
   *
   * If we are enabling CONFED then:
   *
   *   * BGP_PEER_IBGP peers do not change, because that state does not
   *     depend on the CONFED state or on the confed_peer set.
   *
   *   * BGP_PEER_CBGP peers do not currently exist.
   *
   *   * BGP_PEER_EBGP peers will either:
   *
   *      * if the peer->as is in the confed_peer_set:
   *
   *        change state to BGP_PEER_CBGP, and reset the session.
   *
   *        peer->local_as will be set to peer->bgp->as -- change_local_as
   *        does not apply to BGP_PEER_CBGP.
   *
   *     or:
   *
   *      * if the peer->as is NOT in the confed_peer_set:
   *
   *        remain as BGP_PEER_EBGP, but the state may change as discussed
   *        above and the session will be reset as required.
   *
   * If CONFED was enabled before:
   *
   *   * BGP_PEER_IBGP peers do not change, because that state does not
   *     depend on the CONFED state or on the confed_peer set -- no session
   *     reset is required.
   *
   *   * BGP_PEER_CBGP peers do not change, because the confed_peer set is
   *     unchanged -- no session reset is required.
   *
   *   * BGP_PEER_EBGP peers do not change, because the confed_peer set is
   *     unchanged -- but the state may change as discussed above and the
   *     session will be reset as required.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      /* We update and get the peer->sort for all peers.
       *
       * The peer->sort may change if we are enabling CONFED (ie if
       * old_confed_id == BGP_ASN_NULL) because this may change some eBGP
       * to CONFED sessions.
       */
      qassert(peer->bgp == bgp) ;

      switch (peer->sort)
        {
          /* No change if was iBGP
           */
          case BGP_PEER_IBGP:
            qassert(peer->as       == bgp->as) ;
            qassert(peer->local_as == bgp->as) ;
            break ;

          /* No change if was CONFED -- we have not changed confed_peers.
           *
           * Must previously have had CONFED enabled !
           */
          case BGP_PEER_CBGP:
            qassert(peer->as       != bgp->as) ;
            qassert(peer->local_as == bgp->as) ;
            qassert(old_confed_id  != BGP_ASN_NULL) ;
            qassert(asn_set_contains(bgp->confed_peers, peer->as)) ;
            break ;

          /* Was eBGP.
           *
           * If we are enabling CONFED then may now change to CONFED.
           *
           * If remains eBGP, need to process as discussed above.
           */
          case BGP_PEER_EBGP:
            qassert(peer->as != bgp->as) ;

            if (asn_set_contains(bgp->confed_peers, peer->as))
              {
                /* Change to BGP_PEER_CBGP required -- must previously
                 * NOT have had CONFED enabled !
                 */
                qassert(old_confed_id  == BGP_ASN_NULL) ;

                peer_sort_set(peer, BGP_PEER_CBGP) ;
                peer->down_pending = true ;
              }
            else
              {
                /* Remains BGP_PEER_EBGP
                 */
                if (peer->change_local_as == BGP_ASN_NULL)
                  {
                    /* No change_local_as to worry about, so update the
                     * peer->local_as, and if that changes, schedule a reset.
                     */
                    qassert(peer->local_as == old_true_local_as) ;

                    if (peer->local_as != bgp->confed_id)
                      {
                        peer->local_as = bgp->confed_id ;
                        peer->down_pending = true ;
                      } ;
                  }
                else if (peer->change_local_as == bgp->confed_id)
                  {
                    /* The change_local_as is overridden by the new confed_id.
                     *
                     * The change_local_as will have been in force because:
                     *
                     *   * if old confed_id was not set, then by definition the
                     *     change_local_as is not equal to bgp->as and takes
                     *     precedence over it.
                     *
                     *   * if old_confed_id was set, then it was not equal
                     *     to the new confed_id, and hence not equal to the
                     *     change_local_as, so the change_local_as took
                     *     precedence over it.
                     *
                     * in short, change_local_as was in force because it is
                     * not the same as the old true local_as.
                     *
                     * So... we need to reset the session.
                     *
                     * Note that the peer->local_as should not change !
                     */
                    qassert(peer->local_as    == peer->change_local_as) ;
                    qassert(old_true_local_as != peer->change_local_as) ;

                    peer->local_as = bgp->confed_id ;
                    peer->down_pending = true ;
                  }
                else
                  {
                    /* The change_local_as takes precedence over the new
                     * confed_id.
                     */
                    peer->local_as = peer->change_local_as ;

                    if (old_confed_id != BGP_ASN_NULL)
                      {
                        /* The old confed_id was set (and is not equal to the
                         * new confed_id).
                         *
                         * If old confed_id was not equal to change_local_as,
                         * then change_local_as took precedence before, but we
                         * need to reset because the true local_as is changing.
                         *
                         * If old confed_id was equal to change_local_as, then
                         * the old confed_id overrode the change_local_as, so
                         * we need to reset the session because change_local_as
                         * now takes precedence.
                         *
                         * In short, we need to reset.
                         */
                        peer->down_pending = true ;
                      }
                    else
                      {
                        /* The old confed_id was not set.
                         *
                         * Hence, the old true local_as will have been bgp->as.
                         *
                         * So, change_local_as took precedence before -- by
                         * definition change_local_as != bgp->as -- so no
                         * change there.
                         *
                         * The new true local_as is the new confed_id.
                         *
                         * So, if the new confed_id == old_true_local_as, then
                         * nothing changes.
                         *
                         * Otherwise, we have a change of true local_as, and
                         * we need to reset.
                         */
                        qassert(bgp->as == old_true_local_as) ;

                        if (bgp->confed_id != old_true_local_as)
                          peer->down_pending = true ;
                      } ;
                  } ;
              } ;
            break ;

          /* Press on, regardless, if don't recognise the state
           */
          case BGP_PEER_UNSPECIFIED:
          default:
            break ;
        } ;
    } ;

  return bgp_peer_down_pending(bgp, PEER_DOWN_CONFED_ID_CHANGE) ;
} ;

/*------------------------------------------------------------------------------
 * Unset Confederation state of given bgp instance, if any.
 *
 * Does nothing if Confederation state not set
 *
 * If this changes the state of any peer, will set it down_pending.
 * Once has checked all peers, downs any which have changed.  Note that this
 * means that all peers change state "as one", before anything else happens.
 *
 * NB: this does not affect the config_peers set -- which has a separate
 *     life-time.
 */
extern bgp_ret_t
bgp_confederation_id_unset (bgp_inst bgp)
{
  bgp_peer peer ;
  as_t     old_true_local_as ;
  struct listnode *node, *nnode;

  if (bgp->confed_id == BGP_ASN_NULL)
    return BGP_SUCCESS ;                /* no change !  */

  /* Pick up old state and update
   */
  old_true_local_as = bgp->ebgp_as ;
  qassert(old_true_local_as == bgp->confed_id) ;

  bgp->confed_id = BGP_ASN_NULL ;
  bgp->ebgp_as   = bgp->as ;            /* as you was   */

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->local_as as
   * required.  Since CONFED was enabled before:
   *
   *   * BGP_PEER_IBGP peers do not change, because that state does not
   *     depend on the CONFED state or on the confed_peer set.
   *
   *   * BGP_PEER_CBGP peers will change to BGP_PEER_EBGP.
   *
   *     The sessions need to be reset because the sort has changed.
   *
   *   * BGP_PEER_EBGP peers do not change.
   *
   *     But, the peer->local_as needs to be updated, and the sessions reset
   *     if that changes -- and need to take into account change_local_as.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      switch (peer->sort)
        {
          /* No change for iBGP
           */
          case BGP_PEER_IBGP:
            qassert(peer->as       == bgp->as) ;
            qassert(peer->local_as == bgp->as) ;
            break ;

          /* CONFED changes to eBGP.
           */
          case BGP_PEER_CBGP:
            qassert(peer->as       != bgp->as) ;
            qassert(peer->local_as == bgp->as) ;
            qassert(asn_set_contains(bgp->confed_peers, peer->as)) ;

            peer_sort_set(peer, BGP_PEER_EBGP) ;
            peer->down_pending = true ;
            break ;

          /* eBGP stays eBGP, but peer->local_as may change
           *
           * If peer->change_local_as is not set:
           *
           *   Need to update the peer->local_as to the current bgp->ebgp_as,
           *   and if that has changed, reset the session.
           *
           * If peer->change_local_as is set:
           *
           *   It must now take precedence -- by definition.
           *
           *   If change_local_as == old true local_as, then it did not take
           *   precedence before, so need to reset because it takes precedence
           *   now.
           *
           *   If change_local_as != old true local_as, then it took precedence
           *   before, and we need to reset if the new and old true local_as
           *   are not the same.
           */
          case BGP_PEER_EBGP:
            qassert(peer->as != bgp->as) ;

            if (peer->change_local_as == BGP_ASN_NULL)
              {
                if (peer->local_as != bgp->ebgp_as)
                  {
                    peer->local_as = bgp->ebgp_as ;
                    peer->down_pending = true ;
                  } ;
              }
            else
              {
                qassert(peer->change_local_as != bgp->ebgp_as) ;

                peer->local_as = peer->change_local_as ;

                if ( (peer->change_local_as == old_true_local_as)
                                        || (bgp->ebgp_as != old_true_local_as) )
                  peer->down_pending = true ;
              } ;
            break ;

          /* Press on, regardless, if don't recognise the state
           */
          case BGP_PEER_UNSPECIFIED:
          default:
            break ;
        } ;
    } ;

  return bgp_peer_down_pending(bgp, PEER_DOWN_CONFED_ID_CHANGE) ;
} ;

/*------------------------------------------------------------------------------
 * If the given bgp instance is a CONFED, is the given AS a CONFED Member AS,
 * for a *different* CONFED Member.
 *
 * Note that to be a CONFED there must be a confed_id configured.  The
 * set of confed_peers has an independent lifetime.
 *
 * Returns:  true <=> bgp != NULL and this is a CONFED
 *                                and the given AS is a CONFED Member AS
 *                                and the given AS is NOT the bgp->as
 *
 * NB: bgp->confed_peers should not contain the current bgp->as, but we
 *     check for asn == bgp->as in any case -- apart from safety, one notes
 *     that there may be a large number of iBGP sessions.
 */
extern bool
bgp_confederation_peers_check (bgp_inst bgp, as_t asn)
{
  if ((bgp != NULL) && (bgp->confed_id != BGP_ASN_NULL))
    return  (asn != bgp->as) && asn_set_contains(bgp->confed_peers, asn) ;

  return false ;
}

/*------------------------------------------------------------------------------
 * Add an AS to the confederation peers set.
 *
 * Has no effect if the AS is already in the confed_peers set.
 *
 * Caller MUST call bgp_confederation_peers_scan() to complete the process.
 * (Caller may add many ASN to the confed_peers set, before doing this.)
 *
 * NB: the ASN may NOT be bgp->as
 */
extern bgp_ret_t
bgp_confederation_peers_add(bgp_inst bgp, as_t asn)
{
  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;

  if (bgp->as == asn)
    return BGP_ERR_INVALID_AS ; /* cannot be self       */

  bgp->confed_peers = asn_set_add(bgp->confed_peers, asn) ;

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 * Delete an AS from the confederation set.
 *
 * Caller MUST call bgp_confederation_peers_scan() to complete the process.
 * (Caller may add many ASN to the confed_peers set, before doing this.)
 */
extern bgp_ret_t
bgp_confederation_peers_remove (bgp_inst bgp, as_t asn)
{
  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;

  asn_set_del(bgp->confed_peers, asn) ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Scan all peers to see if change to confed_peers set and change any whose
 * state has been affected.
 *
 * Does nothing if the bgp instance is not configured as a confederation.
 *
 * If this changes the state of any peer, will set it down_pending.
 * Once has checked all peers, downs any which have changed.  Note that this
 * means that all peers change state "as one", before anything else happens.
 */
extern bgp_ret_t
bgp_confederation_peers_scan(bgp_inst bgp)
{
  struct peer *peer;
  struct listnode *node, *nnode;

  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;        /* No can do                    */

  if (bgp->confed_id == BGP_ASN_NULL)
    return BGP_SUCCESS ;                /* No difference if not enabled */

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->local_as as
   * required.  Since CONFED was enabled before:
   *
   *   * BGP_PEER_IBGP peers do not change, because that state does not
   *     depend on the confed_peer set.
   *
   *   * BGP_PEER_CBGP peers may change to BGP_PEER_EBGP, where their
   *     asn has been removed from the confed_peers set.
   *
   *   * BGP_PEER_EBGP peers may change to BGP_PEER_CBGP, where their
   *     asn has been added to the confed_peers set.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      switch (peer->sort)
        {
          /* No change for iBGP.
           */
          case BGP_PEER_IBGP:
            qassert(peer->as       == bgp->as) ;
            qassert(peer->local_as == bgp->as) ;
            break ;

          /* CONFED changes to eBGP, if peer->as no longer in confed_peers.
           */
          case BGP_PEER_CBGP:
            qassert(peer->as       != bgp->as) ;
            qassert(peer->local_as == bgp->as) ;

            if (!asn_set_contains(bgp->confed_peers, peer->as))
              {
                /* Change to BGP_PEER_EBGP required.
                 */
                peer_sort_set(peer, BGP_PEER_EBGP) ;
                peer->down_pending = true ;
              } ;
            break ;

          /* eBGP changes to CONFED, if peer->as is now in confed_peers
           */
          case BGP_PEER_EBGP:
            qassert(peer->as       != bgp->as) ;

            if (asn_set_contains(bgp->confed_peers, peer->as))
              {
                /* Change to BGP_PEER_EBGP required.
                 */
                peer_sort_set(peer, BGP_PEER_CBGP) ;
                peer->down_pending = true ;
              } ;
            break ;

          /* Press on, regardless, if don't recognise the state
           */
          case BGP_PEER_UNSPECIFIED:
          default:
            break ;
        } ;
    } ;

  return bgp_peer_down_pending(bgp, PEER_DOWN_CONFED_ID_CHANGE) ;
} ;

/*------------------------------------------------------------------------------
 * Set the bgp->check_confed_id and bgp->check_confed_id_all flags
 *                                                -- depending on current state.
 *
 * When there is a confederation (bgp->confed_id != NULL) then bgp->as is
 * the Member AS, and:
 *
 *  * for iBGP and cBGP sessions we filter out routes which contain bgp->as in
 *    the AS-PATH in any case.
 *
 *    If the bgp->as != confed_id, then should check for the confed_id as well.
 *
 *  * for eBGP sessions we filter out routes which contain the confed_id in
 *    the AS-PATH in any case.
 *
 *    If the bgp->as != confed_id, then should check for the bgp->as as well.
 *
 * So:
 *
 *   * if confed_id == BGP_ASN_NULL or confed_id == bgp->as
 *
 *     clear both flags -- no check required either because is not in a
 *     confederation, or because we check for confed_id or bgp->as anyway.
 *
 *   * otherwise
 *
 *     set bgp->check_confed_id
 *
 *     if confed_id is not in confed_peers
 *
 *       set bgp->check_confed_id_all   -- we do not expect the confed_id to
 *                                         appear *anywhere* in the AS-PATH.
 *
 *       clear bgp->check_confed_id_all -- the confed_id is the Member AS of
 *                                         another member, so may appear in
 *                                         a Confed Segment, but NOT in the
 *                                         main part of the AS-PATH.
 */
static void
bgp_check_confed_id_set(bgp_inst bgp)
{
  if ((bgp->confed_id == BGP_ASN_NULL) || (bgp->confed_id == bgp->as))
    {
      bgp->check_confed_id     = false ;
      bgp->check_confed_id_all = false ;
    }
  else
    {
      bgp->check_confed_id     = true ;
      bgp->check_confed_id_all = !asn_set_contains(bgp->confed_peers,
                                                               bgp->confed_id) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Run along list of peers for given bgp instance, and for any which are
 * marked down_pending, clear the flag and down the peer for the
 * given reason.
 */
static bgp_ret_t
bgp_peer_down_pending(bgp_inst bgp, peer_down_t why)
{
  bgp_peer peer ;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer->down_pending)
        {
          peer->down_pending = false ;
          bgp_peer_down(peer, why) ;
        } ;
    } ;

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Local preference configuration.
 */
extern bgp_ret_t
bgp_default_local_preference_set (bgp_inst bgp, uint32_t local_pref)
{
  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;

  bgp->default_local_pref = local_pref;

  return BGP_SUCCESS ;
}

extern bgp_ret_t
bgp_default_local_preference_unset (bgp_inst bgp)
{
  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;

  bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF;

  return BGP_SUCCESS ;
}

/*==============================================================================
 * BGP Instance creation, lookup, shut-down etc.
 */

static bgp_inst bgp_create (as_t as, const char *name) ;
static bgp_inst bgp_free(bgp_inst bgp) ;

/*------------------------------------------------------------------------------
 * Return first entry of BGP.
 *
 * Where multiple BGP instances are enabled, they are kept on the list of same
 * in arrival order -- and that order is preserved when configuration is
 * written.
 *
 *
 *
 */
extern struct bgp *
bgp_get_default (void)
{
  if (bm->bgp->head)
    return (listgetdata (listhead (bm->bgp)));
  return NULL;
}

/*------------------------------------------------------------------------------
 * Lookup BGP entry -- by ASN and Name
 */
extern struct bgp *
bgp_lookup (as_t as, const char *name)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    if ((bgp->as == as)
        && ((bgp->name == NULL && name == NULL)
            || (bgp->name && name && strcmp (bgp->name, name) == 0)))
      return bgp;
  return NULL;
}

/*------------------------------------------------------------------------------
 * Lookup BGP structure by view name.
 */
extern struct bgp *
bgp_lookup_by_name (const char *name)
{
  struct bgp *bgp;
  struct listnode *node, *nnode;

  for (ALL_LIST_ELEMENTS (bm->bgp, node, nnode, bgp))
    if ((bgp->name == NULL && name == NULL)
        || (bgp->name && name && strcmp (bgp->name, name) == 0))
      return bgp;
  return NULL;
}

/*------------------------------------------------------------------------------
 * Lookup bgp instance for vty.
 *
 * If the given name is NULL, return "default" bgp instance (if any).
 *
 * Otherwise lookup by name.
 */
extern bgp_inst
bgp_lookup_vty(vty vty, const char *name)
{
  bgp_inst bgp ;

  if (name == NULL)
    {
      bgp = bgp_get_default ();
      if (bgp == NULL)
        vty_out (vty, "No BGP process is configured\n");
    }
  else
    {
      bgp = bgp_lookup_by_name (name);
      if (bgp == NULL)
        vty_out (vty, "Can't find BGP view %s\n", name);
    } ;

  return bgp ;
} ;

/*------------------------------------------------------------------------------
 * Find given bgp instance, or create it.
 *
 * *p_as is a read/write argument:
 *
 *   * when bgp_get() is called it must be set to the ASN of the bgp instance,
 *     and must be a valid ASN
 *
 *   * if the bgp instance found has a different ASN, then *p_as is set to its
 *     ASN.
 *
 * BGP_OPT_MULTIPLE_INSTANCE must be set if an instance (view) name is given.
 *
 * NB: a NULL name refers to the first bgp instance created (the "default").
 *
 *     If BGP_OPT_MULTIPLE_INSTANCE is not set, then there is at most one
 *     instance and that is the "unnamed" one.
 *
 *     If BGP_OPT_MULTIPLE_INSTANCE is set, then the first instance may or
 *     may not have a name.
 *
 * NB: a bgp instance must have a unique name, but multiple instances may use
 *     the same ASN.
 *
 * NB: "router bgp <ASN> [view <NAME>]" selects the bgp instance or creates
 *     it if does not already exist.
 *
 *     What this does NOT do is change the ASN for a given bgp instance.  To
 *     do that requires all existing configuration to be discarded, and
 *     everything recreated in a new instance.
 *
 *     NOR does this change the view name of an existing instance.
 */
extern bgp_ret_t
bgp_get (bgp_inst* p_bgp, as_t* p_as, const char *name)
{
  bgp_inst bgp;

  *p_bgp = NULL ;               /* tidy         */

  /* If no name is given, get the default (and possibly only) instance.
   *
   * Otherwise, iff we are allowed multiple instances, look up by name.
   *
   * NB: the default is simply the first instance created, and may or may not
   *     have a name.
   */
  if (name == NULL)
    bgp = bgp_get_default() ;
  else
    {
      if (bm->options & BGP_OPT_MULTIPLE_INSTANCE)
        bgp = bgp_lookup_by_name (name) ;
      else
        return BGP_ERR_MULTIPLE_INSTANCE_NOT_SET;
    }

  /* If bgp instance does not exist, create it.
   *
   * Otherwise, check that the asn matches the given one.
   */
  if (bgp == NULL)
    {
      bgp = bgp_create (*p_as, name) ;
      listnode_add (bm->bgp, bgp) ;

      /* We set the router-id as if we were unsetting an explicitly set
       * router-id -- which implicitly sets the default.
       */
      bgp_router_id_set(bgp, 0, false) ;
    }
  else
    {
      if (bgp->as != *p_as)
        {
          /* Mismatch asn -- return actual ASN and appropriate error.
           */
          *p_as  = bgp->as;

          if (name != NULL)
            return BGP_ERR_INSTANCE_MISMATCH;
          else
            return BGP_ERR_AS_MISMATCH;
        } ;
    } ;

  *p_bgp = bgp;
  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * BGP instance creation by `router bgp' commands.
 */
static bgp_inst
bgp_create (as_t as, const char *name)
{
  bgp_inst bgp;

  bgp = XCALLOC (MTYPE_BGP, sizeof (bgp_inst_t)) ;

  /* Zeroising sets:
   *
   *   * as                      -- X        -- set below
   *   * name                    -- NULL     -- set below, if required
   *
   *   * lock                    -- 0        -- no references, yet
   *
   *   * peer_self               -- X        -- set below
   *
   *   * peer                    -- X        -- set below
   *   * group                   -- X        -- set below
   *
   *   * router_id               -- 0        -- unset
   *   * cluster_id              -- 0        -- unset
   *   * ebgp_as                 -- 0        -- unset
   *
   *   * confed_id               -- BGP_ASN_NULL  -- no CONFED
   *   * confed_peers            -- NULL     -- none, yet
   *   * check_confed_id         -- false
   *   * check_confed_id_all     -- false
   *
   *   * config                  -- 0        -- no bgp_config_bits_t
   *   * flags                   -- 0        -- no bgp_flag_bits_t
   *   * af_flags[qafx]          -- 0s       -- no bgp_af_flag_bits_t
   *
   *   * route[qafx]             -- NULLs    -- no static routes
   *   * aggregate[qafx]         -- NULLs    -- no aggregate routes
   *
   *   * rib[rib_type][qafx]     -- NULLs    -- no RIBs
   *
   *   * redist[AFI_MAX][ZEBRA_ROUTE_MAX]            -- false
   *   * redist_metric_set[AFI_MAX][ZEBRA_ROUTE_MAX] -- false
   *   * redist_metric[AFI_MAX][ZEBRA_ROUTE_MAX]     -- 0
   *   * rmap[AFI_MAX][ZEBRA_ROUTE_MAX].name         -- NULL
   *   *                               .map          -- NULL
   *
   *   * distance_ebgp           -- 0        -- unset
   *   * distance_ibgp           -- 0        -- unset
   *   * distance_local          -- 0        -- unset
   *
   *   * default_local_pref      -- X        )
   *   * default_med             -- X        )
   *   * default_holdtime        -- X        ) set below
   *   * default_keepalive       -- X        )
   *   * restart_time            -- X        )
   *   * stalepath_time          -- X        )
   */
  bgp_lock (bgp);

  bgp->as = bgp->ebgp_as  = as;  /* bgp->confed_id == BGP_ASN_NULL       */

  if (name)
    bgp->name = strdup (name);

  bgp->peer_self = bgp_peer_new (bgp, PEER_TYPE_SELF);
  bgp->peer_self->host = XSTRDUP (MTYPE_BGP_PEER_HOST, "Static announcement");

  bgp->peer = list_new ();
  bgp->peer->cmp = (int (*)(void *, void *)) peer_cmp;

  bgp->group = list_new ();
  bgp->group->cmp = (int (*)(void *, void *)) peer_group_cmp;

  bgp->default_local_pref = BGP_DEFAULT_LOCAL_PREF ;
  bgp->default_med        = 0 ;
  bgp->default_weight     = 0 ;

  /* Set default timer values
   */
  bgp_timers_unset(bgp) ;
  bgp_connect_retry_time_unset(bgp) ;
  bgp_accept_retry_time_unset(bgp) ;
  bgp_open_hold_time_unset(bgp) ;
  bgp_mrai_unset(bgp) ;

  bgp->restart_time       = BGP_DEFAULT_RESTART_TIME ;
  bgp->stalepath_time     = BGP_DEFAULT_STALEPATH_TIME ;

  return bgp;
} ;

/*------------------------------------------------------------------------------
 * Delete BGP instance.
 */
extern bgp_ret_t
bgp_delete (bgp_inst bgp)
{
  struct peer *peer;
  struct peer_group *group;
  struct listnode *node;
  struct listnode *next;
  qAFI_t q_afi;
  int i;

  /* Delete static route.
   */
  bgp_static_delete (bgp);

  /* Unset redistribution.
   */
  for (q_afi = qAFI_first; q_afi <= qAFI_last; q_afi++)
    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
      if (i != ZEBRA_ROUTE_BGP)
        bgp_redistribute_unset (bgp, q_afi, i);

  for (ALL_LIST_ELEMENTS (bgp->peer, node, next, peer))
    bgp_peer_delete (peer);

  for (ALL_LIST_ELEMENTS (bgp->group, node, next, group))
    peer_group_delete (group);

  if (bgp->peer_self)
    bgp->peer_self = bgp_peer_delete(bgp->peer_self);

  /* Remove visibility via the master list - there may however still be
   * routes to be processed still referencing the struct bgp.
   */
  listnode_delete (bm->bgp, bgp);

  bgp_unlock(bgp);  /* initial reference */

  return BGP_SUCCESS ;
}

/*------------------------------------------------------------------------------
 */
extern bgp_inst
bgp_lock (bgp_inst bgp)
{
  ++bgp->lock;
  return bgp ;
}

/*------------------------------------------------------------------------------
 */
extern bgp_inst
bgp_unlock(bgp_inst bgp)
{
  qassert(bgp->lock > 0);

  if (bgp->lock > 1)
    {
      --bgp->lock ;
      return NULL ;
    } ;

    return bgp_free (bgp);
}

/*------------------------------------------------------------------------------
 */
static bgp_inst
bgp_free(bgp_inst bgp)
{
  qafx_t qafx ;

  list_delete (bgp->group);
  list_delete (bgp->peer);

  if (bgp->name)
    free (bgp->name);

  for (qafx = qafx_first ; qafx <= qafx_last ; qafx++)
    {
      bgp->rib[qafx][rib_main] = bgp_rib_destroy(bgp->rib[qafx][rib_main]);
      bgp->rib[qafx][rib_rs]   = bgp_rib_destroy(bgp->rib[qafx][rib_rs]);
      bgp->route[qafx]         = bgp_table_finish (bgp->route[qafx]);
      bgp->aggregate[qafx]     = bgp_table_finish (bgp->aggregate[qafx]);
    } ;

  XFREE (MTYPE_BGP, bgp);

  return NULL ;
}

/*==============================================================================
 */

/* Display "address-family" configuration header.
 */
extern void
bgp_config_write_family_header (struct vty *vty, qafx_t qafx, int* p_write)
{
  const char* name ;

  if (*p_write)
    return;

  if (qafx == qafx_ipv4_unicast)
    return;

#if 0
  /* Don't need to group this, since is bgpd daemon specific
   */
  vty_out_vtysh_config_group(vty, "address-family %u/%u", afi, safi) ;
#endif

  switch (qafx)
    {
      case qafx_ipv4_multicast:
        name = "ipv4 multicast" ;
        break ;

      case qafx_ipv4_mpls_vpn:
        name = "vpnv4 unicast" ;
        break ;

#if HAVE_IPV6
      case qafx_ipv6_unicast:
        name = "ipv6" ;
        break ;

      case qafx_ipv6_multicast:
        name = "ipv6 multicast" ;
#endif

      default:
        vty_out (vty, "!\n UNKNOWN address-family qafx=%u\n", qafx) ;
        return ;
    } ;

  vty_out (vty, "!\n address-family %s\n", name);

  *p_write = 1;
} ;

/*------------------------------------------------------------------------------
 * Address family based peer configuration display.
 */
static int
bgp_config_write_family (struct vty *vty, struct bgp *bgp, qafx_t qafx)
{
  int write = 0;
  struct peer *peer;
  struct peer_group *group;
  struct listnode *node, *nnode;

  bgp_config_write_network (vty, bgp, qafx, &write);

  bgp_config_write_redistribute (vty, bgp, qafx, &write);

  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    {
      if (peer_family_is_active(group->conf, qafx))
        {
          bgp_config_write_family_header (vty, qafx, &write);
          bgp_config_write_peer (vty, bgp, group->conf, qafx);
        }
    } ;

  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      if (peer_family_is_active(peer, qafx))
        {
          bgp_config_write_family_header (vty, qafx, &write);
          bgp_config_write_peer (vty, bgp, peer, qafx);
        }
    }
  if (write)
    {
      vty_out (vty, " exit-address-family%s", VTY_NEWLINE);
#if 0
      /* Don't need to group this, since is bgpd daemon specific
       */
      vty_out_vtysh_config_group_end(vty) ;
#endif
    } ;

  return write;
}

/*------------------------------------------------------------------------------
 *
 */
int
bgp_config_write (struct vty *vty)
{
  int write = 0;
  struct bgp *bgp;
  struct peer_group *group;
  struct peer *peer;
  struct listnode *node, *nnode;
  struct listnode *mnode, *mnnode;
  uint n ;

  /* BGP Multiple instance.
   */
  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "bgp multiple-instance%s", VTY_NEWLINE);
      write++;
    }

  /* BGP Config type.
   */
  if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
    {
      vty_out (vty, "bgp config-type cisco%s", VTY_NEWLINE);
      write++;
    }

  /* BGP configuration.
   */
  for (ALL_LIST_ELEMENTS (bm->bgp, mnode, mnnode, bgp))
    {
      if (write)
        vty_out (vty, "!%s", VTY_NEWLINE);

      /* Router bgp ASN */
      vty_out (vty, "router bgp %u", bgp->as);

      if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
        {
          if (bgp->name)
            vty_out (vty, " view %s", bgp->name);
        }
      vty_out (vty, "%s", VTY_NEWLINE);

      /* No Synchronization */
      if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
        vty_out (vty, " no synchronization%s", VTY_NEWLINE);

      /* BGP fast-external-failover. */
      if (bgp->flags & BGP_FLAG_NO_FAST_EXT_FAILOVER)
        vty_out (vty, " no bgp fast-external-failover%s", VTY_NEWLINE);

      /* BGP router ID. */
      if (bgp->config & BGP_CONFIG_ROUTER_ID)
        vty_out (vty, " bgp router-id %s%s",
                          siptoa(AF_INET, &bgp->router_id).str, VTY_NEWLINE);

      /* BGP log-neighbor-changes. */
      if (bgp_flag_check (bgp, BGP_FLAG_LOG_NEIGHBOR_CHANGES))
        vty_out (vty, " bgp log-neighbor-changes%s", VTY_NEWLINE);

      /* BGP configuration
       */
      if (bgp_flag_check (bgp, BGP_FLAG_ALWAYS_COMPARE_MED))
        vty_out (vty, " bgp always-compare-med%s", VTY_NEWLINE);

      /* BGP default ipv4-unicast.
       */
      if (bgp_flag_check (bgp, BGP_FLAG_NO_DEFAULT_IPV4))
        vty_out (vty, " no bgp default ipv4-unicast%s", VTY_NEWLINE);

      /* BGP default local-preference.
       */
      if (bgp->default_local_pref != BGP_DEFAULT_LOCAL_PREF)
        vty_out (vty, " bgp default local-preference %d%s",
                 bgp->default_local_pref, VTY_NEWLINE);

      /* BGP client-to-client reflection.
       */
      if (bgp_flag_check (bgp, BGP_FLAG_NO_CLIENT_TO_CLIENT))
        vty_out (vty, " no bgp client-to-client reflection%s", VTY_NEWLINE);

      /* BGP cluster ID.
       */
      if (bgp->config & BGP_CONFIG_CLUSTER_ID)
        vty_out (vty, " bgp cluster-id %s%s",
                           siptoa(AF_INET, &bgp->cluster_id).str, VTY_NEWLINE);

      /* Confederation identifier*/
      if (bgp->config & BGP_CONFIG_CONFEDERATION)
       vty_out (vty, " bgp confederation identifier %u%s", bgp->confed_id,
                VTY_NEWLINE);

      /* Confederation peers
       */
      n = asn_set_get_len(bgp->confed_peers) ;
      if (n > 0)
        {
          uint i ;

          vty_out (vty, " bgp confederation peers");

          for (i = 0; i < n ; i++)
            vty_out(vty, " %u", asn_set_get_asn(bgp->confed_peers, i));

          vty_out (vty, "%s", VTY_NEWLINE);
        }

      /* BGP enforce-first-as. */
      if (bgp_flag_check (bgp, BGP_FLAG_ENFORCE_FIRST_AS))
        vty_out (vty, " bgp enforce-first-as%s", VTY_NEWLINE);

      /* BGP deterministic-med. */
      if (bgp_flag_check (bgp, BGP_FLAG_DETERMINISTIC_MED))
        vty_out (vty, " bgp deterministic-med%s", VTY_NEWLINE);

      /* BGP graceful-restart. */
      if (bgp->stalepath_time != BGP_DEFAULT_STALEPATH_TIME)
        vty_out (vty, " bgp graceful-restart stalepath-time %d%s",
                 bgp->stalepath_time, VTY_NEWLINE);
      if (bgp_flag_check (bgp, BGP_FLAG_GRACEFUL_RESTART))
       vty_out (vty, " bgp graceful-restart%s", VTY_NEWLINE);

      /* BGP bestpath method. */
      if (bgp_flag_check (bgp, BGP_FLAG_ASPATH_IGNORE))
        vty_out (vty, " bgp bestpath as-path ignore%s", VTY_NEWLINE);
      if (bgp_flag_check (bgp, BGP_FLAG_ASPATH_CONFED))
        vty_out (vty, " bgp bestpath as-path confed%s", VTY_NEWLINE);
      if (bgp_flag_check (bgp, BGP_FLAG_COMPARE_ROUTER_ID))
        vty_out (vty, " bgp bestpath compare-routerid%s", VTY_NEWLINE);
      if (bgp_flag_check (bgp, BGP_FLAG_MED_CONFED)
          || bgp_flag_check (bgp, BGP_FLAG_MED_MISSING_AS_WORST))
        {
          vty_out (vty, " bgp bestpath med");
          if (bgp_flag_check (bgp, BGP_FLAG_MED_CONFED))
            vty_out (vty, " confed");
          if (bgp_flag_check (bgp, BGP_FLAG_MED_MISSING_AS_WORST))
            vty_out (vty, " missing-as-worst");
          vty_out (vty, "%s", VTY_NEWLINE);
        }

      /* BGP network import check. */
      if (bgp_flag_check (bgp, BGP_FLAG_IMPORT_CHECK))
        vty_out (vty, " bgp network import-check%s", VTY_NEWLINE);

      /* BGP scan interval. */
      bgp_config_write_scan_time (vty);

      /* AFI_IP/SAFI_UNICAST stuff
       */
#if 0
      /* Don't need to group this, since is bgpd daemon specific
       */
      vty_out_vtysh_config_group(vty, "address-family %u/%u", AFI_IP,
                                                                 SAFI_UNICAST) ;
#endif

      /* BGP flag damping.
       */
      if (bgp->af_flags[qafx_ipv4_unicast] & BGP_CONFIG_DAMPING)
        bgp_config_write_damp (vty);

      /* BGP static route configuration.
       */
      bgp_config_write_network (vty, bgp, qafx_ipv4_unicast, &write);

      /* BGP redistribute configuration.
       */
      bgp_config_write_redistribute (vty, bgp, qafx_ipv4_unicast, &write);

      /* BGP timers configuration.
       */
      if ( (bgp->default_keepalive != BGP_DEFAULT_KEEPALIVE) &&
           (bgp->default_holdtime  != BGP_DEFAULT_HOLDTIME) )
        vty_out (vty, " timers bgp %d %d%s", bgp->default_keepalive,
                 bgp->default_holdtime, VTY_NEWLINE);

      /* peer-group
       *
       * NB: peer-groups precede any peers which may depend on the group.
       *
       *     This means that a peer may have configuration which overrides the
       *     group setting.
       */
      for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
        bgp_config_write_peer (vty, bgp, group->conf, qafx_ipv4_unicast);

      /* Normal neighbor configuration.
       */
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        bgp_config_write_peer (vty, bgp, peer, qafx_ipv4_unicast);

      /* Distance configuration.
       */
      bgp_config_write_distance (vty, bgp);

      /* No auto-summary
       */
      if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
        vty_out (vty, " no auto-summary%s", VTY_NEWLINE);

#if 0
      /* Don't need to group this, since is bgpd daemon specific
       */
      vty_out_vtysh_config_group_end(vty) ;
#endif

      /* IPv4 multicast configuration.  */
      write += bgp_config_write_family (vty, bgp, qafx_ipv4_multicast);

      /* IPv4 VPN configuration.  */
      write += bgp_config_write_family (vty, bgp, qafx_ipv4_mpls_vpn);

      /* IPv6 unicast configuration.  */
      write += bgp_config_write_family (vty, bgp, qafx_ipv6_unicast);

      /* IPv6 multicast configuration.  */
      write += bgp_config_write_family (vty, bgp, qafx_ipv6_multicast);

      write++;
    }
  return write;
}

/*==============================================================================
 * Initialisation and shut-down.
 */

/*------------------------------------------------------------------------------
 *
 */
extern void
bgp_master_init (void)
{
  memset (&bgp_master, 0, sizeof (struct bgp_master));

  bm             = &bgp_master;

  bm->bgp        = list_new ();
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
  bgp_peer_index_init(NULL);
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
  access_list_add_hook (peer_distribute_update);
  access_list_delete_hook (peer_distribute_update);

  /* Filter list initialize.
   */
  bgp_filter_init ();
  as_list_add_hook (peer_aslist_update);
  as_list_delete_hook (peer_aslist_update);

  /* Prefix list initialize
   */
  prefix_list_init();
  prefix_list_add_hook (peer_prefix_list_update);
  prefix_list_delete_hook (peer_prefix_list_update);

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
  struct bgp *bgp;
  struct peer *peer;
  struct listnode *node, *nnode;
  struct listnode *mnode, *mnnode;

  /* If we are retaining, then turn off changes to the FIB.
   */
  if (retain_mode)
    {
      assert(terminating) ;             /* Can only retain when terminating  */
      bgp_option_set(BGP_OPT_NO_FIB) ;
    } ;

  /* For all bgp instances...
   */
  for (ALL_LIST_ELEMENTS (bm->bgp, mnode, mnnode, bgp))
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

