/* BGP Instances Configuration Operations
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
#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_inst_config.h"
#include "bgpd/bgp_peer_config.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_aspath.h"

#include "lib/vector.h"

/*==============================================================================
 *
 */
static bool bgp_config_write_redistribute (vty vty, bgp_inst bgp, qafx_t qafx,
                                                                 bool done_af) ;
static bool bgp_config_write_network (vty vty, bgp_inst bgp, qafx_t qafx,
                                                                 bool done_af) ;
static bgp_peer bgp_get_ith_peer(bgp_inst bgp, uint i) ;

/*------------------------------------------------------------------------------
 *
 * Returns:  0 <=> nothing written (!)
 *          >0 <=> something written
 */
extern int
bgp_config_write (vty vty)
{
  bgp_inst      bgp ;
  bgp_peer      peer;
  int           write ;
  uint          n, i ;
  bool          done_view ;

  write = 0 ;

  /* BGP Multiple instance.
   */
  if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "bgp multiple-instance\n");
      write++;
    }

  /* BGP Config type.
   */
  if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
    {
      vty_out (vty, "bgp config-type cisco\n");
      write++;
    }

  /* BGP configuration.
   */
  done_view = (write != 0) ;
  for (bgp = ddl_head(bm->bgps) ; bgp != NULL ; bgp = ddl_next(bgp, bgp_list))
    {
      bgp_bconfig bc ;
      qafx_t      qafx ;
      bool        done_af, done_peer ;

      bc = bgp->c ;

      if (done_view)
        vty_out (vty, "!\n") ;
      else
        done_view = true ;

      vty_out (vty, "router bgp %u", bc->my_as);

      if (bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
        {
          if (bgp->name != NULL)
            vty_out (vty, " view %s", bgp->name);
        }
      vty_out (vty, "\n");

      if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
        vty_out (vty, " no synchronization\n");

      if (bcs_is_on(bc, bcs_NO_FAST_EXT_FAILOVER))
        vty_out (vty, " no bgp fast-external-failover\n");

      if (bcs_is_on(bc, bcs_router_id))
        vty_out (vty, " bgp router-id %s\n",
                                 siptoa(AF_INET, &bc->router_id).str);

      if (bcs_is_on(bc, bcs_LOG_NEIGHBOR_CHANGES))
        vty_out (vty, " bgp log-neighbor-changes\n");

      if (bcs_is_on(bc, bcs_ALWAYS_COMPARE_MED))
        vty_out (vty, " bgp always-compare-med\n");

      if (bcs_is_set(bc, bcs_DEFAULT_IPV4))
        {
          /* If the state of this legacy setting is set -- that is, we have
           * had an explicit command to set it on or off, then we keep that
           * in the output.
           *
           * If the state is unset, then the default is "no", but that may
           * be overridden by command line.
           */
          if (bcs_is_on(bc, bcs_DEFAULT_IPV4))
            vty_out (vty, " bgp default ipv4-unicast\n") ;
          else
            vty_out (vty, " no bgp default ipv4-unicast\n") ;
        } ;

      if (bcs_is_on(bc, bcs_local_pref))
        vty_out (vty, " bgp default local-preference %d\n",
                                                           bc->args.local_pref);

      if (bcs_is_on(bc, bcs_NO_CLIENT_TO_CLIENT))
        vty_out (vty, " no bgp client-to-client reflection\n");

      if (bcs_is_on(bc, bcs_cluster_id))
        vty_out (vty, " bgp cluster-id %s\n",
                                          siptoa(AF_INET, &bc->cluster_id).str);

      n = asn_set_get_len(bc->confed_peers) ;
      if (n > 0)
        {
          uint i ;

          vty_out (vty, " bgp confederation peers");

          for (i = 0; i < n ; i++)
            vty_out(vty, " %u", asn_set_get_asn(bc->confed_peers, i));

          vty_out (vty, "\n");
        }

      if (bcs_is_on(bc, bcs_confed_id))
       vty_out (vty, " bgp confederation identifier %u\n", bc->confed_id);

      if (bcs_is_on(bc, bcs_ENFORCE_FIRST_AS))
        vty_out (vty, " bgp enforce-first-as\n");

      if (bcs_is_on(bc, bcs_DETERMINISTIC_MED))
        vty_out (vty, " bgp deterministic-med\n");

      if (bcs_is_on(bc, bcs_stalepath_time_secs))
        vty_out (vty, " bgp graceful-restart stalepath-time %d\n",
                                                 bc->args.stalepath_time_secs);
      if (bcs_is_on(bc, bcs_GRACEFUL_RESTART))
       vty_out (vty, " bgp graceful-restart\n") ;

      if (bcs_is_on(bc, bcs_ASPATH_IGNORE))
        vty_out (vty, " bgp bestpath as-path ignore\n");
      if (bcs_is_on(bc, bcs_ASPATH_CONFED))
        vty_out (vty, " bgp bestpath as-path confed\n");
      if (bcs_is_on(bc, bcs_COMPARE_ROUTER_ID))
        vty_out (vty, " bgp bestpath compare-routerid\n");
      if (bcs_is_on(bc, bcs_MED_CONFED) ||
          bcs_is_on(bc, bcs_MED_MISSING_AS_WORST))
        {
          vty_out (vty, " bgp bestpath med");
          if (bcs_is_on(bc, bcs_MED_CONFED))
            vty_out (vty, " confed");
          if (bcs_is_on(bc, bcs_MED_MISSING_AS_WORST))
            vty_out (vty, " missing-as-worst");
          vty_out (vty, "\n");
        }

      if (bcs_is_on(bc, bcs_IMPORT_CHECK))
        vty_out (vty, " bgp network import-check\n");

      bgp_config_write_scan_time (vty);

      if (bafcs_is_on(bc->afc[qafx_ipv4_unicast], bafcs_DAMPING))
        bgp_config_write_damp (vty);

      if (bcs_is_on(bc, bcs_holdtime_secs) ||
          bcs_is_on(bc, bcs_keepalive_secs))
        vty_out (vty, " timers bgp %d %d\n",
                                           bc->args.keepalive_secs,
                                           bc->args.holdtime_secs);

      bgp_config_write_distance (vty, bgp);

      if (bgp_option_check (BGP_OPT_CONFIG_CISCO))
        vty_out (vty, " no auto-summary\n");

      done_af = false ;
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        done_af = bgp_config_write_redistribute (vty, bgp, qafx, done_af) ;

      done_af = false ;
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        done_af = bgp_config_write_network (vty, bgp, qafx, done_af) ;

      /* peer-group and peers
       *
       * NB: peer-groups precede any peers which may depend on the group.
       *
       *     This means that a peer may have configuration which overrides the
       *     group setting.
       */
      done_peer = false ;
      i = 0 ;
      while ((peer = bgp_get_ith_peer(bgp, i++)) != NULL)
        done_peer = bgp_peer_config_write(vty, peer, done_peer) ;
    } ;

  return write + (done_view ? 1 : 0) ;
} ;

/*------------------------------------------------------------------------------
 * Display "address-family" configuration header.
 *
 * If the given p_done_af is not NULL, then:
 *
 *   * if *p_done_af is true, do nothing and return true
 *
 *   * otherwise, output "!" spacing line, and set *p_done_af to be true, and
 *     proceed to output address family selection line.
 *
 * Otherwise, output the address family selection line.
 *
 * Returns:  true
 */
extern bool
bgp_config_write_family_header(vty vty, qafx_t qafx, bool* p_done_af)
{
  const char* name ;

  if (p_done_af != NULL)
    {
      if (*p_done_af)
        return true ;

      vty_out(vty, "!\n") ;
      *p_done_af = true ;
    } ;

  switch (qafx)
    {
      case qafx_ipv4_unicast:
        name = "ipv4" ;
        break ;

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
        break ;
#endif

      default:
        vty_out (vty, " address-family UNKNOWN (qafx=%u)\n", qafx) ;
        return true ;
    } ;

  vty_out (vty, " address-family %s\n", name);

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Configuration of static route announcement and aggregate information.
 */
static bool
bgp_config_write_network (vty vty, bgp_inst bgp, qafx_t qafx, bool done_af)
{
/* TODO: reconstruct static routes and aggregation      */
#if 0
  struct bgp_node *rn;
  struct prefix *p;
  struct bgp_static *bgp_static;
  char buf[SU_ADDRSTRLEN];
  struct bgp_aggregate *bgp_aggregate;

  if (qafx == qafx_ipv4_mpls_vpn)
    return bgp_config_write_network_vpnv4 (vty, bgp, qafx, p_write);

  /* Network configuration. */
  for (rn = bgp_table_top (bgp->route[qafx]); rn; rn = bgp_route_next (rn))
    if ((bgp_static = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, qafx, p_write);

        /* "network" configuration display.  */
        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && qafx_is_ipv4(qafx))
          {
            u_int32_t destination;
            struct in_addr netmask;

            destination = ntohl (p->u.prefix4.s_addr);
            masklen2ip (p->prefixlen, &netmask);
            vty_out (vty, " network %s",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN));

            if ((IN_CLASSC (destination) && p->prefixlen == 24)
                || (IN_CLASSB (destination) && p->prefixlen == 16)
                || (IN_CLASSA (destination) && p->prefixlen == 8)
                || p->u.prefix4.s_addr == 0)
              {
                /* Natural mask is not display. */
              }
            else
              vty_out (vty, " mask %s", safe_inet_ntoa (netmask));
          }
        else
          {
            vty_out (vty, " network %s/%d",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     p->prefixlen);
          }

        if (bgp_static->rmap.name)
          vty_out (vty, " route-map %s", bgp_static->rmap.name);
        else
          {
            if (bgp_static->backdoor)
              vty_out (vty, " backdoor");
          }

        vty_out (vty, "%s", VTY_NEWLINE);
      }

  /* Aggregate-address configuration.
   */
  for (rn = bgp_table_top (bgp->aggregate[qafx]); rn;
                                                      rn = bgp_route_next (rn))
    if ((bgp_aggregate = rn->info) != NULL)
      {
        p = &rn->p;

        /* "address-family" display.  */
        bgp_config_write_family_header (vty, qafx, p_write);

        if (bgp_option_check (BGP_OPT_CONFIG_CISCO) && qafx_is_ipv4(qafx))
          {
            struct in_addr netmask;

            masklen2ip (p->prefixlen, &netmask);
            vty_out (vty, " aggregate-address %s %s",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     safe_inet_ntoa (netmask));
          }
        else
          {
            vty_out (vty, " aggregate-address %s/%d",
                     inet_ntop (p->family, &p->u.prefix, buf, SU_ADDRSTRLEN),
                     p->prefixlen);
          }

        if (bgp_aggregate->as_set)
          vty_out (vty, " as-set");

        if (bgp_aggregate->summary_only)
          vty_out (vty, " summary-only");

        vty_out (vty, "%s", VTY_NEWLINE);
      }
#endif

  return false ;
}

/* TODO: reconstruct static routes and aggregation      */
#if 0
static int
bgp_config_write_network_vpnv4 (vty vty, bgp_inst bgp, qafx_t qafx,
                                                                     int *write)
{
  struct bgp_node *prn;
  struct bgp_node *rn;
  struct bgp_table *table;
  struct prefix *p;
  struct bgp_static *bgp_static;
  uint32_t label;

  /* Network configuration. */
  for (prn = bgp_table_top (bgp->route[qafx]); prn;
                                                    prn = bgp_route_next (prn))
    if ((table = prn->info) != NULL)
      for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
        if ((bgp_static = rn->info) != NULL)
          {
            p = &rn->p;
            prd = (struct prefix_rd *) &prn->p;

            /* "address-family" display.
             */
            bgp_config_write_family_header (vty, qafx, write);

            /* "network" configuration display.
             */
            label = mpls_label_decode (bgp_static->tag);

            vty_out (vty, " network %s rd %s tag %u\n",
                      spfxtoa(p).str, srdtoa((struct prefix_rd *)&prn->p).str,
                                                                         label);
          }
  return 0;
}
#endif

/*------------------------------------------------------------------------------
 * Writing the redistribute configuration.
 */
static bool
bgp_config_write_redistribute (vty vty, bgp_inst bgp, qafx_t qafx, bool done_af)
{
  bgp_redist_type_t r_type ;
  bgp_baf_config    bafc ;

  switch (qafx)
  {
    case qafx_ipv4_unicast:
    case qafx_ipv6_unicast:
      break ;

    default:
      return 0 ;
  } ;

  bafc = bgp->c->afc[qafx] ;
  if (bafc == NULL)
    return 0 ;

  for (r_type = 0 ; r_type < redist_type_count ; ++r_type)
    {
      bgp_redist_config redist ;

      if (r_type == ZEBRA_ROUTE_BGP)
        continue ;                      /* not to self  */

      redist = &bafc->redist[r_type] ;

      if (!redist->set)
        continue ;

      /* Display "address-family" when it is not yet diplayed.
       */
      done_af = bgp_config_write_family_header (vty, qafx, &done_af);

      /* "redistribute" configuration.
       */
      vty_out (vty, " redistribute %s", zebra_route_string(r_type));

      if (redist->metric_set)
        vty_out (vty, " metric %d", redist->metric);

      if (redist->rmap_name != NULL)
        vty_out (vty, " route-map %s", ni_nref_name(redist->rmap_name));

      vty_out (vty, "\n");
    } ;

  return done_af ;
} ;

/*==============================================================================
 * Creation and destruction of BGP Instances.
 *
 *
 */
static bgp_inst bgp_lookup_by_name (chs_c name) ;
static bgp_inst bgp_inst_create (as_t as, chs_c name) ;

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
 * NB: a NULL name refers to the "unnamed" instance.
 *
 *     If BGP_OPT_MULTIPLE_INSTANCE is not set, then there is at most one
 *     instance and that is the "unnamed" one.
 *
 *     If BGP_OPT_MULTIPLE_INSTANCE is set, then the first instance may or
 *     may not have a name.
 *
 *     *** The semantics are peculiar.
 *
 *       An unnamed instance must be the first instance.  It is not possible
 *       to create an unnamed instance once a named one has been created.
 *
 *       It is not possible to have multiple instances with the same name
 *       (or no name) but different ASN -- documentation notwithstanding.
 *
 *       Instances are kept in creation order.
 *
 *       bgp_get_default() returns the first created instance -- which will
 *       be the unnamed one, if there is one.
 *
 *     This code does allow an unnamed instance to be created after a
 *     named one, but makes it the first.
 *
 * NB: a NULL name refers to the first bgp instance created (the "default"),
 *     or the unnamed instance, if there is one.
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
bgp_inst_get(bgp_inst* p_bgp, chs_c name, as_t* p_as)
{
  bgp_inst bgp;
  bool     named ;

  *p_bgp = NULL ;               /* tidy         */

  named = (name != NULL) && (name[0] != '\0') ;

  /* Can use named views only if BGP_OPT_MULTIPLE_INSTANCE.
   *
   * If no name is given, get the default (and possibly only) instance.
   *
   * Otherwise, iff we are allowed multiple instances, look up by name.
   *
   * NB: the default is simply the first instance created, and may or may not
   *     have a name.
   */
  if (named && !(bm->options & BGP_OPT_MULTIPLE_INSTANCE))
    return BGP_ERR_MULTIPLE_INSTANCE_NOT_SET;

  bgp = bgp_inst_lookup(name, BGP_ASN_NULL) ;

  /* If bgp instance does not exist, create it -- note that unnamed becomes
   * the first.
   *
   * Otherwise, check that the asn matches the given one.
   */
  if (bgp == NULL)
    {
      bgp = bgp_inst_create (*p_as, name) ;

      if (named)
        ddl_append(bm->bgps, bgp, bgp_list) ;
      else
        ddl_push(bm->bgps, bgp, bgp_list) ;
    }
  else
    {
      /* Found a name match... make sure the ASN also matches.
       */
      if (*p_as != bgp->c->my_as)
        {
          /* Mismatch asn -- return actual ASN and appropriate error.
           */
          *p_as  = bgp->c->my_as;

          return named ? BGP_ERR_INSTANCE_MISMATCH : BGP_ERR_AS_MISMATCH ;
        } ;
    } ;

  *p_bgp = bgp;
  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 *
 */
extern bgp_ret_t
bgp_inst_delete (bgp_inst bgp)
{
  ;
} ;

/*------------------------------------------------------------------------------
 * BGP instance creation
 *
 * Create an empty instance with the given ASN and name (if any)
 *
 * NB: does not add to the parent bgp_env list.
 *
 * Returns:  new, empty bgp_inst with bgp_bconfig set up.
 */
static bgp_inst
bgp_inst_create (as_t as, chs_c name)
{
  bgp_inst      bgp;
  bgp_bconfig   bconf ;

  bgp_config_new_prepare() ;

  bgp   = XCALLOC (MTYPE_BGP, sizeof(bgp_inst_t)) ;

  /* Zeroizing the bgp_inst has set:
   *
   *   * parent_env             -- X            -- set below
   *   * bgp_list               -- NULLs        -- caller's responsibility
   *
   *   * name                   -- NULL         -- set below, if required
   *
   *   * groups                 -- 0's          -- empty embedded vector
   *   * peers                  -- 0's          -- empty embedded vector
   *
   *   * brun                   -- NULL         -- none, yet
   *
   *   * c                      -- NULL         -- set below
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;

  bgp->parent_env = bm ;

  bconf = XCALLOC (MTYPE_BGP_CONFIG, sizeof(bgp_bconfig_t)) ;
  bgp->c = bconf ;

  if ((name != NULL) && (name[0] != '\0'))
    bgp->name = XSTRDUP(MTYPE_BGP_NAME, name) ;

  /* Zeroising the bgp_bconfig sets:
   *
   *   * parent_inst            -- X            -- set below
   *   * my_as                  -- X            -- set below
   *
   *   * set                    -- 0            -- nothing set
   *   * set_on                 -- 0            -- nothing set 'on'
   *
   *   * router_id              -- BGP_ID_NULL  )
   *   * confed_id              -- BGP_ASN_NULL )  nothing set
   *   * confed_peers           -- NULL         )
   *   * cluster_id             -- BGP_ID_NULL  )
   *   * args                   -- 0's          )
   *
   *   * afc                    -- NULLs        -- nothing set
   */
  confirm(BGP_ID_NULL   == 0) ;
  confirm(BGP_ASN_NULL  == 0) ;

  bconf->parent_inst    = bgp ;
  bconf->my_as          = as ;

  return bgp ;
} ;

#if 0

/*------------------------------------------------------------------------------
 * Delete BGP instance.
 *
 * Note that some components are not discarded until the reference count drops
 * to zero -- see bgp_free().
 */
extern bgp_ret_t
bgp_delete (bgp_inst bgp)
{
  bgp_peer peer;
  bgp_peer_group group;
  struct listnode *node, *nnode;
  qAFI_t q_afi;
  qafx_t qafx ;
  int i;

  /* Delete static route.
   */
  bgp_static_delete (bgp);

  /* Delete all aggregates -- TODO
   */

  /* Unset redistribution.
   */
  for (q_afi = qAFI_first; q_afi <= qAFI_last; q_afi++)
    for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
      if (i != ZEBRA_ROUTE_BGP)
        bgp_redistribute_unset (bgp, q_afi, i);

  /* Clear out peers and groups, including self
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    bgp_peer_delete (peer);

  for (ALL_LIST_ELEMENTS (bgp->group, node, nnode, group))
    peer_group_delete (group);

  if (bgp->peer_self)
    bgp->peer_self = bgp_peer_delete(bgp->peer_self);

  /* Remove visibility via the master list - there may however still be
   * routes to be processed still referencing the struct bgp.
   */
  ddl_del(bm->bgps, bgp, bgp_list);

  bgp_unlock(bgp);  /* initial reference */

  return BGP_SUCCESS ;
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
      bgp->rib[qafx]        = bgp_rib_destroy(bgp->rib[qafx]);
      bgp->route[qafx]      = bgp_table_finish (bgp->route[qafx]);
      bgp->aggregate[qafx]  = bgp_table_finish (bgp->aggregate[qafx]);
    } ;

  /* Discard all known route-contexts.
   */
  bgp->rc_view = bgp_rcontext_unlock(bgp->rc_view) ;
  bgp_rcontext_discard_name_index(bgp) ;

  XFREE (MTYPE_BGP, bgp);

  return NULL ;
}
#endif

/*------------------------------------------------------------------------------
 * Lookup BGP entry -- by Name and by ASN (if any)
 *
 * A NULL (or empty) name looks for the unnamed view.
 */
extern bgp_inst
bgp_inst_lookup(chs_c name, as_t as)
{
  bgp_inst bgp;

  for (bgp = ddl_head(bm->bgps) ; bgp != NULL ; bgp = ddl_next(bgp, bgp_list))
    {
      if (bgp_name_match(bgp->name, name))
        {
          if ((as == BGP_ASN_NULL) || (bgp->c->my_as == as))
            return bgp;
        } ;
    } ;

  return NULL;
}

/*------------------------------------------------------------------------------
 * Return "default" BGP.
 *
 * If any BGP instance exists, one of those instances is the "default".
 *
 * Where multiple BGP instances are enabled, they are kept on the list of same
 * in arrival order -- and that order is preserved when configuration is
 * written.
 *
 * Apart from the unnamed instance, which is placed at the head.
 *
 * This is all a ghastly kludge to make "show" and other commands work, where
 * those are not in the BGP_NODE, and hence have no idea which instance to
 * operate on !!!
 */
extern bgp_inst
bgp_inst_default (void)
{
  return ddl_head(bm->bgps) ;
}

/*------------------------------------------------------------------------------
 * Get ith peer-group or peer for the given bgp_inst
 *
 * Returns peer-groups and then peers.
 */
static bgp_peer
bgp_get_ith_peer(bgp_inst bgp, uint i)
{
  uint ge ;

  ge = vector_end(bgp->groups) ;

  if (i < ge)
    return vector_get_item(bgp->groups, i) ;
  else
    return vector_get_item(bgp->peers, i - ge) ;
} ;

/*==============================================================================
 * Configuration changes bgp instance.
 */

/*------------------------------------------------------------------------------
 * Deal with a "bcs_xxx" change.
 *
 * Sets or clears the appropriate bcs_bit(s).  In some cases setting one
 * bit will clear one (or more) others -- we take care of that here.
 *
 * For individual peer, add to list of pending peers -- if not already
 * queued.
 *
 * For peer-group -- unset all group members, and add each to list of pending
 * peers -- if not already queued.
 *
 * Returns:  BGP_SUCCESS
 */
static bgp_ret_t
bgp_config_bcs_change(bgp_bconfig bc, bgp_bc_setting_t bcs, bgp_sc_t bsc)
{
  bgp_bc_set_t  set ;
  bgp_bc_set_t  mask ;

  set = mask = bcs_bit(bcs) ;

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
  switch (bcs)
    {

      default:
        break ;
    } ;

  bc->set &= ~(set | mask) ;            /* unset setting & mask         */
  if (bsc & bsc_set)
    bc->set    |= set ;                 /* set setting if required      */

  bc->set_on &= bc->set ;               /* unset => off                 */
  if (bsc == bsc_set_on)
    bc->set_on |= set ;                 /* set "on" if required         */

  return BGP_SUCCESS ;
} ;


/*------------------------------------------------------------------------------
 * Deal with a "bcs_xxx" change.
 *
 * Sets or clears the appropriate bcs_bit(s).  In some cases setting one
 * bit will clear one (or more) others -- we take care of that here.
 *
 * For individual peer, add to list of pending peers -- if not already
 * queued.
 *
 * For peer-group -- unset all group members, and add each to list of pending
 * peers -- if not already queued.
 *
 * Returns:  BGP_SUCCESS
 */
static bgp_ret_t
bgp_config_bafcs_change(bgp_baf_config bafc, bgp_bafc_setting_t bafcs,
                                                                   bgp_sc_t bsc)
{
  bgp_bafc_set_t  set ;
  bgp_bafc_set_t  mask ;

  set = mask = bcs_bit(bafcs) ;

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
  switch (bafcs)
    {

      default:
        break ;
    } ;

  bafc->set &= ~(set | mask) ;          /* unset setting & mask         */
  if (bsc & bsc_set)
    bafc->set    |= set ;               /* set setting if required      */

  bafc->set_on &= bafc->set ;           /* unset => off                 */
  if (bsc == bsc_set_on)
    bafc->set_on |= set ;               /* set "on" if required         */

  return BGP_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Modify bgp instance "flag".
 *
 * These are states of a bgp instance which are conceptually flags -- which can
 * be set "on"/"off or unset altogether.
 *
 * Modifying the instance will affect all dependent peers and peer-groups.
 */
extern bgp_ret_t
bgp_flag_modify(bgp_inst bgp, bgp_bc_setting_t bcs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  qassert(bcs < bcs_count_of_flags) ;

  bc = bgp_config_inst_prepare(bgp) ;

  /* Validity checking, as required.
   */
  switch (bcs)
    {
      case bcs_ALWAYS_COMPARE_MED:
      case bcs_DETERMINISTIC_MED:
      case bcs_MED_MISSING_AS_WORST:
      case bcs_MED_CONFED:
      case bcs_DEFAULT_IPV4:
      case bcs_NO_CLIENT_TO_CLIENT:
      case bcs_ENFORCE_FIRST_AS:
      case bcs_COMPARE_ROUTER_ID:
      case bcs_ASPATH_IGNORE:
      case bcs_IMPORT_CHECK:
      case bcs_NO_FAST_EXT_FAILOVER:
      case bcs_LOG_NEIGHBOR_CHANGES:
      case bcs_GRACEFUL_RESTART:
      case bcs_ASPATH_CONFED:
        break ;

      /* Anything else is not valid.
       */
      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
  } ;

  return bgp_config_bcs_change(bc, bcs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Modify bgp instance address family "flag".
 *
 * These are address family specific states of a bgp instance which are
 * conceptually flags -- which can be set "on"/"off or unset altogether.
 *
 * Modifying the instance will affect all dependent peers and peer-groups.
 */
extern bgp_ret_t
bgp_af_flag_modify(bgp_inst bgp, qafx_t qafx,
                                         bgp_bafc_setting_t bafcs, bgp_sc_t bsc)
{
  bgp_baf_config bafc ;

  qassert(bafcs < bafcs_count_of_flags) ;

  bafc = bgp_config_inst_af_prepare(bgp, qafx) ;

  /* Validity checking, as required.
   */
  switch (bafcs)
    {

      /* Anything else is not valid.
       */
      default:
        qassert(false) ;
        return BGP_ERR_BUG ;
  } ;

  return bgp_config_bafcs_change(bafc, bafcs, bsc) ;
}

/*------------------------------------------------------------------------------
 * router-id
 *
 * NB: a router-id is an IPv4 address
 *
 *     0.x.x.x are not acceptable -- but any and all other values are.
 */
extern bgp_ret_t
bgp_router_id_set (bgp_inst bgp, chs_c id_str, bgp_sc_t bsc)
{
  bgp_bconfig bc ;
  bgp_id_t    id ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (id_str == NULL)
    id = BGP_ID_NULL ;
  else
    {
      int ret ;

      ret = inet_pton (AF_INET, id_str, &id) ;

      if ((ret < 1) || (id == BGP_ID_NULL))
        return BGP_ERR_INVALID_CLUSTER_ID ;
    } ;

  if (bsc == bsc_set_on)
    {
      if (id == BGP_ID_NULL)
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      id = BGP_ID_NULL ;
    } ;

  bc->router_id = id ;

  return bgp_config_bcs_change(bc, bcs_router_id, bsc) ;

#if 0

  if (!(bgp->config & BGP_CONFIG_CLUSTER_ID))
    bgp->cluster_id_r = router_id ;

  /* Set all peer's local identifier with this value.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer->args_r.local_id = router_id ;
      bgp_peer_down(peer, PEER_DOWN_RID_CHANGE) ;
    }
  return 0;
#endif
}

#if 0
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

  if (bgp->router_id_r == router_id)
    return BGP_SUCCESS ;

  bgp->router_id_r = router_id ;

  if (!(bgp->config & BGP_CONFIG_CLUSTER_ID))
    bgp->cluster_id_r = router_id ;

  /* Set all peer's local identifier with this value.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      peer->args_r.local_id = router_id ;
      bgp_peer_down(peer, PEER_DOWN_RID_CHANGE) ;
    }
  return 0;
}

#endif

/*------------------------------------------------------------------------------
 * cluster-id
 *
 * NB: a cluster-id is either an IPv4 address, or a simple integer.
 *
 *     0.0.0.0 and 0 are not acceptable -- but any and all other values are.
 */
extern bgp_ret_t
bgp_cluster_id_set(bgp_inst bgp, chs_c id_str, bgp_sc_t bsc)
{
  bgp_bconfig bc ;
  bgp_id_t id ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (id_str == NULL)
    id = BGP_ID_NULL ;
  else
    {
      if (strchr(id_str, '.') != NULL)
        {
          int ret ;
          ret = inet_pton (AF_INET, id_str, &id) ;

          if ((ret < 1) || (id == BGP_ID_NULL))
            return BGP_ERR_INVALID_CLUSTER_ID ;
        }
      else
        {
          strtox_t tox ;
          chs_c    end ;

          id = strtol_xr(id_str, &tox, &end, 1, UINT32_MAX) ;
          if ((tox != strtox_ok) || (*end != '\0'))
            return BGP_ERR_INVALID_CLUSTER_ID ;

          id = htonl(id) ;
        } ;
    } ;

  if (bsc == bsc_set_on)
    {
      if (id == BGP_ID_NULL)
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      id = BGP_ID_NULL ;
    } ;

  bc->cluster_id = id ;

  return bgp_config_bcs_change(bc, bcs_cluster_id, bsc) ;

#if 0
    /* Update all IBGP peers.
     */
    for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
      {
        qassert(peer->ptype == PEER_TYPE_REAL) ;

        if (peer->sort != BGP_PEER_IBGP)
          continue;

        bgp_peer_down(peer, PEER_DOWN_CLID_CHANGE) ;
      } ;
#endif
} ;

/*------------------------------------------------------------------------------
 * confed-id
 *
 * In a configuration file, the confed-id setting should precede any peer-group
 * and peer configuration... so there are no side effects !  The confed-peers
 * have no effect until the confed-id is set, so it is best to configure those
 * before setting the confed-id -- though if both precede all peer-groups and
 * peers, it doesn't really matter.
 *
 * The interesting thing about setting/unsetting confed-id is that it can
 * cBGP <-> eBGP... so has a side effect on all peers and peer-groups which
 * have a remote-as in the confed-peers set.
 *
 * Also, if the confed-id is not either my-as or one of the confed-peers, then
 * no peer may have the confed-id.
 *
 * Also, cannot change-local-as to the confed-id or to any active confed-peer.
 *
 * Currently, the only difference between cBGP and eBGP is that cannot use
 * Change-Local-AS with cBGP !  But we here acknowledge the fact that cBGP and
 * eBGP are not entirely the same.
 *
 * So, we disallow the setting of confed-id if:
 *
 *   * the confed-id is used by a peer which will still be eBGP after the
 *     confed-id is set.
 *
 *     Note that: if the confed-id is used as a confed-peer ASN, and one or
 *     more to-be confed-peers are already configured with that ASN, then it
 *     is necessary to configure the confed-peers *before* setting the
 *     confed-id.
 *
 *   * any peer which will become cBGP after the confed-id is set has
 *     change-local-as set.
 *
 *   * any change-local-as uses the given confed-id.
 *
 *   * any change-local-as uses any of the confed-peers (which would be brought
 *     into play by setting the confed-id).
 *
 * Note that the confed_id may be the same as my_as (for one member of the
 * confederation, at least).
 */
extern bgp_ret_t
bgp_confed_id_set (bgp_inst bgp, as_t confed_id, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      /* Setting confed-id may change a peer from eBGP to cBGP.
       *
       * Scan all peer-groups and peers to see if we have a clash with any
       * change_local_as !
       *
       * Also, if the confed_id is not my_as, and is not any of the confed
       * peer, then we'd better not be peering with it.
       */
      bgp_peer  peer ;
      bool      cid_local ;
      uint      i ;

      if ((confed_id < BGP_ASN_FIRST) || (confed_id > BGP_ASN_LAST))
        return BGP_ERR_INVALID_AS ;

      cid_local = (confed_id == bgp->c->my_as) ||
                             asn_set_contains(bgp->c->confed_peers, confed_id) ;

      i = 0 ;
      while ((peer = bgp_get_ith_peer(bgp, i++)) != NULL)
        {
          bgp_pconfig pc ;

          pc = peer->c ;

          if (pcs_is_on(pc, pcs_remote_as))
            {
              /* May not set the confed_id if it is not a "local" ASN and an
               * eBGP peer is using the ASN
               */
              if (!cid_local && (pc->remote_as == confed_id))
                return BGP_ERR_CONFED_ID_USED_AS_EBGP_PEER ;

              /* May not set the confed-id if it would change a peer to cBGP,
               * and that peer has change-local-as set.
               */
              if (asn_set_contains(bgp->c->confed_peers, pc->remote_as) &&
                                            pcs_is_on(pc, pcs_change_local_as))
                return BGP_ERR_NO_CBGP_WITH_LOCAL_AS ;
            } ;

          if (pcs_is_on(pc, pcs_change_local_as))
            {
              /* May not set confed-id if that ASN is in use by any change-
               * local-as
               */
              if (pc->change_local_as == confed_id)
                return BGP_ERR_CONFED_ID_USED_AS_LOCAL_AS ;

              /* May not set confed-id if a change-local-as exists which uses
               * any (about to be activated) confed-peer ASN
               */
              if (asn_set_contains(bgp->c->confed_peers, pc->change_local_as))
                return BGP_ERR_CONFED_PEER_AS_LOCAL_AS ;
            } ;
        } ;
    }
  else
    {
      /* Turning off confed_id will change all cBGP -> eBGP.
       *
       * Currently, all cBGP settings are a subset of eBGP ones, so there
       * is nothing more to do here.
       */
      confed_id = BGP_ASN_NULL ;
    }

  bc->confed_id = confed_id ;

  return bgp_config_bcs_change(bc, bcs_confed_id, bsc) ;


#if 0
  /* Pick up the old state and update.
   *
   * If this changes the state of any peer, will set it down_pending.
   * Once has checked all peers, downs any which have changed.  Note that this
   * means that all peers change state "as one", before anything else happens.
   *
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
   *     if that is set, or bc->c->my_as
   */
  old_confed_id     = bgp->confed_id ;
  old_true_local_as = bgp->ebgp_as ;

  bgp->ebgp_as = bgp->confed_id = confed_id ;

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->args.local_as as
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
   *      * if the peer->args.remote_as is in the confed_peer_set:
   *
   *        change state to BGP_PEER_CBGP, and reset the session.
   *
   *        peer->args.local_as will be set to peer->bgp->my_as --
   *        change_local_as does not apply to BGP_PEER_CBGP.
   *
   *     or:
   *
   *      * if the peer->args.remote_as is NOT in the confed_peer_set:
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
      qassert(peer->parent_bgp == bgp) ;

      switch (peer->sort)
        {
          /* No change if was iBGP
           */
          case BGP_PEER_IBGP:
            qassert(peer->args.remote_as == bc->c->my_as) ;
            qassert(peer->args.local_as  == bc->c->my_as) ;
            break ;

          /* No change if was CONFED -- we have not changed confed_peers.
           *
           * Must previously have had CONFED enabled !
           */
          case BGP_PEER_CBGP:
            qassert(peer->args.remote_as != bc->c->my_as) ;
            qassert(peer->args.local_as  == bc->c->my_as) ;
            qassert(old_confed_id   != BGP_ASN_NULL) ;
            qassert(asn_set_contains(bgp->confed_peers, peer->args.remote_as)) ;
            break ;

          /* Was eBGP.
           *
           * If we are enabling CONFED then may now change to CONFED.
           *
           * If remains eBGP, need to process as discussed above.
           */
          case BGP_PEER_EBGP:
            qassert(peer->args.remote_as != bc->c->my_as) ;

            if (asn_set_contains(bgp->confed_peers, peer->args.remote_as))
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
                     * peer->args.local_as, and if that changes, schedule a
                     * reset.
                     */
                    qassert(peer->args.local_as == old_true_local_as) ;

                    if (peer->args.local_as != bgp->confed_id)
                      {
                        peer->args.local_as = bgp->confed_id ;
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
                     *     change_local_as is not equal to bgp->my_as and takes
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
                     * Note that the peer->args.local_as should not change !
                     */
                    qassert(peer->args.local_as == peer->change_local_as) ;
                    qassert(old_true_local_as   != peer->change_local_as) ;

                    peer->args.local_as = bgp->confed_id ;
                    peer->down_pending  = true ;
                  }
                else
                  {
                    /* The change_local_as takes precedence over the new
                     * confed_id.
                     */
                    peer->args.local_as = peer->change_local_as ;

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
                         * Hence, the old true local_as will have been
                         * bgp->my_as.
                         *
                         * So, change_local_as took precedence before -- by
                         * definition change_local_as != bgp->my_as -- so no
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
                        qassert(bc->c->my_as == old_true_local_as) ;

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
#endif
} ;

#if 0
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
  bgp->ebgp_as   = bgp->c.my_as ;         /* as you was   */

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->args.local_as as
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
   *     But, the peer->args.local_as needs to be updated, and the sessions
   *     reset if that changes -- taking into account change_local_as.
   */
  for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
    {
      switch (peer->sort)
        {
          /* No change for iBGP
           */
          case BGP_PEER_IBGP:
            qassert(peer->args.remote_as == bgp->c.my_as) ;
            qassert(peer->args.local_as  == bgp->c.my_as) ;
            break ;

          /* CONFED changes to eBGP.
           */
          case BGP_PEER_CBGP:
            qassert(peer->args.remote_as != bgp->c.my_as) ;
            qassert(peer->args.local_as  == bgp->c.my_as) ;
            qassert(asn_set_contains(bgp->confed_peers, peer->args.remote_as)) ;

            peer_sort_set(peer, BGP_PEER_EBGP) ;
            peer->down_pending = true ;
            break ;

          /* eBGP stays eBGP, but peer->args.local_as may change
           *
           * If peer->change_local_as is not set:
           *
           *   Need to update the peer->args.local_as to the current
           *   bgp->ebgp_as, and if that has changed, reset the session.
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
            qassert(peer->args.remote_as != bgp->c.my_as) ;

            if (peer->change_local_as == BGP_ASN_NULL)
              {
                if (peer->args.local_as != bgp->ebgp_as)
                  {
                    peer->args.local_as = bgp->ebgp_as ;
                    peer->down_pending = true ;
                  } ;
              }
            else
              {
                qassert(peer->change_local_as != bgp->ebgp_as) ;

                peer->args.local_as = peer->change_local_as ;

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
 * Set the bgp->check_confed_id and bgp->check_confed_id_all flags
 *                                                -- depending on current state.
 *
 * When there is a confederation (bgp->confed_id != NULL) then bgp->my_as is
 * the Member AS, and:
 *
 *  * for iBGP and cBGP sessions we filter out routes which contain bgp->my_as
 *    in the AS-PATH in any case.
 *
 *    If the bgp->my_as != confed_id, then should check for confed_id as well.
 *
 *  * for eBGP sessions we filter out routes which contain the confed_id in
 *    the AS-PATH in any case.
 *
 *    If the bgp->my_as != confed_id, then should check for bgp->my_as as well.
 *
 * So:
 *
 *   * if confed_id == BGP_ASN_NULL or confed_id == bgp->my_as
 *
 *     clear both flags -- no check required either because is not in a
 *     confederation, or because we check for confed_id or bgp->my_as anyway.
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
  if ((bgp->confed_id == BGP_ASN_NULL) || (bgp->confed_id == bgp->c.my_as))
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
  bgp_peer peer;
  struct listnode *node, *nnode;

  if (bgp == NULL)
    return BGP_ERR_INVALID_BGP ;        /* No can do                    */

  if (bgp->confed_id == BGP_ASN_NULL)
    return BGP_SUCCESS ;                /* No difference if not enabled */

  bgp_check_confed_id_set(bgp) ;

  /* Walk all the peers and update the peer->sort and peer->args.local_as as
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
            qassert(peer->args.remote_as == bgp->c.my_as) ;
            qassert(peer->args.local_as  == bgp->c.my_as) ;
            break ;

          /* CONFED changes to eBGP, if peer->args.remote_as no longer in
           * confed_peers.
           */
          case BGP_PEER_CBGP:
            qassert(peer->args.remote_as != bgp->c.my_as) ;
            qassert(peer->args.local_as  == bgp->c.my_as) ;

            if (!asn_set_contains(bgp->confed_peers, peer->args.remote_as))
              {
                /* Change to BGP_PEER_EBGP required.
                 */
                peer_sort_set(peer, BGP_PEER_EBGP) ;
                peer->down_pending = true ;
              } ;
            break ;

          /* eBGP changes to CONFED, if peer->args.remote_as is now in
           * confed_peers
           */
          case BGP_PEER_EBGP:
            qassert(peer->args.remote_as != bgp->c.my_as) ;

            if (asn_set_contains(bgp->confed_peers, peer->args.remote_as))
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

#endif

/*------------------------------------------------------------------------------
 * Add an AS to the confederation peers set.
 *
 * Has no effect if the AS is already in the confed_peers set.
 *
 * Does not add self to the confed_peers set -- but this is not treated as
 * an error.
 *
 * Iff a confed_id is set, then adding removing a confed-peer can change the
 * state of peers cBGP <-> eBGP.
 *
 * The interesting thing about adding/removing a confed-peer is that it can
 * cBGP <-> eBGP... so has a side effect on peers and peer-groups which use
 * the confed-peer ASN -- iff confed-id is set.
 *
 * Currently, the only difference between cBGP and eBGP is that cannot use
 * Change-Local-AS with cBGP !  But we here acknowledge the fact that cBGP and
 * eBGP are not entirely the same.
 *
 * So, we reject a adding a confed-peer if confed-id is set and:
 *
 *   * would change a peer with change-local-as to cBGP
 *
 *   * the confed-peer ASN is already used as a change-local-as
 */
extern bgp_ret_t
bgp_confed_peer_set(bgp_inst bgp, as_t asn, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if ((asn < BGP_ASN_FIRST) || (asn > BGP_ASN_LAST))
    return BGP_ERR_INVALID_AS ;

  if (asn == bc->my_as)
    return BGP_SUCCESS ;        /* do not set self as confed-peer       */

  if (bsc == bsc_set_on)
    {
      if (bcs_is_on(bc, bcs_confed_id))
        {
          /* We have a confed-id, so any new confed-peer needs to be checked.
           *
           * NB: since the confed-peer ASN is != my-as, we are only worrying
           *     about eBGP -> cBGP transitions.
           */
          bgp_peer  peer ;
          uint      i ;

          i = 0 ;
          while ((peer = bgp_get_ith_peer(bgp, i++)) != NULL)
            {
              bgp_pconfig pc ;

              pc = peer->c ;

              if (pcs_is_on(pc, pcs_change_local_as))
                {
                  /* Cannot change to cBGP if with change-local-as set.
                   */
                  if (pcs_is_on(pc, pcs_remote_as) && (pc->remote_as == asn))
                    return BGP_ERR_LOCAL_AS_ALREADY_SET ;

                  /* Cannot change-local-as to a confed-peer.
                   */
                  if (pc->change_local_as == asn)
                    return BGP_ERR_CONFED_PEER_AS_LOCAL_AS ;
                } ;
            } ;
        } ;

      bc->confed_peers = asn_set_add(bc->confed_peers, asn) ;
    }
  else
    asn_set_del(bc->confed_peers, asn) ;

  return bgp_config_bcs_change(bc, bcs_confed_peers, bsc) ;
}

/*------------------------------------------------------------------------------
 * keepalive and holdtime -- set defaults for instance
 *
 * NB: enforces holdtime may not be 1..2 -- silently
 *
 * NB: the keepalive may be any value... the KeepaliveTime for a given session
 *     is subject to negotiation, and this configured value is part of that.
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_timers_set (bgp_inst bgp, uint keepalive, uint holdtime, bgp_sc_t bsc)
{
  bgp_bconfig bc ;
  bgp_ret_t   ret1, ret2 ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((keepalive > 65535) || (holdtime > 65535))
        return BGP_ERR_INVALID_VALUE ;

      if ((holdtime > 0) && (holdtime < 3))
        holdtime = 3 ;                  /* force valid !        */
    }
  else
    {
      keepalive  = 0 ;
      holdtime   = 0 ;
    } ;

  bc->args.keepalive_secs = keepalive ;
  ret1 = bgp_config_bcs_change(bc, bcs_keepalive_secs, bsc) ;

  bc->args.holdtime_secs  = holdtime ;
  ret2 = bgp_config_bcs_change(bc, bcs_holdtime_secs, bsc) ;

  return (ret1 != BGP_SUCCESS) ? ret1 : ret2 ;
} ;

/*------------------------------------------------------------------------------
 * Stale Timer -- set defaults for instance
 *
 * NB: changing this value does not affect any running sessions.
 */
extern bgp_ret_t
bgp_stalepath_time_set (bgp_inst bgp, uint stalepath_time_secs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((stalepath_time_secs < 1) || (stalepath_time_secs > 3600))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      stalepath_time_secs  = 0 ;
    } ;

  bc->args.stalepath_time_secs = stalepath_time_secs ;

  return bgp_config_bcs_change(bc, bcs_stalepath_time_secs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Local preference -- set default for instance
 */
extern bgp_ret_t
bgp_local_pref_set (bgp_inst bgp, uint local_pref, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if (local_pref > UINT32_MAX)
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      local_pref = 0 ;
    } ;

  bc->args.local_pref = local_pref ;

  return bgp_config_bcs_change(bc, bcs_local_pref, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Connect Retry Time -- set default for instance
 *
 * This is generally 120 secs.
 *
 * NB: changing this value does not affect any running sessions.
 */
extern bgp_ret_t
bgp_connect_retry_time_set(bgp_inst bgp, uint connect_retry_secs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((connect_retry_secs < 1) || (connect_retry_secs > 3600))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      connect_retry_secs = 0 ;
    } ;

  bc->args.connect_retry_secs = connect_retry_secs ;

  return bgp_config_bcs_change(bc, bcs_connect_retry_secs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Accept Retry Time -- set default for instance
 *
 * This is generally 240 secs (4 minutes -- same as "OpenHoldTime").
 *
 * NB: changing this values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_accept_retry_time_set (bgp_inst bgp, uint accept_retry_secs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((accept_retry_secs < 1) || (accept_retry_secs > 3600))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      accept_retry_secs = 0 ;
    } ;

  bc->args.accept_retry_secs = accept_retry_secs ;

  return bgp_config_bcs_change(bc, bcs_accept_retry_secs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Open Hold Time -- default for BGP Instance
 *
 * This is generally 240 secs (4 minutes -- RFC4271).
 *
 * NB: changing this values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_open_hold_time_set (bgp_inst bgp, uint open_hold_secs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((open_hold_secs < 1) || (open_hold_secs > 3600))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      open_hold_secs = 0 ;
    } ;

  bc->args.open_hold_secs = open_hold_secs ;

  return bgp_config_bcs_change(bc, bcs_open_hold_secs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * MRAI -- set defaults for instance
 *
 * These are generally 5 secs for iBGP and 30 secs for eBGP and cBGP.
 *
 * NB: changing these values does not affect any running sessions.
 */
extern bgp_ret_t
bgp_mrai_set (bgp_inst bgp, uint ibgp_mrai, uint cbgp_mrai,
                                            uint ebgp_mrai, bgp_sc_t bsc)
{
  bgp_bconfig bc ;
  bgp_ret_t ret, rets ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((ibgp_mrai < 1) || (ibgp_mrai > 300))
        return BGP_ERR_INVALID_VALUE ;

      if ((cbgp_mrai < 1) || (cbgp_mrai > 300))
        return BGP_ERR_INVALID_VALUE ;

      if ((ebgp_mrai < 1) || (ebgp_mrai > 300))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      ibgp_mrai = 0 ;
      cbgp_mrai = 0 ;
      ebgp_mrai = 0 ;
    } ;

  bc->args.ibgp_mrai_secs = ibgp_mrai ;
  bc->args.cbgp_mrai_secs = cbgp_mrai ;
  bc->args.ebgp_mrai_secs = ebgp_mrai ;

  /* We don't expect any of this to fail... but returns the first failure
   * encountered.
   */
  ret = BGP_SUCCESS ;

  rets = bgp_config_bcs_change(bc, bcs_ibgp_mrai_secs, bsc) ;
  if (ret == BGP_SUCCESS)
    ret = rets ;

  rets = bgp_config_bcs_change(bc, bcs_cbgp_mrai_secs, bsc) ;
  if (ret == BGP_SUCCESS)
    ret = rets ;

  rets = bgp_config_bcs_change(bc, bcs_ebgp_mrai_secs, bsc) ;
  if (ret == BGP_SUCCESS)
    ret = rets ;

  return ret ;
} ;

/*------------------------------------------------------------------------------
 * Graceful Restart Timer -- set defaults for instance
 *
 * NB: changing this value does not affect any running sessions.
 */
extern bgp_ret_t
bgp_restart_time_set (bgp_inst bgp, uint restart_time_secs, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if ((restart_time_secs < 1) || (restart_time_secs > 3600))
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      restart_time_secs = 0 ;
    } ;

  bc->args.restart_time_secs = restart_time_secs ;

  return bgp_config_bcs_change(bc, bcs_restart_time_secs, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Local preference -- set default for instance
 */
extern bgp_ret_t
bgp_default_med_set (bgp_inst bgp, uint med, bgp_sc_t bsc)
{
  bgp_bconfig bc ;

  bc = bgp_config_inst_prepare(bgp) ;

  if (bsc == bsc_set_on)
    {
      if (med > UINT32_MAX)
        return BGP_ERR_INVALID_VALUE ;
    }
  else
    {
      med = 0 ;
    } ;

  bc->args.med = med ;

  return bgp_config_bcs_change(bc, bcs_med, bsc) ;
} ;

/*------------------------------------------------------------------------------
 * Set redistribution of given route type for the given address family.
 *
 * For:  bsc_set_on     -- preserves any existing metric and route-map.
 *
 *       bsc_set_off    -- preserves any existing metric and route-map.
 *
 *       bsc_unset      -- unsets everything.
 */
extern bgp_ret_t
bgp_redistribute_set(bgp_inst bgp, qafx_t qafx, bgp_redist_type_t r_type,
                  redist_set_t what, chs_c rmap_name, uint metric, bgp_sc_t bsc)
{
  bgp_bconfig       bc ;
  bgp_baf_config    bafc ;
  bgp_redist_config redist ;
  bgp_ret_t         ret ;

  bc = bgp_config_inst_prepare(bgp) ;

  switch (qafx)
    {
      case qafx_ipv4_unicast:
      case qafx_ipv6_unicast:
        break ;

      default:
        return BGP_ERR_INVALID_FAMILY ;
    } ;

  if ((r_type >= redist_type_count) || (r_type == ZEBRA_ROUTE_BGP))
    return BGP_ERR_INVALID_ROUTE_TYPE ;

  if (bsc == bsc_set)
    {
      if ((what & redist_set_metric) && (metric > UINT32_MAX))
        return BGP_ERR_INVALID_METRIC ;

      if ((what & redist_set_rmap) &&
                                ((rmap_name == NULL) || (rmap_name[0] == '\0')))
        return BGP_ERR_INVALID_VALUE ;
    } ;

  bafc   = &bc->afc[qafx] ;
  redist = &bafc->redist[r_type] ;

  if (what & redist_set_metric)
    {
      if (bsc == bsc_set_on)
        {
          redist->metric_set = true ;
          redist->metric     = metric ;
        }
      else
        {
          redist->metric_set = false ;
          redist->metric     = 0 ;
        } ;
    } ;

  if (what & redist_set_rmap)
    {
      if (bsc == bsc_set_on)
        ni_nref_set_c(&redist->rmap_name, bgp_config_name_index, rmap_name) ;
      else
        ni_nref_clear(&redist->rmap_name) ;
    } ;

  ret = BGP_SUCCESS ;

  if (what & redist_set_action)
    {
      redist->set = (bsc == bsc_set_on) ;

      ret = bgp_config_bafcs_change(bafc, bafcs_redist_first + r_type, bsc) ;
    } ;

  bafc->redist_changed = true ;

  return ret ;
} ;

