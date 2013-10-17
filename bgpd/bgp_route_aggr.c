/* BGP route_aggregation
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
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
#include <misc.h>

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_route_aggr.h"

#include "command.h"
#include "vty.h"

/*==============================================================================
 * Aggregate address:  TODO !!!!
 *
 *   advertise-map  Set condition to advertise attribute
 *   as-set         Generate AS set path information
 *   attribute-map  Set attributes of aggregate
 *   route-map      Set parameters of aggregate
 *   summary-only   Filter more specific routes from updates
 *   suppress-map   Conditionally filter more specific routes from updates
 *   <cr>
 */
#if 0
struct bgp_aggregate
{
  bool  summary_only;
  bool  as_set;

  struct route_map *map;

  urlong count;

  qafx_t  qafx ;
};

static void bgp_aggregate_route (bgp_inst bgp, prefix p,
                                 struct bgp_info *rinew, struct bgp_info *del,
                                               struct bgp_aggregate *aggregate);
static bool bgp_aggregate_merge(struct bgp_aggregate* aggregate,
                                         attr_pair attrs, struct bgp_info* ri) ;
static void bgp_aggregate_delete (bgp_inst bgp, prefix p,
                                               struct bgp_aggregate* aggregate);
static cmd_ret_t bgp_aggregate_unset (struct vty *vty, const char *prefix_str,
                                                                  qafx_t qafx) ;

static struct bgp_aggregate *
bgp_aggregate_new (void)
{
  return XCALLOC (MTYPE_BGP_AGGREGATE, sizeof (struct bgp_aggregate));
}

static void
bgp_aggregate_free (struct bgp_aggregate *aggregate)
{
  XFREE (MTYPE_BGP_AGGREGATE, aggregate);
}


/*------------------------------------------------------------------------------
 * See if the given new or changed route should be aggregated.
 *
 * If so, update (or create) aggregate to include state of the new or changed
 * route.
 *
 * This is done after the route has been installed in the RIB -- so the given
 * bgp_info is sitting on the relevant bgp_node's list.
 *
 * NB: this is for main RIB *only* -- not RS Client RIBs
 */
extern void
bgp_aggregate_increment (bgp_inst bgp, prefix p,
                                               struct bgp_info *ri, qafx_t qafx)
{
  bgp_table aggregate_table ;
  bgp_node ag_rn ;

  aggregate_table = bgp->aggregate[qafx] ;
  if (aggregate_table == NULL)
    return ;

  if (qafx_is_mpls_vpn(qafx))
    return;             /* MPLS-VPN aggregation is not yet supported.   */

  if (BGP_INFO_HOLDDOWN (ri))
    return;

  /* In the bgp->aggregate[] table we keep all the aggregate addresses.
   *
   * If we find that the current prefix is more-specific than the most-specific
   * aggregate address, then we have to do something with it.
   */
  ag_rn = bgp_node_lookup_parent(aggregate_table, p);

  if (ag_rn == NULL)
    return ;            /* prefix is not subject to aggregation         */

  qassert(ag_rn->info != NULL) ;

  /* We are updating a route which is more specific than an aggregate.
   *
   * First we delete the aggregate, then reconstruct it, to include all
   * other existing more specifics, plus the new one.
   */
  bgp_aggregate_delete (bgp, &ag_rn->p, ag_rn->info);
  bgp_aggregate_route (bgp, &ag_rn->p, ri, NULL, ag_rn->info);

  bgp_unlock_node (ag_rn) ;
} ;

/*------------------------------------------------------------------------------
 * See if the given route which is being removed was aggregated.
 *
 * If so, update (or remove) aggregate to remove the previously included route.
 *
 * NB: this is for main RIB *only* -- not RS Client RIBs
 */
extern void
bgp_aggregate_decrement (bgp_inst bgp, prefix p,
                                              struct bgp_info *del, qafx_t qafx)
{
  bgp_table aggregate_table ;
  bgp_node ag_rn ;

  aggregate_table = bgp->aggregate[qafx] ;
  if (aggregate_table == NULL)
    return ;

  if (qafx_is_mpls_vpn(qafx))
    return;             /* MPLS-VPN aggregation is not yet supported.   */

  /* In the bgp->aggregate[] table we keep all the aggregate addresses.
   *
   * If we find that the current prefix is more-specific than the most-specific
   * aggregate address, then we have to do something with it.
   */
  ag_rn = bgp_node_lookup_parent(aggregate_table, p);

  if (ag_rn == NULL)
    return ;            /* prefix is not subject to aggregation         */

  qassert(ag_rn->info != NULL) ;

  /* We are updating a route which is more specific than an aggregate.
   *
   * First we delete the aggregate, then reconstruct it, to include all
   * other existing more specifics, less the one being deleted.
   */
  bgp_aggregate_delete (bgp, &ag_rn->p, ag_rn->info);
  bgp_aggregate_route (bgp, &ag_rn->p, NULL, del, ag_rn->info);

  bgp_unlock_node (ag_rn) ;
} ;

/*------------------------------------------------------------------------------
 * Update aggregate route
 *
 * The aggregate exists in the aggregate table,
 */
static void
bgp_aggregate_route (bgp_inst bgp, prefix p, struct bgp_info *rinew,
                          struct bgp_info *del, struct bgp_aggregate *aggregate)
{
  bgp_table table ;
  bgp_node ag_rn, rn ;
  attr_pair_t attrs[1] ;

  /* Start with a working set of attributes, set to default:
   *
   *   * ORIGIN IGP
   *
   *   * empty AS_PATH
   *
   *   * weight = BGP_ATTR_DEFAULT_WEIGHT
   *
   * Then merge in the attributes for the new bgp_info (if any).
   */
  bgp_attr_pair_load_default(attrs, BGP_ATT_ORG_IGP) ;

  if (rinew != NULL)
    bgp_aggregate_merge(aggregate, attrs, rinew) ;

  /* Walk all the more-specific routes for the aggregate, and merge them in.
   *
   * Skips any bgp_info which is about to be withdrawn.
   */
  table = bgp->rib[aggregate->qafx][rib_main];

  ag_rn = bgp_node_get (table, p);
  rn  = bgp_lock_node(ag_rn) ;
  while ((rn = bgp_route_next_until (rn, ag_rn)) != NULL)
    {
      struct bgp_info* ri ;
      bool match ;

      qassert(rn->p.prefixlen > p->prefixlen) ;

      match = false;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          if (BGP_INFO_HOLDDOWN (ri))
            continue ;                  /* skip invalid, removed etc.   */

          if (ri == del)
            continue ;                  /* skip to be deleted bgp_info  */

          if (ri->sub_type == BGP_ROUTE_AGGREGATE)
            continue ;                  /* skip other aggregates        */

          if (ri != rinew)              /* already done this            */
            if (!bgp_aggregate_merge(aggregate, attrs, ri))
              {
                /* TODO -- need to break out of the loop, not create the
                 *         aggregate and (presumably) undo
                 */
#ifdef AGGREGATE_NEXTHOP_CHECK
#warning AGGREGATE_NEXTHOP_CHECK is not completely implemented !!
#endif
              } ;

          if (aggregate->summary_only)
            {
              (bgp_info_extra_get (ri))->suppress++;
              bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
              match = true ;
            } ;
        } ;

      if (match)
        bgp_process_dispatch  (bgp, rn);
    } ;

  /* If the aggregate has at least one less specific, then create the
   * aggregate route and dispatch it for processing.
   */
  if (aggregate->count > 0)
    {
      struct bgp_info* ag_ri ;

      /* Next hop attribute -- TODO ????     ........................................
       *
       * As it stands, no next_hop has been set... so will send next hop self
       */

      /* Setting of Atomic Aggregate
       *
       * If we haven't made an AS_PATH from all the more specifics' AS_PATHs,
       * then we set ATOMIC_AGGREGATE.
       *
       * TODO -- if all the more specifics' AS_PATHs were empty, then we
       *         don't really need to do this ?
       *
       * TODO -- this uses the confed_id if there is one....
       */
      if (! aggregate->as_set)
        bgp_attr_pair_set_atomic_aggregate(attrs, true) ;

      /* RFC4271: Any AGGREGATOR attributes from the routes to be aggregated
       *          MUST NOT be included in the agggregated route.  The BGP
       *          speaker performing the aggregation MAY attach a new
       *          AGGREGATOR attribute.
       */
      bgp_attr_pair_set_aggregator(attrs,
                    (bgp->confed_id != BGP_ASN_NULL) ? bgp->confed_id
                                                     : bgp->my_as,
                                                              bgp->router_id) ;

      /* RFC4271: If the aggregated route has an AS_SET as the first element
       *          in its AS_PATH attribute, then the router that originates
       *          the route SHOULD NOT advertise the MED attribute with this
       *          route.
       *
       * TODO as it stands, no MED is set in any case !
       */

      /* Now construct bgp_info and set its attributes.
       */
      ag_ri = bgp_info_new ();
      ag_ri->type     = ZEBRA_ROUTE_BGP;
      ag_ri->sub_type = BGP_ROUTE_AGGREGATE;
      ag_ri->peer     = bgp->peer_self;
      ag_ri->flags   |= BGP_INFO_VALID ;

      ag_ri->attr   = bgp_attr_pair_assign(attrs) ;
      ag_ri->uptime = bgp_clock ();

      /* Add route (bgp_info) to the bgp_node and dispatch for processing.
       */
      bgp_info_add (ag_rn, ag_ri);
      bgp_process_dispatch (bgp, ag_rn);
    } ;

  /* Done: undo the lock acquired by bgp_node_get() -- which will destroy the
   *       node if it is redundant.
   *
   *       discard any unstored attributes, or unlock the stored ones.
   */;
  bgp_unlock_node (ag_rn);
  bgp_attr_pair_unload(attrs) ;
} ;

/*------------------------------------------------------------------------------
 * Merge the given bgp_info into the working attributes, if required.
 *
 * Picks up the next_hop and med if not already picked up.  Otherwise, if is
 * required, run the next hop and med check.
 *
 * Counts another route which has been aggregated.
 *
 * Returns:  true <=> OK
 *           false -> failed the next_hop/med check
 */
static bool
bgp_aggregate_merge(struct bgp_aggregate* aggregate, attr_pair attrs,
                                                            struct bgp_info* ri)
{
#ifdef AGGREGATE_NEXTHOP_CHECK
#warning AGGREGATE_NEXTHOP_CHECK
  enum { aggregate_next_hop_check  = true   } ;
#else
  enum { aggregate_next_hop_check  = false  } ;
#endif

  if (attrs->working->next_hop.type == nh_none)
    {
      /* TODO .... non IPv4 aggregation ???
       */
      bgp_attr_pair_set_next_hop(attrs, nh_ipv4,
                                                    &ri->attr->next_hop.ip.v4) ;
      bgp_attr_pair_set_med(attrs, ri->attr->med) ;
    }
  else if (aggregate_next_hop_check)
    {
      /* RFC4271: When aggregating routes which have different NEXT_HOP
       *          attributes, the NEXT_HOP attribute of the aggregated route
       *          SHALL identify an interface on the BGP speaker that performs
       *          the aggregation.
       *
       * RFC4721: Route that have different MED attributes SHALL NOT be
       *          aggregated.
       *
       * TODO ..... checking of IPv4 next hop ??? ........................................
       */
      if ( (ri->attr->next_hop.ip.v4 != attrs->working->next_hop.ip.v4) ||
           (ri->attr->med            != attrs->working->med) )
        return false ;
    } ;

  aggregate->count++;

  if (aggregate->as_set)
    {
      /* RFC4271: any one INCOMPLETE -> INCOMPLETE,
       *          otherwise any one EGP -> EGP
       *          otherwise IGP
       */
      confirm((BGP_ATT_ORG_INCOMP > BGP_ATT_ORG_EGP) &&
                                   (BGP_ATT_ORG_EGP > BGP_ATT_ORG_IGP)) ;

      if (attrs->working->origin < ri->attr->origin)
        bgp_attr_pair_set_origin(attrs, ri->attr->origin) ;

      /* RFC4271: If at least one of the routes to be aggregated has
       *          ATOMIC_AGGREGATE path attribute, then the aggregated route
       *          SHALL have this attribute as well.
       */
      if (ri->attr->have & atb_atomic_aggregate)
        bgp_attr_pair_set_atomic_aggregate(attrs, true) ;

      /* as_path_aggregate() performs minimal RFC4271 operation.
       */
      if (ri->attr->asp != NULL)
        {
          as_path asp ;

          asp = as_path_aggregate (attrs->working->asp, ri->attr->asp) ;
          bgp_attr_pair_set_as_path(attrs, asp) ;
        } ;

      /* Lump all communities together
       */
      if (ri->attr->community != NULL)
        {
          attr_community comm ;

          comm = attr_community_add_list(attrs->working->community,
                                                          ri->attr->community) ;
          bgp_attr_pair_set_community(attrs, comm) ;
        }
    } ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given aggregate prefix from the main table.
 *
 * Adjust the state of any more specific routes of that aggregate.
 */
static void
bgp_aggregate_delete (bgp_inst bgp, prefix p,
                                                struct bgp_aggregate *aggregate)
{
  bgp_table table;
  bgp_node ag_rn, rn ;
  struct bgp_info* ag_ri;

  if (qafx_is_ipv4(aggregate->qafx) && (p->prefixlen == IPV4_MAX_BITLEN))
    return;
  if (qafx_is_ipv6(aggregate->qafx) && (p->prefixlen == IPV6_MAX_BITLEN))
    return;

  /* See if we have the aggregate in the main RIB
   */
  table = bgp->rib[aggregate->qafx][rib_main];

  ag_rn = bgp_node_lookup(table, p) ;
  if (ag_rn == NULL)
    return ;                    /* no aggregate in the table            */

  for (ag_ri = ag_rn->info; ag_ri; ag_ri = ag_ri->info.next)
    if ((ag_ri->peer == bgp->peer_self)
                                 && (ag_ri->type == ZEBRA_ROUTE_BGP)
                                 && (ag_ri->sub_type == BGP_ROUTE_AGGREGATE))
      break;

  if (ag_ri == NULL)
    {
      bgp_unlock_node (ag_rn) ;
      return ;                  /* no aggregate route in the table      */
    } ;

  /* About to withdraw aggregate BGP route from routing table.
   *
   * If routes exists below this node, modify as required to reflect the fact
   * that the parent is about to be removed.
   *
   * Note that bgp_route_next_until() starts by moveing down to the left, and
   * unlocks the node it is on while locking the node it returns (if any).
   */
  rn  = bgp_lock_node(ag_rn) ;
  while ((rn = bgp_route_next_until (rn, ag_rn)) != NULL)
    {
      struct bgp_info *ri;
      bool match ;

      assert(rn->p.prefixlen > p->prefixlen) ;

      match = false ;

      for (ri = rn->info; ri; ri = ri->info.next)
        {
          if (BGP_INFO_HOLDDOWN (ri))
            continue;

          if (ri->sub_type != BGP_ROUTE_AGGREGATE)
            {
              if (aggregate->summary_only && (ri->extra != NULL))
                {
                  ri->extra->suppress--;

                  if (ri->extra->suppress == 0)
                    {
                      bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
                      match = true ;
                    }
                } ;

              aggregate->count--;
            } ;
          } ;

        /* If this node was suppressed, process the change.
         */
        if (match)
          bgp_process_dispatch (bgp, rn);
      } ;

  /* Withdraw aggregate BGP route from routing table.
   */
  bgp_info_delete (ag_rn, ag_ri);
  bgp_process_dispatch (bgp, ag_rn);

  /* Unlock bgp_node_lookup.
   */
  bgp_unlock_node (ag_rn);
}

/*------------------------------------------------------------------------------
 * Set an aggregate prefix
 */
static cmd_ret_t
bgp_aggregate_set (struct vty *vty, const char *prefix_str, qafx_t qafx,
                                                 bool summary_only, bool as_set)
{
  prefix_t p[1] ;
  bgp_node ag_rn ;
  bgp_inst bgp;
  struct bgp_aggregate *aggregate;
  bgp_table aggregate_table ;

  bgp = vty->index;
  aggregate_table = bgp_table_get(&bgp->aggregate[qafx], qafx) ;

  /* Convert string to prefix structure. */
  if (!str2prefix (prefix_str, p))
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  apply_mask (p);

  /* Get BGP structure.
   */
  bgp = vty->index;

  /* Old configuration check -- creates bgp_node in the aggregate table.
   */
  ag_rn = bgp_node_get (aggregate_table, p);

  if (ag_rn->info)
    {
      cmd_ret_t ret ;

      vty_out (vty, "There is already same aggregate network.%s", VTY_NEWLINE);

      ret = bgp_aggregate_unset (vty, prefix_str, qafx);
      if (ret != CMD_SUCCESS)
        {
          vty_out (vty, "Error deleting aggregate.%s", VTY_NEWLINE);
          bgp_unlock_node (ag_rn);
          return CMD_WARNING;
        }
    }

  /* Make aggregate address structure.
   *
   * Note that bgp_node_get() has locked the node, and we retain that lock.
   */
  aggregate = bgp_aggregate_new () ;

  aggregate->summary_only = summary_only;
  aggregate->as_set       = as_set;
  aggregate->qafx         = qafx;

  ag_rn->info = aggregate;

  bgp_aggregate_route(bgp, p, NULL, NULL, ag_rn->info);

  return CMD_SUCCESS;
} ;

/*------------------------------------------------------------------------------
 * Unet an aggregate prefix
 */
static cmd_ret_t
bgp_aggregate_unset (struct vty *vty, const char *prefix_str, qafx_t qafx)
{
  prefix_t  p[1] ;
  bgp_node  ag_rn;
  bgp_inst  bgp;

  bgp = vty->index;

  /* Convert string to prefix structure. */
  if (!str2prefix (prefix_str, p))
    {
      vty_out (vty, "Malformed prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  ;
  apply_mask (p);

  /* Get BGP structure.
   */
  bgp = vty->index;

  /* Old configuration check.
   */
  ag_rn = bgp_node_lookup (bgp->aggregate[qafx], p);

  if (ag_rn == NULL)
    {
      vty_out (vty, "%% There is no aggregate-address configuration.%s",
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  qassert(((struct bgp_aggregate*)ag_rn->info)->qafx == qafx) ;

  bgp_aggregate_delete (bgp, p, ag_rn->info);

  /* Discard aggregate address configuration.
   *
   * Note that bgp_node_lookup() has locked the bgp_node, and when the node was
   * created, it was locked and left locked.
   */
  bgp_aggregate_free (ag_rn->info);
  ag_rn->info = NULL;

  bgp_unlock_node (ag_rn) ;             /* undo bgp_node_lookup()       */

  bgp_unlock_node (ag_rn) ;             /* discard node                 */

  return CMD_SUCCESS;
}
#endif

/*------------------------------------------------------------------------------
 * Aggregate route configuration stuff -- TODO !!
 */
static cmd_ret_t
bgp_aggregate_todo_warning(vty vty)
{
  vty_out (vty, "%% Route Aggregation is disabled -- pro tem\n") ;
  return CMD_WARNING;
} ;

static cmd_ret_t
bgp_aggregate_set(struct vty *vty, const char *prefix_str, qafx_t qafx,
                                                 bool summary_only, bool as_set)
{
  return bgp_aggregate_todo_warning(vty) ;
} ;

static cmd_ret_t
bgp_aggregate_unset(struct vty *vty, const char *prefix_str, qafx_t qafx)
{
  return bgp_aggregate_todo_warning(vty) ;
} ;

#define AGGREGATE_SUMMARY_ONLY true
#define AGGREGATE_AS_SET       true

#define NOT_AGGREGATE_SUMMARY_ONLY false
#define NOT_AGGREGATE_AS_SET       false

DEFUN (aggregate_address,
       aggregate_address_cmd,
       "aggregate-address A.B.C.D/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask,
       aggregate_address_mask_cmd,
       "aggregate-address A.B.C.D A.B.C.D",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_summary_only,
       aggregate_address_summary_only_cmd,
       "aggregate-address A.B.C.D/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_summary_only,
       aggregate_address_mask_summary_only_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_as_set,
       aggregate_address_as_set_cmd,
       "aggregate-address A.B.C.D/M as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                  NOT_AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

DEFUN (aggregate_address_mask_as_set,
       aggregate_address_mask_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                 NOT_AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}


DEFUN (aggregate_address_as_set_summary,
       aggregate_address_as_set_summary_cmd,
       "aggregate-address A.B.C.D/M as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], bgp_node_qafx(vty),
                                      AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_as_set_summary,
       aggregate_address_summary_as_set_cmd,
       "aggregate-address A.B.C.D/M summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_as_set_summary_cmd,
       "aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_set (vty, prefix_str, bgp_node_qafx(vty),
                                      AGGREGATE_SUMMARY_ONLY, AGGREGATE_AS_SET);
}

ALIAS (aggregate_address_mask_as_set_summary,
       aggregate_address_mask_summary_as_set_cmd,
       "aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address,
       no_aggregate_address_cmd,
       "no aggregate-address A.B.C.D/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], bgp_node_qafx(vty));
}

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_only_cmd,
       "no aggregate-address A.B.C.D/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_cmd,
       "no aggregate-address A.B.C.D/M as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_as_set_summary_cmd,
       "no aggregate-address A.B.C.D/M as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address,
       no_aggregate_address_summary_as_set_cmd,
       "no aggregate-address A.B.C.D/M summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

DEFUN (no_aggregate_address_mask,
       no_aggregate_address_mask_cmd,
       "no aggregate-address A.B.C.D A.B.C.D",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n")
{
  int ret;
  char prefix_str[BUFSIZ];

  ret = netmask_str2prefix_str (argv[0], argv[1], prefix_str);

  if (! ret)
    {
      vty_out (vty, "%% Inconsistent address and mask%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_aggregate_unset (vty, prefix_str, bgp_node_qafx(vty));
}

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_only_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_as_set_summary_cmd,
       "no aggregate-address A.B.C.D A.B.C.D as-set summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Generate AS set path information\n"
       "Filter more specific routes from updates\n")

ALIAS (no_aggregate_address_mask,
       no_aggregate_address_mask_summary_as_set_cmd,
       "no aggregate-address A.B.C.D A.B.C.D summary-only as-set",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate address\n"
       "Aggregate mask\n"
       "Filter more specific routes from updates\n"
       "Generate AS set path information\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_aggregate_address,
       ipv6_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_set (vty, argv[0], qafx_ipv6_unicast,
                              NOT_AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (ipv6_aggregate_address_summary_only,
       ipv6_aggregate_address_summary_only_cmd,
       "aggregate-address X:X::X:X/M summary-only",
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_set (vty, argv[0], qafx_ipv6_unicast,
                                  AGGREGATE_SUMMARY_ONLY, NOT_AGGREGATE_AS_SET);
}

DEFUN (no_ipv6_aggregate_address,
       no_ipv6_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")
{
  return bgp_aggregate_unset (vty, argv[0], qafx_ipv6_unicast);
}

DEFUN (no_ipv6_aggregate_address_summary_only,
       no_ipv6_aggregate_address_summary_only_cmd,
       "no aggregate-address X:X::X:X/M summary-only",
       NO_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
{
  return bgp_aggregate_unset (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (ipv6_aggregate_address,
       old_ipv6_aggregate_address_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (ipv6_aggregate_address_summary_only,
       old_ipv6_aggregate_address_summary_only_cmd,
       "ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")

ALIAS (no_ipv6_aggregate_address,
       old_no_ipv6_aggregate_address_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n")

ALIAS (no_ipv6_aggregate_address_summary_only,
       old_no_ipv6_aggregate_address_summary_only_cmd,
       "no ipv6 bgp aggregate-address X:X::X:X/M summary-only",
       NO_STR
       IPV6_STR
       BGP_STR
       "Configure BGP aggregate entries\n"
       "Aggregate prefix\n"
       "Filter more specific routes from updates\n")
#endif /* HAVE_IPV6 */



/*------------------------------------------------------------------------------
 * Table of route aggregation commands
 */
CMD_INSTALL_TABLE(static, bgp_aggregate_cmd_table, BGPD) =
{
  { BGP_NODE,        &aggregate_address_cmd                             },
  { BGP_NODE,        &aggregate_address_mask_cmd                        },
  { BGP_NODE,        &aggregate_address_summary_only_cmd                },
  { BGP_NODE,        &aggregate_address_mask_summary_only_cmd           },
  { BGP_NODE,        &aggregate_address_as_set_cmd                      },
  { BGP_NODE,        &aggregate_address_mask_as_set_cmd                 },
  { BGP_NODE,        &aggregate_address_as_set_summary_cmd              },
  { BGP_NODE,        &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_NODE,        &aggregate_address_summary_as_set_cmd              },
  { BGP_NODE,        &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_NODE,        &no_aggregate_address_cmd                          },
  { BGP_NODE,        &no_aggregate_address_summary_only_cmd             },
  { BGP_NODE,        &no_aggregate_address_as_set_cmd                   },
  { BGP_NODE,        &no_aggregate_address_as_set_summary_cmd           },
  { BGP_NODE,        &no_aggregate_address_summary_as_set_cmd           },
  { BGP_NODE,        &no_aggregate_address_mask_cmd                     },
  { BGP_NODE,        &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_NODE,        &no_aggregate_address_mask_as_set_cmd              },
  { BGP_NODE,        &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_NODE,        &no_aggregate_address_mask_summary_as_set_cmd      },

  /* IPv4 unicast configuration.  */
  { BGP_IPV4_NODE,   &aggregate_address_cmd                             },
  { BGP_IPV4_NODE,   &aggregate_address_mask_cmd                        },
  { BGP_IPV4_NODE,   &aggregate_address_summary_only_cmd                },
  { BGP_IPV4_NODE,   &aggregate_address_mask_summary_only_cmd           },
  { BGP_IPV4_NODE,   &aggregate_address_as_set_cmd                      },
  { BGP_IPV4_NODE,   &aggregate_address_mask_as_set_cmd                 },
  { BGP_IPV4_NODE,   &aggregate_address_as_set_summary_cmd              },
  { BGP_IPV4_NODE,   &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_IPV4_NODE,   &aggregate_address_summary_as_set_cmd              },
  { BGP_IPV4_NODE,   &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_IPV4_NODE,   &no_aggregate_address_cmd                          },
  { BGP_IPV4_NODE,   &no_aggregate_address_summary_only_cmd             },
  { BGP_IPV4_NODE,   &no_aggregate_address_as_set_cmd                   },
  { BGP_IPV4_NODE,   &no_aggregate_address_as_set_summary_cmd           },
  { BGP_IPV4_NODE,   &no_aggregate_address_summary_as_set_cmd           },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_cmd                     },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_as_set_cmd              },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_IPV4_NODE,   &no_aggregate_address_mask_summary_as_set_cmd      },

  /* IPv4 multicast configuration.  */
  { BGP_IPV4M_NODE,  &aggregate_address_cmd                             },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_cmd                        },
  { BGP_IPV4M_NODE,  &aggregate_address_summary_only_cmd                },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_summary_only_cmd           },
  { BGP_IPV4M_NODE,  &aggregate_address_as_set_cmd                      },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_as_set_cmd                 },
  { BGP_IPV4M_NODE,  &aggregate_address_as_set_summary_cmd              },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_as_set_summary_cmd         },
  { BGP_IPV4M_NODE,  &aggregate_address_summary_as_set_cmd              },
  { BGP_IPV4M_NODE,  &aggregate_address_mask_summary_as_set_cmd         },
  { BGP_IPV4M_NODE,  &no_aggregate_address_cmd                          },
  { BGP_IPV4M_NODE,  &no_aggregate_address_summary_only_cmd             },
  { BGP_IPV4M_NODE,  &no_aggregate_address_as_set_cmd                   },
  { BGP_IPV4M_NODE,  &no_aggregate_address_as_set_summary_cmd           },
  { BGP_IPV4M_NODE,  &no_aggregate_address_summary_as_set_cmd           },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_cmd                     },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_summary_only_cmd        },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_as_set_cmd              },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_as_set_summary_cmd      },
  { BGP_IPV4M_NODE,  &no_aggregate_address_mask_summary_as_set_cmd      },

#ifdef HAVE_IPV6
  /* New config IPv6 BGP commands.  */
  { BGP_IPV6_NODE,   &ipv6_aggregate_address_cmd                        },
  { BGP_IPV6_NODE,   &ipv6_aggregate_address_summary_only_cmd           },
  { BGP_IPV6_NODE,   &no_ipv6_aggregate_address_cmd                     },
  { BGP_IPV6_NODE,   &no_ipv6_aggregate_address_summary_only_cmd        },

  /* Old config IPv6 BGP commands.  */
  { BGP_NODE,        &old_ipv6_aggregate_address_cmd                    },
  { BGP_NODE,        &old_ipv6_aggregate_address_summary_only_cmd       },
  { BGP_NODE,        &old_no_ipv6_aggregate_address_cmd                 },
  { BGP_NODE,        &old_no_ipv6_aggregate_address_summary_only_cmd    },
#endif /* HAVE_IPV6 */

  CMD_INSTALL_END
} ;

extern void
bgp_aggregate_cmd_init (void)
{
  cmd_install_table(bgp_aggregate_cmd_table) ;
}

