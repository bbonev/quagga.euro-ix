/* BGP Show Commands -- header
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

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_show.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_run_vty.h"
#include "bgpd/bgp_routemap.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_route_static.h"
#include "bgpd/bgp_adj_in.h"
#include "bgpd/bgp_adj_out.h"
#include "bgpd/bgp_names.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_nexthop.h"

#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "pthread_safe.h"
#include "buffer.h"
#include "hash.h"

/*==============================================================================
 * Here we have all the "show" commands, which are vty/cli commands which
 * operate on the *run-time* state.
 */

/*==============================================================================
 * Showing state of RIB(s).
 */

/*------------------------------------------------------------------------------
 * Output leading part of route display, the prefix to field width 20.
 */
static void
route_vty_out_route (vty vty, prefix pfx)
{
  int len;
  uint32_t destination;

  if (pfx->family == AF_INET)
    {
      len = vty_out (vty, "%s", siptoa(pfx->family, &pfx->u.prefix).str);
      destination = ntohl (pfx->u.prefix4.s_addr);

      if ((IN_CLASSC (destination) && pfx->prefixlen == 24)
          || (IN_CLASSB (destination) && pfx->prefixlen == 16)
          || (IN_CLASSA (destination) && pfx->prefixlen == 8)
          || pfx->u.prefix4.s_addr == 0)
        {
          /* When mask is natural, mask is not displayed. */
        }
      else
        len += vty_out (vty, "/%d", pfx->prefixlen);
    }
  else
    len = vty_out (vty, "%s/%d", siptoa(pfx->family, &pfx->u.prefix).str,
                   pfx->prefixlen);

  len = 17 - len;
  if (len < 1)
    vty_out (vty, "\n%*s", 20, " ");
  else
    vty_out (vty, "%*s", len, " ");
}

enum bgp_display_type
{
  normal_list,
};

/*------------------------------------------------------------------------------
 * Print the short form route status for a bgp_info
 */
static void
route_vty_short_status_out (vty vty, route_info ri)
{
 /* Route status display.
  */
  if (ri->current.flags & BGP_INFO_REMOVED)
    vty_out (vty, "R");
  else if (ri->current.flags & BGP_INFO_STALE)
    vty_out (vty, "S");
  else if (false)               /* suppressed   */
    vty_out (vty, "s");
  else if (! (ri->current.flags & BGP_INFO_HISTORY))
    vty_out (vty, "*");
  else
    vty_out (vty, " ");

  /* Selected
   */
  if (ri->current.flags & BGP_INFO_HISTORY)
    vty_out (vty, "h");
  else if (ri->current.flags & BGP_INFO_DAMPED)
    vty_out (vty, "d");
  else if (ri->current.flags & BGP_INFO_SELECTED)
    vty_out (vty, ">");
  else
    vty_out (vty, " ");

  /* Internal route.
   */
  if (ri->prib->prun->rp.sort == BGP_PEER_IBGP)
    vty_out (vty, "i");
  else
    vty_out (vty, " ");
}

/*------------------------------------------------------------------------------
 * If the as_path is not NULL and not empty, output it using the given
 * format.  Otherwise, output the alternative string.
 */
static void
route_vty_out_as_path(vty vty, chs_c format, as_path asp, chs_c  alt)
{
  chs_c str ;

  if (asp == NULL)
    str = "" ;
  else
    str = as_path_str(asp) ;

  if (*str != '\0')
    vty_out(vty, format, str) ;
  else if ((alt != NULL) & (*alt != '\0'))
    vty_out(vty, "%s", alt) ;
} ;

/*------------------------------------------------------------------------------
 * Basic show route
 */
static void
route_vty_out (vty vty, prefix pfx, route_info ri, bool display)
{
  attr_set attr;

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (vty, pfx);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute
   */
  attr = ri->iroutes[lc_view_id].attr ;
  if (attr != NULL)
    {
      if (pfx->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (pfx->family == AF_INET6)
        {
          int len;

          len = vty_out(vty, "%s",
                 siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "\n%*s", 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->have & atb_med)
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->have & atb_local_pref)
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", attr->weight);

      /* Print aspath */
      route_vty_out_as_path (vty, "%s", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str) ;
    } ;

  vty_out (vty, "\n");
}

/*------------------------------------------------------------------------------
 * Show route ...
 */
static void
route_vty_out_tmp (vty vty, prefix pfx, attr_set attr, qafx_t qafx)
{
  /* Route status display. */
  vty_out (vty, "*");
  vty_out (vty, ">");
  vty_out (vty, " ");

  /* print prefix and mask */
  route_vty_out_route (vty, pfx);

  /* Print attribute */
  if (attr)
    {
      if (pfx->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (pfx->family == AF_INET6)
        {
          int len;

          len = vty_out(vty, "%s",
                siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
          len = 16 - len;
          if (len < 1)
            vty_out (vty, "\n%*s", 36, " ");
          else
            vty_out (vty, "%*s", len, " ");
        }
#endif /* HAVE_IPV6 */

      if (attr->have & atb_med)
        vty_out (vty, "%10u", attr->med);
      else
        vty_out (vty, "          ");

      if (attr->have & atb_local_pref)
        vty_out (vty, "%7u", attr->local_pref);
      else
        vty_out (vty, "       ");

      vty_out (vty, "%7u ", attr->weight);

      /* Print aspath   */
      route_vty_out_as_path (vty, "%s ", attr->asp, "");

      /* Print origin   */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    }

  vty_out (vty, "\n");
}

/*------------------------------------------------------------------------------
 * Show route with tag
 */
static void
route_vty_out_tag (vty vty, prefix pfx, route_info ri, bool display)
{
  attr_set attr;
  uint32_t label = 0;

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (vty, pfx);
  else
    vty_out (vty, "%*s", 17, " ");

  /* Print attribute
   */
  attr = ri->iroutes[lc_view_id].attr ;
  if (attr != NULL)
    {
      if (pfx->family == AF_INET)
        {
          vty_out (vty, "%-16s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
        }
#ifdef HAVE_IPV6
      else if (pfx->family == AF_INET6)
        {
          vty_out(vty, "%s", siptoa(AF_INET6,
                                  &attr->next_hop.ip.v6[in6_global]).str) ;

          if (attr->next_hop.type == nh_ipv6_2)
            vty_out(vty, "(%s)", siptoa(AF_INET6,
                              &attr->next_hop.ip.v6[in6_link_local]).str) ;
        }
#endif /* HAVE_IPV6 */
    }

  label = mpls_tags_label(ri->current.tags, 0);

  vty_out (vty, "notag/%d", label);

  vty_out (vty, "\n");
}

/*------------------------------------------------------------------------------
 * damping route
 */
static void
damp_route_vty_out (vty vty, prefix pfx, route_info ri, bool display)
{
  attr_set attr;
  int len;
  char timebuf[50];

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (! display)
    route_vty_out_route (vty, pfx);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", ri->prib->prun->name);
  len = 17 - len;
  if (len < 1)
    vty_out (vty, "\n%*s", 34, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, ri, timebuf,
                                                              sizeof(timebuf)));
  /* Print attribute
   */
  attr = ri->iroutes[lc_view_id].attr ;
  if (attr != NULL)
    {
      /* Print aspath */
      route_vty_out_as_path (vty, "%s ", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    } ;

  vty_out (vty, "%s", VTY_NEWLINE);
}

/* flap route */
static void
flap_route_vty_out (vty vty, prefix pfx, route_info ri, bool display)
{
  attr_set attr;
  struct bgp_damp_info *bdi;
  int len;
  char timebuf[50];

  if (ri->extra == NULL)
    return;

/* TODO .... reconstruct Route Flap Damping !!          */
#if 0
  bdi = ri->extra->damp_info;
#else
  return ;
#endif

  /* short status lead text
   */
  route_vty_short_status_out (vty, ri);

  /* print prefix and mask
   */
  if (display)
    route_vty_out_route (vty, pfx);
  else
    vty_out (vty, "%*s", 17, " ");

  len = vty_out (vty, "%s", ri->prib->prun->name);
  len = 16 - len;
  if (len < 1)
    vty_out (vty, "\n%*s", 33, " ");
  else
    vty_out (vty, "%*s", len, " ");

  len = vty_out (vty, "%d", bdi->flap);
  len = 5 - len;
  if (len < 1)
    vty_out (vty, " ");
  else
    vty_out (vty, "%*s ", len, " ");

  vty_out (vty, "%s ", peer_uptime (bdi->start_time).str);

  if (CHECK_FLAG (ri->current.flags, BGP_INFO_DAMPED)
      && ! CHECK_FLAG (ri->current.flags, BGP_INFO_HISTORY))
    vty_out (vty, "%s ", bgp_damp_reuse_time_vty (vty, ri,
                                                     timebuf, sizeof(timebuf)));
  else
    vty_out (vty, "%*s ", 8, " ");

  /* Print attribute
   */
  attr = ri->iroutes[lc_view_id].attr ;
  if (attr != NULL)
    {
      /* Print aspath */
      route_vty_out_as_path (vty, "%s", attr->asp, "");

      /* Print origin */
      vty_out (vty, "%s", map_direct(bgp_origin_short_map, attr->origin).str);
    } ;

  vty_out (vty, "%s", VTY_NEWLINE);
}


#define BGP_SHOW_SCODE_HEADER \
  "Status codes: s suppressed, d damped, h history, * valid, > best, "\
  "i - internal,\n"\
  "              r RIB-failure, S Stale, R Removed\n"
#define BGP_SHOW_OCODE_HEADER \
  "Origin codes: i - IGP, e - EGP, ? - incomplete\n"
#define BGP_SHOW_HEADER \
  "   Network          Next Hop            Metric LocPrf Weight Path\n"
#define BGP_SHOW_DAMP_HEADER \
  "   Network          From             Reuse    Path\n"
#define BGP_SHOW_FLAP_HEADER \
  "   Network          From            Flaps Duration Reuse    Path\n"

typedef enum bgp_show_type bgp_show_type_t ;
enum bgp_show_type
{
  bgp_show_type_normal,
  bgp_show_type_regexp,
  bgp_show_type_prefix_list,
  bgp_show_type_filter_list,
  bgp_show_type_route_map,
  bgp_show_type_neighbor,
  bgp_show_type_cidr_only,
  bgp_show_type_prefix_longer,
  bgp_show_type_community_all,
  bgp_show_type_community,
  bgp_show_type_community_exact,
  bgp_show_type_community_list,
  bgp_show_type_community_list_exact,
  bgp_show_type_flap_statistics,
  bgp_show_type_flap_address,
  bgp_show_type_flap_prefix,
  bgp_show_type_flap_cidr_only,
  bgp_show_type_flap_regexp,
  bgp_show_type_flap_filter_list,
  bgp_show_type_flap_prefix_list,
  bgp_show_type_flap_prefix_longer,
  bgp_show_type_flap_route_map,
  bgp_show_type_flap_neighbor,
  bgp_show_type_damped_paths,
  bgp_show_type_damp_neighbor
};

static cmd_ret_t
bgp_show_table (vty vty, bgp_rib rib, bgp_lc_id_t lc, in_addr_t router_id,
                                          bgp_show_type_t sht, void *output_arg)
{
  vector         rv ;
  vector_index_t i ;
  bool   header, show_damp ;
  urlong output_count;

  /* This is first entry point, so reset total line.
   */
  output_count = 0 ;
  header       = false ;

  switch (sht)
    {
      default:
        qassert(false) ;
        fall_through ;

      case bgp_show_type_normal:
      case bgp_show_type_regexp:
      case bgp_show_type_prefix_list:
      case bgp_show_type_filter_list:
      case bgp_show_type_route_map:
      case bgp_show_type_neighbor:
      case bgp_show_type_cidr_only:
      case bgp_show_type_prefix_longer:
      case bgp_show_type_community_all:
      case bgp_show_type_community:
      case bgp_show_type_community_exact:
      case bgp_show_type_community_list:
      case bgp_show_type_community_list_exact:
        show_damp = false ;
        break ;

      case bgp_show_type_flap_statistics:
      case bgp_show_type_flap_address:
      case bgp_show_type_flap_prefix:
      case bgp_show_type_flap_cidr_only:
      case bgp_show_type_flap_regexp:
      case bgp_show_type_flap_filter_list:
      case bgp_show_type_flap_prefix_list:
      case bgp_show_type_flap_prefix_longer:
      case bgp_show_type_flap_route_map:
      case bgp_show_type_flap_neighbor:
      case bgp_show_type_damped_paths:
      case bgp_show_type_damp_neighbor:
        show_damp = true ;
        break ;
    } ;

/* TODO .... reconstruct damping                */
#if 0
#else
  /* Short circuit all the route-flag-damping stuff.
   */
  if (show_damp)
    return bgp_damp_warning(vty) ;
#endif

  /* Start processing of routes.
   */
  rv = bgp_rib_extract(rib, lc, NULL) ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;
      prefix       pfx ;

      bool display ;

      display = true ;

      rn  = vector_get_item(rv, i) ;
      pfx = prefix_id_get_prefix(rn->pfx_id) ;

      for (ri  = svs_head(rn->aroutes[lc].base, rn->avail) ; ri != NULL ;
                                ri = svs_next(ri->iroutes[lc].list, rn->avail))
        {
          attr_set attr ;

          attr = ri->iroutes[lc].attr ;

          if (show_damp && (ri->extra == NULL)
/* TODO .... reconstruct damping                */
#if 0
                        && (ri->extra->damp_info == NULL)
#endif
                                              )
                continue;

          if ( (sht == bgp_show_type_regexp)   ||
               (sht == bgp_show_type_flap_regexp) )
            {
              regex_t *regex = output_arg;

              if (bgp_regexec_asp (regex, attr->asp) == REG_NOMATCH)
                continue;
            }
          if (sht == bgp_show_type_prefix_list
              || sht == bgp_show_type_flap_prefix_list)
            {
              struct prefix_list *plist = output_arg;

              if (prefix_list_apply (plist, pfx) != PREFIX_PERMIT)
                continue;
            }
          if ( (sht == bgp_show_type_filter_list)  ||
               (sht == bgp_show_type_flap_filter_list) )
            {
              struct as_list *as_list = output_arg;

              if (as_list_apply (as_list, attr->asp) != AS_FILTER_PERMIT)
                continue;
            }
          if ( (sht == bgp_show_type_route_map) ||
               (sht == bgp_show_type_flap_route_map) )
            {
              bgp_route_map_t  brm[1] ;
              attr_pair_t      attrs[1] ;
              route_map_result_t ret;

              bgp_attr_pair_load(attrs, attr) ;

              brm->prun      = ri->prib->prun ;
              brm->attrs     = attrs ;
              brm->qafx      = ri->prib->qafx ;
              brm->rmap_type = BGP_RMAP_TYPE_NONE ;

              ret = route_map_apply((route_map)output_arg, pfx,
                                                  RMAP_BGP | RMAP_NO_SET, brm) ;
              bgp_attr_pair_unload(attrs) ;

              if (ret == RMAP_DENY_MATCH)
                continue ;
            }
          if ( (sht == bgp_show_type_neighbor)      ||
               (sht == bgp_show_type_flap_neighbor) ||
               (sht == bgp_show_type_damp_neighbor) )
            {
              sockunion su = &ri->prib->prun->session->cops->remote_su ;

              if ((su == NULL) || ! sockunion_same(su, (sockunion)output_arg))
                continue;
            }
          if ( (sht == bgp_show_type_cidr_only)     ||
               (sht == bgp_show_type_flap_cidr_only) )
            {
              u_int32_t destination;

              destination = ntohl (pfx->u.prefix4.s_addr);
              if (IN_CLASSC (destination) && pfx->prefixlen == 24)
                continue;
              if (IN_CLASSB (destination) && pfx->prefixlen == 16)
                continue;
              if (IN_CLASSA (destination) && pfx->prefixlen == 8)
                continue;
            }
          if ( (sht == bgp_show_type_prefix_longer) ||
               (sht == bgp_show_type_flap_prefix_longer) )
            {
              if (! prefix_match ((prefix)output_arg, pfx))
                continue;
            }
          if (sht == bgp_show_type_community_all)
            {
              if (attr->community == NULL)
                continue;
            }
          if (sht == bgp_show_type_community)
            {
              if ((attr->community == NULL) ||
                  ! attr_community_match(attr->community,
                                                  (attr_community)output_arg))
                continue;
            }
          if (sht == bgp_show_type_community_exact)
            {
              if ((attr->community == NULL) ||
                  ! attr_community_equal(attr->community,
                                                  (attr_community)output_arg))
                continue ;
            }
          if (sht == bgp_show_type_community_list)
            {
              struct community_list *list = output_arg;

              if (! community_list_match (attr->community, list))
                continue;
            }
          if (sht == bgp_show_type_community_list_exact)
            {
              struct community_list *list = output_arg;

              if (! community_list_exact_match (attr->community, list))
                continue;
            }
          if ( (sht == bgp_show_type_flap_address) ||
               (sht == bgp_show_type_flap_prefix) )
            {
              struct prefix *p = output_arg;

              if (! prefix_match (pfx, p))
                continue;

              if (sht == bgp_show_type_flap_prefix)
                if (p->prefixlen != pfx->prefixlen)
                  continue;
            }
          if ( (sht == bgp_show_type_damped_paths) ||
               (sht == bgp_show_type_damp_neighbor) )
            {
              if (! (ri->current.flags & BGP_INFO_DAMPED) ||
                    (ri->current.flags & BGP_INFO_HISTORY) )
                continue;
            }

          /* If we get this far, then we want to output the route.
           */
          if (header)
            {
              vty_out (vty, "BGP table version is 0, local router ID is %s%s",
                               siptoa(AF_INET, &router_id).str, VTY_NEWLINE);
              vty_out (vty, BGP_SHOW_SCODE_HEADER);
              vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");

              if (   (sht == bgp_show_type_damped_paths)
                  || (sht == bgp_show_type_damp_neighbor) )
                vty_out (vty, BGP_SHOW_DAMP_HEADER);
              else if (show_damp)
                vty_out (vty, BGP_SHOW_FLAP_HEADER);
              else
                vty_out (vty, BGP_SHOW_HEADER);

              header = false ;
            }

          if ( (sht == bgp_show_type_damped_paths) ||
               (sht == bgp_show_type_damp_neighbor) )
            damp_route_vty_out (vty, pfx, ri, display);
          else if (show_damp)
            flap_route_vty_out (vty, pfx, ri, display);
          else
            route_vty_out (vty, pfx, ri, display);

          if (display)
            {
              output_count++;
              display = false ;
            } ;
        } ;
    } ;

  /* No route is displayed
   */
  if (output_count == 0)
    {
      if (sht == bgp_show_type_normal)
        vty_out (vty, "No BGP network exists\n");
    }
  else
    vty_out (vty, "\nTotal number of prefixes %" fRL "u\n", output_count);

  return CMD_SUCCESS;
}


/*------------------------------------------------------------------------------
 * Show the contents of the bgp-rib for the given afi/safi and local-context.
 */
static cmd_ret_t
bgp_show_brun(vty vty, bgp_run brun, qafx_t qafx, bgp_lc_id_t lc,
                                          bgp_show_type_t sht, void *output_arg)
{
  bgp_rib rib ;

  rib = brun->rib[qafx] ;

  if (rib == NULL)
    {
      vty_out (vty, "Not configured for the AFI/SAFI\n");
      return CMD_WARNING;
    } ;

  return bgp_show_table (vty, rib, lc, brun->rp.router_id, sht, output_arg) ;
}

/*------------------------------------------------------------------------------
 * Show the contents of the bgp-rib for the given afi/safi and local-context.
 *
 * For NULL view_name, show unnamed or first view.
 */
static cmd_ret_t
bgp_show (vty vty, chs_c view_name, qafx_t qafx, bgp_lc_id_t lc,
                                          bgp_show_type_t sht, void *output_arg)
{
  bgp_run brun ;

  brun = bgp_run_lookup_vty(vty, view_name) ;

  if (brun == NULL)
    return CMD_WARNING;

  return bgp_show_brun(vty, brun, qafx, lc, sht, output_arg) ;
}

/*==============================================================================
 * Showing entire RIB for given address family
 */

/* BGP route print out function. */
DEFUN (show_ip_bgp,
       show_ip_bgp_cmd,
       "show ip bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

DEFUN (show_ip_bgp_ipv4,
       show_ip_bgp_ipv4_cmd,
       "show ip bgp ipv4 (unicast|multicast)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show(vty, NULL, qafx, lc_view_id, bgp_show_type_normal, NULL);
}

ALIAS (show_ip_bgp_ipv4,
       show_bgp_ipv4_safi_cmd,
       "show bgp ipv4 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")

DEFUN (show_ip_bgp_view,
       show_ip_bgp_view_cmd,
       "show ip bgp view WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n")
{
  return bgp_show(vty, argv[0], qafx_ipv4_unicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

#ifdef HAVE_IPV6

DEFUN (show_bgp,
       show_bgp_cmd,
       "show bgp",
       SHOW_STR
       BGP_STR)
{
  return bgp_show(vty, NULL, qafx_ipv6_unicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

ALIAS (show_bgp,
       show_bgp_ipv6_cmd,
       "show bgp ipv6",
       SHOW_STR
       BGP_STR
       "Address family\n")

DEFUN (show_bgp_ipv6_safi,
       show_bgp_ipv6_safi_cmd,
       "show bgp ipv6 (unicast|multicast)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show(vty, NULL, qafx, lc_view_id, bgp_show_type_normal, NULL);
}

/* old command */
DEFUN (show_ipv6_bgp,
       show_ipv6_bgp_cmd,
       "show ipv6 bgp",
       SHOW_STR
       IP_STR
       BGP_STR)
{
  return bgp_show(vty, NULL, qafx_ipv6_unicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

DEFUN (show_bgp_view,
       show_bgp_view_cmd,
       "show bgp view WORD",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n")
{
  return bgp_show(vty, argv[0], qafx_ipv6_unicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

ALIAS (show_bgp_view,
       show_bgp_view_ipv6_cmd,
       "show bgp view WORD ipv6",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n")

/* old command */
DEFUN (show_ipv6_mbgp,
       show_ipv6_mbgp_cmd,
       "show ipv6 mbgp",
       SHOW_STR
       IP_STR
       MBGP_STR)
{
  return bgp_show(vty, NULL, qafx_ipv6_multicast, lc_view_id,
                                                    bgp_show_type_normal, NULL);
}

#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_rsclient,
       show_ip_bgp_view_rsclient_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  bgp_prun  prun;
  bgp_prib  prib ;

  if (argc == 2)
    prun = prun_lookup_view_vty (vty, argv[0], argv[1]);
  else
    prun = prun_lookup_view_vty (vty, NULL, argv[0]);

  if (prun == NULL)
    return CMD_WARNING;

  prib = prun->prib[qafx_ipv4_unicast] ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first\n") ;
      return CMD_WARNING;
    }

  if ( !prib->rp.is_route_server_client)
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client\n");
      return CMD_WARNING;
    }

  return bgp_show_table (vty, prib->rib, prib->lc_id,
                    prun->rp.sargs_conf.remote_id, bgp_show_type_normal, NULL) ;
}

ALIAS (show_ip_bgp_view_rsclient,
       show_ip_bgp_rsclient_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_view_ipv4_safi_rsclient_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                                 "rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  bgp_prun  prun;
  bgp_prib  prib ;
  chs_c     um_arg ;
  qafx_t    qafx ;

  if (argc == 3)
    {
      prun = prun_lookup_view_vty (vty, argv[0], argv[2]);
      um_arg = argv[1] ;
    }
  else
    {
      prun = prun_lookup_view_vty (vty, NULL, argv[1]);
      um_arg = argv[0] ;
    }

  if (prun == NULL)
    return CMD_WARNING;

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  prib = prun->prib[qafx] ;
  if (prib == NULL)
   {
      vty_out (vty, "%% Activate the neighbor for the address family first\n");
      return CMD_WARNING;
    }

  if ( ! prib->rp.is_route_server_client)
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client\n") ;
      return CMD_WARNING;
    }

  return bgp_show_table (vty, prib->rib, prib->lc_id,
                    prun->rp.sargs_conf.remote_id, bgp_show_type_normal, NULL) ;
}

ALIAS (show_bgp_view_ipv4_safi_rsclient,
       show_bgp_ipv4_safi_rsclient_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

/*==============================================================================
 * Showing all entries in table where route has AS Path which matches the given
 * regex.
 */
static int
bgp_show_regexp (vty vty, int argc, argv_t argv, qafx_t qafx,
                                                       enum bgp_show_type type)
{
  int i;
  struct buffer *b;
  char *regstr;
  int first;
  regex_t *regex;
  int rc;

  first = 0;
  b = buffer_new (1024);
  for (i = 0; i < argc; i++)
    {
      if (first)
        buffer_putc (b, ' ');
      else
        {
          if ((strcmp (argv[i], "unicast") == 0) || (strcmp (argv[i], "multicast") == 0))
            continue;
          first = 1;
        }

      buffer_putstr (b, argv[i]);
    }
  buffer_putc (b, '\0');

  regstr = buffer_getstr (b);
  buffer_free (b);

  regex = bgp_regcomp (regstr);
  XFREE(MTYPE_TMP, regstr);
  if (! regex)
    {
      vty_out (vty, "Can't compile regexp %s%s", argv[0],
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  rc = bgp_show(vty, NULL, qafx, lc_view_id, type, regex);
  bgp_regex_free (regex);
  return rc;
}

DEFUN (show_ip_bgp_regexp,
       show_ip_bgp_regexp_cmd,
       "show ip bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv4_unicast,
                          bgp_show_type_regexp);
}

DEFUN (show_ip_bgp_flap_regexp,
       show_ip_bgp_flap_regexp_cmd,
       "show ip bgp flap-statistics regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv4_unicast,
                          bgp_show_type_flap_regexp);
}

DEFUN (show_ip_bgp_ipv4_regexp,
       show_ip_bgp_ipv4_regexp_cmd,
       "show ip bgp ipv4 (unicast|multicast) regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_regexp (vty, argc, argv, qafx, bgp_show_type_regexp);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_regexp,
       show_bgp_regexp_cmd,
       "show bgp regexp .LINE",
       SHOW_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_unicast,
                          bgp_show_type_regexp);
}

ALIAS (show_bgp_regexp,
       show_bgp_ipv6_regexp_cmd,
       "show bgp ipv6 regexp .LINE",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")

/* old command */
DEFUN (show_ipv6_bgp_regexp,
       show_ipv6_bgp_regexp_cmd,
       "show ipv6 bgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the BGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_unicast,
                          bgp_show_type_regexp);
}

/* old command */
DEFUN (show_ipv6_mbgp_regexp,
       show_ipv6_mbgp_regexp_cmd,
       "show ipv6 mbgp regexp .LINE",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the AS path regular expression\n"
       "A regular-expression to match the MBGP AS paths\n")
{
  return bgp_show_regexp (vty, argc, argv, qafx_ipv6_multicast,
                          bgp_show_type_regexp);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given prefix list.
 */
static int
bgp_show_prefix_list (vty vty, chs_c prefix_list_str, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (get_qAFI(qafx), prefix_list_str);
  if (plist == NULL)
    {
      vty_out (vty, "%% %s is not a valid prefix-list name%s",
               prefix_list_str, VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show(vty, NULL, qafx, lc_view_id, type, plist);
}

DEFUN (show_ip_bgp_prefix_list,
       show_ip_bgp_prefix_list_cmd,
       "show ip bgp prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_prefix_list);
}

DEFUN (show_ip_bgp_flap_prefix_list,
       show_ip_bgp_flap_prefix_list_cmd,
       "show ip bgp flap-statistics prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_flap_prefix_list);
}

DEFUN (show_ip_bgp_ipv4_prefix_list,
       show_ip_bgp_ipv4_prefix_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) prefix-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the prefix-list\n"
       "IP prefix-list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_prefix_list (vty, argv[1], qafx, bgp_show_type_prefix_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_list,
       show_bgp_prefix_list_cmd,
       "show bgp prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_prefix_list);
}

ALIAS (show_bgp_prefix_list,
       show_bgp_ipv6_prefix_list_cmd,
       "show bgp ipv6 prefix-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the prefix-list\n"
       "IPv6 prefix-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_list,
       show_ipv6_bgp_prefix_list_cmd,
       "show ipv6 bgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_prefix_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_list,
       show_ipv6_mbgp_prefix_list_cmd,
       "show ipv6 mbgp prefix-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the prefix-list\n"
       "IPv6 prefix-list name\n")
{
  return bgp_show_prefix_list (vty, argv[0], qafx_ipv6_multicast,
                               bgp_show_type_prefix_list);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given filter list.
 */
static int
bgp_show_filter_list (vty vty, chs_c filter, qafx_t qafx,
                                                       enum bgp_show_type type)
{
  struct as_list *as_list;

  as_list = as_list_lookup (filter);
  if (as_list == NULL)
    {
      vty_out (vty, "%% %s is not a valid AS-path access-list name\n", filter);
      return CMD_WARNING;
    }

  return bgp_show(vty, NULL, qafx, lc_view_id, type, as_list);
}

DEFUN (show_ip_bgp_filter_list,
       show_ip_bgp_filter_list_cmd,
       "show ip bgp filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_filter_list);
}

DEFUN (show_ip_bgp_flap_filter_list,
       show_ip_bgp_flap_filter_list_cmd,
       "show ip bgp flap-statistics filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv4_unicast,
                               bgp_show_type_flap_filter_list);
}

DEFUN (show_ip_bgp_ipv4_filter_list,
       show_ip_bgp_ipv4_filter_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) filter-list WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_filter_list (vty, argv[1], qafx, bgp_show_type_filter_list);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_filter_list,
       show_bgp_filter_list_cmd,
       "show bgp filter-list WORD",
       SHOW_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_filter_list);
}

ALIAS (show_bgp_filter_list,
       show_bgp_ipv6_filter_list_cmd,
       "show bgp ipv6 filter-list WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")

/* old command */
DEFUN (show_ipv6_bgp_filter_list,
       show_ipv6_bgp_filter_list_cmd,
       "show ipv6 bgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_unicast,
                               bgp_show_type_filter_list);
}

/* old command */
DEFUN (show_ipv6_mbgp_filter_list,
       show_ipv6_mbgp_filter_list_cmd,
       "show ipv6 mbgp filter-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes conforming to the filter-list\n"
       "Regular expression access list name\n")
{
  return bgp_show_filter_list (vty, argv[0], qafx_ipv6_multicast,
                               bgp_show_type_filter_list);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given route-map.
 */
static int
bgp_show_route_map (vty vty, chs_c rmap_str, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  struct route_map *rmap;

  rmap = route_map_lookup (rmap_str);
  if (! rmap)
    {
      vty_out (vty, "%% %s is not a valid route-map name\n", rmap_str);
      return CMD_WARNING;
    }

  return bgp_show(vty, NULL, qafx, lc_view_id, type, rmap);
}

DEFUN (show_ip_bgp_route_map,
       show_ip_bgp_route_map_cmd,
       "show ip bgp route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv4_unicast,
                                                       bgp_show_type_route_map);
}

DEFUN (show_ip_bgp_flap_route_map,
       show_ip_bgp_flap_route_map_cmd,
       "show ip bgp flap-statistics route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv4_unicast,
                             bgp_show_type_flap_route_map);
}

DEFUN (show_ip_bgp_ipv4_route_map,
       show_ip_bgp_ipv4_route_map_cmd,
       "show ip bgp ipv4 (unicast|multicast) route-map WORD",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route_map (vty, argv[1], qafx, bgp_show_type_route_map);
}

DEFUN (show_bgp_route_map,
       show_bgp_route_map_cmd,
       "show bgp route-map WORD",
       SHOW_STR
       BGP_STR
       "Display routes matching the route-map\n"
       "A route-map to match on\n")
{
  return bgp_show_route_map (vty, argv[0], qafx_ipv6_unicast,
                                                       bgp_show_type_route_map);
}

ALIAS (show_bgp_route_map,
       show_bgp_ipv6_route_map_cmd,
       "show bgp ipv6 route-map WORD",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the route-map\n"
       "A route-map to match on\n")

/*==============================================================================
 * Showing all entries in table where routes are "cidr-only".
 */
DEFUN (show_ip_bgp_cidr_only,
       show_ip_bgp_cidr_only_cmd,
       "show ip bgp cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display only routes with non-natural netmasks\n")
{
    return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                                 bgp_show_type_cidr_only, NULL);
}

DEFUN (show_ip_bgp_flap_cidr_only,
       show_ip_bgp_flap_cidr_only_cmd,
       "show ip bgp flap-statistics cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Display only routes with non-natural netmasks\n")
{
  return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                           bgp_show_type_flap_cidr_only, NULL);
}

DEFUN (show_ip_bgp_ipv4_cidr_only,
       show_ip_bgp_ipv4_cidr_only_cmd,
       "show ip bgp ipv4 (unicast|multicast) cidr-only",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display only routes with non-natural netmasks\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show(vty, NULL, qafx, lc_view_id, bgp_show_type_cidr_only, NULL);
}

/*==============================================================================
 * Showing all entries in table where route matches the given community.
 */
DEFUN (show_ip_bgp_community_all,
       show_ip_bgp_community_all_cmd,
       "show ip bgp community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                             bgp_show_type_community_all, NULL);
}

DEFUN (show_ip_bgp_ipv4_community_all,
       show_ip_bgp_ipv4_community_all_cmd,
       "show ip bgp ipv4 (unicast|multicast) community",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show(vty, NULL, qafx, lc_view_id, bgp_show_type_community_all, NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_all,
       show_bgp_community_all_cmd,
       "show bgp community",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show(vty, NULL, qafx_ipv6_unicast, lc_view_id,
                                            bgp_show_type_community_all, NULL);
}

ALIAS (show_bgp_community_all,
       show_bgp_ipv6_community_all_cmd,
       "show bgp ipv6 community",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_all,
       show_ipv6_bgp_community_all_cmd,
       "show ipv6 bgp community",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show(vty, NULL, qafx_ipv6_unicast, lc_view_id,
                                             bgp_show_type_community_all, NULL);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_all,
       show_ipv6_mbgp_community_all_cmd,
       "show ipv6 mbgp community",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n")
{
  return bgp_show(vty, NULL, qafx_ipv6_multicast, lc_view_id,
                                             bgp_show_type_community_all, NULL);
}
#endif /* HAVE_IPV6 */

static cmd_ret_t
bgp_show_community (vty vty, chs_c view_name,
                                            uint argf, uint argc, argv_t argv,
                                                        bool exact, qafx_t qafx)
{
  cmd_ret_t ret ;
  attr_community comm ;
  char *str ;
  attr_community_type_t act ;

  str = argv_concat(argv, argf, argc) ;
  comm = attr_community_from_str (str, &act);

  if (act == act_simple)
    {
      ret = bgp_show(vty, view_name, qafx, lc_view_id,
                                      (exact ? bgp_show_type_community_exact
                                             : bgp_show_type_community), comm);
    }
  else
    {
      vty_out (vty, "%% Community malformed\n");
      ret = CMD_WARNING;
    } ;

  attr_community_free(comm);
  XFREE (MTYPE_TMP, str);

  return ret ;
}

DEFUN (show_ip_bgp_community,
       show_ip_bgp_community_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv, false /* not exact */,
                                                            qafx_ipv4_unicast) ;
}

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community2_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community3_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_community,
       show_ip_bgp_community4_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community (vty, NULL, 1, argc, argv, false /* not exact */,
                                                                          qafx);
}

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community2_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community3_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_ip_bgp_ipv4_community,
       show_ip_bgp_ipv4_community4_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes containing communities\n")
#else
DEFUN (show_bgp_view_afi_safi_community_all,
       show_bgp_view_afi_safi_community_all_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes containing communities\n")
#endif
{
  qafx_t qafx ;

#ifdef HAVE_IPV6
  if (strncmp (argv[1], "ipv6", 4) == 0)
    qafx = (argv[2][0] == 'm') ? qafx_ipv6_multicast
                               : qafx_ipv6_unicast ;
  else
    qafx = (argv[2][0] == 'm') ? qafx_ipv4_multicast
                               : qafx_ipv4_unicast ;
#else
  qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;
#endif

  return bgp_show(vty, argv[0], qafx, lc_view_id, bgp_show_type_community_all,
                                                                          NULL);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
DEFUN (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif
{
  qafx_t qafx ;
  uint   argf ;

#ifdef HAVE_IPV6
  if (strncmp (argv[1], "ipv6", 4) == 0)
    qafx = (argv[2][0] == 'm') ? qafx_ipv6_multicast
                               : qafx_ipv6_unicast ;
  else
    qafx = (argv[2][0] == 'm') ? qafx_ipv4_multicast
                               : qafx_ipv4_unicast ;
  argf = 3 ;
#else
  qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;
  argf = 2 ;
#endif

  return bgp_show_community (vty, argv[0], argf, argc, argv,
                                                   false /* not exact */, qafx);
}

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community2_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                  "(AA:NN|local-AS|no-advertise|no-export) "
                                  "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community3_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
#endif

#ifdef HAVE_IPV6
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) community "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n") ;
#else
ALIAS (show_bgp_view_afi_safi_community,
       show_bgp_view_afi_safi_community4_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) community "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n") ;
#endif

DEFUN (show_ip_bgp_community_exact,
       show_ip_bgp_community_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv4_unicast);
}

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community2_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community3_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_community_exact,
       show_ip_bgp_community4_exact_cmd,
       "show ip bgp community (AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "(AA:NN|local-AS|no-advertise|no-export) "
                             "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

DEFUN (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community (vty, NULL, 1, argc, argv, true /* exact */, qafx);
}

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community2_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "(AA:NN|local-AS|no-advertise|no-export) "
                                   "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community3_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "(AA:NN|local-AS|no-advertise|no-export) "
                                    "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_ip_bgp_ipv4_community_exact,
       show_ip_bgp_ipv4_community4_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "(AA:NN|local-AS|no-advertise|no-export) "
                                     "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

#ifdef HAVE_IPV6
DEFUN (show_bgp_community,
       show_bgp_community_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                      false /* not exact */, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community,
       show_bgp_ipv6_community_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community2_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community2_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community3_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community3_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_community4_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

ALIAS (show_bgp_community,
       show_bgp_ipv6_community4_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_bgp_community,
       show_ipv6_bgp_community_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                      false /* not exact */, qafx_ipv6_unicast);
}

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community2_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community3_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_bgp_community,
       show_ipv6_bgp_community4_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

DEFUN (show_bgp_community_exact,
       show_bgp_community_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community2_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community2_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community3_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community3_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_community4_exact_cmd,
       "show bgp community (AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "(AA:NN|local-AS|no-advertise|no-export) "
                          "exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

ALIAS (show_bgp_community_exact,
       show_bgp_ipv6_community4_exact_cmd,
       "show bgp ipv6 community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                           true /* exact */, qafx_ipv6_unicast);
}

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community2_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community3_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_bgp_community_exact,
       show_ipv6_bgp_community4_exact_cmd,
       "show ipv6 bgp community (AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "(AA:NN|local-AS|no-advertise|no-export) "
                               "exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
DEFUN (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                    false /* not exact */, qafx_ipv6_multicast);
}

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community2_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community3_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
ALIAS (show_ipv6_mbgp_community,
       show_ipv6_mbgp_community4_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export)",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n")

/* old command */
DEFUN (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
{
  return bgp_show_community (vty, NULL, 0, argc, argv,
                                        true /* exact */, qafx_ipv6_multicast);
}

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community2_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community3_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")

/* old command */
ALIAS (show_ipv6_mbgp_community_exact,
       show_ipv6_mbgp_community4_exact_cmd,
       "show ipv6 mbgp community (AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "(AA:NN|local-AS|no-advertise|no-export) "
                                "exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the communities\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "community number\n"
       "Do not send outside local AS (well-known community)\n"
       "Do not advertise to any peer (well-known community)\n"
       "Do not export to next AS (well-known community)\n"
       "Exact match of the communities")
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table where route matches the given community-list.
 */
static int
bgp_show_community_list (vty vty, chs_c com, bool exact, qafx_t qafx)
{
  struct community_list *list;

  list = community_list_lookup (bgp_clist, COMMUNITY_LIST, com);
  if (list == NULL)
    {
      vty_out (vty, "%% %s is not a valid community-list name%s", com,
               VTY_NEWLINE);
      return CMD_WARNING;
    }

  return bgp_show(vty, NULL, qafx, lc_view_id,
                                    exact ? bgp_show_type_community_list_exact
                                          : bgp_show_type_community_list, list);
}

DEFUN (show_ip_bgp_community_list,
       show_ip_bgp_community_list_cmd,
       "show ip bgp community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_community_list,
       show_ip_bgp_ipv4_community_list_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community_list (vty, argv[1], 0, qafx);
}

DEFUN (show_ip_bgp_community_list_exact,
       show_ip_bgp_community_list_exact_cmd,
       "show ip bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_community_list_exact,
       show_ip_bgp_ipv4_community_list_exact_cmd,
       "show ip bgp ipv4 (unicast|multicast) community-list (<1-500>|WORD) "
                                                                 "exact-match",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_community_list (vty, argv[1], true /* exact */, qafx);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_community_list,
       show_bgp_community_list_cmd,
       "show bgp community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_list,
       show_bgp_ipv6_community_list_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list,
       show_ipv6_bgp_community_list_cmd,
       "show ipv6 bgp community-list WORD",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list,
       show_ipv6_mbgp_community_list_cmd,
       "show ipv6 mbgp community-list WORD",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n")
{
  return bgp_show_community_list (vty, argv[0], 0, qafx_ipv6_multicast);
}

DEFUN (show_bgp_community_list_exact,
       show_bgp_community_list_exact_cmd,
       "show bgp community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_unicast);
}

ALIAS (show_bgp_community_list_exact,
       show_bgp_ipv6_community_list_exact_cmd,
       "show bgp ipv6 community-list (<1-500>|WORD) exact-match",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Display routes matching the community-list\n"
       "community-list number\n"
       "community-list name\n"
       "Exact match of the communities\n")

/* old command */
DEFUN (show_ipv6_bgp_community_list_exact,
       show_ipv6_bgp_community_list_exact_cmd,
       "show ipv6 bgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_community_list_exact,
       show_ipv6_mbgp_community_list_exact_cmd,
       "show ipv6 mbgp community-list WORD exact-match",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Display routes matching the community-list\n"
       "community-list name\n"
       "Exact match of the communities\n")
{
  return bgp_show_community_list (vty, argv[0], 1, qafx_ipv6_multicast);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Showing all entries in table for route and any more specifics.
 */
static int
bgp_show_prefix_longer (vty vty, chs_c prefix, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  int ret;
  struct prefix *p;

  p = prefix_new();

  ret = str2prefix (prefix, p);
  if (! ret)
    {
      vty_out (vty, "%% Malformed Prefix%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = bgp_show(vty, NULL, qafx, lc_view_id, type, p);
  prefix_free(p);
  return ret;
}

DEFUN (show_ip_bgp_prefix_longer,
       show_ip_bgp_prefix_longer_cmd,
       "show ip bgp A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_prefix_longer,
       show_ip_bgp_flap_prefix_longer_cmd,
       "show ip bgp flap-statistics A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_flap_prefix_longer);
}

DEFUN (show_ip_bgp_ipv4_prefix_longer,
       show_ip_bgp_ipv4_prefix_longer_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M longer-prefixes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Display route and more specific routes\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_prefix_longer (vty, argv[1], qafx,
                                                   bgp_show_type_prefix_longer);
}

DEFUN (show_ip_bgp_flap_address,
       show_ip_bgp_flap_address_cmd,
       "show ip bgp flap-statistics A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                                    bgp_show_type_flap_address);
}

DEFUN (show_ip_bgp_flap_prefix,
       show_ip_bgp_flap_prefix_cmd,
       "show ip bgp flap-statistics A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv4_unicast,
                                 bgp_show_type_flap_prefix);
}
#ifdef HAVE_IPV6
DEFUN (show_bgp_prefix_longer,
       show_bgp_prefix_longer_cmd,
       "show bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_unicast,
                                 bgp_show_type_prefix_longer);
}

ALIAS (show_bgp_prefix_longer,
       show_bgp_ipv6_prefix_longer_cmd,
       "show bgp ipv6 X:X::X:X/M longer-prefixes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n"
       "Display route and more specific routes\n")

/* old command */
DEFUN (show_ipv6_bgp_prefix_longer,
       show_ipv6_bgp_prefix_longer_cmd,
       "show ipv6 bgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_unicast,
                                 bgp_show_type_prefix_longer);
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix_longer,
       show_ipv6_mbgp_prefix_longer_cmd,
       "show ipv6 mbgp X:X::X:X/M longer-prefixes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Display route and more specific routes\n")
{
  return bgp_show_prefix_longer (vty, argv[0], qafx_ipv6_multicast,
                                 bgp_show_type_prefix_longer);
}
#endif /* HAVE_IPV6 */

/*==============================================================================
 * Display routes for given prefix/address.
 *
 */
static void bgp_show_route_header (vty vty, bgp_rib rib, bgp_lc_id_t lc,
                           bgp_rib_node rn, prefix_id_entry pie, vector rv,
                                                               route_info ris) ;

static void bgp_show_route_detail (vty vty, bgp_rib rib, bgp_lc_id_t lc,
                          prefix_id_entry pie, route_info ri, route_info ris) ;


#if 0


static int
bgp_show_route_in_table (vty vty, bgp_inst bgp, bgp_rib rib,
                         chs_c ip_str,
                         qafx_t qafx, struct prefix_rd *prd,
                         bool prefix_check)
{
  bgp_inst       bgp ;
  vector         rv ;
  vector_index_t i, l ;
  bool header ;

  prefix_t  match;

  int ret;
  int header;
  int display = 0;
  struct bgp_node *rn;
  struct bgp_node *rm;
  struct bgp_info *ri;
  struct bgp_table *table;

  /* Check IP address argument.
   */
  ret = str2prefix (ip_str, &match);
  if (! ret)
    {
      vty_out (vty, "%% address is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (qafx_is_mpls_vpn(qafx))
    {
      for (rn = bgp_table_top (rib); rn; rn = bgp_route_next (rn))
        {
          if (prd && memcmp (rn->p.u.val, prd->val, 8) != 0)
            continue;

          if ((table = rn->info) != NULL)
            {
              header = 1;

              if ((rm = bgp_node_match (table, &match)) != NULL)
                {
                  if (prefix_check && rm->p.prefixlen == match.prefixlen)
                    {
                      for (ri = rm->info; ri; ri = ri->info.next)
                        {
                          if (header)
                            {
                              bgp_show_route_header (vty, bgp, rm,
                                                  (struct prefix_rd *)&rn->p,
                                                                         qafx);

                              header = 0;
                            }
                          display++;
                          bgp_show_route_detail (vty, bgp, &rm->p, ri, qafx);
                        }
                    }

                  bgp_unlock_node (rm);
                }
            }
        }
    }
  else
    {
      header = 1;

      if ((rn = bgp_node_match (rib, &match)) != NULL)
        {
          if (! prefix_check || rn->p.prefixlen == match.prefixlen)
            {
              for (ri = rn->info; ri; ri = ri->info.next)
                {
                  if (header)
                    {
                      bgp_show_route_header (vty, bgp, rn, NULL, qafx);
                      header = 0;
                    }
                  display++;
                  bgp_show_route_detail (vty, bgp, &rn->p, ri, qafx);
                }
            }

          bgp_unlock_node (rn);
        }
    }

  if (! display)
    {
      vty_out (vty, "%% Network not in table%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  return CMD_SUCCESS;
}
#endif

/*------------------------------------------------------------------------------
 * Display routes for given prefix/address.
 *
 *   1) prefix/address is:
 *
 *       a) prefix -- which requires an exact match
 *
 *          Except for (2b), this is a straight look-up.
 *
 *       b) address -- which requires longest prefix match
 *
 *          Except for (2b), this is a repeated look-up, for reducing prefix
 *          length -- looking for prefix with at least one route.
 *
 *   2) for MPLS prefix/address:
 *
 *       a) with the given Route Discriminator
 *
 *          Which can be done by direct lookup as in (1).
 *
 *       b) for all Route Discriminators
 *
 *          Which requires a scan of the RIB to extract all routes which match
 *          the required route.  With (1b) the scan needs to generate a list
 *          of matches, in descending prefix length order.
 *
 *   3) from given RIB:
 *
 *       a) Main RIB -- which requires the routes after 'in' filtering.
 *
 *          So can simply lookup in the Main RIB.
 *
 *       b) RS RIB, for the given RS Client -- which requires the routes
 *          after 'rs-in' and 'export' and 'import' filtering.
 *
 *          Can lookup in the RS RIB, but must then run the filters to
 *          get the available routes for the given Client.
 *
 *          For (1b) it is possible that the longest prefix has no available
 *          routes after the filtering.
 *
 * Requires: view_name:    name of BGP instance -- NULL => "default"
 *           client_str:   NULL => Main RIB, otherwise "name" of RS Client
 *           qafx:         what sort of address/prefix
 *           ip_str:       address/prefix in question
 *           prefix:       true <=> ip_str is prefix, false <=> is address
 *           prd:          if MPLS qafx: NULL => all RD, otherwise RD.
 */
static cmd_ret_t
bgp_show_route (vty vty, chs_c view_name, chs_c client_name,
                           qafx_t qafx, chs_c ip_str, bool prefix,
                                                             chs_c rd_str)
{
  bgp_run     brun ;
  bgp_rib     rib ;
  bgp_prun    client ;
  prefix_t    pfx[1] ;
  prefix_rd_t prd[1] ;
  bool        is_mpls ;
  vector      rdv, rv ;
  vector_index_t  i ;
  bgp_lc_id_t    lc ;

  /* Lookup either the brun/rib or client/brun/rib.
   */
  if (client_name == NULL)
    {
      brun = bgp_run_lookup_vty(vty, view_name) ;
      if (brun == NULL)
        return CMD_WARNING ;

      client = NULL ;
      lc     = lc_view_id ;
    }
  else
    {
      client = prun_lookup_view_qafx_vty(vty, view_name, client_name, qafx) ;
      if (client == NULL)
        return CMD_WARNING;

      if (!client->prib[qafx]->rp.is_route_server_client)
        {
          vty_out (vty, "%% Neighbor is not a Route-Server client\n") ;
          return CMD_WARNING;
        } ;

      brun = client->brun ;
      lc = client->prib[qafx]->lc_id ;
    } ;

  rib = brun->rib[qafx] ;
  if (rib == NULL)
    {
      vty_out (vty, "%% No RIB for address family\n") ;
      return CMD_WARNING;
    } ;

  /* Convert rd_str (if any) to prefix_rd.
   *
   * NB: expect that for non-mpls qafx that no rd_str will be presented, but
   *     if one is presented, it will be checked.
   */
  if (rd_str != NULL)
    {
      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING ;
    } ;

  /* Fill in prefix, checking the IP address/prefix argument.
   */
  if (!str2prefix (ip_str, pfx))
    {
      vty_out (vty, "%% address is malformed\n") ;
      return CMD_WARNING;
    }

  /* Worry about the Route Discriminator, if any
   *
   * Constructs the vector rdv:
   *
   *   * if not mpls: contains one entry == NULL <=> no RD
   *
   *   * if mpls and want all RDs:  contains the prefix_rd_id_entry for each RD
   *                                known to exist in the RIB.
   *
   *                                May be empty !
   *
   *   * if mpls and want given RD: contains the prefix_rd_id_entry for the
   *                                given RD, iff it is known to exist in the
   *                                RIB.
   *
   *                                May be empty !
   */
  is_mpls = qafx_is_mpls_vpn(qafx) ;

  if (is_mpls)
    {
      if (rd_str == NULL)
        {
          /* Get list of prefix_rd_id_entry known to this RIB, in RD order.
           */
          rdv = bgp_rib_rd_extract(rib) ;
        }
      else
        {
          /* If the given RD is known to the RIB, get its prefix_rd_id_entry
           * and create one entry list.
           *
           * Otherwise, create an empty list.
           */
          prefix_rd_id_entry rdie ;

          rdie = bgp_rib_rd_seek(rib, prd) ;

          if (rdie == NULL)
            rdv = vector_new(0) ;
          else
            {
              rdv = vector_new(1) ;
              vector_push_item(rdv, rdie) ;
            } ;
        } ;
    }
  else
    {
      rdv = vector_new(1) ;
      vector_push_item(rdv, NULL) ;
    } ;

  /* So, now we run all the Route Discriminators, and for each one, extract
   * a list of available routes, which are sorted into order and then output.
   */
  rv = NULL ;           /* no routes, yet       */

  for (i = 0 ; i < vector_length(rdv) ; ++i)
    {
      prefix_rd_id_entry rdie ;
      prefix_t        find[1] ;
      bgp_rib_node    rn ;
      route_info      ris, ri ;
      prefix_id_entry pie ;
      vector_index_t  j ;

      /* Prepare 'find' to search for the given prefix or for the longest match
       * for the given address.
       *
       * If we have more than one RD, we start the process afresh for each one.
       */
      rdie = vector_get_item(rdv, i) ;

      *find = *pfx ;
      if (rdie != NULL)
        find->rd_id = rdie->id ;
      else
        find->rd_id = prefix_rd_id_null ;

      /* This loops (if not prefix) in order to find longest match which
       * provides at least one route.
       *
       * The RIB can only be looked up for an exact prefix match, for an exact
       * RD.  This is why we arrange to try only the RD which we know are
       * present in the RIB.  To find the longest match for an address, we
       * try the maximum length prefix first, and then reduce to 0 !
       */
      while (1)
        {
          apply_mask(find) ;

          pie = prefix_id_seek_entry(find) ;

          if (pie == NULL)
            {
              rn  = NULL ;
              ris = NULL ;
            }
          else
            {
              rn = ihash_get_item(rib->nodes_table, pie->id, NULL) ;

              if ((rn != NULL) && (lc < rn->local_context_count))
                ris = svs_head(rn->aroutes[lc].base, rn->avail) ;
              else
                ris = NULL ;
            } ;

          if (prefix || (find->prefixlen == 0))
            break ;

          find->prefixlen -= 1 ;
        } ;

      if (ris == NULL)
        continue ;              /* nothing for this RD (if any) */

      /* We have at least one route for this RD.
       *
       * Collect the routes and sort into...
       */
      rv = vector_re_init(rv, 12) ;
      ri = ris ;

      do
        {
          vector_push_item(rv, ri) ;
          ri = svs_next(ri->iroutes[lc].list, rn->avail) ;
        }
      while (ri != NULL) ;

/* TODO: sort prefixes before showing routes            */
#if 0
      vector_sort(rv, bgp_show_route_sort) ;
#endif

      qassert(vector_length(rv) != 0) ;

      /* Now output the header which describes the prefix, followed by all the
       * available routes.
       */
      bgp_show_route_header (vty, rib, lc, rn, pie, rv, ris) ;

      for (j = 0 ; j < vector_length(rv) ; ++j)
        {
          ri = vector_get_item(rv, j) ;

          bgp_show_route_detail (vty, rib, lc, pie, ri, ris) ;
        } ;
    } ;

  return CMD_SUCCESS ;
} ;

/*------------------------------------------------------------------------------
 * Header of detailed BGP route information -- one per Route Discriminator
 */
static void
bgp_show_route_header (vty vty, bgp_rib rib, bgp_lc_id_t lc, bgp_rib_node rn,
                                 prefix_id_entry pie, vector rv, route_info ris)
{
  bgp_prib prib ;
  bool announced ;

  vty_out (vty, "BGP routing table entry for ") ;
  if (qafx_is_mpls_vpn(rib->qafx))
    vty_out (vty, "%s:", srdtoa(prefix_rd_id_get_val(pie->pfx->rd_id)).str) ;
  vty_out(vty, "%s\n", spfxtoa(pie->pfx).str) ;

  vty_out (vty, "Paths: (%u available", vector_length(rv)) ;

  if (ris != NULL)
    {
      vector_index_t i ;
      uint best ;
      bool suppress ;
      attr_community_state_t known ;

      suppress = false ;
      known    = 0 ;
      best     = 0 ;

      best = 0 ;
      for (i = 0 ; i < vector_length(rv) ; ++i)
        {
          if (ris == vector_get_item(rv, i))
            {
              best = i + 1 ;
              break ;
            } ;
        } ;

      if (best == 0)
        ris = NULL ;
      else
        {
          attr_set attr ;

          if (lc < ris->local_context_count)
            attr = ris->iroutes[lc].attr ;
          else
            attr = NULL ;

          vty_out (vty, ", best #%u", best) ;

          if (qafx_is_unicast(rib->qafx))
            vty_out (vty, ", table Default-IP-Routing-Table");

          if (attr != NULL)
            known = attr_community_known (attr->community) ;
          else
            known = false ;

          if (known & cms_no_advertise)
            vty_out (vty, ", not advertised to any peer");
          else if (known & cms_no_export)
            vty_out (vty, ", not advertised to EBGP peer");
          else if (known & cms_local_as)
            vty_out (vty, ", not advertised outside local AS");

          if (suppress)
            vty_out (vty, ", Advertisements suppressed by an aggregate.");
        } ;
    } ;

  if (ris == NULL)
    vty_out (vty, ", no best path") ;

  vty_out (vty, ")\n");

  /* Advertised to Peer(s) or Client(s)
   */
  announced = false ;

  for (prib = ddl_head(rib->pribs) ; // TODO sort rib->known_peers !
       prib != NULL ;
       prib = ddl_next(prib, prib_list))
    {
      adj_out_ptr_t ao ;

      if (prib->lc_id != lc)
        continue ;

      ao = bgp_adj_out_lookup(prib, pie->id) ;

      if (bgp_adj_out_attr(prib, ao) != NULL)
        {
          if (! announced)
            {
              vty_out (vty, "  Advertised to non peer-group peers:\n ") ;
              announced = true ;
            } ;

          vty_out (vty, " %s", sutoa(&prib->prun->rp.cops_conf.remote_su).str);
        } ;
    } ;

  if (announced)
    vty_out (vty, "\n");
  else
    vty_out (vty, "  Not advertised to any peer\n") ;
} ;

/*------------------------------------------------------------------------------
 * Body of detailed BGP route information -- one per route
 */
static void
bgp_show_route_detail (vty vty, bgp_rib rib, bgp_lc_id_t lc,
                            prefix_id_entry pie, route_info ri, route_info ris)
{
  attr_set attr ;
  time_t tbuf ;

  if (lc >= ri->local_context_count)
    return ;

  attr = ri->iroutes[lc].attr ;
  if (attr == NULL)
    return ;

  /* Line1 display AS-path, Aggregator
   */
  route_vty_out_as_path (vty, "  %s", attr->asp, "  Local");

  if (ri->current.flags & RINFO_REMOVED)
    vty_out (vty, ", (removed)");
  if (ri->current.flags & RINFO_STALE)
    vty_out (vty, ", (stale)");

  if (attr->aggregator_as != BGP_ASN_NULL)
    vty_out (vty, ", (aggregated by %u %s)", attr->aggregator_as,
                                siptoa(AF_INET, &attr->aggregator_ip).str);

  if (ri->prib->rp.is_route_reflector_client)
    vty_out (vty, ", (Received from a RR-client)");

  if (ri->prib->rp.is_route_server_client)
    vty_out (vty, ", (Received from a RS-client)");

  if (ri->current.flags & RINFO_HISTORY)
    vty_out (vty, ", (history entry)");
  else if (ri->current.flags & RINFO_DAMPED)
    vty_out (vty, ", (suppressed due to damping)");

  vty_out (vty, "\n");

  /* Line2 display Next-hop, Neighbor, Router-id
   */
  if (pie->pfx->family == AF_INET)
    {
      vty_out (vty, "    %s", siptoa(AF_INET, &attr->next_hop.ip.v4).str) ;
    }
#ifdef HAVE_IPV6
  else
    {
       vty_out (vty, "    %s",
             siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_global]).str) ;
    }
#endif /* HAVE_IPV6 */

  if (ri->prib->prun == rib->brun->prun_self)
    {
      vty_out (vty, " from %s (%s)",
                        pie->pfx->family == AF_INET ? "0.0.0.0" : "::",
                                 siptoa(AF_INET, &rib->brun->rp.router_id).str);
    }
  else
    {
      in_addr_t  originator ;

/* TODO  IGP Metric Stuff               */
#if 0
      if (! (ri->flags & RINFO_VALID))
        vty_out (vty, " (inaccessible)");
      else if ((ri->extra != NULL) && (ri->extra->igpmetric))
        vty_out (vty, " (metric %d)", ri->extra->igpmetric);
#endif

      if (attr->have & atb_originator_id)
        originator = attr->originator_id ;
      else
        originator = ri->prib->prun->rp.sargs_conf.remote_id ;

      vty_out (vty, " from %s (%s)", ri->prib->prun->name,
                                        siptoa(AF_INET, &originator).str) ;
    }
  vty_out (vty, "\n");

#ifdef HAVE_IPV6
  /* display nexthop local */
  if (attr->next_hop.type == nh_ipv6_2)
    {
      vty_out (vty, "    (%s)\n",
             siptoa(AF_INET6, &attr->next_hop.ip.v6[in6_link_local]).str) ;
    }
#endif /* HAVE_IPV6 */

  /* Line 3 display:
   *  Origin, Med, Locpref, Weight, valid, Int/Ext/Local, Atomic, best
   */
  vty_out (vty, "      Origin %s",
                        map_direct(bgp_origin_long_map, attr->origin).str) ;

  if (attr->have & atb_med)
    vty_out (vty, ", metric %u", attr->med);

  vty_out (vty, ", localpref %u%s", attr->local_pref,
                             (attr->have & atb_local_pref) ? "" : "(default)");

  if (attr->weight != 0)
    vty_out (vty, ", weight %u", attr->weight);

  if (! (ri->current.flags & RINFO_HISTORY))
    vty_out (vty, ", valid");

  if (ri->prib->prun != rib->brun->prun_self)
    {
      chs_c sort_str ;

      switch (ri->prib->prun->rp.sort)
      {
        case BGP_PEER_IBGP:
          sort_str = "internal" ;
          break ;

        case BGP_PEER_CBGP:
          sort_str = "confed-external" ;
          break ;

        case BGP_PEER_EBGP:
          sort_str = "external" ;
          break ;

        case BGP_PEER_UNSPECIFIED:
        default:
          sort_str = "*unknown-sort:BUG*" ;
          break ;
      } ;

      vty_out (vty, ", %s", sort_str) ;
    }
  else if (bgp_route_subtype(ri->current.route_type) == BGP_ROUTE_AGGREGATE)
    vty_out (vty, ", aggregated, local");
  else if (bgp_zebra_route(ri->current.route_type) != ZEBRA_ROUTE_BGP)
    vty_out (vty, ", sourced");
  else
    vty_out (vty, ", sourced, local");

  if (attr->have & atb_atomic_aggregate)
    vty_out (vty, ", atomic-aggregate");

  if (ri == ris)
    vty_out (vty, ", best");

  vty_out (vty, "\n");

  /* Line 4 display Community
   */
  if (attr->community != NULL)
    vty_out (vty, "      Community: %s\n",
                                     attr_community_str(attr->community)) ;

  /* Line 5 display Extended-community
   */
  if (attr->ecommunity != NULL)
    vty_out (vty, "      Extended Community: %s\n",
                                    attr_ecommunity_str(attr->ecommunity));

  /* Line 6 display Originator, Cluster-id
   */
  if ((attr->have & atb_originator_id) || (attr->cluster != NULL))
    {
      chs_c str ;

      vty_out (vty, "      Originator: %s",
                  (attr->have & atb_originator_id)
                             ? siptoa(AF_INET, &attr->originator_id).str
                             : "-none-") ;

      str = attr_cluster_str(attr->cluster) ;

      if (*str != '\0')
        vty_out (vty, ", Cluster list: %s", str);

      vty_out (vty, "\n");
    } ;

/* TODO: reconstruct Route Flap Damping         */
#if 0
  /* Line ? Route Flap damping
   */
  if ((ri->extra != NULL) && (ri->extra->damp_info))
    bgp_damp_info_vty (vty, ri);
#endif

  /* Line 7 display Uptime
   */
  tbuf = bgp_wall_clock(ri->uptime);
  vty_out (vty, "      Last update: %s\n", ctime(&tbuf));
} ;

DEFUN (show_ip_bgp_route,
       show_ip_bgp_route_cmd,
       "show ip bgp A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_ipv4_route,
       show_ip_bgp_ipv4_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_ipv4_route,
       show_bgp_ipv4_safi_route_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_vpnv4_all_route,
       show_ip_bgp_vpnv4_all_route_cmd,
       "show ip bgp vpnv4 all A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_vpnv4_rd_route,
       show_ip_bgp_vpnv4_rd_route_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             argv[0]) ;         /* Route Disc.          */
}

DEFUN (show_ip_bgp_prefix,
       show_ip_bgp_prefix_cmd,
       "show ip bgp A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_ipv4_prefix,
       show_ip_bgp_ipv4_prefix_cmd,
       "show ip bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_ipv4_prefix,
       show_bgp_ipv4_safi_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_ip_bgp_vpnv4_all_prefix,
       show_ip_bgp_vpnv4_all_prefix_cmd,
       "show ip bgp vpnv4 all A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_vpnv4_rd_prefix,
       show_ip_bgp_vpnv4_rd_prefix_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_mpls_vpn,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             argv[0]) ;         /* Route Disc.          */
}

DEFUN (show_ip_bgp_view_route,
       show_ip_bgp_view_route_cmd,
       "show ip bgp view WORD A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_ip_bgp_view_prefix,
       show_ip_bgp_view_prefix_cmd,
       "show ip bgp view WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv4_unicast,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

#ifdef HAVE_IPV6

DEFUN (show_bgp_route,
       show_bgp_route_cmd,
       "show bgp X:X::X:X",
       SHOW_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_route,
       show_bgp_ipv6_route_cmd,
       "show bgp ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_ipv6_safi_route,
       show_bgp_ipv6_safi_route_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Network in the BGP routing table to display\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_bgp_route,
       show_ipv6_bgp_route_cmd,
       "show ipv6 bgp X:X::X:X",
       SHOW_STR
       IP_STR
       BGP_STR
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_bgp_prefix,
       show_bgp_prefix_cmd,
       "show bgp X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_prefix,
       show_bgp_ipv6_prefix_cmd,
       "show bgp ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "IPv6 prefix <network>/<length>\n")

DEFUN (show_bgp_ipv6_safi_prefix,
       show_bgp_ipv6_safi_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_bgp_prefix,
       show_ipv6_bgp_prefix_cmd,
       "show ipv6 bgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

DEFUN (show_bgp_view_route,
       show_bgp_view_route_cmd,
       "show bgp view WORD X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Network in the BGP routing table to display\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[1],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_route,
       show_bgp_view_ipv6_route_cmd,
       "show bgp view WORD ipv6 X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_prefix,
       show_bgp_view_prefix_cmd,
       "show bgp view WORD X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "IPv6 prefix <network>/<length>\n")
{
  return bgp_show_route(vty, argv[0],           /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_unicast,
                             argv[1],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_prefix,
       show_bgp_view_ipv6_prefix_cmd,
       "show bgp view WORD ipv6 X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "IPv6 prefix <network>/<length>\n")

/* old command */
DEFUN (show_ipv6_mbgp_route,
       show_ipv6_mbgp_route_cmd,
       "show ipv6 mbgp X:X::X:X",
       SHOW_STR
       IP_STR
       MBGP_STR
       "Network in the MBGP routing table to display\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_multicast,
                             argv[0],           /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

/* old command */
DEFUN (show_ipv6_mbgp_prefix,
       show_ipv6_mbgp_prefix_cmd,
       "show ipv6 mbgp X:X::X:X/M",
       SHOW_STR
       IP_STR
       MBGP_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return bgp_show_route(vty, NULL,              /* bgp view             */
                             NULL,              /* RS Client            */
                             qafx_ipv6_multicast,
                             argv[0],           /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_view_rsclient_route_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  chs_c view_name, client_str, ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv4_unicast,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_view_rsclient_route,
       show_ip_bgp_rsclient_route_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_view_ipv4_safi_rsclient_route_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                          "rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  chs_c view_name, um_arg, client_str, ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_route,
       show_bgp_ipv4_safi_rsclient_route_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) A.B.C.D",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_view_rsclient_prefix_cmd,
       "show ip bgp view WORD rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  chs_c view_name, client_str, ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv4_unicast,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_ip_bgp_view_rsclient_prefix,
       show_ip_bgp_rsclient_prefix_cmd,
       "show ip bgp rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

DEFUN (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_view_ipv4_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  chs_c view_name, um_arg, client_str, ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv4_safi_rsclient_prefix,
       show_bgp_ipv4_safi_rsclient_prefix_cmd,
       "show bgp ipv4 (unicast|multicast) "
                                        "rsclient (A.B.C.D|X:X::X:X) A.B.C.D/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")

#ifdef HAVE_IPV6

DEFUN (show_bgp_view_rsclient_route,
       show_bgp_view_rsclient_route_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  chs_c view_name, client_str, ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv6_unicast,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_rsclient_route,
       show_bgp_rsclient_route_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_view_ipv6_safi_rsclient_route_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) "
                                         "rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")
{
  chs_c view_name, um_arg, client_str, ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             false,             /* address (not prefix) */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_route,
       show_bgp_ipv6_safi_rsclient_route_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X) X:X::X:X",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "Network in the BGP routing table to display\n")

DEFUN (show_bgp_view_rsclient_prefix,
       show_bgp_view_rsclient_prefix_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  chs_c view_name, client_str, ip_str ;

  if (argc == 3)
    {
      view_name  = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }
  else
    {
      view_name  = NULL ;
      client_str = argv[0] ;
      ip_str     = argv[1] ;
    }

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx_ipv6_unicast,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_rsclient_prefix,
       show_bgp_rsclient_prefix_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")

DEFUN (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_view_ipv6_safi_rsclient_prefix_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  chs_c   view_name, um_arg, client_str, ip_str ;
  qafx_t  qafx ;

  if (argc == 4)
    {
      view_name  = argv[0] ;
      um_arg     = argv[1] ;
      client_str = argv[2] ;
      ip_str     = argv[3] ;
    }
  else
    {
      view_name  = NULL ;
      um_arg     = argv[0] ;
      client_str = argv[1] ;
      ip_str     = argv[2] ;
    }

  qafx = qafx_from_q(qAFI_IP, (*um_arg == 'm') ? qSAFI_Multicast
                                               : qSAFI_Unicast) ;

  return bgp_show_route(vty, view_name,         /* bgp view             */
                             client_str,        /* RS Client            */
                             qafx,
                             ip_str,            /* address/prefix       */
                             true,              /* prefix               */
                             NULL) ;            /* no Route Disc.       */
}

ALIAS (show_bgp_view_ipv6_safi_rsclient_prefix,
       show_bgp_ipv6_safi_rsclient_prefix_cmd,
       "show bgp ipv6 (unicast|multicast) "
                                       "rsclient (A.B.C.D|X:X::X:X) X:X::X:X/M",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR
       "IP prefix <network>/<length>, e.g., 3ffe::/16\n")

#endif /* HAVE_IPV6 */

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 *
 */
static void
show_adj_route (vty vty, bgp_prun prun, qafx_t qafx, bool in)
{
  bgp_prib    prib ;
  urlong      output_count;
  bool        header1, header2 ;
  bgp_run     brun;

  brun = prun->brun;

  if (brun == NULL)
    return;

  prib = prun->prib[qafx] ;
  if (prib == NULL)
    return ;

  header1 = header2 = true ;
  output_count = 0;

  if (!in && prib->rp.do_default_originate)
    {
      vty_out (vty, "BGP table version is 0, local router ID is %s\n",
                                      siptoa(AF_INET, &brun->rp.router_id).str);
      vty_out (vty, BGP_SHOW_SCODE_HEADER);
      vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");

      vty_out (vty, "Originating default network 0.0.0.0\n\n");
      header1 = false ;
    }

  if (in)
    {
      ihash_walker_t walk[1] ;
      route_info  ri ;

      ihash_walk_start(prib->adj_in, walk) ;
      while ((ri = ihash_walk_next(walk, NULL)) != NULL)
        {
          prefix_id_entry pie ;

          if (ri->current.flags & (RINFO_REFUSED | RINFO_WITHDRAWN))
            continue ;

          if (header1)
            {
              vty_out (vty, "BGP table version is 0, local router ID is %s\n",
                                     siptoa(AF_INET, &brun->rp.router_id).str) ;
              vty_out (vty, BGP_SHOW_SCODE_HEADER);
              vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");
              header1 = false;
            } ;

          if (header2)
            {
              vty_out (vty, BGP_SHOW_HEADER);
              header2 = false ;
            } ;

          pie = prefix_id_get_entry(ri->pfx_id) ;

          route_vty_out_tmp (vty, pie->pfx, ri->current.attr, prib->qafx);
          output_count++;
        } ;
    }
  else
    {
      ihash_walker_t walk[1] ;
      adj_out_ptr_t  ao ;

      ihash_walk_start(prib->adj_out, walk) ;
      while ((ao.anon = ihash_walk_next(walk, NULL)) != NULL)
        {
          prefix_id_entry pie ;
          attr_set  attr ;

          attr = bgp_adj_out_attr(prib, ao) ;
          if (attr == NULL)
            continue ;

          if (header1)
            {
              vty_out (vty, "BGP table version is 0, local router ID is %s\n",
                                      siptoa(AF_INET, &brun->rp.router_id).str);
              vty_out (vty, BGP_SHOW_SCODE_HEADER);
              vty_out (vty, BGP_SHOW_OCODE_HEADER "\n");
              header1 = false;
            }
          if (header2)
            {
              vty_out (vty, BGP_SHOW_HEADER);
              header2 = false;
            } ;

          pie  = prefix_id_get_entry(walk->self) ;

          route_vty_out_tmp (vty, pie->pfx, attr, prib->qafx);
          output_count++;
        } ;
    } ;

  if (output_count != 0)
    vty_out (vty, "\nTotal number of prefixes %"fRL"u\n", output_count);
}

static int
peer_adj_routes (vty vty, chs_c view_name, chs_c peer_name, qafx_t qafx,
                                                                        bool in)
{
  bgp_prun prun ;

  prun = prun_lookup_view_qafx_vty (vty, view_name, peer_name, qafx);
  if (prun == NULL)
    return CMD_WARNING;

  if (in && !prun->prib[qafx]->rp.do_soft_reconfig)
    {
      vty_out (vty, "%% Inbound soft reconfiguration not enabled\n");
      return CMD_WARNING;
    }

  show_adj_route (vty, prun, qafx, in);

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_view_neighbor_advertised_route_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    } ;

  return peer_adj_routes (vty, view_name, peer_name, qafx_ipv4_unicast,
                                                               false /* out */);
}

ALIAS (show_ip_bgp_view_neighbor_advertised_route,
       show_ip_bgp_neighbor_advertised_route_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_advertised_route,
       show_ip_bgp_ipv4_neighbor_advertised_route_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  qafx_t qafx ;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return peer_adj_routes (vty, NULL, argv[1], qafx, false /* out */);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_neighbor_advertised_route_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    } ;

  return peer_adj_routes (vty, view_name, peer_name, qafx_ipv6_unicast,
                                                               false /* out */);
}

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_view_ipv6_neighbor_advertised_route_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

DEFUN (show_bgp_view_neighbor_received_routes,
       show_bgp_view_neighbor_received_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    } ;

  return peer_adj_routes (vty, view_name, peer_name, qafx_ipv6_unicast,
                                                                 true /* in */);
}

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_view_ipv6_neighbor_received_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_neighbor_advertised_route_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

ALIAS (show_bgp_view_neighbor_advertised_route,
       show_bgp_ipv6_neighbor_advertised_route_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_advertised_route,
       ipv6_bgp_neighbor_advertised_route_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_advertised_route,
       ipv6_mbgp_neighbor_advertised_route_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) advertised-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return peer_adj_routes (vty, NULL, argv[0], qafx_ipv6_multicast,
                                                               false /* out */);
}
#endif /* HAVE_IPV6 */

DEFUN (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_view_neighbor_received_routes_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    } ;

  return peer_adj_routes (vty, view_name, peer_name, qafx_ipv4_unicast,
                                                                 true /* in */);
}

ALIAS (show_ip_bgp_view_neighbor_received_routes,
       show_ip_bgp_neighbor_received_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_ip_bgp_ipv4_neighbor_received_routes,
       show_ip_bgp_ipv4_neighbor_received_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  qafx_t qafx ;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return peer_adj_routes (vty, NULL, argv[1], qafx, true /* in */);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) "
            "neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
#else
DEFUN (show_bgp_view_afi_safi_neighbor_adv_recd_routes,
       show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) "
            "neighbors (A.B.C.D|X:X::X:X) (advertised-routes|received-routes)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address family modifier\n"
       "Address family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the advertised routes to neighbor\n"
       "Display the received routes from neighbor\n")
#endif
{
  chs_c view_name, ip_name, um_str, peer_name, dir_name ;
  bool in;
  qafx_t qafx ;

  view_name = argv[0] ;

#ifdef HAVE_IPV6
  ip_name   = argv[1] ;
  um_str    = argv[2] ;
  peer_name = argv[3] ;
  dir_name  = argv[4] ;
#else
  ip_name   = "ipv4" ;
  um_str    = argv[1] ;
  peer_name = argv[2] ;
  dir_name  = argv[3] ;
#endif

  if (strncmp (ip_name, "ipv6", 4) == 0)
    qafx = (um_str[0] == 'm') ? qafx_ipv6_multicast
                              : qafx_ipv6_unicast ;
  else
    qafx = (um_str[0] == 'm') ? qafx_ipv4_multicast
                              : qafx_ipv4_unicast ;

  in = (dir_name[0] == 'r') ;

  return peer_adj_routes (vty, view_name, peer_name, qafx, in) ;
}

DEFUN (show_ip_bgp_neighbor_received_prefix_filter,
       show_ip_bgp_neighbor_received_prefix_filter_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  bgp_prun    prun;
  int count;

  prun = prun_lookup_view_qafx_vty (vty, NULL, argv[0], qafx_ipv4_unicast);
  if (prun == NULL)
    return CMD_WARNING;

  prefix_bgp_orf_name_set(name, &prun->rp.cops_conf.remote_su, qafx_ipv4_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count != 0)
    {
      vty_out (vty, "Address family: IPv4 Unicast\n");
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_neighbor_received_prefix_filter,
       show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd,
       "show ip bgp ipv4 (unicast|multicast) "
                          "neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  bgp_prun     prun;
  qafx_t       qafx ;
  chs_c        tag ;
  int count;

  if (argv[0][0] == 'm')
    {
      qafx = qafx_ipv4_multicast ;
      tag  = "Multicast" ;
    }
  else
    {
      qafx = qafx_ipv4_unicast ;
      tag  = "Unicast" ;
    } ;

  prun = prun_lookup_view_qafx_vty (vty, NULL, argv[1], qafx);
  if (prun == NULL)
    return CMD_WARNING;

  prefix_bgp_orf_name_set(name, &prun->rp.cops_conf.remote_su, qafx) ;
  count =  prefix_bgp_show_prefix_list (NULL, name);

  if (count != 0)
    {
      vty_out (vty, "Address family: IPv4 %s\n", tag);
      prefix_bgp_show_prefix_list (vty, name);
    } ;

  return CMD_SUCCESS;
}


#ifdef HAVE_IPV6
ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_neighbor_received_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

ALIAS (show_bgp_view_neighbor_received_routes,
       show_bgp_ipv6_neighbor_received_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

DEFUN (show_bgp_neighbor_received_prefix_filter,
       show_bgp_neighbor_received_prefix_filter_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  bgp_prun    prun;
  int count;

  prun = prun_lookup_view_qafx_vty (vty, NULL, argv[0], qafx_ipv6_unicast);
  if (prun == NULL)
    return CMD_WARNING;

  prefix_bgp_orf_name_set(name, &prun->rp.cops_conf.remote_su,
                                                            qafx_ipv6_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast\n");
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_neighbor_received_prefix_filter,
       show_bgp_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")

/* old command */
ALIAS (show_bgp_view_neighbor_received_routes,
       ipv6_bgp_neighbor_received_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_received_routes,
       ipv6_mbgp_neighbor_received_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) received-routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the received routes from neighbor\n")
{
  return peer_adj_routes (vty, NULL, argv[0], qafx_ipv6_multicast,
                                                                 true /* in */);
}

DEFUN (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")
{
  bgp_orf_name name ;
  bgp_prun    prun;
  int count;

  prun = prun_lookup_view_qafx_vty (vty, argv[0], argv[1], qafx_ipv6_unicast);
  if (prun == NULL)
    return CMD_WARNING;

  prefix_bgp_orf_name_set(name, &prun->rp.cops_conf.remote_su,
                                                            qafx_ipv6_unicast) ;

  count =  prefix_bgp_show_prefix_list (NULL, name);
  if (count)
    {
      vty_out (vty, "Address family: IPv6 Unicast\n");
      prefix_bgp_show_prefix_list (vty, name);
    }

  return CMD_SUCCESS;
}

ALIAS (show_bgp_view_neighbor_received_prefix_filter,
       show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) received prefix-filter",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display information received from a BGP neighbor\n"
       "Display the prefixlist filter\n")

#endif /* HAVE_IPV6 */

/*------------------------------------------------------------------------------
 * Show routes for given prun --
 */
static int
bgp_show_neighbor_route (vty vty, chs_c view_name, chs_c peer_name, qafx_t qafx,
                                                        enum bgp_show_type type)
{
  bgp_prun prun ;
  sockunion_t  su_s ;
  sockunion    su ;

  prun = prun_lookup_view_qafx_vty (vty, view_name, peer_name, qafx);
  if (prun == NULL)
    return CMD_WARNING;

  /* Need a not-const copy of the su... such is life
   */
  su = sockunion_copy(&su_s, &prun->rp.cops_conf.remote_su) ;

  return bgp_show_brun(vty, prun->brun, qafx, lc_view_id, type, su) ;
}

DEFUN (show_ip_bgp_neighbor_routes,
       show_ip_bgp_neighbor_routes_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, NULL,  argv[0], qafx_ipv4_unicast,
                                                        bgp_show_type_neighbor);
}

DEFUN (show_ip_bgp_neighbor_flap,
       show_ip_bgp_neighbor_flap_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, NULL, argv[0], qafx_ipv4_unicast,
                                                   bgp_show_type_flap_neighbor);
}

DEFUN (show_ip_bgp_neighbor_damp,
       show_ip_bgp_neighbor_damp_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  return bgp_show_neighbor_route (vty, NULL, argv[0], qafx_ipv4_unicast,
                                                   bgp_show_type_damp_neighbor);
}

DEFUN (show_ip_bgp_ipv4_neighbor_routes,
       show_ip_bgp_ipv4_neighbor_routes_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  qafx_t qafx ;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return bgp_show_neighbor_route (vty, NULL, argv[1], qafx,
                                                        bgp_show_type_neighbor);
}

#ifdef HAVE_IPV6

DEFUN (show_bgp_view_neighbor_routes,
       show_bgp_view_neighbor_routes_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    } ;

  return bgp_show_neighbor_route (vty, view_name, peer_name, qafx_ipv6_unicast,
                                                        bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_view_ipv6_neighbor_routes_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

DEFUN (show_bgp_view_neighbor_damp,
       show_bgp_view_neighbor_damp_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    }
  return bgp_show_neighbor_route (vty, view_name, peer_name, qafx_ipv6_unicast,
                                                   bgp_show_type_damp_neighbor);
}

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_view_ipv6_neighbor_damp_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

DEFUN (show_bgp_view_neighbor_flap,
       show_bgp_view_neighbor_flap_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")
{
  chs_c view_name, peer_name ;

  if (argc == 2)
    {
      view_name = argv[0] ;
      peer_name = argv[1] ;
    }
  else
    {
      view_name = NULL ;
      peer_name = argv[0] ;
    }
  return bgp_show_neighbor_route (vty, view_name, peer_name, qafx_ipv6_unicast,
                                                   bgp_show_type_flap_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_view_ipv6_neighbor_flap_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_neighbor_routes_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")


ALIAS (show_bgp_view_neighbor_routes,
       show_bgp_ipv6_neighbor_routes_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
ALIAS (show_bgp_view_neighbor_routes,
       ipv6_bgp_neighbor_routes_cmd,
       "show ipv6 bgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")

/* old command */
DEFUN (ipv6_mbgp_neighbor_routes,
       ipv6_mbgp_neighbor_routes_cmd,
       "show ipv6 mbgp neighbors (A.B.C.D|X:X::X:X) routes",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_neighbor_route (vty, NULL, argv[0], qafx_ipv6_multicast,
                                                        bgp_show_type_neighbor);
}

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_neighbor_flap_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_flap,
       show_bgp_ipv6_neighbor_flap_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) flap-statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display flap statistics of the routes learned from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_neighbor_damp_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")

ALIAS (show_bgp_view_neighbor_damp,
       show_bgp_ipv6_neighbor_damp_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) dampened-routes",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display the dampened routes received from neighbor\n")


DEFUN (show_bgp_view_rsclient,
       show_bgp_view_rsclient_cmd,
       "show bgp view WORD rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  bgp_prun prun ;
  bgp_prib prib ;

  if (argc == 2)
    prun = prun_lookup_view_vty (vty, argv[0], argv[1]);
  else
    prun = prun_lookup_view_vty (vty, NULL, argv[0]);

  if (prun == NULL)
    return CMD_WARNING;

  prib = prun->prib[qafx_ipv6_unicast] ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first\n") ;
      return CMD_WARNING;
    }

  if (!prib->rp.is_route_server_client)
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client\n") ;
      return CMD_WARNING;
    }

  return bgp_show_table (vty, prib->rib, prib->lc_id,
                    prun->rp.sargs_conf.remote_id, bgp_show_type_normal, NULL) ;
}

ALIAS (show_bgp_view_rsclient,
       show_bgp_rsclient_cmd,
       "show bgp rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

DEFUN (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_view_ipv6_safi_rsclient_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "BGP view name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)
{
  bgp_prun prun;
  bgp_prib prib ;
  chs_c    um_arg ;
  qafx_t   qafx ;

  if (argc == 3)
    {
      prun = prun_lookup_view_vty (vty, argv[0], argv[2]);
      um_arg = argv[1] ;
    }
  else
    {
      prun = prun_lookup_view_vty (vty, NULL, argv[1]);
      um_arg = argv[0] ;
    }

  if (prun == NULL)
    return CMD_WARNING;

  qafx = qafx_from_q(qAFI_IP6, (*um_arg == 'm') ? qSAFI_Multicast
                                                : qSAFI_Unicast) ;

  prib = prun->prib[qafx] ;
  if (prib == NULL)
    {
      vty_out (vty, "%% Activate the neighbor for the address family first\n") ;
      return CMD_WARNING;
    }

  if (!prib->rp.is_route_server_client)
    {
      vty_out (vty, "%% Neighbor is not a Route-Server client\n");
      return CMD_WARNING;
    }

  return bgp_show_table (vty, prib->rib, prib->lc_id,
                    prun->rp.sargs_conf.remote_id, bgp_show_type_normal, NULL) ;
}

ALIAS (show_bgp_view_ipv6_safi_rsclient,
       show_bgp_ipv6_safi_rsclient_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Client\n"
       NEIGHBOR_ADDR_STR)

#endif

/*==============================================================================
 *
 */
enum bgp_stats
{
  BGP_STATS_MAXBITLEN = 0,
  BGP_STATS_RIB,
  BGP_STATS_PREFIXES,
  BGP_STATS_TOTPLEN,
  BGP_STATS_UNAGGREGATEABLE,
  BGP_STATS_MAX_AGGREGATEABLE,
  BGP_STATS_AGGREGATES,
  BGP_STATS_SPACE,
  BGP_STATS_ASPATH_COUNT,
  BGP_STATS_ASPATH_MAXHOPS,
  BGP_STATS_ASPATH_TOTHOPS,
  BGP_STATS_ASPATH_MAXSIZE,
  BGP_STATS_ASPATH_TOTSIZE,
  BGP_STATS_ASN_HIGHEST,
  BGP_STATS_MAX,
};

static chs_c table_stats_strs[] =
{
  [BGP_STATS_PREFIXES]            = "Total Prefixes",
  [BGP_STATS_TOTPLEN]             = "Average prefix length",
  [BGP_STATS_RIB]                 = "Total Advertisements",
  [BGP_STATS_UNAGGREGATEABLE]     = "Unaggregateable prefixes",
  [BGP_STATS_MAX_AGGREGATEABLE]   = "Maximum aggregateable prefixes",
  [BGP_STATS_AGGREGATES]          = "BGP Aggregate advertisements",
  [BGP_STATS_SPACE]               = "Address space advertised",
  [BGP_STATS_ASPATH_COUNT]        = "Advertisements with paths",
  [BGP_STATS_ASPATH_MAXHOPS]      = "Longest AS-Path (hops)",
  [BGP_STATS_ASPATH_MAXSIZE]      = "Largest AS-Path (bytes)",
  [BGP_STATS_ASPATH_TOTHOPS]      = "Average AS-Path length (hops)",
  [BGP_STATS_ASPATH_TOTSIZE]      = "Average AS-Path size (bytes)",
  [BGP_STATS_ASN_HIGHEST]         = "Highest public ASN",
  [BGP_STATS_MAX] = NULL,
};

struct bgp_table_stats
{
  bgp_rib rib ;
  urlong  counts[BGP_STATS_MAX];
};

#if 0
#define TALLY_SIGFIG 100000
static unsigned long
ravg_tally (unsigned long count, unsigned long oldavg, unsigned long newval)
{
  unsigned long newtot = (count-1) * oldavg + (newval * TALLY_SIGFIG);
  unsigned long res = (newtot * TALLY_SIGFIG) / count;
  unsigned long ret = newtot / count;

  if ((res % TALLY_SIGFIG) > (TALLY_SIGFIG/2))
    return ret + 1;
  else
    return ret;
}
#endif

static int
bgp_table_stats_walker (struct thread *t)
{
  ihash_walker_t walk[1] ;
  bgp_rib_node rn;
  struct bgp_table_stats *ts = THREAD_ARG (t);
  uint space ;

  ts = THREAD_ARG (t) ;

  switch (get_qafx_sa_family(ts->rib->qafx))
    {
      case AF_INET:
        space = IPV4_MAX_BITLEN;
        break;

#ifdef HAVE_IPV6
      case AF_INET6:
        space = IPV6_MAX_BITLEN;
        break;
#endif

      default:
        space = 0 ;
        break ;
    }

  ts->counts[BGP_STATS_MAXBITLEN] = space;

  ihash_walk_start(ts->rib->nodes_table, walk) ;

  while ((rn = ihash_walk_next(walk, NULL)) != NULL)
    {
      prefix_id_entry pie ;
      route_info      ri ;
      uint            rinum;

      pie = prefix_id_get_entry(rn->pfx_id) ;

      ts->counts[BGP_STATS_PREFIXES]++;
      ts->counts[BGP_STATS_TOTPLEN] += pie->pfx->prefixlen;

#if 0
      ts->counts[BGP_STATS_AVGPLEN]
        = ravg_tally (ts->counts[BGP_STATS_PREFIXES],
                      ts->counts[BGP_STATS_AVGPLEN],
                      rn->p.prefixlen);
#endif

/* TODO: PROBLEM... can no longer tell if prefix is a sub-prefix of another
 */
#if 0
      /* check if the prefix is included by any other announcements */
      while (prn && !prn->info)
        prn = prn->parent;

      if (prn == NULL || prn == top)
        {
#endif
          ts->counts[BGP_STATS_UNAGGREGATEABLE]++;
          /* announced address space */
          if (space)
            ts->counts[BGP_STATS_SPACE] += 1 << (space - pie->pfx->prefixlen);
#if 0
        }
      else if (prn->info)
        ts->counts[BGP_STATS_MAX_AGGREGATEABLE]++;
#endif

      rinum = 0 ;
      for (ri = svs_head(rn->aroutes[lc_view_id].base, rn->avail) ; ri != NULL ;
                            ri = svs_next(ri->iroutes[lc_view_id].list, rn->avail))
        {
          attr_set attr ;

          attr = ri->iroutes[lc_view_id].attr ;

          rinum++;
          ts->counts[BGP_STATS_RIB]++;

          if (attr->have & atb_atomic_aggregate)
            ts->counts[BGP_STATS_AGGREGATES]++;

          /* as-path stats
           */
          if (attr->asp != NULL)
            {
              uint hops = as_path_simple_path_length (attr->asp);
              uint size = as_path_size (attr->asp);
              as_t highest = as_path_highest (attr->asp);

              ts->counts[BGP_STATS_ASPATH_COUNT]++;

              if (hops > ts->counts[BGP_STATS_ASPATH_MAXHOPS])
                ts->counts[BGP_STATS_ASPATH_MAXHOPS] = hops;

              if (size > ts->counts[BGP_STATS_ASPATH_MAXSIZE])
                ts->counts[BGP_STATS_ASPATH_MAXSIZE] = size;

              ts->counts[BGP_STATS_ASPATH_TOTHOPS] += hops;
              ts->counts[BGP_STATS_ASPATH_TOTSIZE] += size;
#if 0
              ts->counts[BGP_STATS_ASPATH_AVGHOPS]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGHOPS],
                              hops);
              ts->counts[BGP_STATS_ASPATH_AVGSIZE]
                = ravg_tally (ts->counts[BGP_STATS_ASPATH_COUNT],
                              ts->counts[BGP_STATS_ASPATH_AVGSIZE],
                              size);
#endif
              if (highest > ts->counts[BGP_STATS_ASN_HIGHEST])
                ts->counts[BGP_STATS_ASN_HIGHEST] = highest;
            }
        }
    }
  return 0;
}

static int
bgp_table_stats (vty vty, bgp_run brun, qafx_t qafx)
{
  struct bgp_table_stats ts;
  unsigned int i;

  if (brun->rib[qafx] == NULL)
    {
      vty_out (vty, "%% No RIB exist for the AFI/SAFI\n");
      return CMD_WARNING;
    }

  memset (&ts, 0, sizeof (ts));
  ts.rib = brun->rib[qafx] ;
  thread_execute (bm->master, bgp_table_stats_walker, &ts, 0);

  vty_out (vty, "BGP %s RIB statistics\n\n", get_qafx_name(qafx));

  for (i = 0; i < BGP_STATS_MAX; i++)
    {
      if (!table_stats_strs[i])
        continue;

      switch (i)
        {
#if 0
          case BGP_STATS_ASPATH_AVGHOPS:
          case BGP_STATS_ASPATH_AVGSIZE:
          case BGP_STATS_AVGPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     (float)ts.counts[i] / (float)TALLY_SIGFIG);
            break;
#endif
          case BGP_STATS_ASPATH_TOTHOPS:
          case BGP_STATS_ASPATH_TOTSIZE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] /
                      (float)ts.counts[BGP_STATS_ASPATH_COUNT]
                     : 0);
            break;
          case BGP_STATS_TOTPLEN:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12.2f",
                     ts.counts[i] ?
                     (float)ts.counts[i] /
                      (float)ts.counts[BGP_STATS_PREFIXES]
                     : 0);
            break;
          case BGP_STATS_SPACE:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12" fRL "u\n", ts.counts[i]);
            if (ts.counts[BGP_STATS_MAXBITLEN] < 9)
              break;
            vty_out (vty, "%30s: ", "%% announced ");
            vty_out (vty, "%12.2f\n",
                     100 * (float)ts.counts[BGP_STATS_SPACE] /
                      (float)((uint64_t)1UL << ts.counts[BGP_STATS_MAXBITLEN]));
            vty_out (vty, "%30s: ", "/8 equivalent ");
            vty_out (vty, "%12.2f\n",
                     (float)ts.counts[BGP_STATS_SPACE] /
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 8)));
            if (ts.counts[BGP_STATS_MAXBITLEN] < 25)
              break;
            vty_out (vty, "%30s: ", "/24 equivalent ");
            vty_out (vty, "%12.2f",
                     (float)ts.counts[BGP_STATS_SPACE] /
                       (float)(1UL << (ts.counts[BGP_STATS_MAXBITLEN] - 24)));
            break;
          default:
            vty_out (vty, "%-30s: ", table_stats_strs[i]);
            vty_out (vty, "%12"fRL"u", ts.counts[i]);
        }

      vty_out (vty, "\n");
    }
  return CMD_SUCCESS;
}

static int
bgp_table_stats_vty (vty vty, chs_c name, chs_c afi_str, chs_c safi_str)
{
  bgp_run brun ;
  qAFI_t  q_afi ;
  qSAFI_t q_safi ;

  brun = bgp_run_lookup_vty(vty, name) ;

  if (brun == NULL)
    return CMD_WARNING;

  if      (strncmp (afi_str, "ipv4", 4) == 0)
    q_afi = qAFI_IP ;
#ifdef HAVE_IPV6
  else if (strncmp (afi_str, "ipv6", 4) == 0)
    q_afi = qAFI_IP6 ;
#endif
  else
    {
      vty_out (vty, "%% Invalid address family %s\n", afi_str);
      return CMD_WARNING;
    } ;

  if      (safi_str[0] == 'u')
    q_safi = qSAFI_Unicast ;
  else if (safi_str[0] == 'm')
    q_safi = qSAFI_Multicast ;
  else if ( (strncmp (safi_str, "vpnv4", 5) == 0)
#ifdef HAVE_IPV6
         || (strncmp (safi_str, "vpnv6", 5) == 0)
#endif
          )
    q_safi = qSAFI_MPLS_VPN ;
  else
    {
      vty_out (vty, "%% Invalid subsequent address family %s\n", safi_str);
      return CMD_WARNING;
    } ;

  return bgp_table_stats (vty, brun, qafx_from_q(q_afi, q_safi));
}

DEFUN (show_bgp_statistics,
       show_bgp_statistics_cmd,
       "show bgp (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics,
       show_bgp_statistics_vpnv4_cmd,
       "show bgp (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

DEFUN (show_bgp_statistics_view,
       show_bgp_statistics_view_cmd,
       "show bgp view WORD (ipv4|ipv6) (unicast|multicast) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")
{
  return bgp_table_stats_vty (vty, NULL, argv[0], argv[1]);
}

ALIAS (show_bgp_statistics_view,
       show_bgp_statistics_view_vpnv4_cmd,
       "show bgp view WORD (ipv4) (vpnv4) statistics",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "Address family\n"
       "Address Family modifier\n"
       "BGP RIB advertisement statistics\n")

enum bgp_pcounts
{
  PCOUNT_ADJ_IN = 0,
  PCOUNT_DAMPED,
  PCOUNT_REMOVED,
  PCOUNT_HISTORY,
  PCOUNT_STALE,
  PCOUNT_VALID,
  PCOUNT_ALL,
  PCOUNT_COUNTED,
  PCOUNT_PFCNT, /* the figure we display to users */
  PCOUNT_MAX,
};

static chs_c pcount_strs[] =
{
  [PCOUNT_ADJ_IN]  = "Adj-in",
  [PCOUNT_DAMPED]  = "Damped",
  [PCOUNT_REMOVED] = "Removed",
  [PCOUNT_HISTORY] = "History",
  [PCOUNT_STALE]   = "Stale",
  [PCOUNT_VALID]   = "Valid",
  [PCOUNT_ALL]     = "All RIB",
  [PCOUNT_COUNTED] = "PfxCt counted",
  [PCOUNT_PFCNT]   = "Usable",
  [PCOUNT_MAX]     = NULL,
};

struct peer_pcounts
{
  uint          count[PCOUNT_MAX];
  bgp_prun_c    prun;
  bgp_prib_c    prib ;
};

static int
bgp_peer_count_walker (struct thread *t)
{
  ihash_walker_t walk[1] ;
  route_info  ri ;
  struct peer_pcounts *pc ;

  pc = THREAD_ARG (t);

  ihash_walk_start(pc->prib->adj_in, walk) ;
  while ((ri = ihash_walk_next(walk, NULL)) != NULL)
    {
      if (ri->current.flags & (RINFO_REFUSED | RINFO_WITHDRAWN))
        continue ;

      pc->count[PCOUNT_ADJ_IN]++;

      if (ri->current.flags & RINFO_DENIED)
        continue ;

      pc->count[PCOUNT_ALL]++;

      if (CHECK_FLAG (ri->current.flags, BGP_INFO_DAMPED))
        pc->count[PCOUNT_DAMPED]++;
      if (CHECK_FLAG (ri->current.flags, BGP_INFO_HISTORY))
        pc->count[PCOUNT_HISTORY]++;
      if (CHECK_FLAG (ri->current.flags, BGP_INFO_REMOVED))
        pc->count[PCOUNT_REMOVED]++;
      if (CHECK_FLAG (ri->current.flags, BGP_INFO_STALE))
        pc->count[PCOUNT_STALE]++;
      if (CHECK_FLAG (ri->current.flags, BGP_INFO_VALID))
        pc->count[PCOUNT_VALID]++;
      if (!CHECK_FLAG (ri->current.flags, BGP_INFO_UNUSEABLE))
        pc->count[PCOUNT_PFCNT]++;

#if 0
      if (CHECK_FLAG (ri->current.flags, BGP_INFO_COUNTED))
        {
          pc->count[PCOUNT_COUNTED]++;
          if (CHECK_FLAG (ri->current.flags, BGP_INFO_UNUSEABLE))
            plog_warn (prun->log,
                       "%s [pcount] %s/%d is counted but flags 0x%x",
                       prun->name,
                       inet_ntop(rn->p.family, &rn->p.u.prefix,
                                 buf, SU_ADDRSTRLEN),
                       rn->p.prefixlen,
                       ri->current.flags);
        }
      else
        {
          if (!CHECK_FLAG (ri->current.flags, BGP_INFO_UNUSEABLE))
            plog_warn (prun->log,
                       "%s [pcount] %s/%d not counted but flags 0x%x",
                       prun->name,
                       inet_ntop(rn->p.family, &rn->p.u.prefix,
                                 buf, SU_ADDRSTRLEN),
                       rn->p.prefixlen,
                       ri->current.flags);
        }
#endif
    } ;

  return 0;
}

static cmd_ret_t
bgp_peer_counts (vty vty, chs_c view_name, chs_c peer_name, qafx_t qafx)
{
  bgp_prun prun ;
  struct   peer_pcounts pcounts ;
  uint     i ;

  prun = prun_lookup_view_qafx_vty(vty, view_name, peer_name, qafx) ;

  if (prun == NULL)
    return CMD_WARNING;

  memset (&pcounts, 0, sizeof(pcounts));
  pcounts.prun = prun;
  pcounts.prib = prun->prib[qafx] ;

  /* in-place call via thread subsystem so as to record execution time
   * stats for the thread-walk (i.e. ensure this can't be blamed on
   * on just vty_read()).
   */
  thread_execute (bm->master, bgp_peer_count_walker, &pcounts, 0);

  vty_out (vty, "Prefix counts for %s, %s\n", prun->name,
                                                           get_qafx_name(qafx));
  vty_out (vty, "PfxCt: %u\n", pcounts.prib->pcount_in);
  vty_out (vty, "\nCounts from RIB table walk:\n\n") ;

  for (i = 0; i < PCOUNT_MAX; i++)
      vty_out (vty, "%20s: %-10d\n", pcount_strs[i], pcounts.count[i]);

  if (pcounts.count[PCOUNT_PFCNT] != pcounts.prib->pcount_in)
    {
      vty_out (vty, "%s [pcount] PfxCt drift!\n", prun->name);
      vty_out (vty, "Please report this bug, with the above command output\n") ;
    }

  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_neighbor_prefix_counts,
       show_ip_bgp_neighbor_prefix_counts_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  return bgp_peer_counts (vty, NULL, argv[0], qafx_ipv4_unicast);
}

DEFUN (show_bgp_ipv6_neighbor_prefix_counts,
       show_bgp_ipv6_neighbor_prefix_counts_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  return bgp_peer_counts (vty, NULL, argv[0], qafx_ipv6_unicast);
}

DEFUN (show_ip_bgp_ipv4_neighbor_prefix_counts,
       show_ip_bgp_ipv4_neighbor_prefix_counts_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  qafx_t qafx ;

  qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                             : qafx_ipv4_unicast ;

  return bgp_peer_counts (vty, NULL, argv[1], qafx);
}

DEFUN (show_ip_bgp_vpnv4_neighbor_prefix_counts,
       show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd,
       "show ip bgp vpnv4 all neighbors (A.B.C.D|X:X::X:X) prefix-counts",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n"
       "Display detailed prefix count information\n")
{
  return bgp_peer_counts (vty, NULL, argv[0], qafx_ipv4_mpls_vpn) ;
}


DEFUN (show_ip_bgp_dampened_paths,
       show_ip_bgp_dampened_paths_cmd,
       "show ip bgp dampened-paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display paths suppressed due to dampening\n")
{
  return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                              bgp_show_type_damped_paths, NULL);
}

DEFUN (show_ip_bgp_flap_statistics,
       show_ip_bgp_flap_statistics_cmd,
       "show ip bgp flap-statistics",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display flap statistics of routes\n")
{
  return bgp_show(vty, NULL, qafx_ipv4_unicast, lc_view_id,
                                           bgp_show_type_flap_statistics, NULL);
}


/*==============================================================================
 * MPLS show stuff.
 */
static int
show_adj_route_vpn (vty vty, const char* peer_name, const char* rd_str)
{
  bgp_prun       prun ;
  prefix_rd_t    prd_s ;
  prefix_rd      prd ;
  bgp_run        brun ;
  vector         rv ;
  vector_index_t i ;
  bool header ;
  const char* v4_header = "   Network          Next Hop            "
                                                 "Metric LocPrf Weight Path\n" ;
  prefix_rd_id_t rd_id ;

  prun = prun_lookup_view_qafx_vty (vty, NULL, peer_name, qafx_ipv4_mpls_vpn);
  if (prun == NULL)
    return CMD_WARNING;

  if (rd_str == NULL)
    prd = NULL ;
  else
    {
      prd = &prd_s ;

      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING;
    } ;


  /* TODO -- this is broken... should be walking the peer's adj_out !
   */
#if 1
  brun = prun->brun ;
#else
  /* This is the previous code... which doesn't seem to make a lot of sense,
   * since this is supposed to be showing the routes advertised to a given
   * peer.
   */
  bgp = bgp_get_default ();
  if (bgp == NULL)
    {
      vty_out (vty, "No BGP process is configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
#endif

  rv = bgp_rib_extract(brun->rib[qafx_ipv4_mpls_vpn], lc_view_id, prd) ;

  header = false ;
  rd_id  = prefix_rd_id_null ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;
      prefix       pfx ;

      rn = vector_get_item(rv, i) ;
      ri = svs_head(rn->aroutes[lc_view_id].base, rn->avail) ;

      if (ri == NULL)
        continue ;

      if (!header)
        {
          vty_out (vty, "BGP table version is 0, local router ID is %s\n",
                                      siptoa(AF_INET, &brun->rp.router_id).str);
          vty_out (vty, "Status codes: s suppressed, d damped, h history, "
                                            "* valid, > best, i - internal\n");
          vty_out (vty, "Origin codes: i - IGP, e - EGP, "
                                                         "? - incomplete\n\n") ;
          vty_out (vty, v4_header);
          header = true ;
        } ;

      pfx = prefix_id_get_prefix(rn->pfx_id) ;

      if (pfx->rd_id != rd_id)
        {
          mpls_rd_t rd[1] ;

          rd_id = pfx->rd_id ;

          /* Decode RD type.
           */
          mpls_rd_decode(rd, prefix_rd_id_get_val(rd_id)->val);

          vty_out (vty, "Route Distinguisher: ");

          switch (rd->type)
            {
              case RD_TYPE_AS:
                vty_out (vty, "%u:%d", rd->u.as.asn, rd->u.as.val) ;
                break ;

              case RD_TYPE_IP:
                vty_out (vty, "%s:%d", sipv4toa(rd->u.ip.addr).str,
                                                       rd->u.ip.val) ;
                break ;

              default:
                vty_out (vty, "%d:??", rd->type) ;
                break ;
            } ;

          vty_out (vty, "\n") ;
        } ;

      do
        {
          route_vty_out_tmp (vty, pfx, ri->iroutes[0].attr, ri->current.qafx);

          ri = svs_next(ri->iroutes[lc_view_id].list, rn->avail) ;
        }
      while (ri != NULL) ;
    } ;
  return CMD_SUCCESS;
}

static int
bgp_show_mpls_vpn (vty vty, const char* rd_str, enum bgp_show_type type,
                                                void* output_arg, bool tags)
{
  bgp_run        brun ;
  vector         rv ;
  vector_index_t i ;
  bool           header ;
  prefix_rd_t    prd_s ;
  prefix_rd      prd ;
  prefix_rd_id_t rd_id ;

  const char* v4_header =
      "   Network          Next Hop            Metric LocPrf Weight Path\n" ;
  const char* v4_header_tag =
      "   Network          Next Hop      In tag/Out tag\n";

  brun = bgp_run_lookup_vty(vty, NULL) ;

  if (brun == NULL)
    return CMD_WARNING;

  if (rd_str == NULL)
    prd = NULL ;
  else
    {
      prd = &prd_s ;

      if (! str2prefix_rd_vty (vty, prd, rd_str))
        return CMD_WARNING;
    } ;

  rv = bgp_rib_extract(brun->rib[qafx_ipv4_mpls_vpn], lc_view_id, prd) ;

  header = false ;
  rd_id  = prefix_rd_id_null ;

  for (i = 0 ; i < vector_length(rv) ; ++i)
    {
      bgp_rib_node rn ;
      route_info   ri ;

      rn = vector_get_item(rv, i) ;
      ri = svs_head(rn->aroutes[lc_view_id].base, rn->avail) ;

      while (ri != NULL)
        {
          prefix  pfx ;

          if (type == bgp_show_type_neighbor)
            {
              sockunion su ;

              su = &ri->prib->prun->session->cops->remote_su ;

              if (!sockunion_same(su, (sockunion)output_arg))
                continue;
            } ;

          if (!header)
            {
              if (tags)
                vty_out (vty, v4_header_tag);
              else
                {
                  vty_out (vty, "BGP table version is 0, "
                                                      "local router ID is %s\n",
                                      siptoa(AF_INET, &brun->rp.router_id).str);
                  vty_out (vty, "Status codes: s suppressed, d damped, "
                                  "h history, * valid, > best, i - internal\n");
                  vty_out (vty, "Origin codes: i - IGP, e - EGP, "
                                                          "? - incomplete\n\n");
                  vty_out (vty, v4_header);
                } ;

              header = true;
            }

          pfx = prefix_id_get_prefix(rn->pfx_id) ;

          if (pfx->rd_id != rd_id)
            {
              mpls_rd_t rd[1] ;

              rd_id = pfx->rd_id ;

              /* Decode RD type.
               */
              mpls_rd_decode(rd, prefix_rd_id_get_val(rd_id)->val);

              vty_out (vty, "Route Distinguisher: ");

              switch (rd->type)
                {
                  case RD_TYPE_AS:
                    vty_out (vty, "%u:%d", rd->u.as.asn, rd->u.as.val) ;
                    break ;

                  case RD_TYPE_IP:
                    vty_out (vty, "%s:%d", sipv4toa(rd->u.ip.addr).str,
                                                           rd->u.ip.val) ;
                    break ;

                  default:
                    vty_out (vty, "%d:??", rd->type) ;
                    break ;
                } ;

              vty_out (vty, "\n") ;
            } ;

          if (tags)
            route_vty_out_tag (vty, pfx, ri, true);
          else
            route_vty_out (vty, pfx, ri, true);

          ri = svs_next(ri->iroutes[lc_view_id].list, rn->avail) ;
        } ;
    } ;

  return CMD_SUCCESS;
}

static int
bgp_show_mpls_vpn_neighbor (vty vty, const char* rd_str,
                                               const char* peer_str, bool tags)
{
  bgp_prun prun;
  sockunion_t  su_s ;
  sockunion    su ;

  prun = prun_lookup_view_qafx_vty (vty, NULL, peer_str, qafx_ipv4_mpls_vpn) ;
  if (prun == NULL)
    return CMD_WARNING;

  /* Need a not-const copy of the su... such is life
   */
  su = sockunion_copy(&su_s, &prun->rp.cops_conf.remote_su) ;

  return bgp_show_mpls_vpn (vty, rd_str, bgp_show_type_neighbor, su, tags) ;
} ;

DEFUN (show_ip_bgp_vpnv4_all,
       show_ip_bgp_vpnv4_all_cmd,
       "show ip bgp vpnv4 all",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL, false);
}

DEFUN (show_ip_bgp_vpnv4_rd,
       show_ip_bgp_vpnv4_rd_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
  return bgp_show_mpls_vpn (vty, argv[0], bgp_show_type_normal, NULL, 0);
}

DEFUN (show_ip_bgp_vpnv4_all_tags,
       show_ip_bgp_vpnv4_all_tags_cmd,
       "show ip bgp vpnv4 all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, NULL, bgp_show_type_normal, NULL,  1);
}

DEFUN (show_ip_bgp_vpnv4_rd_tags,
       show_ip_bgp_vpnv4_rd_tags_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn tags",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
  return bgp_show_mpls_vpn (vty, argv[0], bgp_show_type_normal, NULL, 1);
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_routes,
       show_ip_bgp_vpnv4_all_neighbor_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_mpls_vpn_neighbor (vty, NULL, argv[0], false) ;
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_routes,
       show_ip_bgp_vpnv4_rd_neighbor_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n")
{
  return bgp_show_mpls_vpn_neighbor (vty, argv[0], argv[1], false) ;
}

DEFUN (show_ip_bgp_vpnv4_all_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return show_adj_route_vpn (vty, argv[0], NULL);
}

DEFUN (show_ip_bgp_vpnv4_rd_neighbor_advertised_routes,
       show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors "
                                                    "A.B.C.D advertised-routes",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n")
{
  return show_adj_route_vpn (vty, argv[1], argv[0]);
}

/*==============================================================================
 *
 */

DEFUN (show_bgp_views,
       show_bgp_views_cmd,
       "show bgp views",
       SHOW_STR
       BGP_STR
       "Show the defined BGP views\n")
{
  bgp_run       brun ;

  if (!bgp_option_check (BGP_OPT_MULTIPLE_INSTANCE))
    {
      vty_out (vty, "Multiple BGP views are not defined\n");
      return CMD_WARNING;
    }

  vty_out (vty, "Defined BGP views:\n") ;
  for (brun = ddl_head(bm->bruns) ; brun != NULL ;
                                    brun = ddl_next(brun, brun_list))
    vty_out (vty, "\t%s (AS%u)\n",
               ((brun->view_name != NULL) ? brun->view_name : "(null)"),
                                                               brun->rp.my_as) ;

  return CMD_SUCCESS;
}

DEFUN (show_bgp_memory,
       show_bgp_memory_cmd,
       "show bgp memory",
       SHOW_STR
       BGP_STR
       "Global BGP memory statistics\n")
{
  mem_stats_t mst[1] ;
  char memstrbuf[MTYPE_MEMSTR_LEN];
  ulong count;

  mem_get_stats(mst) ;

  /* RIB related usage stats */
  count = mem_get_alloc(mst, MTYPE_BGP_NODE);
  vty_out (vty, "%ld RIB nodes, using %s of memory\n", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_node)));

  count = mem_get_alloc(mst, MTYPE_BGP_ROUTE);
  vty_out (vty, "%ld BGP routes, using %s of memory\n", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_info)));
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ROUTE_EXTRA)))
    vty_out (vty, "%ld BGP route ancillaries, using %s of memory\n", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_info_extra)));

  if ((count = mem_get_alloc(mst, MTYPE_BGP_STATIC)))
    vty_out (vty, "%ld Static routes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_static)),
             VTY_NEWLINE);

/* TODO some work on the memory reporting !!            */
#if 0
  /* Adj-In/Out */
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ADJ_IN)))
    vty_out (vty, "%ld Adj-In entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_in)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_BGP_ADJ_OUT)))
    vty_out (vty, "%ld Adj-Out entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct bgp_adj_out)),
             VTY_NEWLINE);
#endif

  if ((count = mem_get_alloc(mst, MTYPE_BGP_NEXTHOP_CACHE)))
    vty_out (vty, "%ld Nexthop cache entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_nexthop_cache)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_DAMP_INFO)))
    vty_out (vty, "%ld Dampening entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (struct bgp_damp_info)),
             VTY_NEWLINE);

  /* Attributes */
  count = bgp_attr_count();
  vty_out (vty, "%ld BGP attributes, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof(attr_set_t)),
           VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_BGP_UNKNOWN_ATTR)))
    vty_out (vty, "%ld unknown attributes%s", count, VTY_NEWLINE);

  /* AS_PATH attributes */
  count = as_path_count ();
  vty_out (vty, "%ld BGP AS-PATH entries, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (as_path_t)),
           VTY_NEWLINE);

  count = mem_get_alloc(mst, MTYPE_AS_PATH_BODY);
  vty_out (vty, "%ld BGP AS-PATH bodies, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (as_path_t)),    /* TODO fix !  */
           VTY_NEWLINE);

  /* Other attributes */
  if ((count = mem_get_alloc(mst, MTYPE_COMMUNITY)))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_community_t)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_ECOMMUNITY)))
    vty_out (vty, "%ld BGP community entries, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_ecommunity_t)),
             VTY_NEWLINE);

  if ((count = mem_get_alloc(mst, MTYPE_CLUSTER)))
    vty_out (vty, "%ld Cluster lists, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (attr_cluster_t)),
             VTY_NEWLINE);

  /* Peer related usage */
  count = mem_get_alloc(mst, MTYPE_BGP_PEER);
  vty_out (vty, "%ld peers, using %s of memory%s", count,
           mtype_memstr (memstrbuf, sizeof (memstrbuf),
                         count * sizeof (bgp_prun_t)),
           VTY_NEWLINE);
#if 0
  if ((count = mem_get_alloc(mst, MTYPE_PEER_GROUP)))
    vty_out (vty, "%ld peer groups, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (bgp_peer_group_t)),
             VTY_NEWLINE);
#endif
  /* Other */
  if ((count = mem_get_alloc(mst, MTYPE_HASH)))
    vty_out (vty, "%ld hash tables, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_HASH_BACKET)))
    vty_out (vty, "%ld hash buckets, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (struct hash_backet)),
             VTY_NEWLINE);
  if ((count = mem_get_alloc(mst, MTYPE_BGP_REGEXP)))
    vty_out (vty, "%ld compiled regexes, using %s of memory%s", count,
             mtype_memstr (memstrbuf, sizeof (memstrbuf),
                           count * sizeof (regex_t)),
             VTY_NEWLINE);
  return CMD_SUCCESS;
}

/*------------------------------------------------------------------------------
 * Show BGP peer's summary information.
 */
static int
bgp_show_summary (vty vty, bgp_rib rib)
{
  bgp_prib prib ;
  unsigned int count = 0;
  int len;
  bgp_session_stats_t stats;

  /* Header string for each address family.
   */
  static const char header[] =
   /*123456789012345_1_12345_1234567_1234567_12345678_1234_1234_*/
    "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ "
   /*                         12345678_123456789012 */
                             "Up/Down  State/PfxRcd";

  for (prib = ddl_head(rib->pribs) ; prib != NULL ;
                                     prib = ddl_next(prib, prib_list))
    {
      bgp_prun prun ;
      bgp_run  brun ;

      prun = prib->prun ;
      brun = prun->brun ;

      if (count == 0)
        {
#if 0
          ulong ents;
          char memstrbuf[MTYPE_MEMSTR_LEN];
#endif

          /* Usage summary and header */
          vty_out (vty,
                   "BGP router identifier %s, local AS number %u\n",
                siptoa(AF_INET, &brun->rp.router_id).str, brun->rp.my_as) ;

#if 0
          ents = bgp_rib_count (brun->rib[qafx]);
          vty_out (vty, "RIB entries %ld, using %s of memory%s", ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (bgp_rib_node_t)),
                   VTY_NEWLINE);
          ents = bgp_rib_count (bgp->rib[qafx][rib_rs]);
          if (ents != 0)
            vty_out (vty, "RIB entries %ld, using %s of memory%s", ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (bgp_rib_node_t)),
                   VTY_NEWLINE);

          /* Peer related usage */
          ents = listcount (bgp->peer);
          vty_out (vty, "Peers %ld, using %s of memory%s",
                   ents,
                   mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                 ents * sizeof (bgp_peer_t)),
                   VTY_NEWLINE);

          if ((ents = listcount (bgp->rsclient)))
            vty_out (vty, "RS-Client peers %ld, using %s of memory%s",
                     ents,
                     mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                   ents * sizeof (struct peer)),
                     VTY_NEWLINE);
          if ((ents = listcount (bgp->group)))
            vty_out (vty, "Peer groups %ld, using %s of memory\n", ents,
                     mtype_memstr (memstrbuf, sizeof (memstrbuf),
                                   ents * sizeof (bgp_peer_group_t)));
#endif

          if (rib->rp.do_damping)
            vty_out (vty, "Dampening enabled.\n");

          vty_out (vty, "\n"
                        "%s\n", header);
        }

      count++;

      vty_out (vty, "%s", prun->name);
      len = 15 - strlen(prun->name);
      if      (len < 0)
        vty_out (vty, "\n%*s", 15, " ");
      else if (len > 0)
        vty_out (vty, "%*s",  len, " ");

      vty_out (vty, " 4 ");

      vty_out (vty, "%5u %7d %7d %8d %4d %4lu ",
               prun->rp.sargs_conf.remote_as,
               stats.open_in + stats.update_in + stats.keepalive_in
               + stats.notify_in + stats.refresh_in + stats.dynamic_cap_in,
               stats.open_out + stats.update_out + stats.keepalive_out
               + stats.notify_out + stats.refresh_out
               + stats.dynamic_cap_out,
               0, 0, (ulong)0 /* TODO "output queue depth" */);

      vty_out (vty, "%-8s", peer_uptime (prun->uptime).str);

      if (prun->state == bgp_pEstablished)
        vty_out (vty, " %8u", prib->pcount_in) ;
      else
        vty_out(vty, " %-11s",
                         bgp_peer_idle_state_str(prun->state, prun->idle).str) ;
      vty_out (vty, "\n");
    } ;

  if (count)
    vty_out (vty, "\nTotal number of neighbors %d\n", count);
  else
    vty_out (vty, "No %s neighbor is configured\n",
                                     qafx_is_ipv4(rib->qafx) ? "IPv4" : "IPv6");
  return CMD_SUCCESS;
}

static int
bgp_show_summary_vty (struct vty *vty, chs_c view_name, qafx_t qafx)
{
  bgp_run brun ;
  bgp_rib rib ;

  brun = bgp_run_lookup_vty(vty, view_name) ;

  if (brun == NULL)
    return CMD_WARNING;

  rib = brun->rib[qafx] ;
  if (rib == NULL)
    {
      vty_out(vty, "%% nothing configured for this afi/safi\n") ;
      return CMD_WARNING ;
    }

  bgp_show_summary (vty, rib);

  return CMD_SUCCESS;
}

/* `show ip bgp summary' commands. */
DEFUN (show_ip_bgp_summary,
       show_ip_bgp_summary_cmd,
       "show ip bgp summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_instance_summary,
       show_ip_bgp_instance_summary_cmd,
       "show ip bgp view WORD summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, argv[0], qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_summary,
       show_ip_bgp_ipv4_summary_cmd,
       "show ip bgp ipv4 (unicast|multicast) summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_summary_vty (vty, NULL, qafx);
}

ALIAS (show_ip_bgp_ipv4_summary,
       show_bgp_ipv4_safi_summary_cmd,
       "show bgp ipv4 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_instance_ipv4_summary,
       show_ip_bgp_instance_ipv4_summary_cmd,
       "show ip bgp view WORD ipv4 (unicast|multicast) summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[1][0] == 'm') ? qafx_ipv4_multicast
                                    : qafx_ipv4_unicast ;

  return bgp_show_summary_vty (vty, argv[0], qafx);
}

ALIAS (show_ip_bgp_instance_ipv4_summary,
       show_bgp_instance_ipv4_safi_summary_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_ip_bgp_vpnv4_all_summary,
       show_ip_bgp_vpnv4_all_summary_cmd,
       "show ip bgp vpnv4 all summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_mpls_vpn);
}

DEFUN (show_ip_bgp_vpnv4_rd_summary,
       show_ip_bgp_vpnv4_rd_summary_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Summary of BGP neighbor status\n")
{
  struct prefix_rd prd;

  if (! str2prefix_rd_vty (vty, &prd, argv[0]))
    return CMD_WARNING;

  return bgp_show_summary_vty (vty, NULL, qafx_ipv4_mpls_vpn);
}

#ifdef HAVE_IPV6
DEFUN (show_bgp_summary,
       show_bgp_summary_cmd,
       "show bgp summary",
       SHOW_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

DEFUN (show_bgp_instance_summary,
       show_bgp_instance_summary_cmd,
       "show bgp view WORD summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (show_bgp_summary,
       show_bgp_ipv6_summary_cmd,
       "show bgp ipv6 summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Summary of BGP neighbor status\n")

ALIAS (show_bgp_instance_summary,
       show_bgp_instance_ipv6_summary_cmd,
       "show bgp view WORD ipv6 summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Summary of BGP neighbor status\n")

DEFUN (show_bgp_ipv6_safi_summary,
       show_bgp_ipv6_safi_summary_cmd,
       "show bgp ipv6 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[0][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_summary_vty (vty, NULL, qafx);
}

DEFUN (show_bgp_instance_ipv6_safi_summary,
       show_bgp_instance_ipv6_safi_summary_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Summary of BGP neighbor status\n")
{
  qafx_t qafx = (argv[1][0] == 'm') ? qafx_ipv6_multicast
                                    : qafx_ipv6_unicast ;

  return bgp_show_summary_vty (vty, argv[0], qafx);
}

/* old command */
DEFUN (show_ipv6_bgp_summary,
       show_ipv6_bgp_summary_cmd,
       "show ipv6 bgp summary",
       SHOW_STR
       IPV6_STR
       BGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

/* old command */
DEFUN (show_ipv6_mbgp_summary,
       show_ipv6_mbgp_summary_cmd,
       "show ipv6 mbgp summary",
       SHOW_STR
       IPV6_STR
       MBGP_STR
       "Summary of BGP neighbor status\n")
{
  return bgp_show_summary_vty (vty, NULL, qafx_ipv6_multicast);
}
#endif /* HAVE_IPV6 */

static const char *
qafx_string(qafx_t qafx)
{
  switch (qafx)
    {
      case qafx_ipv4_unicast:
        return "IPv4 Unicast";

      case qafx_ipv4_multicast:
        return "IPv4 Multicast";

      case qafx_ipv4_mpls_vpn:
        return "VPNv4 Unicast";

      case qafx_ipv6_unicast:
        return "IPv6 Unicast";

      case qafx_ipv6_multicast:
        return "IPv6 Multicast";

      default:
        return "Unknown";
    } ;
} ;

/* Show BGP peer's information. */
enum show_type
{
  show_all,
  show_peer
};

static void
bgp_show_peer_afi_orf_cap (vty vty, bgp_orf_cap_bits_t orf_pfx_sent,
                                                          bgp_orf_cap_bits_t sm,
                                    bgp_orf_cap_bits_t orf_pfx_recv,
                                                          bgp_orf_cap_bits_t rm)
{
  bool sent, recv ;

  /* Send-Mode
   */
  sent = (orf_pfx_sent & sm) ;
  recv = (orf_pfx_recv & rm) ;

  if (sent || recv)
    {
      vty_out (vty, "      Send-mode: ");
      if (sent)
        vty_out (vty, "requested");
      if (sent && recv)
        vty_out (vty, " and ") ;
      if (recv)
        vty_out (vty, "allowed") ;
      vty_out (vty, "\n");
    } ;

  /* Receive-Mode
   */
  sent = (orf_pfx_sent & rm) ;
  recv = (orf_pfx_recv & sm) ;

  if (sent || recv)
    {
      vty_out (vty, "      Receive-mode: ");
      if (sent)
        vty_out (vty, "requested");
      if (sent && recv)
        vty_out (vty, " and ") ;
      if (recv)
        vty_out (vty, "allowed") ;
      vty_out (vty, "\n");
    } ;
} ;

static void
bgp_show_prun_afi (vty vty, bgp_prun prun, qafx_t qafx)
{
  bgp_prib     prib ;
  access_list  dlist ;
  prefix_list  plist ;
  as_list      flist ;
  route_map    rmap ;
  bgp_orf_name orf_pfx_name;
  int orf_pfx_count;

  prib = prun->prib[qafx] ;
  qassert(prib != NULL) ;
  if (prib == NULL)
    return ;

  vty_out (vty, " For address family: %s\n", qafx_string(qafx));

  if (peer->c->c_af_member != qafx_empty_set)
    vty_out (vty, "  %s peer-group member\n", peer->c->group->name);

  if (prun->state == bgp_pEstablished)
    {
      bgp_orf_cap_bits_t orf_pfx_sent, orf_pfx_recv ;

      orf_pfx_sent = prun->session->open_recv->sargs->can_orf_pfx.af[qafx] ;
      orf_pfx_recv = prun->session->open_recv->sargs->can_orf_pfx.af[qafx] ;

      if ((orf_pfx_sent | orf_pfx_recv) != 0)
        vty_out (vty, "  AF-dependant capabilities:\n");

      if ((orf_pfx_sent | orf_pfx_recv) & (ORF_SM | ORF_RM) )
        {
          vty_out (vty,
                   "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
                                                                BGP_ORF_T_PFX);
          bgp_show_peer_afi_orf_cap (vty, orf_pfx_sent, orf_pfx_recv,
                                                               ORF_SM, ORF_RM) ;
        } ;

      if ((orf_pfx_sent | orf_pfx_recv) & (ORF_SM_pre | ORF_RM_pre) )
        {
          vty_out (vty,
                   "    Outbound Route Filter (ORF) type (%d) Prefix-list:\n",
                                                             BGP_ORF_T_PFX_pre);
          bgp_show_peer_afi_orf_cap (vty, orf_pfx_sent, orf_pfx_recv,
                                                       ORF_SM_pre, ORF_RM_pre) ;
        } ;
    } ;

  prefix_bgp_orf_name_set(orf_pfx_name, &prun->rp.cops_conf.remote_su, qafx) ;

  orf_pfx_count = prefix_bgp_show_prefix_list (NULL, orf_pfx_name);

  if (prib->orf_pfx_sent || (orf_pfx_count != 0))
    {
      vty_out (vty, "  Outbound Route Filter (ORF):");
      if (prib->orf_pfx_sent)
        vty_out (vty, " sent;");
      if (orf_pfx_count)
        vty_out (vty, " received (%d entries)", orf_pfx_count);
      vty_out (vty, "\n");
    } ;

  if (prib->orf_pfx_wait)
      vty_out (vty, "  First update is deferred until ORF or ROUTE-REFRESH "
                                                  "is received\n");

  if (prib->rp.is_route_reflector_client)
    vty_out (vty, "  Route-Reflector Client\n");
  if (prib->rp.is_route_server_client)
    vty_out (vty, "  Route-Server Client\n");
  if (prib->rp.do_soft_reconfig)
    vty_out (vty, "  Inbound soft reconfiguration allowed\n");
  if (prib->rp.do_remove_private_as)
    vty_out (vty, "  Private AS number removed from updates to this neighbor\n");
  if (prib->rp.do_next_hop_self)
    vty_out (vty, "  NEXT_HOP is always this router\n");
  if (prib->rp.do_as_path_unchanged)
    vty_out (vty, "  AS_PATH is propagated unchanged to this neighbor\n");
  if (prib->rp.do_next_hop_unchanged)
    vty_out (vty, "  NEXT_HOP is propagated unchanged to this neighbor\n");
  if (prib->rp.do_med_unchanged)
    vty_out (vty, "  MED is propagated unchanged to this neighbor\n");
  if (prib->rp.do_send_community || prib->rp.do_send_ecommunity)
    {
      vty_out (vty, "  Community attribute sent to this neighbor");
      if (prib->rp.do_send_community && prib->rp.do_send_ecommunity)
        vty_out (vty, "(both)\n");
      else if ( prib->rp.do_send_ecommunity)
        vty_out (vty, "(extended)\n");
      else
        vty_out (vty, "(standard)\n");
    }
  if (prib->rp.do_default_originate)
    {
      vty_out (vty, "  Default information originate,");

      if (prib->default_rmap != NULL)
        vty_out (vty, " default route-map %s%s,",
                 route_map_is_set(prib->default_rmap) ? "*" : "",
                 route_map_get_name(prib->default_rmap)) ;
      if (prib->default_sent)
        vty_out (vty, " default sent\n");
      else
        vty_out (vty, " default not sent\n");
    }

  if ( (prib->plist[FILTER_IN]  != NULL)  ||
       (prib->dlist[FILTER_IN]  != NULL)  ||
       (prib->flist[FILTER_IN] != NULL) ||
       (prib->rmap[RMAP_IN]     != NULL) )
    vty_out (vty, "  Inbound path policy configured\n");

  if (prib->rmap[RMAP_INX] != NULL)
    vty_out (vty, "  RS-Inbound policy configured\n");

  if ( (prib->plist[FILTER_OUT]  != NULL)  ||
       (prib->dlist[FILTER_OUT]  != NULL)  ||
       (prib->flist[FILTER_OUT] != NULL) ||
       (prib->rmap[RMAP_OUT]     != NULL) ||
       (prib->us_rmap            != NULL) )
    vty_out (vty, "  Outbound path policy configured\n");

  if (prib->rmap[RMAP_IMPORT] != NULL)
    vty_out (vty, "  Import policy for this RS-client configured\n");

  if (prib->rmap[RMAP_EXPORT] != NULL)
    vty_out (vty, "  Export policy for this RS-client configured\n");

  /* prefix-list */
  plist = prib->plist[FILTER_IN] ;
  if (plist != NULL)
    vty_out (vty, "  Incoming update prefix filter list is %s%s\n",
             prefix_list_is_set(plist) ? "*" : "", prefix_list_get_name(plist));

  plist = prib->plist[FILTER_OUT] ;
  if (plist != NULL)
    vty_out (vty, "  Outgoing update prefix filter list is %s%s\n",
             prefix_list_is_set(plist) ? "*" : "", prefix_list_get_name(plist));

  /* distribute-list */
  dlist = prib->dlist[FILTER_IN] ;
  if (dlist != NULL)
    vty_out (vty, "  Incoming update network filter list is %s%s\n",
             access_list_is_set(dlist) ? "*" : "", access_list_get_name(dlist));
  dlist = prib->dlist[FILTER_OUT] ;
  if (dlist != NULL)
    vty_out (vty, "  Outgoing update network filter list is %s%s\n",
             access_list_is_set(dlist) ? "*" : "", access_list_get_name(dlist));

  /* filter-list. */
  flist = prib->flist[FILTER_IN] ;
  if (flist != NULL)
    vty_out (vty, "  Incoming update AS path filter list is %s%s\n",
             as_list_is_set(flist) ? "*" : "", as_list_get_name(flist));
  flist = prib->flist[FILTER_OUT] ;
  if (flist != NULL)
    vty_out (vty, "  Outgoing update AS path filter list is %s%s\n",
             as_list_is_set(flist) ? "*" : "", as_list_get_name(flist));

  /* route-map. */
  rmap = prib->rmap[RMAP_IN] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for incoming advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_INX] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for RS incoming advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_OUT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for outgoing advertisements is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_IMPORT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for advertisements going into this"
                                                 " RS-client's table is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));
  rmap = prib->rmap[RMAP_EXPORT] ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for advertisements coming from this "
                                                          "RS-client is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));

  /* unsuppress-map
   */
  rmap = prib->us_rmap ;
  if (rmap != NULL)
    vty_out (vty, "  Route map for selective unsuppress is %s%s\n",
             route_map_is_set(rmap) ? "*" : "", route_map_get_name(rmap));

  /* Receive prefix count
   */
  vty_out (vty, "  %u accepted prefixes (%u received)\n", prib->pcount_in,
                                                            prib->pcount_recv) ;

  /* Maximum prefix
   */
  if (prib->pmax.set)
    {
      vty_out (vty, "  Maximum prefixes allowed %u%s\n", prib->pmax.limit,
                              (prib->pmax.warning) ? " (warning-only)" : "") ;
      vty_out (vty, "  Threshold for warning message %d%%",
                                                       prib->pmax.thresh_pc);
      if (prib->pmax.restart != 0)
        vty_out (vty, ", restart interval %d min", prib->pmax.restart);

      vty_out (vty, "\n");
    }

  vty_out (vty, "\n");
}


/*------------------------------------------------------------------------------
 * Show state of a *real* peer
 */
#if 0   // reinstate showing any capability issues
static void bgp_capability_vty_out (struct vty *vty, bgp_peer peer) ;
#endif

static void
bgp_show_peer (struct vty *vty, bgp_prun prun)
{
  bgp_run  brun;
  qafx_t qafx ;
  bgp_session_stats_t stats;
  bool established_gr ;

  brun = prun->brun ;

  bgp_session_get_stats(&stats, prun->session);

  /* Configured IP address.
   */
  vty_out (vty, "BGP neighbor is %s, ", prun->name);
  vty_out (vty, "remote AS %u, ", prun->rp.sargs_conf.remote_as);
  vty_out (vty, "local AS %u", prun->rp.sargs_conf.local_as) ;
  if ((prun->rp.sort == BGP_PEER_EBGP)
        && (prun->rp.change_local_as != BGP_ASN_NULL)
        && (prun->rp.change_local_as != brun->rp.my_as_ebgp))
    vty_out (vty, " (changed%s)", (prun->rp.do_local_as_prepend
                                                       ? "" : " no-prepend")) ;
  vty_out (vty, ", %s link\n",
                   (prun->rp.sort == BGP_PEER_IBGP) ? "internal" : "external") ;

  /* Description.
   */
  if (prun->rp.desc != NULL)
    vty_out (vty, " Description: %s\n", prun->rp.desc) ;

  /* Peer-group
   */
  if (prun->c->group)
    vty_out (vty, " Member of peer-group %s for session parameters\n",
                                                     peer->c->group->name);

  /* Administrative shutdown.
   */
  if (prun->idle & bgp_pisShutdown)
    vty_out (vty, " Administratively shut down\n");

  /* BGP Version.
   */
  vty_out (vty, "  BGP version 4");
  vty_out (vty, ", remote router ID %s%s\n",
                    siptoa(AF_INET, &prun->rp.sargs_conf.remote_id).str,
                     (prun->state == bgp_pEstablished) ? ""
                                                       : " (in last session)") ;
  /* Confederation
   */
  if (bgp_confederation_peers_check (brun, prun->rp.sargs_conf.remote_as))
    vty_out (vty, "  Neighbor under common administration\n");

  /* Status.
   */
  vty_out (vty, "  BGP state = %s",
                       bgp_peer_idle_state_str(prun->state, prun->idle).str) ;

  if (prun->state == bgp_pEstablished)
    vty_out (vty, ", up for %-8s", peer_uptime (prun->uptime).str) ;

  /* TODO: what is state "Active" now?  pStarted ? */
#if 0
  else if (prun->status == Active)
    {
      if (CHECK_FLAG (prun->c_flags, PEER_FLAG_PASSIVE))
        vty_out (vty, " (passive)");
      else if (prun->nsf_restarting)
        vty_out (vty, " (NSF passive)");
    }
#endif

  vty_out (vty, "\n");

  /* read timer and holdtime/keepalive
   */
  vty_out (vty, "  Last read %s", peer_uptime (prun->readtime).str);
  if (prun->state == bgp_pEstablished)
    vty_out (vty, " -- current "
                      "hold time is %u, keepalive interval is %u seconds\n",
                                          prun->session->sargs->holdtime_secs,
                                          prun->session->sargs->keepalive_secs) ;
  else
    vty_out (vty, " -- configured "
                      "hold time is %u, keepalive interval is %u seconds\n",
        prun->rp.sargs_conf.holdtime_secs, prun->rp.sargs_conf.keepalive_secs) ;

  /* Capabilities.
   */
  established_gr = false ;

  if (prun->state == bgp_pEstablished)
    {
      bgp_sargs args_sent, args_recv, args ;

      args_sent = prun->session->open_sent->sargs ;
      args_recv = prun->session->open_recv->sargs ;
      args      = prun->session->sargs ;

      vty_out (vty, "  Neighbor capabilities:\n");

      if (args_sent->can_capability)
        {
          if (!args_recv->can_capability)
            vty_out(vty, "    capabilities sent, but none received") ;
        }
      else
        {
          if (args_sent->cap_suppressed)
            vty_out(vty, "    peer refused capabilities") ;
          else
            vty_out(vty, "    'dont-capability-negotiate'") ;

          if (args_recv->can_capability)
            vty_out(vty, " BUT some received\n") ;
          else
            vty_out(vty, " and none received\n") ;
        } ;

      /* AS4
       */
      if ((args_sent->can_as4) || (args_sent->can_as4))
        {
          vty_out (vty, "    4 Byte AS:");
          if (args_sent->can_as4)
            vty_out (vty, " advertised%s", (args_recv->can_as4) ? " and"
                                                                : "") ;
          if (args_recv->can_as4)
            vty_out (vty, " received");
          vty_out (vty, "\n");
        }

      /* Multiprotocol Extensions
       */
      for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
        {
          qafx_bit_t qb ;

          qb = qafx_bit(qafx) ;

          if ((args_sent->can_af |args_recv->can_af | args->can_af) & qb)
            {
              const char* and ;

              vty_out (vty, "    Address family %s:", qafx_string(qafx));

              /* args_sent->can_af registers which afi/safi have been
               * advertised, explicitly by MP-Ext or implicitly.
               */
              and = "" ;
              if (args_sent->can_af & qb)
                {
                  if      (args_sent->can_mp_ext)
                    vty_out(vty, " advertised") ;
                  else
                    vty_out(vty, " implied") ;

                  and = " and" ;
                } ;

              /* args_recv->can_af registers which afi/safi were announced, or
               * implicitly announced.
               *
               * So, if is not args_recv->can_af, but is args->can_af, then it
               * must have been forced !
               */
              if      (args_recv->can_af & qb)
                {
                  if (args_recv->can_mp_ext)
                    vty_out(vty, "%s received", and) ;
                  else
                    vty_out(vty, "%s implied", and) ;
                }
              else if (args->can_af & qb)
                vty_out(vty, "%s forced", and) ;

              /* args->can_af is the final result.
               */
              if (args->can_af & qb)
                vty_out (vty, " -- in use") ;

              vty_out (vty, "\n");
            } ;
        } ;

      /* Route Refresh
       */
      if ( (args_sent->can_rr != bgp_form_none) ||
           (args_recv->can_rr != bgp_form_none) )
        {
          const char* adv_tag ;
          const char* rcv_tag ;

          adv_tag = "" ;
          if (args_sent->can_rr == bgp_form_pre)
            adv_tag = "(old)" ;

          rcv_tag = "" ;
          if (args_recv->can_rr == bgp_form_pre)
            rcv_tag = "(old)" ;

          vty_out (vty, "    Route refresh:");
          if (args_sent->can_rr != bgp_form_none)
            vty_out (vty, " advertised%s%s", adv_tag,
                        ((args_recv->can_rr != bgp_form_none) ? " and" : "")) ;
          if (args_recv->can_rr != bgp_form_none)
            vty_out (vty, " received%s", rcv_tag) ;
          vty_out (vty, "\n");
        }

      /* Graceful Restart
       */
      established_gr = args->gr.can ;

      if (args_sent->gr.can || args_recv->gr.can)
        {
          vty_out (vty, "    Graceful Restart Capability:");
          if (args_sent->gr.can)
            vty_out (vty, " advertised%s", (args_recv->gr.can ? " and" : ""));
          if (args_recv->gr.can)
            vty_out (vty, " received");
          vty_out (vty, "\n");

          if (args_recv->gr.can)
            {
              int restart_af_count = 0;

              vty_out (vty, "      Remote Restart timer is %d seconds\n",
                                                           prun->v_gr_restart) ;
              vty_out (vty, "      Address families by peer:\n"
                            "        ") ;

              for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
                {
                  qafx_bit_t qb ;

                  qb = qafx_bit(qafx) ;

                  if (args_recv->gr.can_preserve & qb)
                    {
                      vty_out (vty, "%s%s(%s)", (restart_af_count ? ", " : ""),
                                                qafx_string(qafx),
                          (args_recv->gr.can_preserve & qb ? "preserved"
                                                           : "not preserved")) ;
                      restart_af_count++;
                    } ;
                } ;

              if (restart_af_count == 0)
                vty_out (vty, "none");
              vty_out (vty, "\n") ;
            } ;
        } ;

      /* Dynamic
       */
      if (args_sent->can_dynamic || args_recv->can_dynamic)
        {
          vty_out (vty, "    Dynamic:");
          if (args_sent->can_dynamic)
            vty_out (vty, " advertised%s",
                                         args_recv->can_dynamic ? " and" : "") ;
          if (args_recv->can_dynamic)
            vty_out (vty, " received") ;
          vty_out (vty, "\n");
        } ;

      /* Dynamic Deprecated
       */
      if (args_sent->can_dynamic_dep || args_recv->can_dynamic_dep)
        {
          vty_out (vty, "    Dynamic (deprecated):");
          if (args_sent->can_dynamic_dep)
            vty_out (vty, " advertised%s",
                                     args_recv->can_dynamic_dep ? " and" : "") ;
          if (args_recv->can_dynamic_dep)
            vty_out (vty, " received") ;
          vty_out (vty, "\n");
        } ;
    } ;

  /* graceful restart information
   */
  if ( established_gr || (prun->t_gr_restart != NULL)
                      || (prun->t_gr_stale   != NULL) )
    {
      int eor_send_af_count = 0;
      int eor_receive_af_count = 0;

      vty_out (vty, "  Graceful Restart information:\n");

      if (prun->state == bgp_pEstablished)
        {
          vty_out (vty, "    End-of-RIB sent: ");
          for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
            {
              bgp_prib prib ;
              prib = prun->prib[qafx] ;

              if ((prib != NULL) && (prib->eor_sent))
                {
                  vty_out (vty, "%s%s", eor_send_af_count ? ", " : "",
                                                            qafx_string(qafx));
                  eor_send_af_count++;
                } ;
              } ;
          vty_out (vty, "\n");

          vty_out (vty, "    End-of-RIB received: ");
          for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
            {
              bgp_prib prib ;
              prib = prun->prib[qafx] ;

              if ((prib != NULL) && prib->eor_received)
                {
                  vty_out (vty, "%s%s", eor_receive_af_count ? ", " : "",
                                                            qafx_string(qafx));
                  eor_receive_af_count++;
                } ;
            } ;
          vty_out (vty, "\n");
        }

      if (prun->t_gr_restart)
        vty_out (vty, "    The remaining time of restart timer is %ld\n",
                              thread_timer_remain_second (prun->t_gr_restart)) ;

      if (prun->t_gr_stale)
        vty_out (vty, "    The remaining time of stalepath timer is %ld\n",
                                thread_timer_remain_second (prun->t_gr_stale)) ;
    }

  /* Packet counts.
   */
  vty_out (vty, "  Message statistics:\n");
  vty_out (vty, "    Inq depth is 0\n");
  vty_out (vty, "    Outq depth is %lu\n", (ulong)0 /* TODO */);
  vty_out (vty, "                         Sent       Rcvd\n");
  vty_out (vty, "    Opens:         %10u %10u\n", stats.open_out,
                                                  stats.open_in);
  vty_out (vty, "    Notifications: %10u %10u\n", stats.notify_out,
                                                  stats.notify_in);
  vty_out (vty, "    Updates:       %10u %10u\n", stats.update_out,
                                                  stats.update_in);
  vty_out (vty, "    Keepalives:    %10u %10u\n", stats.keepalive_out,
                                                  stats.keepalive_in);
  vty_out (vty, "    Route Refresh: %10u %10u\n", stats.refresh_out,
                                                  stats.refresh_in);
  vty_out (vty, "    Capability:    %10u %10u\n", stats.dynamic_cap_out,
                                                  stats.dynamic_cap_in);
  vty_out (vty, "    Total:         %10u %10u\n",
              (stats.open_out + stats.notify_out + stats.update_out +
               stats.keepalive_out + stats.refresh_out + stats.dynamic_cap_out),
              (stats.open_in + stats.notify_in + stats.update_in +
               stats.keepalive_in + stats.refresh_in + stats.dynamic_cap_in));

  /* advertisement-interval
   */
  vty_out (vty, "  Minimum time between advertisement runs is %d seconds\n",
                                                                 prun->rp.mrai_secs);

  /* Update-source.
   */
  if ((prun->rp.cops_conf.ifname[0] != '\0') ||
      (sockunion_family(&prun->rp.cops_conf.local_su) != AF_UNSPEC))
    {
#if 0
      if (prun->c->c_set & PEER_CONFIG_INTERFACE)
        {
          vty_out (vty, "  Interface is %s\n", prun->c_cops.ifname);
        }
      else
        {
#endif
          vty_out (vty, "  Update source is ");
          if (prun->rp.cops_conf.ifname[0] != '\0')
            vty_out (vty, "%s", prun->rp.cops_conf.ifname);
          else
            vty_out (vty, "%s", sutoa(&prun->rp.cops_conf.local_su).str);
          vty_out (vty, "\n");
#if 0
        } ;
#endif
    } ;

  /* Default weight
   */
  if (prun->rp.weight != 0)
    vty_out (vty, "  Default weight %d\n", prun->rp.weight);

  vty_out (vty, "\n");

  /* Address Family Information
   */
  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    if (prun->prib[qafx] != NULL)
      bgp_show_prun_afi (vty, prun, qafx);

  vty_out (vty, "  Connections established %d; dropped %d\n",
                                             prun->established, prun->dropped) ;

  if (! prun->dropped)
    vty_out (vty, "  Last reset never\n");
  else
    vty_out (vty, "  Last reset %s, due to %s\n",
                      peer_uptime (prun->resettime).str,
                          map_direct(bgp_peer_down_map, prun->last_reset).str) ;

  if (prun->idle & (bgp_pisMaxPrefixWait | bgp_pisMaxPrefixStop))
    {
      vty_out (vty,
          "  Peer had exceeded the max. no. of prefixes configured.\n") ;

      if (prun->idle & bgp_pisMaxPrefixStop)
        vty_out (vty, "  Needs 'clear ip bgp %s' to restore peering\n",
                                                                   prun->name) ;
      else
        vty_out (vty, "  Will restart %s in %ld seconds\n", prun->name,
                         (long)(qtimer_has_left(prun->qt_restart) / QTIME(1))) ;
    } ;

  /* EBGP Multihop and GTSM -- for these purposes eBGP includes Confed eBGP.
   */
  if (prun->rp.sort != BGP_PEER_IBGP)
    {
      if (prun->rp.cops_conf.gtsm)
        vty_out (vty, "  External BGP neighbor may be up to %d hops away"
                                                            " -- using GTSM.\n",
                                                       prun->rp.cops_conf.ttl) ;
      else if (prun->rp.cops_conf.ttl > 1)
        vty_out (vty, "  External BGP neighbor may be up to %d hops away.\n",
                                                       prun->rp.cops_conf.ttl) ;
    }

  /* Local address and remote address, if established.
   *
   * Also next-hop(s)
   */
  if (prun->state == bgp_pEstablished)
    {
      vty_out (vty, "Local host: %s, Local port: %u\n",
                         sutoa(&prun->session->cops->local_su).str,
                          ntohs(prun->session->cops->local_su.sin.sin_port)) ;

      vty_out (vty, "Foreign host: %s, Foreign port: %u\n",
                        sutoa(&prun->session->cops->remote_su).str,
                          ntohs(prun->session->cops->remote_su.sin.sin_port)) ;

      vty_out (vty, "Nexthop: %s\n", siptoa(AF_INET, &prun->nexthop.v4).str) ;
#ifdef HAVE_IPV6
      vty_out (vty, "Nexthop global: %s\n",
                                 siptoa(AF_INET6, &prun->nexthop.v6_global).str) ;
      vty_out (vty, "Nexthop local: %s\n",
                                  siptoa(AF_INET6, &prun->nexthop.v6_local).str) ;
      vty_out (vty, "BGP connection: %s\n",
               prun->shared_network ? "shared network" : "non shared network");
#endif /* HAVE_IPV6 */
    }

  /* TODO: Timer information. */
#if 0
  if (prun->t_start)
    vty_out (vty, "Next start timer due in %ld seconds%s",
             thread_timer_remain_second (prun->t_start), VTY_NEWLINE);
  if (prun->t_connect)
    vty_out (vty, "Next connect timer due in %ld seconds%s",
             thread_timer_remain_second (prun->t_connect), VTY_NEWLINE);
#endif

#if 0
  vty_out (vty, "Read thread: %s  Write thread: %s%s",
           prun->t_read ? "on" : "off",
           prun->t_write ? "on" : "off",
           VTY_NEWLINE);
#endif

#if 0   // reinstate showing any capability issues
  if (prun->session != NULL && prun->session->note != NULL
      && prun->session->note->code    == BGP_NOMC_OPEN
      && prun->session->note->subcode == BGP_NOMS_O_CAPABILITY)
    bgp_capability_vty_out (vty, peer);
#endif

  vty_out (vty, "%s", VTY_NEWLINE);
}

#if 0   // reinstate showing any capability issues

static void
bgp_capability_vty_out (struct vty *vty, bgp_peer peer)
{
  /* Standard header for capability TLV */
  struct capability_header
  {
    u_char code;
    u_char length;
  };

  /* Generic MP capability data */
  typedef struct capability_mp_data  capability_mp_data_t ;
  typedef struct capability_mp_data* capability_mp_data ;

  struct capability_mp_data
  {
    afi_t afi;
    u_char reserved;
    safi_t safi;
  };
  CONFIRM(offsetof(capability_mp_data_t, reserved) == 2) ;
  CONFIRM(offsetof(capability_mp_data_t, safi) == 3) ;

  #pragma pack(1)
  struct capability_orf_entry
  {
    struct capability_mp_data mpc;
    u_char num;
    struct {
      u_char ptype;
      u_char mode;
    } orfs[];
  } __attribute__ ((packed));
  #pragma pack()

  struct capability_as4
  {
    uint32_t as4;
  };

  struct graceful_restart_af
  {
    afi_t afi;
    safi_t safi;
    u_char flag;
  };

  struct capability_gr
  {
    u_int16_t restart_flag_time;
    struct graceful_restart_af gr[];
  };

  /* Cooperative Route Filtering Capability.  */

  /* ORF Type */
  #define ORF_TYPE_PREFIX                64
  #define ORF_TYPE_PREFIX_OLD           128

  /* ORF Mode */
  #define ORF_MODE_RECEIVE                1
  #define ORF_MODE_SEND                   2
  #define ORF_MODE_BOTH                   3

  /* Capability Message Action.  */
  #define CAPABILITY_ACTION_SET           0
  #define CAPABILITY_ACTION_UNSET         1

  /* Graceful Restart */
  #define RESTART_R_BIT              0x8000
  #define RESTART_F_BIT              0x80

#if 0
  static const struct message orf_type_str[] =
  {
    { ORF_TYPE_PREFIX,            "Prefixlist"            },
    { ORF_TYPE_PREFIX_OLD,        "Prefixlist (old)"      },
  };
  static const int orf_type_str_max
          = sizeof(orf_type_str)/sizeof(orf_type_str[0]);

  static const struct message orf_mode_str[] =
  {
    { ORF_MODE_RECEIVE,   "Receive"       },
    { ORF_MODE_SEND,      "Send"          },
    { ORF_MODE_BOTH,      "Both"          },
  };
  static const int orf_mode_str_max
           = sizeof(orf_mode_str)/sizeof(orf_mode_str[0]);

  static const struct message capcode_str[] =
  {
    { BGP_CAN_MP_EXT    ,                 "MultiProtocol Extensions"      },
    { BGP_CAN_R_REFRESH,                  "Route Refresh"                 },
    { BGP_CAN_ORF,                        "Cooperative Route Filtering"   },
    { BGP_CAN_G_RESTART,                  "Graceful Restart"              },
    { BGP_CAN_AS4,                        "4-octet AS number"             },
    { BGP_CAN_DYNAMIC_CAP_dep,            "Dynamic"                       },
    { BGP_CAN_R_REFRESH_pre,              "Route Refresh (Old)"           },
    { BGP_CAN_ORF_pre,                    "ORF (Old)"                     },
  };
  static const int capcode_str_max = sizeof(capcode_str)/sizeof(capcode_str[0]);

  /* Minimum sizes for length field of each cap (so not inc. the header)
   */
  static const size_t cap_minsizes[] =
  {
    [BGP_CAN_MP_EXT]              = sizeof (struct capability_mp_data),
    [BGP_CAN_R_REFRESH]           = BGP_CAP_RRF_L,
    [BGP_CAN_ORF]                 = sizeof (struct capability_orf_entry),
    [BGP_CAN_G_RESTART]           = sizeof (struct capability_gr),
    [BGP_CAN_AS4]                 = BGP_CAP_AS4_L,
    [BGP_CAN_DYNAMIC_CAP_dep]     = BGP_CAP_DYN_L,
    [BGP_CAN_R_REFRESH_pre]       = BGP_CAP_RRF_L,
    [BGP_CAN_ORF_pre]             = sizeof (struct capability_orf_entry),
  };
#endif

  char *pnt;
  char *end;
  struct capability_mp_data mpc;
  struct capability_header *hdr;

  if ((peer == NULL) || (prun->session == NULL)
                     || (prun->session->note == NULL))
    return;

  pnt = (char*)prun->session->note->data;
  end = pnt + prun->session->note->length;

  while (pnt < end)
    {
      if (pnt + sizeof (struct capability_mp_data) + 2 > end)
        return;

      hdr = (struct capability_header *)pnt;
      if (pnt + hdr->length + 2 > end)
        return;

      memcpy (&mpc, pnt + 2, sizeof(struct capability_mp_data));

      if (hdr->code == BGP_CAN_MP_EXT)
        {
          vty_out (vty, "  Capability error for: Multi protocol ");

          switch (ntohs (mpc.afi))
            {
            case iAFI_IP:
              vty_out (vty, "AFI IPv4, ");
              break;
            case iAFI_IP6:
              vty_out (vty, "AFI IPv6, ");
              break;
            default:
              vty_out (vty, "AFI Unknown %d, ", ntohs (mpc.afi));
              break;
            }
          switch (mpc.safi)
            {
            case iSAFI_Unicast:
              vty_out (vty, "SAFI Unicast");
              break;
            case iSAFI_Multicast:
              vty_out (vty, "SAFI Multicast");
              break;
            case iSAFI_MPLS_VPN:
              vty_out (vty, "SAFI MPLS-labeled VPN");
              break;
            default:
              vty_out (vty, "SAFI Unknown %d ", mpc.safi);
              break;
            }
          vty_out (vty, "%s", VTY_NEWLINE);
        }
      else if (hdr->code >= 128)
        vty_out (vty, "  Capability error: vendor specific capability code %d",
                                                                   hdr->code);
      else
        vty_out (vty, "  Capability error: unknown capability code %d",
                                                                   hdr->code);
      pnt += hdr->length + 2;
    }
}
#endif

static int
bgp_show_neighbor (vty vty, bgp_run brun,
                   enum show_type type, union sockunion *su)
{
  bgp_prun prun;
  uint     i ;
  bool     found ;

  found = false ;
  i = 0 ;
  while ((prun = vector_get_item(brun->pruns, i++)) != NULL)
    {
      switch (type)
        {
          case show_all:
            bgp_show_peer (vty, prun);
            break;

          case show_peer:
            if (sockunion_same (&prun->rp.cops_conf.remote_su, su))
              {
                bgp_show_peer (vty, prun);
                found = true ;
              }
            break;

          default:
            break ;
        }
    }

  if (type == show_peer && ! found)
    vty_out (vty, "%% No such neighbor\n");

  return CMD_SUCCESS;
}

static int
bgp_show_neighbor_vty (vty vty, chs_c name, enum show_type type, chs_c ip_str)
{
  int ret;
  bgp_run brun ;
  union sockunion su;

  if (ip_str)
    {
      ret = str2sockunion (ip_str, &su);
      if (ret < 0)
        {
          vty_out (vty, "%% Malformed address: %s%s", ip_str, VTY_NEWLINE);
          return CMD_WARNING;
        }
    }

  brun = bgp_run_lookup_vty(vty, name) ;
  if (brun == NULL)
    return CMD_WARNING ;

  bgp_show_neighbor (vty, brun, type, &su);

  return CMD_SUCCESS;
}

/* "show ip bgp neighbors" commands.  */
DEFUN (show_ip_bgp_neighbors,
       show_ip_bgp_neighbors_cmd,
       "show ip bgp neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")
{
  return bgp_show_neighbor_vty (vty, NULL, show_all, NULL);
}

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_ipv4_neighbors_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_all_neighbors_cmd,
       "show ip bgp vpnv4 all neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_ip_bgp_vpnv4_rd_neighbors_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_neighbors_cmd,
       "show bgp neighbors",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_neighbors,
       show_bgp_ipv6_neighbors_cmd,
       "show bgp ipv6 neighbors",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFUN (show_ip_bgp_neighbors_peer,
       show_ip_bgp_neighbors_peer_cmd,
       "show ip bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  return bgp_show_neighbor_vty (vty, NULL, show_peer, argv[argc - 1]);
}

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_ipv4_neighbors_peer_cmd,
       "show ip bgp ipv4 (unicast|multicast) neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_all_neighbors_peer_cmd,
       "show ip bgp vpnv4 all neighbors A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_ip_bgp_vpnv4_rd_neighbors_peer_cmd,
       "show ip bgp vpnv4 rd ASN:nn_or_IP-address:nn neighbors A.B.C.D",
       SHOW_STR
       IP_STR
       BGP_STR
       "Display VPNv4 NLRI specific information\n"
       "Display information about all VPNv4 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_neighbors_peer_cmd,
       "show bgp neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_neighbors_peer,
       show_bgp_ipv6_neighbors_peer_cmd,
       "show bgp ipv6 neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

DEFUN (show_ip_bgp_instance_neighbors,
       show_ip_bgp_instance_neighbors_cmd,
       "show ip bgp view WORD neighbors",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n")
{
  return bgp_show_neighbor_vty (vty, argv[0], show_all, NULL);
}

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_neighbors_cmd,
       "show bgp view WORD neighbors",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n")

ALIAS (show_ip_bgp_instance_neighbors,
       show_bgp_instance_ipv6_neighbors_cmd,
       "show bgp view WORD ipv6 neighbors",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n")

DEFUN (show_ip_bgp_instance_neighbors_peer,
       show_ip_bgp_instance_neighbors_peer_cmd,
       "show ip bgp view WORD neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")
{
  return bgp_show_neighbor_vty (vty, argv[0], show_peer, argv[1]);
}

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_neighbors_peer_cmd,
       "show bgp view WORD neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

ALIAS (show_ip_bgp_instance_neighbors_peer,
       show_bgp_instance_ipv6_neighbors_peer_cmd,
       "show bgp view WORD ipv6 neighbors (A.B.C.D|X:X::X:X)",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Neighbor to display information about\n")

/* Show BGP's AS paths internal data.  There are both `show ip bgp
   paths' and `show ip mbgp paths'.  Those functions results are the
   same.*/
DEFUN (show_ip_bgp_paths,
       show_ip_bgp_paths_cmd,
       "show ip bgp paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Path information\n")
{
  as_path_print_all_vty (vty);
  return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_ipv4_paths,
       show_ip_bgp_ipv4_paths_cmd,
       "show ip bgp ipv4 (unicast|multicast) paths",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Path information\n")
{
  as_path_print_all_vty (vty);
  return CMD_SUCCESS;
}

/* Show BGP's community internal data. */
DEFUN (show_ip_bgp_community_info,
       show_ip_bgp_community_info_cmd,
       "show ip bgp community-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp community information\n")
{
  attr_community_print_all_vty (vty) ;

  return CMD_SUCCESS;
}

/* Show BGP's ecommunity internal data. */
DEFUN (show_ip_bgp_ecommunity_info,
       show_ip_bgp_ecommunity_info_cmd,
       "show ip bgp extcommunity-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp extcommunity information\n")
{
  attr_ecommunity_print_all_vty (vty) ;

  return CMD_SUCCESS;
}


DEFUN (show_ip_bgp_attr_info,
       show_ip_bgp_attr_info_cmd,
       "show ip bgp attribute-info",
       SHOW_STR
       IP_STR
       BGP_STR
       "List all bgp attribute information\n")
{
  bgp_attr_show_all (vty);
  return CMD_SUCCESS;
}

static int
bgp_write_rsclient_summary (vty vty, bgp_peer rsclient, qafx_t qafx)
{
  char rmbuf[14];
  const char *rmname;
  int len;
  int count = 0;
  bgp_prib prib ;
  bgp_prun prun ;

  count = 0 ;

  if (rsclient->ptype == PEER_TYPE_GROUP)
    {
      for (rsclient = ddl_head(rsclient->c->group.members) ;
           rsclient != NULL ;
           rsclient = ddl_next(rsclient->c, member.list))
        {
          prun = rsclient->prun ;

          if (prun == NULL)
            continue ;

          count++;
          bgp_write_rsclient_summary (vty, rsclient, qafx);
        }
      return count;
    }

  prun = rsclient->prun ;
  if (prun == NULL)
    return 0 ;

  prib = prun->prib[qafx] ;
  if (prib == NULL)
    return 0 ;

  vty_out (vty, "%s", rsclient->name);
  len = 16 - strlen(rsclient->name) ;

  if (len < 1)
    vty_out (vty, "%s%*s", VTY_NEWLINE, 16, " ");
  else
    vty_out (vty, "%*s", len, " ");

  vty_out (vty, "4 ");

  vty_out (vty, "%11d ", prun->rp.sargs_conf.remote_as);

  rmname = route_map_get_name(prib->rmap[RMAP_EXPORT]);
  if ( rmname && strlen (rmname) > 13 )
    {
      sprintf (rmbuf, "%13s", "...");
      rmname = strncpy (rmbuf, rmname, 10);
    }
  else if (! rmname)
    rmname = "<none>";
  vty_out (vty, " %13s ", rmname);

  rmname = route_map_get_name(prib->rmap[RMAP_IMPORT]);
  if ( rmname && strlen (rmname) > 13 )
    {
      sprintf (rmbuf, "%13s", "...");
      rmname = strncpy (rmbuf, rmname, 10);
    }
  else if (! rmname)
    rmname = "<none>";
  vty_out (vty, " %13s ", rmname);

  vty_out (vty, "%8s", peer_uptime (prun->uptime).str);
  vty_out (vty, " %-11s",
                 bgp_peer_idle_state_str(prun->state, prun->idle).str) ;

  vty_out (vty, "\n");

  return 1;
}

static int
bgp_show_rsclient_summary (struct vty *vty, bgp_run brun, qafx_t qafx)
{
  bgp_prib   prib ;
  uint count = 0;

  /* Header string for each address family. */
  static char header[] =
       "Neighbor        V    AS  Export-Policy  Import-Policy  Up/Down  State";

  if (brun->rib[qafx] != NULL)
    prib = ddl_head(brun->rib[qafx]->pribs) ;
  else
    prib = NULL ;

  for (; prib != NULL ; prib = ddl_next(prib, prib_list))
    {
      bgp_prun   prun ;

      if (!prib->rp.is_route_server_client)
        continue ;

      prun = prib->prun ;

      if (count == 0)
        {
          vty_out (vty, "Route Server's BGP router identifier %s\n",
                               siptoa(AF_INET, &prun->brun->rp.router_id).str) ;
          vty_out (vty, "Route Server's local AS number %u\n",
                                                         prun->brun->rp.my_as);

          vty_out (vty, "\n"
                        "%s\n", header) ;
        }

      count += bgp_write_rsclient_summary (vty, prun, qafx);
    }

  if (count)
    vty_out (vty, "\n"
                  "Total number of Route Server Clients %u\n", count) ;
  else
    vty_out (vty, "No %s Route Server Client is configured\n",
                                   get_qAFI(qafx) == qAFI_IP ? "IPv4" : "IPv6");
  return CMD_SUCCESS;
}

static int
bgp_show_rsclient_summary_vty (vty vty, chs_c view_name, qafx_t qafx)
{
  bgp_run brun ;

  brun = bgp_run_lookup_vty(vty, view_name) ;

  if (brun == NULL)
    return CMD_WARNING;

  bgp_show_rsclient_summary (vty, brun, qafx);

  return CMD_SUCCESS;
}

/* 'show bgp rsclient' commands. */
DEFUN (show_ip_bgp_rsclient_summary,
       show_ip_bgp_rsclient_summary_cmd,
       "show ip bgp rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, NULL, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_instance_rsclient_summary,
       show_ip_bgp_instance_rsclient_summary_cmd,
       "show ip bgp view WORD rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  const char* name ;

  name = argv[0] ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx_ipv4_unicast);
}

DEFUN (show_ip_bgp_ipv4_rsclient_summary,
      show_ip_bgp_ipv4_rsclient_summary_cmd,
      "show ip bgp ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  name = NULL ;
  cast = argv[0] ;

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

DEFUN (show_ip_bgp_instance_ipv4_rsclient_summary,
      show_ip_bgp_instance_ipv4_rsclient_summary_cmd,
      "show ip bgp view WORD ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       IP_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  name = argv[0] ;
  cast = argv[1] ;

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

DEFUN (show_bgp_instance_ipv4_safi_rsclient_summary,
       show_bgp_instance_ipv4_safi_rsclient_summary_cmd,
       "show bgp view WORD ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  if (argc == 1)
    {
      name = NULL ;
      cast = argv[0] ;
    }
  else
    {
      name = argv[0] ;
      cast = argv[1] ;
    }

  qafx = (*cast == 'm') ? qafx_ipv4_multicast : qafx_ipv4_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

ALIAS (show_bgp_instance_ipv4_safi_rsclient_summary,
       show_bgp_ipv4_safi_rsclient_summary_cmd,
       "show bgp ipv4 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

#ifdef HAVE_IPV6
DEFUN (show_bgp_rsclient_summary,
       show_bgp_rsclient_summary_cmd,
       "show bgp rsclient summary",
       SHOW_STR
       BGP_STR
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, NULL, qafx_ipv6_unicast);
}

DEFUN (show_bgp_instance_rsclient_summary,
       show_bgp_instance_rsclient_summary_cmd,
       "show bgp view WORD rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  return bgp_show_rsclient_summary_vty (vty, argv[0], qafx_ipv6_unicast);
}

ALIAS (show_bgp_rsclient_summary,
      show_bgp_ipv6_rsclient_summary_cmd,
      "show bgp ipv6 rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

ALIAS (show_bgp_instance_rsclient_summary,
      show_bgp_instance_ipv6_rsclient_summary_cmd,
       "show bgp view WORD ipv6 rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

DEFUN (show_bgp_instance_ipv6_safi_rsclient_summary,
       show_bgp_instance_ipv6_safi_rsclient_summary_cmd,
       "show bgp view WORD ipv6 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "BGP view\n"
       "View name\n"
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")
{
  qafx_t qafx ;
  const char* name ;
  const char* cast ;

  if (argc == 1)
    {
      name = NULL ;
      cast = argv[0] ;
    }
  else
    {
      name = argv[0] ;
      cast = argv[1] ;
    }

  qafx = (*cast == 'm') ? qafx_ipv6_multicast : qafx_ipv6_unicast ;

  return bgp_show_rsclient_summary_vty (vty, name, qafx);
}

ALIAS (show_bgp_instance_ipv6_safi_rsclient_summary,
       show_bgp_ipv6_safi_rsclient_summary_cmd,
       "show bgp ipv6 (unicast|multicast) rsclient summary",
       SHOW_STR
       BGP_STR
       "Address family\n"
       "Address Family modifier\n"
       "Address Family modifier\n"
       "Information about Route Server Clients\n"
       "Summary of all Route Server Clients\n")

#endif /* HAVE IPV6 */

/*==============================================================================
 * Table of bgp_show commands
 */
CMD_INSTALL_TABLE(static, bgp_show_cmd_table, BGPD) =
{
  { VIEW_NODE,       &show_ip_bgp_cmd                                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_cmd                              },
  { VIEW_NODE,       &show_bgp_ipv4_safi_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_route_cmd                             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_route_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv4_safi_route_cmd                      },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_route_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_prefix_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv4_safi_prefix_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_view_cmd                              },
  { VIEW_NODE,       &show_ip_bgp_view_route_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_view_prefix_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_regexp_cmd                            },
  { VIEW_NODE,       &show_ip_bgp_ipv4_regexp_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_prefix_list_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_filter_list_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_ipv4_filter_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_route_map_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_route_map_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_cidr_only_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_cidr_only_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_community_all_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_all_cmd                },
  { VIEW_NODE,       &show_ip_bgp_community_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_community2_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_community3_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_community4_cmd                        },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community2_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community3_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community4_cmd                   },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community_all_cmd          },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community_cmd              },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community2_cmd             },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community3_cmd             },
  { VIEW_NODE,       &show_bgp_view_afi_safi_community4_cmd             },
  { VIEW_NODE,       &show_ip_bgp_community_exact_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_community2_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_community3_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_community4_exact_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_exact_cmd              },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community2_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community3_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community4_exact_cmd             },
  { VIEW_NODE,       &show_ip_bgp_community_list_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_list_cmd               },
  { VIEW_NODE,       &show_ip_bgp_community_list_exact_cmd              },
  { VIEW_NODE,       &show_ip_bgp_ipv4_community_list_exact_cmd         },
  { VIEW_NODE,       &show_ip_bgp_prefix_longer_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_ipv4_prefix_longer_cmd                },
  { VIEW_NODE,       &show_ip_bgp_neighbor_advertised_route_cmd         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_advertised_route_cmd    },
  { VIEW_NODE,       &show_ip_bgp_neighbor_received_routes_cmd          },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_received_routes_cmd     },
  { VIEW_NODE,       &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd },
  { VIEW_NODE,       &show_ip_bgp_neighbor_routes_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_routes_cmd              },
  { VIEW_NODE,       &show_ip_bgp_neighbor_received_prefix_filter_cmd   },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_ip_bgp_dampened_paths_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_flap_statistics_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_flap_address_cmd                      },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_flap_cidr_only_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_flap_regexp_cmd                       },
  { VIEW_NODE,       &show_ip_bgp_flap_filter_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_list_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_flap_prefix_longer_cmd                },
  { VIEW_NODE,       &show_ip_bgp_flap_route_map_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_neighbor_flap_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_neighbor_damp_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_rsclient_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_cmd                   },
  { VIEW_NODE,       &show_ip_bgp_rsclient_route_cmd                    },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { VIEW_NODE,       &show_ip_bgp_rsclient_prefix_cmd                   },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { VIEW_NODE,       &show_ip_bgp_view_neighbor_advertised_route_cmd    },
  { VIEW_NODE,       &show_ip_bgp_view_neighbor_received_routes_cmd     },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_cmd                     },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_cmd              },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_route_cmd               },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { VIEW_NODE,       &show_ip_bgp_view_rsclient_prefix_cmd              },
  { VIEW_NODE,       &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },

  /* Restricted node: VIEW_NODE - (set of dangerous commands) */
  { RESTRICTED_NODE, &show_ip_bgp_route_cmd                             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_route_cmd                        },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_route_cmd                      },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_prefix_cmd                            },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_prefix_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_prefix_cmd                     },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_view_route_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_view_prefix_cmd                       },
  { RESTRICTED_NODE, &show_ip_bgp_community_cmd                         },
  { RESTRICTED_NODE, &show_ip_bgp_community2_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_community3_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_community4_cmd                        },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_cmd                   },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community_all_cmd          },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community_cmd              },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community2_cmd             },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community3_cmd             },
  { RESTRICTED_NODE, &show_bgp_view_afi_safi_community4_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_community_exact_cmd                   },
  { RESTRICTED_NODE, &show_ip_bgp_community2_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_community3_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_community4_exact_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community_exact_cmd              },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community2_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community3_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_community4_exact_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_route_cmd                    },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_prefix_cmd                   },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { RESTRICTED_NODE, &show_ip_bgp_view_rsclient_route_cmd               },
  { RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { RESTRICTED_NODE, &show_ip_bgp_view_rsclient_prefix_cmd              },
  { RESTRICTED_NODE, &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },
  { ENABLE_NODE,     &show_ip_bgp_cmd                                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_cmd                              },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_route_cmd                             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_route_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_route_cmd                      },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_route_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_route_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_prefix_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_prefix_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_prefix_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_prefix_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_view_cmd                              },
  { ENABLE_NODE,     &show_ip_bgp_view_route_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_view_prefix_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_regexp_cmd                            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_regexp_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_prefix_list_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_filter_list_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_filter_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_route_map_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_route_map_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_cidr_only_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_cidr_only_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_community_all_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_all_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_community_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_community2_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_community3_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_community4_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community2_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community3_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community4_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community_all_cmd          },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community_cmd              },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community2_cmd             },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community3_cmd             },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_community4_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_community_exact_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_community2_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_community3_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_community4_exact_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_exact_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community2_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community3_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community4_exact_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_community_list_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_list_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_community_list_exact_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_community_list_exact_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_prefix_longer_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_prefix_longer_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_advertised_route_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_advertised_route_cmd    },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_received_routes_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_received_routes_cmd     },
  { ENABLE_NODE,     &show_bgp_view_afi_safi_neighbor_adv_recd_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_routes_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_routes_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_received_prefix_filter_cmd   },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_ip_bgp_dampened_paths_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_flap_statistics_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_flap_address_cmd                      },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_flap_cidr_only_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_flap_regexp_cmd                       },
  { ENABLE_NODE,     &show_ip_bgp_flap_filter_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_list_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_flap_prefix_longer_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_flap_route_map_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_flap_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_neighbor_damp_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_route_cmd                    },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_route_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_prefix_cmd                   },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_prefix_cmd            },
  { ENABLE_NODE,     &show_ip_bgp_view_neighbor_advertised_route_cmd    },
  { ENABLE_NODE,     &show_ip_bgp_view_neighbor_received_routes_cmd     },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_cmd                     },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_cmd              },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_route_cmd               },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_route_cmd        },
  { ENABLE_NODE,     &show_ip_bgp_view_rsclient_prefix_cmd              },
  { ENABLE_NODE,     &show_bgp_view_ipv4_safi_rsclient_prefix_cmd       },

  { ENABLE_NODE,     &show_ip_bgp_neighbor_prefix_counts_cmd            },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbor_prefix_counts_cmd       },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_neighbor_prefix_counts_cmd      },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_prefix_counts_cmd          },

  { VIEW_NODE,       &show_bgp_cmd                                      },
  { VIEW_NODE,       &show_bgp_ipv6_cmd                                 },
  { VIEW_NODE,       &show_bgp_ipv6_safi_cmd                            },
  { VIEW_NODE,       &show_bgp_route_cmd                                },
  { VIEW_NODE,       &show_bgp_ipv6_route_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_safi_route_cmd                      },
  { VIEW_NODE,       &show_bgp_prefix_cmd                               },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_safi_prefix_cmd                     },
  { VIEW_NODE,       &show_bgp_regexp_cmd                               },
  { VIEW_NODE,       &show_bgp_ipv6_regexp_cmd                          },
  { VIEW_NODE,       &show_bgp_prefix_list_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_list_cmd                     },
  { VIEW_NODE,       &show_bgp_filter_list_cmd                          },
  { VIEW_NODE,       &show_bgp_ipv6_filter_list_cmd                     },
  { VIEW_NODE,       &show_bgp_route_map_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_route_map_cmd                       },
  { VIEW_NODE,       &show_bgp_community_all_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_community_all_cmd                   },
  { VIEW_NODE,       &show_bgp_community_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_community_cmd                       },
  { VIEW_NODE,       &show_bgp_community2_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community2_cmd                      },
  { VIEW_NODE,       &show_bgp_community3_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community3_cmd                      },
  { VIEW_NODE,       &show_bgp_community4_cmd                           },
  { VIEW_NODE,       &show_bgp_ipv6_community4_cmd                      },
  { VIEW_NODE,       &show_bgp_community_exact_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_community_exact_cmd                 },
  { VIEW_NODE,       &show_bgp_community2_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community2_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community3_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community3_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community4_exact_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_community4_exact_cmd                },
  { VIEW_NODE,       &show_bgp_community_list_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_community_list_cmd                  },
  { VIEW_NODE,       &show_bgp_community_list_exact_cmd                 },
  { VIEW_NODE,       &show_bgp_ipv6_community_list_exact_cmd            },
  { VIEW_NODE,       &show_bgp_prefix_longer_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_prefix_longer_cmd                   },
  { VIEW_NODE,       &show_bgp_neighbor_advertised_route_cmd            },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_advertised_route_cmd       },
  { VIEW_NODE,       &show_bgp_neighbor_received_routes_cmd             },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_received_routes_cmd        },
  { VIEW_NODE,       &show_bgp_neighbor_routes_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_routes_cmd                 },
  { VIEW_NODE,       &show_bgp_neighbor_received_prefix_filter_cmd      },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_neighbor_flap_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_flap_cmd                   },
  { VIEW_NODE,       &show_bgp_neighbor_damp_cmd                        },
  { VIEW_NODE,       &show_bgp_ipv6_neighbor_damp_cmd                   },
  { VIEW_NODE,       &show_bgp_rsclient_cmd                             },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_cmd                   },
  { VIEW_NODE,       &show_bgp_rsclient_route_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { VIEW_NODE,       &show_bgp_rsclient_prefix_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { VIEW_NODE,       &show_bgp_view_cmd                                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_cmd                            },
  { VIEW_NODE,       &show_bgp_view_route_cmd                           },
  { VIEW_NODE,       &show_bgp_view_ipv6_route_cmd                      },
  { VIEW_NODE,       &show_bgp_view_prefix_cmd                          },
  { VIEW_NODE,       &show_bgp_view_ipv6_prefix_cmd                     },
  { VIEW_NODE,       &show_bgp_view_neighbor_advertised_route_cmd       },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_advertised_route_cmd  },
  { VIEW_NODE,       &show_bgp_view_neighbor_received_routes_cmd        },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_received_routes_cmd   },
  { VIEW_NODE,       &show_bgp_view_neighbor_routes_cmd                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_routes_cmd            },
  { VIEW_NODE,       &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { VIEW_NODE,       &show_bgp_view_neighbor_flap_cmd                   },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_flap_cmd              },
  { VIEW_NODE,       &show_bgp_view_neighbor_damp_cmd                   },
  { VIEW_NODE,       &show_bgp_view_ipv6_neighbor_damp_cmd              },
  { VIEW_NODE,       &show_bgp_view_rsclient_cmd                        },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_cmd              },
  { VIEW_NODE,       &show_bgp_view_rsclient_route_cmd                  },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { VIEW_NODE,       &show_bgp_view_rsclient_prefix_cmd                 },
  { VIEW_NODE,       &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },

  /* Restricted:
   * VIEW_NODE - (set of dangerous commands) - (commands dependent on prev)
   */
  { RESTRICTED_NODE, &show_bgp_route_cmd                                },
  { RESTRICTED_NODE, &show_bgp_ipv6_route_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_route_cmd                      },
  { RESTRICTED_NODE, &show_bgp_prefix_cmd                               },
  { RESTRICTED_NODE, &show_bgp_ipv6_prefix_cmd                          },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_prefix_cmd                     },
  { RESTRICTED_NODE, &show_bgp_community_cmd                            },
  { RESTRICTED_NODE, &show_bgp_ipv6_community_cmd                       },
  { RESTRICTED_NODE, &show_bgp_community2_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community2_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community3_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community3_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community4_cmd                           },
  { RESTRICTED_NODE, &show_bgp_ipv6_community4_cmd                      },
  { RESTRICTED_NODE, &show_bgp_community_exact_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv6_community_exact_cmd                 },
  { RESTRICTED_NODE, &show_bgp_community2_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community2_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_community3_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community3_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_community4_exact_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_community4_exact_cmd                },
  { RESTRICTED_NODE, &show_bgp_rsclient_route_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { RESTRICTED_NODE, &show_bgp_rsclient_prefix_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { RESTRICTED_NODE, &show_bgp_view_route_cmd                           },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_route_cmd                      },
  { RESTRICTED_NODE, &show_bgp_view_prefix_cmd                          },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_prefix_cmd                     },
  { RESTRICTED_NODE, &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { RESTRICTED_NODE, &show_bgp_view_rsclient_route_cmd                  },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { RESTRICTED_NODE, &show_bgp_view_rsclient_prefix_cmd                 },
  { RESTRICTED_NODE, &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },
  { ENABLE_NODE,     &show_bgp_cmd                                      },
  { ENABLE_NODE,     &show_bgp_ipv6_cmd                                 },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_cmd                            },
  { ENABLE_NODE,     &show_bgp_route_cmd                                },
  { ENABLE_NODE,     &show_bgp_ipv6_route_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_route_cmd                      },
  { ENABLE_NODE,     &show_bgp_prefix_cmd                               },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_prefix_cmd                     },
  { ENABLE_NODE,     &show_bgp_regexp_cmd                               },
  { ENABLE_NODE,     &show_bgp_ipv6_regexp_cmd                          },
  { ENABLE_NODE,     &show_bgp_prefix_list_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_list_cmd                     },
  { ENABLE_NODE,     &show_bgp_filter_list_cmd                          },
  { ENABLE_NODE,     &show_bgp_ipv6_filter_list_cmd                     },
  { ENABLE_NODE,     &show_bgp_route_map_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_route_map_cmd                       },
  { ENABLE_NODE,     &show_bgp_community_all_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_community_all_cmd                   },
  { ENABLE_NODE,     &show_bgp_community_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_community_cmd                       },
  { ENABLE_NODE,     &show_bgp_community2_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community2_cmd                      },
  { ENABLE_NODE,     &show_bgp_community3_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community3_cmd                      },
  { ENABLE_NODE,     &show_bgp_community4_cmd                           },
  { ENABLE_NODE,     &show_bgp_ipv6_community4_cmd                      },
  { ENABLE_NODE,     &show_bgp_community_exact_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_community_exact_cmd                 },
  { ENABLE_NODE,     &show_bgp_community2_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community2_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community3_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community3_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community4_exact_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_community4_exact_cmd                },
  { ENABLE_NODE,     &show_bgp_community_list_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_community_list_cmd                  },
  { ENABLE_NODE,     &show_bgp_community_list_exact_cmd                 },
  { ENABLE_NODE,     &show_bgp_ipv6_community_list_exact_cmd            },
  { ENABLE_NODE,     &show_bgp_prefix_longer_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_prefix_longer_cmd                   },
  { ENABLE_NODE,     &show_bgp_neighbor_advertised_route_cmd            },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_advertised_route_cmd       },
  { ENABLE_NODE,     &show_bgp_neighbor_received_routes_cmd             },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_received_routes_cmd        },
  { ENABLE_NODE,     &show_bgp_neighbor_routes_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_routes_cmd                 },
  { ENABLE_NODE,     &show_bgp_neighbor_received_prefix_filter_cmd      },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_neighbor_flap_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_flap_cmd                   },
  { ENABLE_NODE,     &show_bgp_neighbor_damp_cmd                        },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbor_damp_cmd                   },
  { ENABLE_NODE,     &show_bgp_rsclient_cmd                             },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_cmd                   },
  { ENABLE_NODE,     &show_bgp_rsclient_route_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_route_cmd             },
  { ENABLE_NODE,     &show_bgp_rsclient_prefix_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_prefix_cmd            },
  { ENABLE_NODE,     &show_bgp_view_cmd                                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_cmd                            },
  { ENABLE_NODE,     &show_bgp_view_route_cmd                           },
  { ENABLE_NODE,     &show_bgp_view_ipv6_route_cmd                      },
  { ENABLE_NODE,     &show_bgp_view_prefix_cmd                          },
  { ENABLE_NODE,     &show_bgp_view_ipv6_prefix_cmd                     },
  { ENABLE_NODE,     &show_bgp_view_neighbor_advertised_route_cmd       },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_advertised_route_cmd  },
  { ENABLE_NODE,     &show_bgp_view_neighbor_received_routes_cmd        },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_received_routes_cmd   },
  { ENABLE_NODE,     &show_bgp_view_neighbor_routes_cmd                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_routes_cmd            },
  { ENABLE_NODE,     &show_bgp_view_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_received_prefix_filter_cmd },
  { ENABLE_NODE,     &show_bgp_view_neighbor_flap_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_flap_cmd              },
  { ENABLE_NODE,     &show_bgp_view_neighbor_damp_cmd                   },
  { ENABLE_NODE,     &show_bgp_view_ipv6_neighbor_damp_cmd              },
  { ENABLE_NODE,     &show_bgp_view_rsclient_cmd                        },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_cmd              },
  { ENABLE_NODE,     &show_bgp_view_rsclient_route_cmd                  },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_route_cmd        },
  { ENABLE_NODE,     &show_bgp_view_rsclient_prefix_cmd                 },
  { ENABLE_NODE,     &show_bgp_view_ipv6_safi_rsclient_prefix_cmd       },

  /* Statistics */
  { ENABLE_NODE,     &show_bgp_statistics_cmd                           },
  { ENABLE_NODE,     &show_bgp_statistics_vpnv4_cmd                     },
  { ENABLE_NODE,     &show_bgp_statistics_view_cmd                      },
  { ENABLE_NODE,     &show_bgp_statistics_view_vpnv4_cmd                },

  /* old command */
  { VIEW_NODE,       &show_ipv6_bgp_cmd                                 },
  { VIEW_NODE,       &show_ipv6_bgp_route_cmd                           },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_cmd                          },
  { VIEW_NODE,       &show_ipv6_bgp_regexp_cmd                          },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_list_cmd                     },
  { VIEW_NODE,       &show_ipv6_bgp_filter_list_cmd                     },
  { VIEW_NODE,       &show_ipv6_bgp_community_all_cmd                   },
  { VIEW_NODE,       &show_ipv6_bgp_community_cmd                       },
  { VIEW_NODE,       &show_ipv6_bgp_community2_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community3_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community4_cmd                      },
  { VIEW_NODE,       &show_ipv6_bgp_community_exact_cmd                 },
  { VIEW_NODE,       &show_ipv6_bgp_community2_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community3_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community4_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_bgp_community_list_cmd                  },
  { VIEW_NODE,       &show_ipv6_bgp_community_list_exact_cmd            },
  { VIEW_NODE,       &show_ipv6_bgp_prefix_longer_cmd                   },
  { VIEW_NODE,       &show_ipv6_mbgp_cmd                                },
  { VIEW_NODE,       &show_ipv6_mbgp_route_cmd                          },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_regexp_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_list_cmd                    },
  { VIEW_NODE,       &show_ipv6_mbgp_filter_list_cmd                    },
  { VIEW_NODE,       &show_ipv6_mbgp_community_all_cmd                  },
  { VIEW_NODE,       &show_ipv6_mbgp_community_cmd                      },
  { VIEW_NODE,       &show_ipv6_mbgp_community2_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community3_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community4_cmd                     },
  { VIEW_NODE,       &show_ipv6_mbgp_community_exact_cmd                },
  { VIEW_NODE,       &show_ipv6_mbgp_community2_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community3_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community4_exact_cmd               },
  { VIEW_NODE,       &show_ipv6_mbgp_community_list_cmd                 },
  { VIEW_NODE,       &show_ipv6_mbgp_community_list_exact_cmd           },
  { VIEW_NODE,       &show_ipv6_mbgp_prefix_longer_cmd                  },

  /* old command */
  { ENABLE_NODE,     &show_ipv6_bgp_cmd                                 },
  { ENABLE_NODE,     &show_ipv6_bgp_route_cmd                           },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_cmd                          },
  { ENABLE_NODE,     &show_ipv6_bgp_regexp_cmd                          },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_list_cmd                     },
  { ENABLE_NODE,     &show_ipv6_bgp_filter_list_cmd                     },
  { ENABLE_NODE,     &show_ipv6_bgp_community_all_cmd                   },
  { ENABLE_NODE,     &show_ipv6_bgp_community_cmd                       },
  { ENABLE_NODE,     &show_ipv6_bgp_community2_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community3_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community4_cmd                      },
  { ENABLE_NODE,     &show_ipv6_bgp_community_exact_cmd                 },
  { ENABLE_NODE,     &show_ipv6_bgp_community2_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community3_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community4_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_bgp_community_list_cmd                  },
  { ENABLE_NODE,     &show_ipv6_bgp_community_list_exact_cmd            },
  { ENABLE_NODE,     &show_ipv6_bgp_prefix_longer_cmd                   },
  { ENABLE_NODE,     &show_ipv6_mbgp_cmd                                },
  { ENABLE_NODE,     &show_ipv6_mbgp_route_cmd                          },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_regexp_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_list_cmd                    },
  { ENABLE_NODE,     &show_ipv6_mbgp_filter_list_cmd                    },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_all_cmd                  },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_cmd                      },
  { ENABLE_NODE,     &show_ipv6_mbgp_community2_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community3_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community4_cmd                     },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_exact_cmd                },
  { ENABLE_NODE,     &show_ipv6_mbgp_community2_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community3_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community4_exact_cmd               },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_list_cmd                 },
  { ENABLE_NODE,     &show_ipv6_mbgp_community_list_exact_cmd           },
  { ENABLE_NODE,     &show_ipv6_mbgp_prefix_longer_cmd                  },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_advertised_route_cmd            },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_advertised_route_cmd            },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_advertised_route_cmd           },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_advertised_route_cmd           },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_received_routes_cmd             },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_received_routes_cmd             },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_received_routes_cmd            },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_received_routes_cmd            },

  /* old command */
  { VIEW_NODE,       &ipv6_bgp_neighbor_routes_cmd                      },
  { ENABLE_NODE,     &ipv6_bgp_neighbor_routes_cmd                      },
  { VIEW_NODE,       &ipv6_mbgp_neighbor_routes_cmd                     },
  { ENABLE_NODE,     &ipv6_mbgp_neighbor_routes_cmd                     },
#endif /* HAVE_IPV6 */

  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_cmd                          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_tags_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_tags_cmd                     },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbor_routes_cmd         },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_cmd                          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_tags_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_tags_cmd                     },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbor_routes_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbor_routes_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbor_advertised_routes_cmd },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbor_advertised_routes_cmd },

  /* "show ip bgp summary" commands. */
  { VIEW_NODE,       &show_ip_bgp_summary_cmd                           },
  { VIEW_NODE,       &show_ip_bgp_instance_summary_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_ipv4_summary_cmd                      },
  { VIEW_NODE,       &show_bgp_ipv4_safi_summary_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_instance_ipv4_summary_cmd             },
  { VIEW_NODE,       &show_bgp_instance_ipv4_safi_summary_cmd           },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_summary_cmd                              },
  { VIEW_NODE,       &show_bgp_instance_summary_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_summary_cmd                         },
  { VIEW_NODE,       &show_bgp_ipv6_safi_summary_cmd                    },
  { VIEW_NODE,       &show_bgp_instance_ipv6_summary_cmd                },
  { VIEW_NODE,       &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */
  { RESTRICTED_NODE, &show_ip_bgp_summary_cmd                           },
  { RESTRICTED_NODE, &show_ip_bgp_instance_summary_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_summary_cmd                      },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_summary_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_instance_ipv4_summary_cmd             },
  { RESTRICTED_NODE, &show_bgp_instance_ipv4_safi_summary_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { RESTRICTED_NODE, &show_bgp_summary_cmd                              },
  { RESTRICTED_NODE, &show_bgp_instance_summary_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_summary_cmd                         },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_summary_cmd                    },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_summary_cmd                },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */
  { ENABLE_NODE,     &show_ip_bgp_summary_cmd                           },
  { ENABLE_NODE,     &show_ip_bgp_instance_summary_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_summary_cmd                      },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_summary_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_instance_ipv4_summary_cmd             },
  { ENABLE_NODE,     &show_bgp_instance_ipv4_safi_summary_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_summary_cmd                 },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_summary_cmd                  },
#ifdef HAVE_IPV6
  { ENABLE_NODE,     &show_bgp_summary_cmd                              },
  { ENABLE_NODE,     &show_bgp_instance_summary_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_summary_cmd                         },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_summary_cmd                    },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_summary_cmd                },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_safi_summary_cmd           },
#endif /* HAVE_IPV6 */

  /* "show ip bgp neighbors" commands. */
  { VIEW_NODE,       &show_ip_bgp_neighbors_cmd                         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbors_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_neighbors_peer_cmd                    },
  { VIEW_NODE,       &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbors_cmd               },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbors_cmd                },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { VIEW_NODE,       &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { VIEW_NODE,       &show_ip_bgp_instance_neighbors_cmd                },
  { VIEW_NODE,       &show_ip_bgp_instance_neighbors_peer_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_neighbors_peer_cmd                    },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { RESTRICTED_NODE, &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_instance_neighbors_peer_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_neighbors_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbors_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_neighbors_peer_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_neighbors_peer_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbors_cmd               },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbors_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_all_neighbors_peer_cmd          },
  { ENABLE_NODE,     &show_ip_bgp_vpnv4_rd_neighbors_peer_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_instance_neighbors_cmd                },
  { ENABLE_NODE,     &show_ip_bgp_instance_neighbors_peer_cmd           },

#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_neighbors_cmd                            },
  { VIEW_NODE,       &show_bgp_ipv6_neighbors_cmd                       },
  { VIEW_NODE,       &show_bgp_neighbors_peer_cmd                       },
  { VIEW_NODE,       &show_bgp_ipv6_neighbors_peer_cmd                  },
  { VIEW_NODE,       &show_bgp_instance_neighbors_cmd                   },
  { VIEW_NODE,       &show_bgp_instance_ipv6_neighbors_cmd              },
  { VIEW_NODE,       &show_bgp_instance_neighbors_peer_cmd              },
  { VIEW_NODE,       &show_bgp_instance_ipv6_neighbors_peer_cmd         },
  { RESTRICTED_NODE, &show_bgp_neighbors_peer_cmd                       },
  { RESTRICTED_NODE, &show_bgp_ipv6_neighbors_peer_cmd                  },
  { RESTRICTED_NODE, &show_bgp_instance_neighbors_peer_cmd              },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_neighbors_peer_cmd         },
  { ENABLE_NODE,     &show_bgp_neighbors_cmd                            },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbors_cmd                       },
  { ENABLE_NODE,     &show_bgp_neighbors_peer_cmd                       },
  { ENABLE_NODE,     &show_bgp_ipv6_neighbors_peer_cmd                  },
  { ENABLE_NODE,     &show_bgp_instance_neighbors_cmd                   },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_neighbors_cmd              },
  { ENABLE_NODE,     &show_bgp_instance_neighbors_peer_cmd              },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_neighbors_peer_cmd         },

  /* Old commands.  */
  { VIEW_NODE,       &show_ipv6_bgp_summary_cmd                         },
  { VIEW_NODE,       &show_ipv6_mbgp_summary_cmd                        },
  { ENABLE_NODE,     &show_ipv6_bgp_summary_cmd                         },
  { ENABLE_NODE,     &show_ipv6_mbgp_summary_cmd                        },
#endif /* HAVE_IPV6 */

  /* "show bgp memory" commands. */
  { VIEW_NODE,       &show_bgp_memory_cmd                               },
  { RESTRICTED_NODE, &show_bgp_memory_cmd                               },
  { ENABLE_NODE,     &show_bgp_memory_cmd                               },

  /* "show bgp views" commands. */
  { VIEW_NODE,       &show_bgp_views_cmd                                },
  { RESTRICTED_NODE, &show_bgp_views_cmd                                },
  { ENABLE_NODE,     &show_bgp_views_cmd                                },

  /* "show ip bgp rsclient" commands. */
  { VIEW_NODE,       &show_ip_bgp_rsclient_summary_cmd                  },
  { VIEW_NODE,       &show_ip_bgp_instance_rsclient_summary_cmd         },
  { VIEW_NODE,       &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { VIEW_NODE,       &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { VIEW_NODE,       &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { VIEW_NODE,       &show_bgp_ipv4_safi_rsclient_summary_cmd           },
  { RESTRICTED_NODE, &show_ip_bgp_rsclient_summary_cmd                  },
  { RESTRICTED_NODE, &show_ip_bgp_instance_rsclient_summary_cmd         },
  { RESTRICTED_NODE, &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { RESTRICTED_NODE, &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { RESTRICTED_NODE, &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { RESTRICTED_NODE, &show_bgp_ipv4_safi_rsclient_summary_cmd           },
  { ENABLE_NODE,     &show_ip_bgp_rsclient_summary_cmd                  },
  { ENABLE_NODE,     &show_ip_bgp_instance_rsclient_summary_cmd         },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_rsclient_summary_cmd             },
  { ENABLE_NODE,     &show_ip_bgp_instance_ipv4_rsclient_summary_cmd    },
  { ENABLE_NODE,     &show_bgp_instance_ipv4_safi_rsclient_summary_cmd  },
  { ENABLE_NODE,     &show_bgp_ipv4_safi_rsclient_summary_cmd           },

#ifdef HAVE_IPV6
  { VIEW_NODE,       &show_bgp_rsclient_summary_cmd                     },
  { VIEW_NODE,       &show_bgp_ipv6_rsclient_summary_cmd                },
  { VIEW_NODE,       &show_bgp_instance_rsclient_summary_cmd            },
  { VIEW_NODE,       &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { VIEW_NODE,       &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { VIEW_NODE,       &show_bgp_ipv6_safi_rsclient_summary_cmd           },
  { RESTRICTED_NODE, &show_bgp_rsclient_summary_cmd                     },
  { RESTRICTED_NODE, &show_bgp_ipv6_rsclient_summary_cmd                },
  { RESTRICTED_NODE, &show_bgp_instance_rsclient_summary_cmd            },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { RESTRICTED_NODE, &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { RESTRICTED_NODE, &show_bgp_ipv6_safi_rsclient_summary_cmd           },
  { ENABLE_NODE,     &show_bgp_rsclient_summary_cmd                     },
  { ENABLE_NODE,     &show_bgp_ipv6_rsclient_summary_cmd                },
  { ENABLE_NODE,     &show_bgp_instance_rsclient_summary_cmd            },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_rsclient_summary_cmd       },
  { ENABLE_NODE,     &show_bgp_instance_ipv6_safi_rsclient_summary_cmd  },
  { ENABLE_NODE,     &show_bgp_ipv6_safi_rsclient_summary_cmd           },
#endif /* HAVE_IPV6 */

  /* "show ip bgp paths" commands. */
  { VIEW_NODE,       &show_ip_bgp_paths_cmd                             },
  { VIEW_NODE,       &show_ip_bgp_ipv4_paths_cmd                        },
  { ENABLE_NODE,     &show_ip_bgp_paths_cmd                             },
  { ENABLE_NODE,     &show_ip_bgp_ipv4_paths_cmd                        },

  /* "show ip bgp community" commands. */
  { VIEW_NODE,       &show_ip_bgp_community_info_cmd                    },
  { ENABLE_NODE,     &show_ip_bgp_community_info_cmd                    },

  /* "show ip bgp extcommunity" commands. */
  { VIEW_NODE,       &show_ip_bgp_ecommunity_info_cmd                   },
  { ENABLE_NODE,     &show_ip_bgp_ecommunity_info_cmd                   },

  /* "show ip bgp attribute-info" commands. */
  { VIEW_NODE,       &show_ip_bgp_attr_info_cmd                         },
  { ENABLE_NODE,     &show_ip_bgp_attr_info_cmd                         },

  CMD_INSTALL_END
} ;

/* Install commands
 */
extern void
bgp_show_cmd_init (void)
{
  cmd_install_table(bgp_show_cmd_table) ;
} ;
