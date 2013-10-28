/* BGP Route-Context handling -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
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

#ifndef _QUAGGA_BGP_RCONTEXT_H
#define _QUAGGA_BGP_RCONTEXT_H

#include "bgpd/bgp_common.h"

#include "routemap.h"
#include "svector.h"

/*==============================================================================
 * Each Global Route Context (rcontext) has a name and an rc-id.
 *
 * The rc-id is a small, non-zero, integer, allocated when the rcontext is
 * created.
 *
 * The name is local to the enclosing bgp view (instance) -- so a given "global"
 * route-context is only actually used within a single view.
 *
 * The theory is that each bgp view is quite distinct, so is likely to have
 * distinct route-contexts.  Even where one view shares some contexts with
 * another, it is possible that the inter-context IGP may be different, or
 * some other properties are different.  The south-side may map the rc-id used
 * by different views to the same thing as necessary.
 */

/*==============================================================================
 * Route-Context-Id and Local-Context-Id
 */
typedef uint16_t bgp_rc_id_t ;
typedef uint16_t bgp_lc_id_t ;

/*------------------------------------------------------------------------------
 * The rcontext.
 *
 * The rcontext maps the rc-id and the view/name to a table of lcontexts.
 *
 * An rcontext may be associated with the bgp view itself, or with one or
 * more peers within the view:
 *
 *   * for standard bgpd -- if there is no rcontext associated with the
 *     view, there is no IGP, and no means to install routes !
 *
 *     Only the unnamed view can have an rcontext associated with it.
 *
 *   * for SDN bgpd, one or more peers may be associated with an rcontext,
 *     but that may not be the same as the 'view' (if it has an rcontext).
 *
 *   * for route-server -- each route-server-client or rsc-group has its own
 *                         rcontext.
 */
enum
{
  bgp_rc_id_null  = 0
} ;

typedef enum bgp_rcontext_type bgp_rcontext_type_t ;
enum bgp_rcontext_type
{
  rc_is_view    = 0,            /* bgp view                             */
  rc_is_peer,                   /* peer(s) or peer-group                */
  rc_is_rs_client,              /* rs-client or group of same           */
} ;

typedef struct bgp_rcontext  bgp_rcontext_t ;
typedef struct bgp_rcontext const* bgp_rcontext_c ;

struct bgp_rcontext
{
  /* The name is the key for a vhash for finding route-contexts within the
   * 'view'.
   */
  vhash_node_t  vhash ;

  /* Each route-context is known to the south-side by its rc-id, and that
   * is "global" across all bgp-instances.
   *
   * All the know route-contexts are kept on the svl_list based on the root
   * svec's base.
   */
  bgp_rc_id_t   id ;
  svl_list_t    known[1] ;

  /* Each route-context may have a lcontext in each afi/safi (so for each rib
   * in the bgp instance).
   *
   * This table is used to map from the global rc-id, or from the rcontext name,
   * to the lcontext for a given afi/safi.
   */
  bgp_lcontext  lcontexts[qafx_count] ;

  /* Each route-context has a parent bgp instance, and a type.  The type
   * specifies whether the rcontext is associated with:
   *
   *   * the 'view', and hence with any peers which are not explicitly
   *     associated with a context -- eg for standard BGP.
   *
   *   * a single route-server client.
   *
   *   * one or more ordinary peers
   *
   * Each route-context has a name, by which it is known to the configuration,
   * within the parent bgp instance.
   *
   * For Route-Server Clients that has the form: RS <neighbor name>
   * (so ordinary route-context names may not contain ' ' -- at least.
   */
  bgp_run       brun ;

  bgp_rcontext_type_t type ;

  char          name[1] ;
} ;

CONFIRM(offsetof(bgp_rcontext_t, vhash) == 0) ; /* see vhash.h  */



struct bgp_rcontext_config
{

} ;

/*------------------------------------------------------------------------------
 * The lcontext.
 *
 * In each afi/safi in which a given rcontext is used (so in each rib in which
 * it is used) there is an lcontext, and that has an lc-id, which is a dense
 * set .
 */
typedef struct bgp_lcontext  bgp_lcontext_t ;

struct bgp_lcontext
{
  /* For convenience and completeness, rib and the qafx this is for.
   */
  bgp_rib       rib ;
  qafx_t        qafx ;

  /* The rc-id, the lc-id and the list for lc-id in use.
   */
  bgp_rc_id_t   rc_id ;

  bgp_lc_id_t   id ;
  svl_list_t    lcs[1] ;

  /* The pribs which are attached to the lcontext.
   */
  struct dl_base_pair(bgp_prib) pribs ;

  /* The rc_in_to and rc_in_from route-maps.
   */
  route_map     in_to ;
  route_map     in_from ;
} ;

/*==============================================================================
 *
 */
extern void bgp_rcontext_init(void) ;
extern void bgp_rcontext_finish(void) ;
extern void bgp_rcontext_discard_name_index(bgp_run brun) ;

extern bgp_lcontext bgp_lcontext_new(bgp_rib rib, bgp_rcontext rc) ;

extern bgp_rcontext bgp_rcontext_lookup(bgp_run brun, const char* name,
                                        bgp_rcontext_type_t type, bool* added) ;

extern bgp_lcontext bgp_rcontext_attach_prib(bgp_rcontext rc, bgp_prib prib) ;
extern bgp_lcontext bgp_lcontext_attach_prib(bgp_lcontext lc, bgp_prib prib) ;
extern void bgp_lcontext_detach_prib(bgp_prib prib) ;


extern bgp_rcontext bgp_rcontext_get(bgp_rc_id_t rc_id) ;
extern bgp_rcontext bgp_rcontext_unlock(bgp_rcontext rc) ;

#endif /* _QUAGGA_BGP_RCONTEXT_H */

