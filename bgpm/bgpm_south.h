/* Quagga Atomic Operations support -- header
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Quagga.
 *
 * GNU Quagga is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Quagga; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _QUAGGA_BGPM_SOUTH_H
#define _QUAGGA_BGPM_SOUTH_H

#include "misc.h"

#include <sys/socket.h>

/*==============================================================================
 * Quagga bgpm -- South-Bound Interface.
 *
 * The interface comprises:
 *
 *   * red-tape for:
 *
 *       - set-up and tear-down
 *
 *       - creation/destruction of neighbors
 *
 *       - creation/destruction of contexts
 *
 *   * downwards publication of BGP routes -- prefixes & attributes:
 *
 *       - received from neighbors
 *
 *       - announced to neighbors
 *
 *       - ....
 *
 *   * downwards installation of routes -- prefixes & next-hops
 *
 *       - per prefix, per context
 *
 *   * requests for information
 *
 *       - properties of given next-hop from given neighbor, in given context
 *
 *       - next hop to use for given address family and neighbor
 *
 *       - ....
 *
 *==============================================================================
 * Naming.
 *
 * Things which belong to the Quagga BGP Module are named bgpm_xxxx.
 *
 * Things which belong on the south-side of the South Interface are named
 * bgps_xxxx.  So:
 *
 *   * functions called by the bgpm will be named bgps_xxxx().
 *
 *   * call-back functions, called from the south-side, will be named bgpm_xxx()
 */

/*==============================================================================
 * Routeing-Context-ID
 *
 * The Routeing-Context-ID is created when a context is configured.  No context
 * has ID 0.  When a new context is created, its ID is published to the
 * south-interface.  When a context is destroyed, that too is published.
 * The life of a given context ID ends when it is freed, by call-back.
 */
typedef uint32_t bgpm_rcon_id_t ;

/* Adding a new context -- the ID will not have been used before, unless
 * it has been freed -- see call-back.
 *
 * The name is an arbitrary string from the bgpm configuration
 *
 * The callee must not retain the given address.
 */
extern void bgps_rcon_add(bgpm_rcon_id_t rcon_id, const char* name) ;

/* Delete an existing neighbor.
 */
extern void bgps_rcon_del(bgpm_rcon_id_t rcon_id) ;

/* Call-back to free the given ID.
 *
 * Once the callee has digested the deletion of a Context ID, it can call back
 * to release the ID for future re-use.
 */
extern void bgpm_rcon_free(bgpm_rcon_id_t rcon_id) ;

/*==============================================================================
 * Neighbor-ID
 *
 * The Neighbor-ID is created when a neighbor is configured.  No neighbor
 * has ID 0.  When a new neighbor is created, its ID is published to the
 * south-interface.  When a neighbor is destroyed, that too is published.
 * The life of a given neighbor-id ends when it is freed, by call-back.
 */
typedef uint32_t bgpm_nghbr_id_t ;

typedef struct bgpm_nghbr_name  bgpm_nghbr_name_t ;
typedef struct bgpm_nghbr_name* bgpm_nghbr_name ;
typedef const struct bgpm_nghbr_name* bgpm_nghbr_name_c ;

struct bgpm_nghbr_name
{
  /* The ID is used to refer to the neighbor once it has been added.
   */
  bgpm_nghbr_id_t nghbr_id ;

  /* The ID for the context in which the neighbor is known to reside.
   *
   * This will be an existing context (not a new one).
   */
  bgpm_rcon_id_t  rcon_id ;

  /* The name is an arbitrary string, set by configuration, and is passed from
   * the north-interface straight through.
   */
  const char*     name ;

  /* The address (including port) is the "real" name of the neighbor from
   * the bgpm perspective -- BGP connections are created/accepted on the basis
   * of this.
   */
  struct sockaddr sa ;
} ;

/* Adding a new neighbor -- the ID will not have been used before, unless
 * it has been freed -- see call-back.
 *
 * The callee must not retain the given address.
 */
extern void bgps_nghbr_add(bgpm_nghbr_name_c nghbr_name) ;

/* Delete an existing neighbor.
 */
extern void bgps_nghbr_del(bgpm_nghbr_id_t nghbr_id) ;

/* Call-back to free the given ID.
 *
 * Once the callee has digested the deletion of a Neighbor ID, it can call
 * back to release the ID for future re-use.
 */
extern void bgpm_nghbr_free_f(bgpm_nghbr_id_t nghbr_id) ;

/*==============================================================================
 * BGP Routes -- these are neighbor + prefix + attribute set
 */
typedef const struct bgpm_attr_set* bgpm_attr_set_c ;
typedef const struct bgpm_prefix*   bgpm_prefix_c ;

typedef struct bgpm_bgp_route  bgpm_bgp_route_t ;
typedef struct bgpm_bgp_route* bgpm_bgp_route ;
typedef const struct bgpm_bgp_route* bgpm_bgp_route_c ;

struct bgpm_bgp_route
{
  bgpm_nghbr_id_t nghbr_id ;

  bgpm_attr_set_c attrib ;

  uint16_t      afi ;
  uint16_t      safi ;

  uint8_t       prefix_length ;
  uint8_t       prefix[] ;
} ;

/* The following may happen to a route.
 */
typedef enum bgpm_bgp_route_event bgpm_bgp_route_event_t ;

enum bgpm_bgp_route_event
{
  bgpm_rev_withdraw,
  bgpm_rev_add,
  bgpm_rev_replace,

  bgpm_rev_stale,
  bgpm_rev_discard,
} ;

/* Functions to signal changes to adj_in or adj_out.
 */
extern void bgps_route_adj_in(bgpm_bgp_route_c route,
                                                   bgpm_bgp_route_event_t rev) ;
extern void bgps_route_adj_out(bgpm_bgp_route_c route,
                                                   bgpm_bgp_route_event_t rev) ;

/*------------------------------------------------------------------------------
 * A prefix
 *
 * The body of the prefix is the raw BGP ....
 */
typedef struct bgpm_prefix  bgpm_prefix_t ;
typedef struct bgpm_prefix* bgpm_prefix ;

struct bgpm_prefix
{
  uint16_t      afi ;
  uint16_t      safi ;

  uint8_t       bits ;
  uint8_t       body[] ;
} ;

/*------------------------------------------------------------------------------
 * A set of attributes.
 */

/* For attributes where need to know whether the attribute is set or not, and
 * that cannot be determined from its value.
 */
typedef enum bgpm_attr_bits  bgpm_attr_bits_t ;
enum bgpm_attr_bits
{
  bgpm_atb_origin                = BIT( 0),
  bgpm_atb_local_pref            = BIT( 1),
  bgpm_atb_med                   = BIT( 2),
  bgpm_atb_atomic_aggregate      = BIT( 3),  /* presence/absence is it  */
  bgpm_atb_originator_id         = BIT( 4),
} ;

typedef struct bgpm_attr_set  bgpm_attr_set_t ;
typedef struct bgpm_attr_set* bgpm_attr_set ;

typedef struct bgpm_attr_next_hop*     bgpm_attr_next_hop ;
typedef struct bgpm_attr_as_path*      bgpm_attr_as_path ;
typedef struct bgpm_attr_community*    bgpm_attr_community ;
typedef struct bgpm_attr_ecommunity*   bgpm_attr_ecommunity ;
typedef struct bgpm_attr_cluster*      bgpm_attr_cluster ;
typedef struct bgpm_attr_unknown*      bgpm_attr_unknown ;

struct bgpm_attr_set
{
  /* The simple attributes.
   */
  bgpm_attr_bits_t bits ;

  uint8_t       origin ;        /* zero unless bgpm_atb_origin          */

  uint16_t      weight;         /* zero => none (or zero)               */

  uint32_t      med ;           /* zero unless bgpm_atb_med             */
  uint32_t      local_pref ;    /* zero unless bgpm_atb_local_pref       */

  uint32_t      originator_id ; /* zero unless atb_originator_id        */

  uint32_t      aggregator_as ; /* zero if none                         */
  uint32_t      aggregator_ip ; /* zero if none                         */

  /* The Next-Hop.
   */
  bgpm_attr_next_hop    next_hop ;      /* NULL if none set             */

  /* The longer attributes -- all NULL if not present
   */
  bgpm_attr_as_path     asp ;
  bgpm_attr_community   community ;
  bgpm_attr_ecommunity  ecommunity ;
  bgpm_attr_cluster     cluster ;

  bgpm_attr_unknown     transitive ;
} ;

/* The Next-Hop -- raw, taken from UPDATE Message
 */
typedef struct bgpm_attr_next_hop     bgpm_attr_next_hop_t ;

struct bgpm_attr_next_hop
{
  uint16_t  len ;
  byte      body[] ;
} ;

/* AS-PATH -- list of type, repeat, ASN
 */
typedef struct bgpm_attr_as_path      bgpm_attr_as_path_t ;

typedef struct bgpm_attr_as_path_item bgpm_attr_as_path_item_t ;

struct bgpm_attr_as_path_item
{
  uint16_t      type ;                  /* SEGMENT, SET etc     */
  uint16_t      rep ;
  uint32_t      asn ;
} ;

struct bgpm_attr_as_path
{
  uint16_t      item_count ;
  bgpm_attr_as_path_item_t  items[] ;
} ;

/* Community -- list of community values -- host order.
 */
typedef struct bgpm_attr_community    bgpm_attr_community_t ;

struct bgpm_attr_community
{
  uint16_t  item_count ;
  uint32_t  items[] ;
} ;

/* Extended Community -- list of Extended Community values -- host order
 */
typedef struct bgpm_attr_ecommunity   bgpm_attr_ecommunity_t ;

struct bgpm_attr_ecommunity
{
  uint16_t  item_count ;
  uint64_t  items[] ;
} ;

/* Cluster List
 */
typedef struct bgpm_attr_cluster      bgpm_attr_cluster_t ;

struct bgpm_attr_cluster
{
  uint16_t  item_count ;
  uint32_t  items[] ;
} ;

/* Unknown Attributes
 */
typedef struct bgpm_attr_unknown      bgpm_attr_unknown_t ;

struct bgpm_attr_unknown
{
  uint16_t  len ;
  byte      body[] ;
} ;

/*==============================================================================
 * Next-Hop-ID
 *
 * Routes arrive from a given neighbor with a Next-Hop, which bgpm will map to
 * a Next-Hop-ID.  BGP then needs to know:
 *
 *   1) is the Next-Hop reachable, in the given context ?
 *
 *   2) the IGP metric for the Next-Hop in each context.
 *
 *   3) the Next-Hop to a given Neighbor.
 */
typedef uint32_t bgpm_nhop_id_t ;

typedef struct bgpm_nhop_raw  bgpm_nhop_raw_t ;
typedef struct bgpm_nhop_raw* bgpm_nhop_raw ;
typedef const struct bgpm_nhop_raw* bgpm_nhop_raw_c ;

enum bgpm_nhop_raw_len
{
  bgpm_nhop_raw_len_max  = 255
} ;

struct bgpm_nhop_raw
{
  uint16_t  afi ;               /* of the prefixes      */
  uint16_t  safi ;

  uint8_t   len ;
  byte      body[] ;
} ;

typedef enum bgpm_nhop_cost bgpm_nhop_cost_t ;

enum bgpm_nhop_cost
{
  bgpm_nhop_cost_unknown     = 0,
  bgpm_nhop_cost_unreachable = UINT32_MAX,
} ;

typedef struct bgpm_nhop_metrics  bgpm_nhop_metrics_t ;
typedef struct bgpm_nhop_metrics* bgpm_nhop_metrics ;
typedef const struct bgpm_nhop_metrics*  bgpm_nhop_metrics_c ;

struct bgpm_nhop_metrics
{
  bgpm_rcon_id_t   last ;

  bgpm_nhop_cost_t costs[] ;
} ;

/* Adding a new next-hop -- the ID will not have been used before, unless
 * it has been freed -- see call-back.
 *
 * The callee must not retain the given address.
 */
extern void bgps_nhop_add(bgpm_nhop_id_t nhop_id, bgpm_nhop_raw_c nhop_raw) ;

/* Delete an existing neighbor.
 */
extern void bgps_nhop_del(bgpm_nhop_id_t nhop_id) ;

/* Call-back to free the given ID.
 *
 * Once the callee has digested the deletion of a Next-Hop-ID, it can call back
 * to release the ID for future re-use.
 */
extern void bgpm_nhop_free(bgpm_nhop_id_t nhop_id) ;

/* Getting the metrics
 *
 * The given metrics has the 'last' entry filled in, and will be large enough
 * for metrics up to and including that r-context.
 *
 * Returns:  true <=> done already.
 *          false  => deferred
 */
extern bool bgps_nhop_get_metrics(bgpm_nhop_id_t nhop_id,
                                                    bgpm_nhop_metrics metrics) ;

/* Setting metrics -- call-back
 *
 * The given metrics has the 'last' entry filled in, and will be large enough
 * for metrics up to and including that r-context.
 */
extern void bgpm_nhop_set_metrics(bgpm_nhop_id_t nhop_id,
                                                  bgpm_nhop_metrics_c metrics) ;

/* Getting Next-Hop Self for the given Neighbor
 *
 * NB: no mechanism to defer this.
 */
extern void bgps_nhop_get_self(bgpm_nghbr_id_t nghbr_id,
                                                       bgpm_nhop_raw nhop_raw) ;

/*==============================================================================
 * Installing Routes
 */
typedef struct bgpm_route  bgpm_route_t ;
typedef struct bgpm_route* bgpm_route ;
typedef const struct bgpm_route* bgpm_route_c ;

struct bgpm_route
{
  bgpm_nghbr_id_t  nghbr_id ;

  bgpm_nhop_id_t   nhop_id ;            /* 0 <=> withdraw       */

  bgpm_prefix_t    prefix ;
} ;

/* Install/Uninstall Route
 *
 * Returns:  true <=> done
 *          false  => deferred
 */
extern bool bgps_route_set(bgpm_rcon_id_t rcon_id, bgpm_route_c route) ;

/* Signal ready to Install/Uninstall more routes
 *
 * Has installed/uninstalled up to and including the last route set.
 */
extern void bgpm_route_ready(bgpm_rcon_id_t rcon_id) ;

/*==============================================================================
 * Red-Tape
 */
typedef struct bgpm_red_tape  bgpm_red_tape_t ;
typedef struct bgpm_red_tape* bgpm_red_tape ;
typedef const struct bgpm_red_tape* bgpm_red_tape_c ;

struct bgpm_red_tape
{
  /* Version
   */
  uint16_t      version_major ;
  uint16_t      version_minor ;

};

extern void bgps_startup(bgpm_red_tape_c red_tape) ;
extern void bgps_shutdown(void) ;



#endif /* _QUAGGA_BGPM_SOUTH_H */
