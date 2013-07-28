/* BGP RIB -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, see:
 * <http://www.gnu.org/licenses/>.
 */
#ifndef _QUAGGA_BGP_RIB_H
#define _QUAGGA_BGP_RIB_H

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_filter.h"

#include "list_util.h"
#include "prefix_id.h"
#include "ihash.h"
#include "vhash.h"
#include "pfifo.h"
#include "qtime.h"
#include "qtimers.h"
#include "workqueue.h"
#include "filter.h"
#include "plist.h"
#include "routemap.h"

/*==============================================================================
 * For each AFI/SAFI in a given bgp instance (view) there will be a bgp_rib,
 * if there are any neighbors in that view which are configured for that
 * AFI/SAFI.
 *
 * Each prefix in the AFI/SAFI has a "pnode", pointed at by an ihash by
 * prefix_id -- while there are any routes for that prefix.
 *
 * Each route for a given prefix is represented by an "rnode".  Each pnode has
 * a list of rnodes hung from it.
 *
 *
 *
 *
 */

/*------------------------------------------------------------------------------
 * For some timing we use "binary second" based periods.
 *
 * The basic unit of time used is the nano-second.  The binary second (bS) is
 * 2^30 nano-seconds = 1.073741824 seconds.
 *
 * The periods used here are 1/4 of a bS ~ 0.268 S (0.268435456 S, to be
 * precise).
 */
enum
{
  bgp_binary_second     = 1 << 30,
  bgp_period_shift      = 30 - 2,
  bgp_period_nano_secs  = 1 << bgp_period_shift,
} ;
/*                               123456789 */
CONFIRM(bgp_binary_second    == 1073741824) ;
CONFIRM(bgp_period_nano_secs ==  268435456) ;

/*------------------------------------------------------------------------------
 * RIB types...
 */
typedef enum rib_type rib_type_t ;

enum rib_type
{
  rib_main    = 0,
  rib_rs      = 1,

  rib_type_count
} ;

/*------------------------------------------------------------------------------
 * Peer RIB states...
 */
typedef enum prib_state prib_state_t ;

enum prib_state
{
  prib_initial = 0,
  prib_update  = 1,

  prib_state_count
} ;

/*------------------------------------------------------------------------------
 * RIB Item Header.
 *
 * Each bgp_rib_node is hung off the bgp-rib's process queue (for the
 * respective rib_type).
 *
 * That queue also contains the "walkers" which step along the process queue
 * to do the required processing and any announcing of routes.
 *
 * The following is the common (header) part of the bgp_rib_node and the
 * bgp_rib_walker.
 */
typedef struct bgp_rib_item  bgp_rib_item_t ;

typedef enum rib_item_type rib_item_type_t ;

enum rib_item_type
{
  rib_it_node     = 0,
  rib_it_walker   = 1,
} ;

typedef enum rib_item_flags rib_item_flags_t ;

enum rib_item_flags
{
  /* For all rib_item_type
   */
  rib_itf_rib_queue   = BIT(0), /* item is on the rib queue             */

  /* For rib_it_walker
   */
  rib_itf_wq_queue    = BIT(1), /* work queue item is on the work queue */
} ;

struct bgp_rib_item
{
  bgp_rib       rib ;

  struct dl_list_pair(bgp_rib_item) queue ;

  byte          type ;          /* bgp_rib_item_t               */
  byte          flags ;         /* bgp_rib_item_flags_t         */
} ;

/*------------------------------------------------------------------------------
 * There is one bgp_rib_node in a bgp_rib for each active prefix.
 */
enum bgp_rib_node_flags
{
  rnf_selected           = BIT(0),      /* something has been selected  */
  rnf_deterministic_med  = BIT(1),

  rnf_processed          = BIT(7),      /* update process completed     */
};

typedef byte bgp_rib_node_flags_t ;     /* NB: 8 bits   */

typedef struct bgp_rib_node  bgp_rib_node_t ;
typedef const struct bgp_rib_node* bgp_rib_node_c ;

struct bgp_rib_node
{
  bgp_rib_item_t  it ;

  struct dl_list_pair(bgp_rib_node) list ;

  struct dl_base_pair(route_info) routes ;      /* all available routes */

  route_info    candidates ;    /* candidate routes                     */
  route_info    selected ;      /* currently selected route             */

  route_zebra   zebra ;         /* route as announced to zebra          */

  prefix_id_t   pfx_id ;

  bgp_rib_node_flags_t flags ;
} ;

CONFIRM(offsetof(bgp_rib_node_t, it) == 0) ;

/*------------------------------------------------------------------------------
 * The "merit" of a route combines the first 5 steps of the route comparison
 * into a single 64-bit value:
 *
 *       16           32        1   13   2
 *   +--------+----------------+-+------+-+
 *   | ~Weight|   Local Pref   |L| ~ASP |O|
 *   +--------+----------------+-+------+-+
 *
 * We select for greater merit.
 *
 * So we have, from the MS end:
 *
 *   1. ~Weight
 *
 *      The 1's complement of the weight -- lower weight has greater merit.
 *
 *   2. Local Preference
 *
 *      Greater local preference has greater merit.
 *
 *      Note that this value may (well) be set to the default for the bgp
 *      instance.
 *
 *   3. Local Route
 *
 *      Any form of local route is deemed to have greater merit than any
 *      normal (learned from peer) route.
 *
 *      So: 1 <=> local, 0 <=> normal.
 *
 *   4. ~AS-PATH Length
 *
 *      The 1's complement of the effective AS-PATH Length -- shorter path
 *      has greater merit.
 *
 *      This is the effective AS-PATH length because:
 *
 *        a) for Local Routes this field is set to 0 (path length == 0x1FFF).
 *
 *        b) if bgp->flags & BGP_FLAG_ASPATH_IGNORE then this field is set to 0
 *
 *        c) if bgp->flags & BGP_FLAG_ASPATH_CONFED then this includes any
 *           confederation segments.
 *
 *        d) otherwise it is the simple path length.
 *
 *      Note that the maximum path length is "limited" to 8191 !
 *
 *   5. ~ORIGIN
 *
 *      The valid origin values are IGP (0), EGP (1) and INCOMPLETE (2).
 *      The smaller origin value has greater merit.
 *
 *      Serendipity has left value 3 unused.
 *
 *      This field is set to 0 (origin == 3) for Local Routes and for
 *      no merit at all.
 *
 * Happily we can encode merit_none as 0 (which is maximum weight, minimum
 * local preference, ordinary route, maximum AS-PATH, *unused* origin type).
 * Routes which should not be considered at all have merit_none.
 *
 * See bgp_route_merit()
 */
typedef uint64_t route_merit_t ;

enum route_merit
{
  route_merit_none  = 0,

  route_merit_weight_bits       = 16,
  route_merit_local_pref_bits   = 32,
  route_merit_local_bits        =  1,
  route_merit_as_path_bits      = 13,
  route_merit_origin_bits       =  2,

  route_merit_weight_shift      = 2 + 13 + 1 + 32,
  route_merit_local_pref_shift  = 2 + 13 + 1,
  route_merit_local_shift       = 2 + 13,
  route_merit_as_path_shift     = 2,
  route_merit_origin_shift      = 0,
};

/*------------------------------------------------------------------------------
 * There is one route_info for each route received from a peer.
 *
 * The route_info lives in the peer's adj_in.
 *
 * It will also live on the relevant bgp_rib_node's list of routes -- unless
 * the route has been filtered out.
 */
enum route_info_flags
{
  RINFO_IGP_CHANGED    = BIT( 0),
  RINFO_ATTR_CHANGED   = BIT( 1),

  RINFO_DAMPED         = BIT( 2),
  RINFO_HISTORY        = BIT( 3),
//RINFO_SELECTED       = BIT( 3),

  RINFO_VALID          = BIT( 4),

  RINFO_STALE          = BIT( 8),
  RINFO_REMOVED        = BIT( 9),
  RINFO_COUNTED        = BIT(10),


  RINFO_TREAT_AS_WITHDRAW = BIT(14),

  RINFO_RS_DENIED      = BIT(15),
} ;
typedef uint16_t rinfo_flags_t ;        /* <= 16 flag bits      */

typedef struct route_info route_info_t ;

struct route_info
{
  /* The parent peer rib -- will be in the prib->adj_in[rib_type_t].
   */
  peer_rib      prib ;

  /* The bgp_rib_node (if any) to which the route is attached, and the list
   * pointers for the list of routes available for that prefix.
   */
  bgp_rib_node  rn ;
  struct dl_list_pair(route_info) route_list ;

  /* The current candidates list -- if the route_info is on the route_list
   * for the bgp_rib_node, may also be amongst the current candidates for
   * selection.
   */
  route_info    candidate_list ;

  /* The list pointers for the list of stale routes.  Only rib_main route_info
   * can be stale.  When refreshing an adj-in, we hope that the vast majority
   * of routes will be re-instated, so only a few (if any) will remain on this
   * list.
   */
  struct dl_list_pair(route_info) stale_list ;

  /* The prefix_id for this route, and the related MPLS tag set.
   *
   * Each route_info entry holds a clock on the related
   */
  prefix_id_t   pfx_id ;
  mpls_tags_t   tag ;           /* For MPLS VPN                 */

  /* The attributes "received" and the attributes to be used.
   *
   * For a Main RIB route_info these are:
   *
   *   * attr_rcv     -- the attributes as received from the peer.
   *
   *   * attr         -- the attributes after all incoming filters have been
   *                     run, including the 'in' route-map.
   *
   * For an RS RIB route_info these are:
   *
   *   * attr_rcv     -- the attributes received *after* they are processed
   *                     through the 'rs-in' route-map.
   *
   *   * attr         -- the attributes after the last run of 'export' and
   *                     'import' filters -- where that
   */
  attr_set      attr_rcv ;
  attr_set      attr ;

  route_merit_t merit ;

  as_t          med_as ;
  uint32_t      igp_metric ;

  route_extra   extra ;

  time_t        uptime ;

  uint          lock ;

  rinfo_flags_t flags ;

  byte          rib_type ;
  byte          qafx ;
  byte          route_type ;


  byte          type ;          /* static, RIP, OSPF, BGP etc.  */
  byte          sub_type ;      /* normal, static, etc.         */
} ;

/*------------------------------------------------------------------------------
 * Route Incoming "Parcel".
 *
 * Routes as they arrive are bundled up in a parcel, which collects all the
 * properties in one place, and can be queued for processing.
 */
typedef enum route_in_action  route_in_action_t ;
enum route_in_action
{
  ra_in_withdraw  = BIT(0),
  ra_in_update    = BIT(1),

  ra_in_treat_as_withdraw = ra_in_update | ra_in_withdraw,
};

typedef struct route_in_parcel  route_in_parcel_t ;

typedef struct dl_base_pair(route_in_parcel) route_in_parcel_base_t ;
typedef route_in_parcel_base_t* route_in_parcel_base ;

struct route_in_parcel
{
  struct dl_list_pair(route_in_parcel) list ;

  attr_set      attr ;

  prefix_id_t   pfx_id ;
  mpls_tags_t   tag ;

  byte          qafx ;
  byte          action ;

  bgp_route_type_t route_type ;
} ;

/*------------------------------------------------------------------------------
 * Route Outgoing "Parcel".
 *
 * Routes as they sent are bundled up in a parcel, which collects all the
 * properties in one place, and can be queued for output.
 */
typedef enum route_out_action  route_out_action_t ;
enum route_out_action
{
  ra_out_initial   = 0,         /* update from nothing                     */
  ra_out_withdraw  = 1,         /* update from something to nothing        */
  ra_out_update    = 2,         /* update from something to something else */
  ra_out_eor       = 3,
};

typedef struct route_out_parcel  route_out_parcel_t ;

typedef struct dl_base_pair(route_out_parcel) route_out_parcel_base_t ;
typedef route_out_parcel_base_t* route_out_parcel_base ;

struct route_out_parcel
{
  struct dl_list_pair(route_out_parcel) list ;

  attr_set       attr ;

  prefix_id_t    pfx_id ;
  mpls_tags_t    tag ;

  byte           qafx ;
  byte           action ;
} ;

/*------------------------------------------------------------------------------
 * RIB Walker.
 *
 * When they are active, these live on the relevant bgp_rib queue, along with
 * the bgp_rib_node objects.  The bgp_rib_item_t is the common part for these
 * two types of object.
 *
 * When a RIB Walker is active there is also a work queue item, which may be
 * sitting on the bgp_master work queue.
 *
 * An "initial" walker processes only the walker's peers list.
 *
 * An "update" walker processes the bgp_rib's and the walker's peers list.
 *
 * When a walker hits the end of the bgp_rib queue, all entries on the walker's
 * peers list are scanned and may be sent EoR.  For an "update" all entries on
 * the walker's list are added to the bgp_rib's, and the walk terminates.  For
 * an "initial" walker: if there is no active "update" walker, then the same
 * happens; otherwise, stays on the queue, marked "spent" and the work queue
 * item is terminated.
 *
 * When an update walker meets an initial walker, or an initial walker meets an
 * update one: the initial walker is added to the walker's peers (if is not
 * "spent") or to the bgp_rib's peers (if it is "spent") and the initial
 * walker is terminated.
 *
 * When an "initial" walker meets another "initial" walker, if they are both
 * "spent" or both not "spent", they can be merged and the current not active
 * walker terminated.  Otherwise, the current active walker must be the not
 * "spent" one, and it steps over the "spent" one (which will be collected by
 * the active "update" walker in due course).
 */
typedef struct dl_base_pair(peer_rib) peer_rib_base_pair_t ;
typedef peer_rib_base_pair_t* peer_rib_base_pair ;

typedef struct bgp_rib_walker  bgp_rib_walker_t ;
struct bgp_rib_walker
{
  bgp_rib_item_t  it ;

  wq_item         wqi ;

  peer_rib_base_pair_t peers[prib_state_count] ;
} ;

CONFIRM(offsetof(bgp_rib_walker_t, it) == 0) ;

/*------------------------------------------------------------------------------
 * For each address family which has at least one active peer in it, there
 * is a bgp_rib for the Main RIB and (if there are any RS Clients), a second
 * bgp_rib for the RS RIB.
 */
typedef struct bgp_rib bgp_rib_t ;

struct bgp_rib
{
  bgp_inst      bgp ;                   /* parent bgp instance          */

  /* State of the RIB
   */
  qafx_t        qafx ;
  rib_type_t    rib_type ;              /* Main or RS                   */

  uint          peer_count ;            /* Number of activated peers    */

  uint          lock;

  /* The nodes_table is an ihash by prefix_id_t, for all the prefixes in this
   * RIB.  Each prefix has a bgp_rib_node.
   *
   * Note that nodes (generally) only exist where there is at least one usable
   * route for the prefix.  The presence of a node in the Main RIB is no
   * guarantee of a corresponding node in the corresponding RS RIB -- or vice
   * versa.
   */
  ihash_table   nodes_table ;

  /* For MPLS IPVN RIBs, each prefix has an associated Route Distinguisher.
   *
   * The rds_table is an ihash by prefix_rd_id_t, with one entry for each
   * Route Distinguisher for which there is at least one prefix in the
   * nodes_table.  This is kept to provide the RDs to be used when searching
   * for routes in all RDs.
   */
  ihash_table   rds_table ;

  /* The queue runs through all bgp_rib_nodes, and any active "walkers".
   *
   * When the routes available for a given prefix change such that the full
   * route selection must be re-run, the bgp_rib_node is moved to the end
   * of the queue.
   */
  struct dl_base_pair(bgp_rib_item) queue ;

  /* The processing of changed prefixes is done by a "walker", which lives on
   * the "queue" while it is active.
   */
  bgp_rib_walker walker ;               /* Walker for "update" walk     */
} ;

/*==============================================================================
 * Functions
 */
extern bgp_rib bgp_rib_new(bgp_inst bgp, qafx_t qafx, rib_type_t rib_type) ;
extern bgp_rib bgp_rib_destroy(bgp_rib rib) ;

extern bgp_rib_node bgp_rib_node_get(bgp_rib rib, prefix_id_entry pie) ;

extern bgp_rib_walker bgp_rib_walker_new(bgp_rib rib) ;
extern bgp_rib_walker bgp_rib_walker_discard(bgp_rib_walker rw) ;
extern bgp_rib_walker bgp_rib_walker_free(bgp_rib_walker rw) ;
extern bgp_rib_walker bgp_rib_walker_detach(peer_rib prib) ;
extern bgp_rib_walker bgp_rib_walker_start_initial(peer_rib prib,
                                                             wq_function func) ;
extern bgp_rib_walker bgp_rib_walker_start(bgp_rib_walker rw,
                                                             wq_function func) ;

extern uint bgp_rib_count(bgp_rib rib) ;

extern vector bgp_rib_extract(bgp_rib rib, prefix_rd prd) ;
extern vector bgp_rib_rd_extract(bgp_rib rib) ;
extern prefix_rd_id_entry bgp_rib_rd_seek(bgp_rib rib, prefix_rd prd) ;
extern int bgp_rib_node_cmp(const bgp_rib_node_c* p_a,
                            const bgp_rib_node_c* p_b) ;

extern peer_rib peer_rib_new(bgp_peer peer, qafx_t qafx) ;
extern peer_rib peer_rib_free(peer_rib prib) ;
extern peer_rib peer_rib_set_rs(bgp_peer peer, qafx_t qafx) ;
extern peer_rib peer_rib_unset_rs(bgp_peer peer, qafx_t qafx) ;

#endif /* _QUAGGA_BGP_RIB_H */
