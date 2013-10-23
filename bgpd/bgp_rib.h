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

#include "misc.h"

#include "bgpd/bgp_common.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_config.h"
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_rcontext.h"

#include "list_util.h"
#include "prefix_id.h"
#include "ihash.h"
#include "vhash.h"
#include "svector.h"
#include "pfifo.h"
#include "qtime.h"
#include "qtimers.h"
#include "workqueue.h"
#include "filter.h"
#include "plist.h"
#include "routemap.h"

/*==============================================================================
 * The RIB, the Peer-RIBs, Route-Contexts, RIB_Walkers etc.
 *
 * For each bgp instance (view), for each AFI/SAFI, there will be a bgp_rib,
 * aka the RIB -- if there are any neighbors in that view which are configured
 * for that AFI/SAFI.  Each prefix in the RIB has a "rib-node", in an ihash by
 * prefix_id.
 *
 * For each peer, for each AFI/SAFI, there will be a peer_rib.  The peer-rib
 * contains (inter alia) the adj-in and adj-out for the peer.  The adj-in
 * the adj-in is an ihash by prefix-id of "route-info" objects, comprising the
 * routes received from that peer.  The adj-out is also an ihash by prefix-id,
 * comprising all routes announced to that peer.
 *
 * For each route-context, for each AFI/SAFI, there will be a bgp_rcontext.
 * The route-context has some incoming filters associated with it.  Each
 * route-context has a global-id -- by which it is known to the next-hop and
 * in particular to the next-hop metric stuff.  Within a given RIB there is
 * a local-id (the local-context) -- so that the tables of things by context
 * in the rib-node and the route-info can be as dense as possible.
 *
 * Each route-info has a table, by local-context of "iroute"s, which contain
 * the attributes and merit for each route available from the peer in that
 * context.  Each rib-node has a table of lists, by local-context, of the
 * available iroutes, in that context, from all peers -- the first iroute on
 * the list is the current selection.
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


/*==============================================================================
 * A bgp_route_type is a packed value:
 *
 *   * bits 1..0:  the bgp_route_subtype, as below
 *
 *   * bits 7..2:  the zebra route type (ZEBRA_ROUTE_XXX)
 */
typedef enum bgp_route_subtype bgp_route_subtype_t ;
typedef uint bgp_zebra_route_t ;

enum bgp_route_subtype
{
  /* BGP_ROUTE_NORMAL  -- learned from peer
   *
   */
  BGP_ROUTE_NORMAL,
  BGP_ROUTE_AGGREGATE,
  BGP_ROUTE_REDISTRIBUTE,
  BGP_ROUTE_STATIC,

  BGP_ROUTE_SUBTYPE_COUNT
};

typedef enum bgp_route_type bgp_route_type_t ;
enum bgp_route_type
{
  BGP_ZEBRA_ROUTE_SHIFT   = 2,

  BGP_ROUTE_SUBTYPE_MASK  = BIT(BGP_ZEBRA_ROUTE_SHIFT)     - 1,
  BGP_ZEBRA_ROUTE_MASK    = BIT(8 - BGP_ZEBRA_ROUTE_SHIFT) - 1,

  bgp_route_type_null     = 0,

  bgp_route_type_normal   = (ZEBRA_ROUTE_BGP << BGP_ZEBRA_ROUTE_SHIFT)
                                                             | BGP_ROUTE_NORMAL,

  bgp_route_type_t_max    = BGP_ROUTE_SUBTYPE_MASK | BGP_ZEBRA_ROUTE_MASK,
} ;

CONFIRM((BGP_ROUTE_SUBTYPE_COUNT - 1) <= BGP_ROUTE_SUBTYPE_MASK) ;
CONFIRM((ZEBRA_ROUTE_MAX         - 1) <= BGP_ZEBRA_ROUTE_MASK) ;
CONFIRM(bgp_route_type_null == ((ZEBRA_ROUTE_SYSTEM << BGP_ZEBRA_ROUTE_SHIFT)
                                                          | BGP_ROUTE_NORMAL)) ;
CONFIRM(bgp_route_type_t_max <= 255) ;  /* byte         */

/*==============================================================================
 *
 */
typedef struct bgp_run_redist  bgp_run_redist_t ;
struct bgp_run_redist
{
  bool          set ;
  bool          metric_set ;
  uint          metric ;

  route_map     map;
};

/*==============================================================================
 * The bgp-rib -- RIB.
 *
 * For each address family which has at least one active peer in it, there
 * is a bgp_rib.
 */
typedef struct bgp_rib bgp_rib_t ;

struct bgp_rib
{
  bgp_run       brun ;                  /* parent bgp running instance */

  /* State of the RIB and various flags which we have here for convenience
   */
  qafx_t        qafx ;
  bool          real_rib ;

  /* The Run-Time Parameters and compilation stuff.
   */
  bgp_rib_param_t  rp ;

  bgp_run_delta_t  delta ;

  /* Each RIB has a number of local contexts, which are aliases for the sub-set
   * of global route-contexts which the RIB uses.
   *
   * The 'view' always has a local context, lc_view_id == 0.  That is set up
   * when the rib is created, and may later be associated with a route-context.
   * All peers are, by default associated with lc_view_id.
   *
   * All other local contexts are mapped to the respective global route-context
   * by the rc_map.  All active local contexts are hung off the rc_map->base
   * list.
   */
  uint          peer_count ;            /* Number of activated peers    */
  uint          local_context_count ;   /* Number of route-contexts     */

  bgp_lcontext  lc_view ;               /* The "view" lcontext          */
  svec4_t       lc_map[1] ;             /* lc-id -> lcontext            */

  /* The pribs known to this RIB.
   */
  struct dl_base_pair(bgp_prib) pribs ;

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
  struct dl_base_pair(bgp_rib_item) queue_base ;

  /* The processing of changed prefixes is done by this dedicated "update" rib-
   * walker, which lives on rib's queue -- at the end when there is no work
   * to be done.
   */
  bgp_rib_walker walker ;               /* Walker for "update" walk     */

  /* The peer-ribs to update, per local context -- this excludes the peers
   * which are in "refresh" state, which are attached to a refresh walker.
   *
   * The "view" local context is special !
   */
  bgp_prib      update_view_peers ;
  svec4_t       update_peers[1] ;

  /* Static route configuration.
   */
  bgp_table     route ;

  /* Aggregate address configuration.
   */
  bgp_table     aggregate ;

  /* Redistribution route-maps -- if any
   */
  route_map     redist_rmap[redist_type_count] ;
} ;

/*------------------------------------------------------------------------------
 * Local Context -- these are the contexts within a bgp-rib.
 *
 * Local Context 0 is the "view"s context, which has special properties:
 *
 *   * incoming routes are filtered by the 'in' route-map and all the other
 *     neighbor incoming filters.
 *
 *   * for standard BGP, this is the only context in the RIB, and for the
 *     "unnamed" view is the one which feeds into Zebra and hence the Kernel.
 *
 *   * for Route-Server, this collects routes from all neighbors, including
 *     non-Route-Server-Clients, and behaves as standard BGP.
 *
 *     This is the default behaviour... preserved for compatibility TODO ....
 *
 *   * for SDN, this collects all routes which are acceptable to at least the
 *     general filtering, prior to being fed to the real route contexts.
 *
 * The bgp-rib maps local contexts to the global contexts and to filters and
 * such using svec "small vectors", so the number of local contexts is
 * "limited".
 *
 * Note that Local Context 0 is not a usable svec_index (since those start at
 * '1'), so the special properties of this context include the fact that it
 * cannot be mapped to anything via any svec -- so requires special treatment.
 * (One hopes not to come to regret this.)
 *
 * Note that in rib-node and route-info objects, the local context is used
 * as an index into the 'aroutes', 'iroutes' and 'zroutes' arrays.  Those are
 * simple C arrays, where '0' is a perfectly ordinary index.
 */
enum
{
  lc_view_id    = 0,

  lc_first_id   = 1,            /* first ordinary local context         */
  lc_last_id    = 4094,         /* last ordinary local context          */

  lc_end_id     = 4095,         /* alternative list end marker          */

  lc_id_mask    = MASK(12),     /* mask to extract local context        */

  /* For lists which use local-context as the "pointer", we use these values.
   *
   * Where such a list does not include lc_view, can use lc_null as an end
   * marker.  Where a list can contain lc_view, can use lc_end.
   *
   * The list of changed contexts uses lc_end to signal the end of a list, and
   * lc_null to signal that route is not on the list.
   */
  lc_id_null    = 0,

  /* Note that have space for 4 flags at the top of a bgp_lc_t value.
   */
} ;
CONFIRM(lc_view_id  == (uint)SVEC_NULL) ;
CONFIRM(lc_first_id == (uint)SVEC_FIRST) ;
CONFIRM(lc_last_id  <= (uint)SVEC_LAST) ;
CONFIRM(lc_end_id   == lc_id_mask) ;

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

  rib_itf_update      = BIT(2), /* this is the rib's update walker      */
} ;

struct bgp_rib_item
{
  bgp_rib       rib ;

  struct dl_list_pair(bgp_rib_item) queue ;

  rib_item_type_t       type ;
  rib_item_flags_t      flags ;
} ;

/*==============================================================================
 * The rib-node and rib-walker.
 *
 * There is one bgp_rib_node in a bgp_rib for each active prefix.
 *
 * The rib-nodes and rib-walkers are both rib-items, and share a common header
 * so that they can both live on the rib's processing list.
 */

/* Each local context known to the rib-node has an 'aroute' entry, where:
 *
 *   * base    -- is the base of the list of available routes in the
 *                local context.
 *
 *                The first entry on this list is the currently selected
 *                route (or the soon to be anointed route).
 *
 *   * next    -- is used to link all local contexts for which a rib-node
 *                processing run is required, and may contain other flags.
 *
 *                Values:  lc_null    -- not scheduled for rib-node processing
 *                         <lc>       -- scheduled, and <lc> is next on list
 *                         lc_end     -- scheduled, and is last on list
 */
typedef struct aroute  aroute_t ;
struct aroute
{
  svs_base_t    base[1] ;
  bgp_lc_id_t   next ;
} ;

typedef struct bgp_rib_node  bgp_rib_node_t ;
typedef const struct bgp_rib_node* bgp_rib_node_c ;

struct bgp_rib_node
{
  /* Each rib-node is a rib-item, so that rib-nodes and rib-walkers have the
   * same "header":
   *
   * The rib-node lives on queue of rib-nodes to be processed by rib-walker(s).
   */
  bgp_rib_item_t  it ;

  prefix_id_t   pfx_id ;

  bool          processed ;
  bool          has_changed ;

  /* Temporarily, during route selection the current selection for the
   * current local_context,
   */

  /* All of the routes available for the prefix are kept in an svec, so that
   * the lists of those per context use svec_index references.
   */
  svec4_t       avail[1] ;

  /* For each Local Context we have a list of 'iroute', where the first
   * entry on each list is the current selection.
   *
   * For 'real_rib' ribs we also have a 'zroute'.  Space for the array of
   * 'zroute' is allocated after the 'iroute_bases', and pointed to by the
   * zroutes entry.
   *
   * We allocate rib-nodes as a single unit, expecting that the number of
   * times the number of contexts will change are strictly limited.  We have
   * one or two vectors of stuff by context-id:
   *
   *   iroute_bases[]
   *   zroutes[]
   *
   * NB: when extending a rib-node, we copy upto but excluding the
   *     local_context_count, and then copy the iroute_bases and any following
   *     zroutes, separately.
   *
   *     So: NOTHING other than iroute_bases and zroutes can follow
   *         the local_context_count !
   */
  bgp_lc_id_t   local_context_count ;
  svl_base_t    changed[1] ;

  zroute        zroutes ;

  aroute_t      aroutes[] ;
} ;

CONFIRM(offsetof(bgp_rib_node_t, it) == 0) ;

/*------------------------------------------------------------------------------
 * When a route is installed we store its state.
 */
typedef struct zroute  zroute_t ;

struct zroute
{
  iSAFI_t     i_safi ;                  /* iSAFI value  */
  byte        flags ;

  uint32_t    med ;

  ip_union_t  next_hop ;
  uint        ifindex;
} ;

Need_alignof(zroute_t) ;

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
 * There is one "update" walker per bgp-rib, which processes changes to the
 * rib and dispatches updates to the rib's .
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
typedef struct bgp_rib_walker  bgp_rib_walker_t ;
struct bgp_rib_walker
{
  bgp_rib_item_t  it ;

  wq_item         wqi ;

  struct dl_base_pair(bgp_prib) refresh_peers ;
} ;

CONFIRM(offsetof(bgp_rib_walker_t, it) == 0) ;

/*==============================================================================
 * The route-info
 *
 * There is one route-info in a peer-rib's adj-in for each prefix for which
 * there is a route.
 */

/*------------------------------------------------------------------------------
 * The "merit" of a route combines the first 5 steps of the route comparison
 * into a single, signed 64-bit value:
 *
 *        16           32          10     2    4
 *   +---....---+---........---+--....--+---+-...-+
 *   |  Weight  |  Local Pref  |  ~ASP  | o |flags|
 *   +---....---+---........---+--....--+---+-...-+
 *
 * along with some flags for other route handling.
 *
 * We select for greater merit.
 *
 * So we have, from the MS end:
 *
 *   a. Weight
 *
 *      Greater weight has greater merit.
 *
 *   b. Local Preference
 *
 *      Greater local preference has greater merit.
 *
 *      Note that this value may (well) be set to the default for the bgp
 *      instance.
 *
 *   c. ~(AS-PATH Length + 1) or Local Routes (0x3FF)
 *
 *      Local Routes are preferred over Neighbor Routes, so the largest
 *      possible value of this field is reserved for such routes.
 *
 *      For routes learned from neighbors this is the 1's complement of the
 *      effective AS-PATH Length + 1 -- shorter path has greater merit.
 *
 *      This is the effective AS-PATH length because:
 *
 *        * if bgp->flags & BGP_FLAG_ASPATH_IGNORE then the length is zero
 *          (so the field is 0x3FE).
 *
 *        * if bgp->flags & BGP_FLAG_ASPATH_CONFED then this includes any
 *          confederation segments.
 *
 *        * otherwise it is the simple path length.
 *
 *      Note that the maximum path length is "limited" to 1022 !
 *
 *   d. ~ORIGIN
 *
 *      The valid origin values are IGP (0), EGP (1) and INCOMPLETE (2).
 *      The smaller origin value has greater merit.
 *
 *      Serendipity has left value 3 unused.
 *
 *      For Local Routes this field is set to 0 (unused origin).
 *
 *   e. flags -- ignored for merit comparison
 *
 * Happily we can encode merit_none as 0 (which is minimum weight, minimum
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
  route_merit_as_path_bits      = 10,
  route_merit_origin_bits       =  2,
  route_merit_flag_bits         =  4,

  route_merit_weight_shift      = route_merit_local_pref_bits
                                + route_merit_as_path_bits
                                + route_merit_origin_bits
                                + route_merit_flag_bits,
  route_merit_local_pref_shift  = route_merit_as_path_bits
                                + route_merit_origin_bits
                                + route_merit_flag_bits,
  route_merit_as_path_shift     = route_merit_origin_bits
                                + route_merit_flag_bits,
  route_merit_origin_shift      = route_merit_flag_bits,
  route_merit_flags_shift       = 0,

  /* The as-path field is set to the maximum value for the field for Local
   * Routes.
   */
  route_merit_as_path_max       = BIT(route_merit_as_path_bits) - 1,

  /* The mask for the flag bits.
   */
  route_merit_flags_mask        = BIT(route_merit_flag_bits) - 1,
} ;

#define route_merit_mask (~(route_merit_t)route_merit_flags_mask)

CONFIRM(route_merit_mask == (UINT64_MAX ^ route_merit_flags_mask)) ;

/*------------------------------------------------------------------------------
 * Each routeing context has its own attributes and merit, held in the
 * route_info.
 *
 * Each of those is held on the relevant rib node's candidate list, which is
 * arranged in descending order of merit.  For items with equal merit, later
 * ones are added after earlier ones, except where we have deterministic MEDs
 * and items with equal med-as: in that case, new items are added after the
 * last one with equal med-as.
 *
 * NB: there is an assumption here that there are relatively few routes
 *     per prefix -- so simple insertion sort is acceptable.
 *
 *     When new routes arrive, they do not disturb the main RIB unless the
 *     selected route changes.  But when that does change, selecting the
 *     next best route is straightforward.
 *
 *     It is not, in fact, essential to fully sort the list... that could be
 *     done either or demand, or later.
 *
 * NB: in deterministic MED, adding a new route must scan for its med-as
 *     buddies, will the same merit.
 */
typedef struct iroute iroute_t ;
typedef const struct iroute* iroute_c ;

struct iroute
{
  svs_list_t    list[1] ;

  attr_set      attr ;
  route_merit_t merit ;
} ;

/*------------------------------------------------------------------------------
 * There is one route_info for each route received from a peer.
 *
 * The route_info lives in the peer's adj_in.
 *
 * It will also live on the relevant bgp_rib_node's list of routes -- unless
 * the route has been filtered out.
 */
enum route_merit_flags
{
  /* The perfect arrangement of routes would be:
   *
   *   * current selection first
   *
   *   * followed by other routes with the same merit (clustered by med_as)
   *
   *   * followed by other routes of less merit in descending order of
   *     same (clustered by med_as, where the merit is equal).
   *
   * However, a full sort could be expensive, and generally routes are stable,
   * so when we process a rib-node we need to find:
   *
   *   * all routes with the greatest merit (clustered by med_as)
   *
   *   * the best route amongst those candidates
   *
   *   * a means to record the current selection, because that figures in the
   *     tie break.
   *
   * So, our compromise arrangement of routes is:
   *
   *   * the current selection first
   *
   *   * other routes, possibly completely unsorted.
   *
   * We have an UNSORTED flag for each route, and we have the rule that:
   *
   *   * a sorted route is >= all following routes, sorted or not.
   *
   *   * conversely, all routes (sorted or not) are <= any preceding
   *                                                               sorted routes
   *
   * This means that when finding all routes with the greatest merit, the scan
   * can stop as soon as it finds a sorted route of less merit.
   */
  RMERIT_UNSORTED     = BIT(0),

  RMERIT_SELECTED     = BIT(1),
} ;

typedef enum route_info_flags route_info_flags_t ;

enum route_info_flags
{
  RINFO_NULL            = 0,            /* Nothing of interest  */

  /* In the current iroute_state_t:
   *
   *   * RINFO_STALE   <=> route-info is sitting on the prib->stale_queue
   *
   *                       is not RINFO_REFUSED | RINFO_WITHDRAWN
   *                       so there must be current.attr, and will be
   *                       attached to a rib-node.
   *
   *                       Cannot also be RINFO_PENDING !
   *
   * In the pending iroute_state_t:
   *
   *   * RINFO_PENDING <=> route-info is sitting on the prib->pending_queue.
   *
   *                       may be RINFO_REFUSED | RINFO_WITHDRAWN
   *
   *                       Cannot also be RINFO_STALE !
   *
   */
  RINFO_STALE           = BIT( 0),
  RINFO_PENDING         = BIT( 0),

  /* Various degrees of "not-a-route"
   *
   *   * RINFO_DENIED    -- denied by filtering
   *
   *   * RINFO_REFUSED   -- broken attributes received, but session not dropped
   *
   *   * RINFO_WITHDRAWN -- neighbor withdrew the route
   */
  RINFO_DENIED          = BIT(13),
  RINFO_REFUSED         = BIT(14),
  RINFO_WITHDRAWN       = BIT(15),







  RINFO_IGP_CHANGED     = BIT( 0),
  RINFO_ATTR_CHANGED    = BIT( 1),

  RINFO_DAMPED          = BIT( 2),
  RINFO_HISTORY         = BIT( 3),
//RINFO_SELECTED        = BIT( 3),

  RINFO_VALID           = BIT( 4),

//RINFO_STALE           = BIT( 8),
  RINFO_REMOVED         = BIT( 9),
  RINFO_COUNTED         = BIT(10),


  RINFO_RS_DENIED      = BIT(15),

  route_info_t_max     = UINT16_MAX,
} ;

typedef struct iroute_state  iroute_state_t ;
typedef struct iroute_state* iroute_state ;
typedef const struct iroute_state* iroute_state_c ;

struct iroute_state
{
  attr_set          attr ;

  route_info_flags_t flags : 16 ;

  qafx_t            qafx       : 8;
  bgp_route_type_t  route_type : 8 ;
} ;

CONFIRM(route_info_t_max     <= UINT16_MAX) ;
CONFIRM(qafx_t_max           <= UINT8_MAX) ;
CONFIRM(bgp_route_type_t_max <= UINT8_MAX) ;

typedef enum route_info_flags rinfo_flags_t ;




typedef struct route_info route_info_t ;
typedef const struct route_info* route_info_c ;

struct route_info
{
  /* The parent peer rib -- will be in the prib->adj_in[rib_type_t].
   */
  bgp_prib      prib ;

  /* When the route-info is attached to a rib-node, we have:
   *
   *   rn      -- points to the rib-node in question
   *   rlist   -- list "pointer"s for route-infos known to the rib-node
   *   rindex  -- index of this route-info in the rib-node's svec of known
   *              route-infos
   */
  bgp_rib_node  rn ;
  svl_list_t    rlist[1] ;

  svec_index_t  rindex ;

  /* The prefix_id for this route -- once attached to a rib-node, this is
   * redundant -- but route_info need not always be attached.
   */
  prefix_id_t   pfx_id ;

  /* The current and pending state of the route.
   */
  iroute_state_t current ;
  iroute_state_t pending ;

  uint32_t      igp_metric ;            // TODO !!!!

  /* The 'plist' (pending) is used:
   *
   *   1) when a new route has arrived and is waiting to be processed.
   *
   *   2) when a route is 'stale' -- moves to 'plist' when new route arrives
   */
  struct dl_list_pair(route_info) plist ;

  /* Other current state of the route
   */
  as_t          med_as ;

  route_extra   extra ;

  time_t        uptime ;

  /* For each Routing Context we may have a route which is a candidate for
   * selection.  Each one has its attr and merit.  Where this is a candidate
   * in a given context, it will live on that context's selection list.
   */
  uint          local_context_count ;
  iroute_t      iroutes[] ;
} ;

/*==============================================================================
 * Functions
 */
extern bgp_rib bgp_rib_new(bgp_run brun, qafx_t qafx) ;
extern bgp_rib bgp_rib_destroy(bgp_rib rib) ;

extern bgp_rib_node bgp_rib_node_get(bgp_rib rib, prefix_id_entry pie) ;
extern bgp_rib_node bgp_rib_node_extend(bgp_rib_node rn) ;


extern bgp_rib_walker bgp_rib_walker_new(bgp_rib rib) ;
extern bgp_rib_walker bgp_rib_walker_discard(bgp_rib_walker rw) ;
extern bgp_rib_walker bgp_rib_walker_free(bgp_rib_walker rw) ;
extern bgp_rib_walker bgp_rib_walker_detach(bgp_prib prib) ;
extern bgp_rib_walker bgp_rib_walker_start_refresh(bgp_prib prib,
                                                             wq_function func) ;
extern bgp_rib_walker bgp_rib_walker_start(bgp_rib_walker rw,
                                                             wq_function func) ;

extern uint bgp_rib_count(bgp_rib rib) ;

extern vector bgp_rib_extract(bgp_rib rib, bgp_lc_id_t lc, prefix_rd prd) ;
extern vector bgp_rib_rd_extract(bgp_rib rib) ;
extern prefix_rd_id_entry bgp_rib_rd_seek(bgp_rib rib, prefix_rd prd) ;
extern int bgp_rib_node_cmp(const bgp_rib_node_c* p_a,
                            const bgp_rib_node_c* p_b) ;


Inline bgp_route_subtype_t bgp_route_subtype(bgp_route_type_t type)
                                                                 Always_Inline ;
Inline bgp_zebra_route_t bgp_zebra_route(bgp_route_type_t type)  Always_Inline ;
Inline bgp_route_type_t bgp_route_type(bgp_zebra_route_t ztype,
                                    bgp_route_subtype_t stype)   Always_Inline ;
Inline bgp_lcontext bgp_lcontext_get(bgp_rib rib, bgp_lc_id_t lc_id) ;


/*==============================================================================
 * The inlines
 */

/*------------------------------------------------------------------------------
 * Extract bgp_route_subtype_t from given bgp_route_type_t
 */
Inline bgp_route_subtype_t
bgp_route_subtype(bgp_route_type_t type)
{
  return type & BGP_ROUTE_SUBTYPE_MASK ;
} ;

/*------------------------------------------------------------------------------
 * Extract bgp_zebra_route_t from given bgp_route_type_t
 */
Inline bgp_zebra_route_t
bgp_zebra_route(bgp_route_type_t type)
{
  return type >> BGP_ZEBRA_ROUTE_SHIFT ;
}

/*------------------------------------------------------------------------------
 * Construct bgp_route_type_t from given bgp_zebra_route_t + bgp_route_subtype_t
 */
Inline bgp_route_type_t
bgp_route_type(bgp_zebra_route_t ztype, bgp_route_subtype_t stype)
{
  return (ztype << BGP_ZEBRA_ROUTE_SHIFT) | stype ;
} ;

/*------------------------------------------------------------------------------
 * Get the lcontext associated with the given lc-id, in the given rib.
 */
Inline bgp_lcontext
bgp_lcontext_get(bgp_rib rib, bgp_lc_id_t lc_id)
{
  if (lc_id == lc_view_id)
    return rib->lc_view ;
  else
    return svec_get(rib->lc_map, lc_id) ;
}

#endif /* _QUAGGA_BGP_RIB_H */
