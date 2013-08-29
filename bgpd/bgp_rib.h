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
#include "bgpd/bgp_attr_store.h"
#include "bgpd/bgp_filter.h"

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

  rib_item_type_t       type ;
  rib_item_flags_t      flags ;
} ;

/*------------------------------------------------------------------------------
 * There is one bgp_rib_node in a bgp_rib for each active prefix.
 */
typedef enum bgp_rib_node_flags bgp_rib_node_flags_t ;

enum bgp_rib_node_flags
{
  rnf_selected           = BIT(0),      /* something has been selected  */
  rnf_deterministic_med  = BIT(1),

  rnf_processed          = BIT(7),      /* update process completed     */
};

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

  bgp_rib_node_flags_t flags ;

  /* All of the routes available for the prefix are kept in an svec, so that
   * the lists of those per context use svec_index references.
   */
  svec4_t       avail[1] ;

  /* For each Routing Context we have a list of 'iroute', where the first
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
   *     context_count, and then copy the iroute_bases and any following
   *     zroutes, separately.
   *
   *     So: NOTHING other than iroute_bases and zroutes can follow
   *         the context_count !
   */
  uint          context_count ;

  zroute*       zroutes ;

  svs_base_t    iroute_bases[] ;
} ;

CONFIRM(offsetof(bgp_rib_node_t, it) == 0) ;

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
  /* The RMERIT_CHANGED flag forces the current selection to be re-announced.
   */
  RMERIT_CHANGED      = BIT(0),

  /* The RMERIT_UNSORTED flag causes a route selection process to run.
   */
  RMERIT_UNSORTED     = BIT(1),
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
  mpls_tags_t       tags ;

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
  peer_rib      prib ;

  /* When the route-info is attached to a rib-node, we have:
   *
   *   rn      -- points to the rib-node in question
   *   rlist   -- list "pointer"s for route-infos known to the rib-node
   *   rindex  -- index of this route-info in the rib-node's svec of known
   *              route-infos
   */
  bgp_rib_node  rn ;
  svl_list_t    rlist ;

  svec_index_t  rindex ;

  /* The prefix_id for this route
   */
  prefix_id_t   pfx_id ;

  /* The current and pending state of the route.
   */
  iroute_state_t current ;
  iroute_state_t pending ;

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
  uint          context_count ;
  iroute_t      iroutes[] ;
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

  attr_set              attr ;

  prefix_id_t           pfx_id ;
  mpls_tags_t           tag ;

  qafx_t                qafx ;
  route_in_action_t     action ;

  bgp_route_type_t      route_type ;
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
 * is a bgp_rib.
 */
typedef struct bgp_rib bgp_rib_t ;

struct bgp_rib
{
  bgp_inst      bgp ;                   /* parent bgp instance          */

  /* State of the RIB and various flags which we have here for convenience
   */
  qafx_t        qafx ;
  bool          real_rib ;

  bool          always_compare_med ;    /* BGP_FLAG_ALWAYS_COMPARE_MED  */
  bool          confed_compare_med ;    /* BGP_FLAG_MED_CONFED          */
  bool          aspath_ignore ;         /* BGP_FLAG_ASPATH_IGNORE       */
  bool          aspath_confed ;         /* BGP_FLAG_ASPATH_CONFED       */

  uint32_t      default_local_pref ;    /* copy of bgp entry            */
  uint          lock;

  /* Each RIB has a table of the local route-contexts, which refers to the
   * global route-contexts for the bgp instance.
   */
  svec4_t       rc_map ;

  uint          peer_count ;            /* Number of activated peers    */
  uint          context_count ;         /* Number of route-contexts     */

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

  /* The processing of changed prefixes is done by a "walker", which lives on
   * the "queue" while it is active.
   */
  bgp_rib_walker walker ;               /* Walker for "update" walk     */
} ;

/*==============================================================================
 * Functions
 */
extern bgp_rib bgp_rib_new(bgp_inst bgp, qafx_t qafx) ;
extern bgp_rib bgp_rib_destroy(bgp_rib rib) ;

extern bgp_rib_node bgp_rib_node_get(bgp_rib rib, prefix_id_entry pie) ;
extern bgp_rib_node bgp_rib_node_extend(bgp_rib_node rn) ;


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
