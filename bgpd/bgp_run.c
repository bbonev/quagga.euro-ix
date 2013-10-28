/* BGP Running Instances
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
#include "bgpd/bgp_run.h"
#include "bgpd/bgpd.h"

#include "list_util.h"

/*==============================================================================
 * The running state of a bgp instance.
 *
 * This is the root of a forest of data structures which manage peers,
 * routeing contexts, ribs, adj-in, adj-out, etc etc.
 *
 * Each brun has a name, which may be no-name -- known as the 'view'.  Each
 * brun contains:
 *
 *   * all running parameters common to all aff/safi -- though some of those
 *     are duplicated across the ribs.
 *
 *   * a rib for each afi/safi supported
 *
 *   * a number of peers/neighbors
 *
 *     All neighbors across all views must be distinct -- such that a distinct
 *     BGP Session can be set up.
 *
 *     Neighbors are known by their IP Address (pro tem TODO), so every
 *     neighbor (in every view) must have a unique IP Address.
 *
 *   * a number of groups -- whose names are scoped within the view
 *
 *     The groups have no effect, except that group membership for peers
 *     is preserved from the configuration.
 *
 *   * a number of route-contexts ("global" route-contexts)
 *
 *     Each route-context has a route-context id and a name.  A route-
 *     context applies to all afi/safi.  Route-context id == 0 is no-context.
 *
 *     The route-context name is coped within the 'view', the route-context
 *     id's are global across views.
 *
 *     Each neighbor may have a route-context associated with it, which it may
 *     share with a number of other neighbors within the view.
 *
 *     Where a neighbor does not have its own route-context, it shares the
 *     'view's route-context.
 *
 *     The 'view' may not have a 'route-context' -- in which case there is
 *     no IGP and no installation of routes.
 *
 * For each afi/safi for which the brun is configured we have a rib, and
 * the rib contains:
 *
 *   * the running parameters for the afi/safi.
 *
 *   * the "local-context" map.
 *
 *     Each rib has a dense set of local-context ids, where id == 0 is the
 *     'view' local-context.  Those map to the route-contexts.
 *
 *     Each local-context has its own set of candidate routes, its own
 *     currently selected route and so on.
 *
 *     Every neighbor (running in the afi/safi) is associated with a local-
 *     context.
 *
 *   * a list of all the pribs (peer-ribs) currently running.
 *
 *   * a table of bgp_rib_node -- by prefix_id
 *
 *     each prefix known in the rib has a bgp_rib_node, and can be found via
 *     this table by its prefix-id.
 *
 *   * a table of route-distinguishers
 *
 *   * the bgp_rib_node queue.
 *
 *     All bgp_rib_nodes live on this queue.  Also on this queue are one or
 *     more rib-walkers.
 *
 *     Nodes are scheduled for route-selection etc. by moving them to the
 *     end of this queue.  The walkers will then move forward until there
 *     is nothing ahead of them.
 *
 *     There is a "main" walker, which is always ahead of any other walkers.
 *     It performs route-selection etc. and updates all peers in steady
 *     state, and all peers attached to the walker which are in "refresh"
 *     state.
 *
 *     When a peer is first established, or when route-refresh is executed,
 *     or when a soft-out refresh is executed, the peer is put into "refresh"
 *     state, and a walker starts at the beginning of the queue to process
 *     all current selections out to the peer.  If walkers run into each other,
 *     they coalesce their "refresh" lists.  When a refresh walker runs into
 *     the "main" walker, the "main" walker subsumes it.
 *
 *   * the table of "update" (or "steady state") neighbors (pribs).
 *
 *   * static and aggregate routes -- TBA TODO !!!
 *
 *==============================================================================
 * The scheduling of work.
 *
 * This is an overview of the process of receiving routes from a peer,
 * processing those into the RIB, selecting routes and sending updates to all
 * peers.
 *
 * 1) arrival of UPDATEs etc in the read ring-buffer
 *
 *    These arrive via the session->read_rb from the BGP Engine.
 *
 *    The ring-buffer has a mechanism to signal when the reader has emptied
 *    out the ring-buffer, and should be kicked when something new is added.
 *    That mechanism translates to a message queue message to prompt the
 *    prun -- that message may be sent by the BGP Engine or by the Routeing
 *    Engine to itself.
 *
 *    The message is ignored if the prun is no longer bgp_pEstablished.
 *
 *    TODO ... actual scheduling of work, so that it can be suspended and
 *             later restarted or otherwise.
 *
 * 2) processing of messages out of the read ring-buffer
 *
 *    bgp_packet_read_stuff() takes messages out of the ring-buffer and
 *    parses them into calls of:
 *
 *      * bgp_packet_update_nlri() which updates the state of the adj-in for
 *        a given nlri, calling bgp_adj_in_update_prefix().
 *
 *        This adds prefixes to the adj-in's pending queue.
 *
 *      * bgp_announce_family() and other stuff for Route Refresh.
 *
 *    TODO scheduling of bgp_packet_read_stuff() ???
 *
 * 3) processing the adj-in pending queue
 *
 *    bgp_adj_in_process() runs the adj-in pending queue, and processes a
 *    route_info into or out of the candidates for the rib_node.
 *
 *    Here we perform all the: 'in', 'inx', 'export' and 'import' filtering
 *    etc. for all local contexts.  Updates the route merit and updates the
 *    candidate list for each affected route context.
 *
 *    Local contexts which are
 *
 *    Where the route-merit requires it, schedule the rib-node for processing.
 *    A rib-node is scheduled for processing by placing it at the end of the
 *    rib-node queue, and handing over to the main rib-walker.
 *
 *    TODO ... actual scheduling of work and suspension of same.
 *
 * 4) processing the rib-node queue -- the main rib-walker
 *
 *    bgp_process_walker() for the main rib-walker will do bgp_process_node(),
 *    which will -- for all changed local contexts -- do bgp_route_select_lc()
 *    and then bgp_route_announce() to all peers in the context.
 *
 *    TODO ... actual scheduling of work and suspension of same.
 *
 * 5) processing selected routes
 *
 *    bgp_route_announce() performs outbound filtering and final construction
 *    of attributes to be sent into the adj-out.
 *
 *    TODO ... actual scheduling
 *
 * 6) marshaling of routes
 *
 * 7) dispatch of updates.
 *
 *
 * Each rib has a work-queue .... TODO
 *
 * Each peer
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

/*------------------------------------------------------------------------------
 * Look-up brun by name -- this is for run-time operations, such as "show".
 *
 * For historical reasons, a NULL name returns the first brun on the list,
 * which will be the "unnamed view", if there is one.
 *
 * To lookup the unnamed view specifically, use "" (its other name).
 */
extern bgp_run
bgp_run_lookup(chs_c view_name)
{
  bgp_run brun;

  if (view_name == NULL)
    return ddl_head(bm->bruns) ;

  for (brun = ddl_head(bm->bruns) ; brun != NULL ;
                                    brun = ddl_next(brun, brun_list))
    if (bgp_name_match(brun->view_name, view_name))
      return brun ;

  return NULL;
} ;

/*------------------------------------------------------------------------------
 * Get first prib in given qafx -- if any.
 *
 * TODO -- make sure the list is sorted !!
 */
extern bgp_prib
bgp_run_get_pribs(bgp_run brun, qafx_t qafx)
{
  bgp_rib rib ;

  rib = brun->rib[qafx] ;

  if (rib == NULL)
    return NULL ;

  return NULL ;                 // TODO ????
} ;

