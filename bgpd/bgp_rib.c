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
#include "zebra.h"

#include "bgp_rib.h"
#include "bgp_peer.h"

/*==============================================================================
 * The RIB spaghetti.
 *
 * Each bgp_inst has a rib_main bgp_rib for each AFI/SAFI with one or more
 * peers activated in that AFI/SAFI, or static routes or anything else defined
 * for it.  Once a rib_main bgp_rib has been created, it is not destroyed
 * until the bgp_inst is destroyed.
 *
 * A bgp_inst will (also) have a rib_rs bgp_rib for an AFI/SAFI while there is
 * one or more Route Server Clients.
 *
 * The bgp_inst has a list of all the peers configured for that instance.
 * That list is kept in peer "name" order.
 *
 * bgp_inst->rib[qafx][rib_main] -> bgp_rib for all known prefixes
 *                    [rib_rs]   -> bgp_rib if...
 *
 *
 *
 *
 *
 */



/*==============================================================================
 * Creation/Destruction of BGP RIB
 */

/*------------------------------------------------------------------------------
 * Create and initialise a new, empty bgp_rib
 *
 * Requires that there is currently no bgp_rib for the given rib_type/qafx.
 * (Will leak memory if there is, and the bgp_rib will simply be cast loose.)
 *
 * Returns:  address of the new bgp_rib
 */
extern bgp_rib
bgp_rib_new(bgp_inst bgp, qafx_t qafx, rib_type_t rib_type)
{
  bgp_rib  rib ;

  rib = XCALLOC(MTYPE_BGP_RIB, sizeof(bgp_rib_t)) ;

  /* Zeroizing has set:
   *
   *   * bgp            -- X          -- set below
   *
   *   * qafx           -- X          -- set below
   *   * rib_type       -- X          -- set below
   *
   *   * lock           -- 0          -- initial value
   *
   *   * nodes_table    -- NULL       -- none, yet
   *   * rds_table      -- NULL       -- none, yet
   *
   *   * queue          -- NULLs      -- empty queue, but walker added, below
   *   * walker         -- X          -- set below
   */
  rib->bgp         = bgp ;
  rib->qafx        = qafx ;
  rib->rib_type    = rib_type ;

  rib->nodes_table = ihash_table_init(rib->nodes_table, 0, 60) ;

  rib->walker      = bgp_rib_walker_new(rib) ;
  ddl_append(rib->queue, &rib->walker->it, queue) ;

  return bgp->rib[qafx][rib_type] = rib ;
} ;

/*------------------------------------------------------------------------------
 * Empty out and discard the given bgp_rib.
 *
 *
 */
extern bgp_rib
bgp_rib_destroy(bgp_rib rib)
{
  if (rib != NULL)
    {
      bgp_rib_node rn ;

      while ((rn = ihash_table_ream(rib->nodes_table, keep_it /* embedded */))
                                                                       != NULL)
        pnode_unlock(rn) ;

      XFREE (MTYPE_BGP_RIB, rib);
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get RIB Node for the given prefix, of the given type in the given RIB.
 *
 *
 *
 */
extern bgp_rib_node
bgp_rib_node_get(bgp_rib rib, prefix_id_entry pie)
{
  bgp_rib_node  rn ;

  /* See if we have a RIB Node for this already.
   *
   * Note that we do not store NULL pointers in this table.
   */
  rn = ihash_get_item(rib->nodes_table, pie->id, NULL) ;

  if (rn == NULL)
    {
      /* Need to create a new RIB Node.
       */
      rn = XCALLOC(MTYPE_BGP_RIB_NODE, sizeof(bgp_rib_node_t)) ;

      /* Zeroising has set:
       *
       *   * it.rib                 -- X        -- set below
       *   * it.queue               -- NULLs    -- not on any queue, yet
       *   * it.type                -- rib_it_node
       *   * it.flags               -- 0
       *
       *   * list                   -- NULLs    -- not on any list, yet
       *
       *   * available              -- NULLs    -- no available routes, yet
       *   * candidates             -- NULL     -- no candidates, yet
       *   * selected               -- NULL     -- no selected route, yet
       *
       *   * zebra                  -- NULL     -- no route in FIB, yet
       *
       *   * pfx_id                 -- X        -- set below
       *
       *   * flags                  -- 0        -- nothing, yet
       */
      confirm(rib_it_node == 0) ;

      rn->it.rib  = rib ;
      rn->pfx_id  = pie->id ;

      prefix_id_entry_inc_ref(pie) ;
      ihash_set_item(rib->nodes_table, pie->id, rn) ;
    } ;

  return rn ;
} ;

/*------------------------------------------------------------------------------
 * Get number of entries in the given bgp_rib (if any).
 */
extern uint
bgp_rib_count(bgp_rib rib)
{
  return (rib != NULL) ? ihash_entry_count(rib->nodes_table) : 0 ;
} ;

/*==============================================================================
 * Rib walker creation, destruction etc.
 */

/*------------------------------------------------------------------------------
 * Create a new, empty bgp_rib_walker
 */
extern bgp_rib_walker
bgp_rib_walker_new(bgp_rib rib)
{
  bgp_rib_walker rw ;

  rw = XCALLOC(MTYPE_BGP_RIB_WALKER, sizeof(bgp_rib_walker_t)) ;

  /* Zeroising has set:
   *
   *   * it.rib            -- X           -- set below
   *   * it.queue          -- NULLs
   *   * it.type           -- X           -- set below
   *   * it.flags          -- 0           -- nothing, yet
   *
   *   * wqi               -- NULL        -- no work queue item, yet
   *
   *   * peers             -- NULLs       -- empty lists
   */
  rw->it.rib    = rib ;
  rw->it.type   = rib_it_walker ;

  return rw ;
}

/*------------------------------------------------------------------------------
 * Discard the given bgp_rib_walker (if any).
 *
 * Tidies up: takes walker off the rib queue if it is on it.
 *
 *            deletes and frees any related work queue item.
 *
 *            ensures that there are no dangling references to pribs
 *
 * NB: it is the caller's responsibility to discard any pointers to the walker.
 *
 * Returns:  NULL
 */
extern bgp_rib_walker
bgp_rib_walker_discard(bgp_rib_walker rw)
{
  if (rw != NULL)
    {
      prib_state_t pst ;

      qassert(rw->it.type == rib_it_walker) ;

      if (rw->wqi != NULL)
        {
          if (rw->it.flags & rib_itf_wq_queue)
            {
              wq_item_del(&bm->bg_wq, rw->wqi) ;
              rw->it.flags ^= rib_itf_wq_queue ;
            } ;

          rw->wqi = wq_item_free(rw->wqi) ;
        } ;

      if (rw->it.flags & rib_itf_rib_queue)
        {
          ddl_del(rw->it.rib->queue, &rw->it, queue) ;
          rw->it.flags ^= rib_itf_rib_queue ;
        } ;

      for (pst = 0 ; pst < prib_state_count ; ++pst)
        {
          peer_rib prib ;

          for (prib = ddl_head(rw->peers[pst]) ;
                                       prib != NULL ;
                                       prib = ddl_next(prib, walk_list))
            prib->walker = NULL ;
        } ;

      XFREE(MTYPE_BGP_RIB_WALKER, rw) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Free the given bgp_rib_walker.
 *
 * NB: does nothing at all with:
 *
 *      * any work queue item -- except that if one exists, it's "data" pointer
 *        will be cleared.
 *
 *      * any entries in the peers lists
 *
 * NB: MUST not be on the rib->queue !!
 *
 * NB: it is the caller's responsibility to discard any pointers to the walker.
 *
 * Returns:  NULL
 */
extern bgp_rib_walker
bgp_rib_walker_free(bgp_rib_walker rw)
{
  qassert(rw->it.type == rib_it_walker) ;
  qassert(!(rw->it.flags & rib_itf_rib_queue)) ;

  if (rw->wqi != NULL)
    rw->wqi->data = NULL ;

  if (qdebug)
    memset(rw, 0, sizeof(bgp_rib_walker_t)) ;

  XFREE(MTYPE_BGP_RIB_WALKER, rw) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Detach given prib from any rib walker.
 *
 * If this is the only prib attached to the walker, free the walker if it is
 * a rib_it_initial_walk.
 *
 * NB: to be done before the prib->update_state is changed.
 *
 * Sets prib->walker to NULL.
 *
 * This may leave a rib_it_update_walk with no pribs attached, and that walker
 * may be on the queue and be active -- tant pis.
 *
 * Returns:  NULL
 */
extern bgp_rib_walker
bgp_rib_walker_detach(peer_rib prib)
{
  bgp_rib_walker rw ;

  rw = prib->walker ;
  if (rw != NULL)
    {
      ddl_del(rw->peers[prib->update_state], prib, walk_list) ;
      prib->walker = NULL ;

      if (rw != prib->rib->walker)
        {
          qassert(prib->update_state == prib_initial) ;
          qassert(ddl_head(rw->peers[prib_update]) == NULL) ;

          if (ddl_head(rw->peers[prib_initial]) == NULL)
            bgp_rib_walker_discard(rw) ;
        } ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Start an "initial" rib walker for the given peer_rib.
 *
 * The "initial" rib walker walks the rib_main or rib_rs, depending on the
 * rib_type of the peer.
 *
 * Detach the prib from its current walker, if any.  (Were the prib to already
 * be attached to an initial walker, and be the only prib so attached, then
 * this would be a bit of a waste of time... but we don't expect that to be
 * the case !)
 *
 * If there is a walker already queued at the start of the bgp_rib queue, then
 * join that and make sure it is going.
 *
 * Otherwise, create a new rib_it_walker, and set it going.
 *
 * Returns: address of the rib walker
 */
extern bgp_rib_walker
bgp_rib_walker_start_initial(peer_rib prib, wq_function func)
{
  bgp_rib        rib ;
  bgp_rib_walker rw ;
  bgp_rib_item   item ;

  bgp_rib_walker_detach(prib) ;

  rib = prib->rib ;     /* the bgp_rib for prib's address family, and for
                         * rib_main/rib_rs depending on the peer type.  */

  item = ddl_head(rib->queue) ;

  if ((item != NULL) && (item->type == rib_it_walker))
    {
      /* There is a walker at the start of the queue, which we can attach to.
       */
      rw = (bgp_rib_walker)item ;
      confirm(offsetof(bgp_rib_walker_t, it) == 0) ;
    }
  else
    {
      /* We need a new walker.
       */
      rw = bgp_rib_walker_new(rib) ;
    } ;

  return bgp_rib_walker_start(rw, func) ;
} ;

/*------------------------------------------------------------------------------
 * For the given walker set the work queue item going.
 *
 * Creates a work queue item is there is none.
 *
 * Does nothing if already has an active work queue item.
 */
extern bgp_rib_walker
bgp_rib_walker_start(bgp_rib_walker rw, wq_function func)
{
  qassert(rw->it.type == rib_it_walker) ;
  qassert(rw->it.flags & rib_itf_rib_queue) ;

  if (!(rw->it.flags & rib_itf_wq_queue))
    {
      if (rw->wqi == NULL)
        rw->wqi = wq_item_init_new(NULL, func, rw) ;

      wq_item_add(&bm->bg_wq, rw->wqi) ;
      rw->it.flags |= rib_itf_wq_queue ;
    } ;

  return rw ;
} ;

/*==============================================================================
 * Extracting all or part of a bgp_rib
 */
static bool bgp_rib_node_rd_select(const bgp_rib_node_c* p_a,
                                                      prefix_rd_id_entry rdie) ;

/*------------------------------------------------------------------------------
 * Extract a vector of pointers to bgp_rib_nodes for the current contents of
 * the given bgp_rib.
 *
 * Returns:  new vector with pointers to bgp_rib_nodes in prefix order.
 *           the vector is empty if the rib is NULL or empty.
 *
 * NB: it is the caller's responsibility to vector_free() the vector once it is
 *     done with it.
 *
 * NB: if prefixes are added to the RIB they will not be added to the vector.
 *
 *     If prefixes are deleted, then the vector will contain dangling pointers.
 *
 *     It would be wise to do the extract, process the result and discard the
 *     vector all in one go !
 */
extern vector
bgp_rib_extract(bgp_rib rib, prefix_rd prd)
{
  prefix_rd_id_entry  rdie ;

  if ((rib == NULL) || (ihash_entry_count(rib->nodes_table) == 0))
    return vector_new(0) ;

  if (prd == NULL)
    return ihash_table_extract(rib->nodes_table, NULL, NULL, true,
                                            (ihash_sort_cmp*)bgp_rib_node_cmp) ;

  rdie = prefix_rd_id_seek_entry(prd->val) ;
  if (rdie == NULL)
    return NULL ;

  return ihash_table_extract(rib->nodes_table,
                      (ihash_select_test*)bgp_rib_node_rd_select, rdie, false,
                                          (ihash_sort_cmp*)bgp_rib_node_cmp) ;
} ;

/*------------------------------------------------------------------------------
 * Compare two bgp_rib_node entries by their pfx_id
 */
extern int
bgp_rib_node_cmp(const bgp_rib_node_c* p_a, const bgp_rib_node_c* p_b)
{
  return prefix_id_cmp((*p_a)->pfx_id, (*p_b)->pfx_id) ;
} ;

/*------------------------------------------------------------------------------
 * Select bgp_rib_node entry if it matches the give Route Distinguisher
 */
static bool
bgp_rib_node_rd_select(const bgp_rib_node_c* p_a, prefix_rd_id_entry rdie)
{
  prefix_id_entry pie ;

  pie = prefix_id_get_entry((*p_a)->pfx_id) ;

  return pie->pfx->rd_id == rdie->id ;
} ;

/*------------------------------------------------------------------------------
 * Extract a vector of pointers to prefix_rd_id_entry for the Route
 * Discriminators used in the given bgp_rib.
 *
 * Returns:  new vector with pointers to prefix_rd_id_entry in order.
 *           the vector is empty if the rib is NULL or there are no Route
 *           Discriminators.
 *
 * NB: it is the caller's responsibility to vector_free() the vector once it is
 *     done with it.
 *
 * NB: if prefixes are added to the RIB they will not be added to the vector.
 *
 *     If prefixes are deleted, then the vector will contain dangling pointers.
 *
 *     It would be wise to do the extract, process the result and discard the
 *     vector all in one go !
 */
extern vector
bgp_rib_rd_extract(bgp_rib rib)
{
  if ((rib == NULL) || (ihash_entry_count(rib->rds_table) == 0))
    return vector_new(0) ;

  return ihash_table_extract(rib->rds_table, NULL, NULL, true,
                                    (ihash_sort_cmp*)prefix_rd_id_p_entry_cmp) ;
} ;

/*------------------------------------------------------------------------------
 * Seek given Route Discriminator amongst those used in the given bgp_rib.
 *
 * Returns:  address of prefix_rd_id_entry -- or NULL if not in use
 */
extern prefix_rd_id_entry
bgp_rib_rd_seek(bgp_rib rib, prefix_rd prd)
{
  prefix_rd_id_entry rdie, rib_rdie ;

  if (rib->rds_table == NULL)
    return NULL ;               /* no RD known to this RIB              */

  rdie = prefix_rd_id_seek_entry(prd->val) ;

  if (rdie == NULL)
    return NULL ;               /* given RD is not used anywhere        */

  rib_rdie = ihash_get_item(rib->rds_table, rdie->id, NULL) ;

  if (rib_rdie != NULL)
    qassert(rib_rdie == rdie) ;

  return rib_rdie ;
} ;

/*==============================================================================
 * Creation and destruction of peer_rib structures.
 */

/*------------------------------------------------------------------------------
 * Create new, empty peer_rib structure.
 *
 * Requires that there is currently no peer_rib for the given qafx.  (Will leak
 * memory if there is, and the peer_rib will simply be cast loose.)
 *
 * Creates a completely empty 'rib_main' peer_rib.
 *
 * If there is no 'rib_main' bgp_rib, creates an empty one.
 *
 * Returns:  address of the new peer_rib
 */
extern peer_rib
peer_rib_new(bgp_peer peer, qafx_t qafx)
{
  peer_rib prib ;
  bgp_rib  rib ;

  qassert(peer->prib[qafx] == NULL) ;

  prib = XCALLOC(MTYPE_BGP_PEER_RIB, sizeof(peer_rib_t)) ;

  /* Zeroising has set:
   *
   *   * peer                 -- X        -- set below
   *
   *   * rib                  -- X        -- set below
   *
   *   * walker               -- NULL     -- none, yet
   *   * walk_list            -- NULLs    -- not on any walker's list, yet

   *   * qafx                 -- X        -- set below
   *   * rib_type             -- rib_main -- default
   *
   *   * update_state         -- prib_initial   -- starting state
   *
   *   * is_mpls              -- X        -- set below, per qafx
   *   * refresh              -- false    -- not yet
   *   * eor_required         -- false    -- not yet
   *
   *   * lock                 -- 0
   *
   *   * af_flags             -- 0        -- nothing set
   *   * af_sflags            -- 0        -- nothing set
   *   * af_cap               -- 0        -- nothing set
   *
   *   * af_group_member      -- false
   *   * af_session_up        -- false
   *
   *   * allowas_in           -- 0        -- default state
   *
   *   * nsf                  -- false    -- initial state
   *
   *   * pcount               -- 0        -- nothing yet
   *   * scount               -- 0        -- nothing yet
   *
   *   * dlist                -- NULLs   )
   *   * plist                -- NULLs   )
   *   * flist                -- NULLs   )   no filters/routemaps, yet
   *   * rmap                 -- NULLs   )
   *   * us_rmap              -- NULL    )
   *   * default_rmap         -- NULL    )
   *   * orf_plist            -- NULL    )
   *
   *   * pmax                 -- all zero -- nothing
   *     pmax.set             -- false
   *
   *   * adj_in               -- NULLs    -- see bgp_adj_in_init()
   *   * stale_routes         -- NULLs    -- none, yet
   *
   *   * batch_delay          -- 0       )
   *   * batch_delay_extra    -- 0       )
   *   * announce_delay       -- 0       )
   *   * mrai_delay           -- 0       )   see bgp_adj_out_init()
   *   * mrai_delay_left      -- 0       )
   *   * period_origin        -- 0       )
   *   * now                  -- 0       )
   *   * t0                   -- 0       )
   *   * tx                   -- 0       )
   *
   *   * adj_out              -- NULL     -- see bgp_adj_out_init()
   *
   *   * fifo_batch           -- NULL    )
   *   * fifo_mrai            -- NULL    )
   *   * announce_queue       -- NULL    )   see bgp_adj_out_init()
   *   * withdraw_queue       -- NULLs   )
   *   * attr_flux_hash       -- NULL    )
   *   * eor                  -- NULL    )
   *
   *   * dispatch_delay       -- 0       )
   *   * dispatch_time        -- 0       )   see bgp_adj_out_init()
   *   * dispatch_qtr         -- NULL    )
   */
  confirm(prib_initial == 0) ;
  confirm(rib_main == 0) ;

  prib->peer    = peer ;
  prib->qafx    = qafx ;

  prib->is_mpls = qafx_is_mpls_vpn(qafx) ;

  /* Now worry about the bgp->rib.
   *
   * The peer_rib is automatically associated with the Main bgp_rib.  If there
   * is no such rib, then we create an empty one here and now.
   *
   * If the peer is later set to be a Route-Server Client, then the peer_rib
   * will be associated with the RS bgp_rib (and that will be created, if
   * necessary).  Note that even if there are no Main RIB peers, there is
   * always a Main RIB.
   */
  rib =  peer->bgp->rib[qafx][rib_main] ;
  if (rib == NULL)
    rib = peer->bgp->rib[qafx][rib_main] =
                                       bgp_rib_new(peer->bgp, qafx, rib_main) ;
  prib->rib = rib ;

  rib->peer_count += 1 ;

  /* Set and return the new prib.
   */
  return peer->prib[qafx] = prib ;
} ;

/*------------------------------------------------------------------------------
 * If the given peer is not already an RS Client for the AFI/SAFI, set it to be
 *                                                                 an RS Client.
 *
 * Does nothing if is already a rib_rs peer.
 *
 * Creates a completely empty peer_rib, if one does not exist.  Creates as a
 * rib_main peer, associated with the rib_main bgp_rib (creating that, if
 * required).
 *
 * Creates a rib_rs bgp_rib if required.
 *
 * If was a rib_main peer, then discards any walker with which the peer was
 * associated.
 *
 * Returns:  address of the new peer_rib
 */
extern peer_rib
peer_rib_set_rs(bgp_peer peer, qafx_t qafx)
{
  peer_rib prib ;
  bgp_rib  rib ;

  prib = peer->prib[qafx] ;

  if (prib == NULL)
    prib = peer_rib_new(peer, qafx) ;   /* creates rib_main bgp_rib if
                                         * required                     */
  else if (prib->rib_type == rib_rs)
    return prib ;

  /* We (now) have a prib, and it is rib_main.
   */
  rib = prib->rib ;                     /* the rib_main bgp_rib         */

  qassert(rib->rib_type == rib_main) ;

  bgp_rib_walker_detach(prib) ;         /* stop if walking rib_main     */

  rib->peer_count -= 1 ;

  rib = peer->bgp->rib[qafx][rib_rs] ;
  if (rib == NULL)
    rib = peer->bgp->rib[qafx][rib_rs] = bgp_rib_new(peer->bgp, qafx, rib_rs) ;

  prib->rib_type = rib_rs ;
  prib->rib = rib ;

  rib->peer_count += 1 ;

  return prib ;
} ;

/*------------------------------------------------------------------------------
 * If the given peer is an RS Client for the AFI/SAFI, unset that.
 *
 * Creates a completely empty peer_rib, if one does not exist.  Creates as a
 * rib_main peer, associated with the rib_main bgp_rib (creating that, if
 * required).
 *
 * Creates a rib_rs bgp_rib if required.
 *
 * Does nothing if is already a rib_rs peer.
 *
 * If was a rib_main peer, then discards any walker with which the peer was
 * associated.
 *
 * Returns:  address of the new peer_rib
 */
extern peer_rib
peer_rib_unset_rs(bgp_peer peer, qafx_t qafx)
{
  peer_rib prib ;
  bgp_rib  rib ;

  prib = peer->prib[qafx] ;

  if (prib == NULL)
    prib = peer_rib_new(peer, qafx) ;   /* creates rib_main bgp_rib if
                                         * required                     */

  if (prib->rib_type == rib_main)
    return prib ;

  /* We (now) have a prib, and it is rib_rs.
   */
  rib = prib->rib ;                     /* the rib_rs bgp_rib           */
  qassert(rib->rib_type == rib_rs) ;

  bgp_rib_walker_detach(prib) ;         /* stop if walking rib_rs       */

  rib->peer_count -= 1 ;

  rib = peer->bgp->rib[qafx][rib_main] ;
  qassert(rib != NULL) ;

  prib->rib_type = rib_main ;
  prib->rib = rib ;

  rib->peer_count += 1 ;

  return prib ;
} ;

/*------------------------------------------------------------------------------
 * Discard peer_rib structure.
 */
extern peer_rib
peer_rib_free(peer_rib prib)
{


  XFREE(MTYPE_BGP_PEER_RIB, prib) ;
  return NULL ;
} ;


