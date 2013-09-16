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
#include "bgp_adj_in.h"

/*==============================================================================
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
bgp_rib_new(bgp_inst bgp, qafx_t qafx)
{
  bgp_rib  rib ;

  rib = XCALLOC(MTYPE_BGP_RIB, sizeof(bgp_rib_t)) ;

  /* Zeroizing has set:
   *
   *   * bgp            -- X          -- set below
   *
   *   * qafx           -- X          -- set below
   *   * real_rib       -- X          -- copied from bgp_instance
   *
   *   * peer_count     -- 0          -- none, yet
   *   * local_context_count  -- 0          -- none, yet
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
  rib->real_rib    = bgp->real_rib ;

  rib->nodes_table = ihash_table_init(rib->nodes_table, 0, 60) ;

  rib->walker      = bgp_rib_walker_new(rib) ;
  rib->walker->it.flags = rib_itf_rib_queue | rib_itf_update ;

  ddl_append(rib->queue_base, &rib->walker->it, queue) ;

  return bgp->rib[qafx] = rib ;
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

#if 0
      while ((rn = ihash_table_ream(rib->nodes_table, keep_it /* embedded */))
                                                                       != NULL)
        pnode_unlock(rn) ;
#endif

      XFREE (MTYPE_BGP_RIB, rib);
    } ;

  return NULL ;
} ;

/*==============================================================================
 * Creation/Destruction etc. of Rib-Nodes
 */
static bgp_rib_node bgp_rib_node_new(bgp_rib rib, prefix_id_t pfx_id) ;
static bgp_rib_node bgp_rib_node_free(bgp_rib_node rn, bool clear_avail) ;

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
    return rn ;

  prefix_id_entry_inc_ref(pie) ;
  return bgp_rib_node_new(rib, pie->id) ;
} ;

/*------------------------------------------------------------------------------
 * Extend the number of route-contexts supported by the given rib-node, if
 *                                                                     required.
 *
 * If a rib-node has to be extended, has to allocate a new one, update all
 * pointers to the current one, and discard the current one.  Happily, this
 * should happen once in a blue moon.
 *
 * NB: this does not change any property of the rib-node, so does not change
 *     its place in the rib-queue.
 */
extern bgp_rib_node
bgp_rib_node_extend(bgp_rib_node rn)
{
  bgp_rib_node rn_new ;
  route_info   ri ;
  uint         lcc_new, lcc_old ;
  zroute       zroutes_new ;

  /* Hope for a quick get-away.
   */
  lcc_new = rn->it.rib->local_context_count ;
  lcc_old = rn->local_context_count ;

  if (lcc_new <= lcc_old)
    return rn ;

  /* We need a new rib-node, which will replace the one we have.
   *
   * The new rib-node will inherit all the properties of the existing one,
   * including any locks it owns.
   */
  rn_new      = bgp_rib_node_new(rn->it.rib, rn->pfx_id) ;
  zroutes_new = rn_new->zroutes ;

  memcpy(rn_new, rn, offsetof(bgp_rib_node_t, aroutes[lcc_old])) ;

  /* Copying has moved across:
   *
   *   * it.rib
   *   * it.queue               -- see below
   *   * it.type
   *   * it.flags
   *
   *   * pfx_id                 -- with the previous lock
   *   * flags
   *
   *   * avail                  -- see below
   *
   *   * local_context_count    -- old version
   *   * changed
   *
   *   * zroutes                -- old version, if any
   *
   *   * aroutes[]              -- for the old contexts
   *
   *   * zroutes[]              -- still all zero, copied as required, below
   */
  rn_new->local_context_count = lcc_new ;

  if (rn->it.rib->real_rib)
    {
      rn_new->zroutes = zroutes_new ;
      memcpy(zroutes_new, rn->zroutes, sizeof(zroute_t) * lcc_old) ;
    }
  else
    qassert(zroutes_new == NULL) ;

  /* The it.queue is based at it.rib->queue, and the new item must now
   * replace the old item in that queue.
   */
  ddl_replace(rn->it.rib->queue_base, (bgp_rib_item)rn, queue,
                                                         (bgp_rib_item)rn_new) ;
  confirm(offsetof(bgp_rib_node_t, it) == 0) ;

  /* All the route-infos which refer to the old rib-node must now refer to the
   * new one...  at the same time, all the route-infos may, themselves, have
   * to be extended !
   */
  ri = svl_head(rn->avail->base, rn->avail) ;
  while (ri != NULL)
    {
      qassert(ri->rindex != SVEC_NULL) ;

      ri->rn = rn_new ;

      if (ri->local_context_count < lcc_new)
        ri = bgp_route_info_extend(ri) ;

      ri = svl_next(ri->rlist, rn->avail) ;
    } ;

  /* Finally, release the old rib-node.
   *
   * We have copied the 'avail' svec to the new rib-node, so we need
   */
  bgp_rib_node_free(rn, false /* not clear_avail */) ;

  return rn_new ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, empty rib-node and place it in the RIB.
 *
 * NB: the pfx_id MUST be locked by the caller, for a brand new rib-node
 *
 * NB: if a rib-node already exists, it is replaced -- it is the caller's
 *     responsibility to deal with that.
 */
static bgp_rib_node
bgp_rib_node_new(bgp_rib rib, prefix_id_t pfx_id)
{
  bgp_rib_node rn ;
  uint    context_count ;
  uint    size, zroutes_offset ;

  context_count = rib->local_context_count ;

  size = offsetof(bgp_rib_node_t, aroutes[context_count]) ;
  zroutes_offset = uround_up(size, alignof(zroute_t)) ;
  if (rib->real_rib)
    size = zroutes_offset + (context_count * sizeof(zroute_t)) ;

  rn = XCALLOC(MTYPE_BGP_RIB_NODE, size) ;

  /* Zeroising has set:
   *
   *   * it.rib                 -- X        -- set below
   *   * it.queue               -- NULLs    -- not on any queue, yet
   *   * it.type                -- rib_it_node
   *   * it.flags               -- 0
   *
   *   * pfx_id                 -- X        -- set below
   *   * flags                  -- 0        -- nothing, yet
   *
   *   * avail                  -- SVEC_NULLs -- nothing available, yet
   *
   *   * local_context_count          -- X        -- set below
   *   * zroutes                -- NULL     -- set below, if required
   *   * iroutes[]              -- SVEC_NULLs -- nothing for the context
   *
   *   * body of zroutes        -- all zeros, if any
   *             .XXX fill in how empty zroute is initialised #########################
   */
  confirm(SVEC_NULL   == 0)
  confirm(rib_it_node == 0) ;

  rn->it.rib        = rib ;
  rn->pfx_id        = pfx_id ;
  rn->local_context_count = context_count ;

  if (rib->real_rib)
    rn->zroutes = (void*)((char*)rn + zroutes_offset) ;

  ihash_set_item(rib->nodes_table, pfx_id, rn) ;

  return rn ;
} ;

/*------------------------------------------------------------------------------
 * Free the given, empty, rib-node -- very low level free.
 *
 * The caller must have dealt with:
 *
 *   * the rn->it.queue
 *
 *   * the lock on the pfx_id.
 *
 *   * emptying the rn->avail svec.
 *
 *   * emptying the rn->routes   -- the .ilist for each route-context
 *                                      .aroute ditto (if 'main')
 *
 * Will now clear the rn->avail svec, if required.  (When extending a rib-node
 * all the above are copied to the new node, including the avail svec, which
 * we *really* do not wish now to clear !)
 */
static bgp_rib_node
bgp_rib_node_free(bgp_rib_node rn, bool clear_avail)
{
  if (rn != NULL)
    {
      if (clear_avail)
        svec_clear(rn->avail) ;

      XFREE(MTYPE_BGP_RIB_NODE, rn) ;
    } ;

  return NULL ;
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
 *            ensures that there are no dangling references to pribs, and
 *            clears the prib->walker pointer for all related refresh pribs.
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
      bgp_prib     prib ;

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
          ddl_del(rw->it.rib->queue_base, &rw->it, queue) ;
          rw->it.flags ^= rib_itf_rib_queue ;
        } ;

      for (prib = ddl_head(rw->refresh_peers) ; prib != NULL ;
                                               prib = ddl_next(prib, walk_list))
        {
          qassert(prib->refresh) ;
          prib->walker       = NULL ;
          prib->refresh      = false ;
          prib->eor_required = false ;
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
 * Detach the prib from its current walker, if any.  If is in the prib's
 * update_view_peers or update_peers, remove it.
 *
 * If is currently attached to a "refresh" walker, and this is the only
 * prib attached to that walker, then we can discard the walker.
 *
 * NB: to be done before starting a new refresh walk, or when stopping the
 *     prib altogether.
 *
 * Sets prib->walker to NULL.
 *
 * Returns:  NULL
 */
extern bgp_rib_walker
bgp_rib_walker_detach(bgp_prib prib)
{
  bgp_rib_walker rw ;

  rw = prib->walker ;

  if (rw == NULL)
    qassert(!prib->refresh) ;
  else
    {
      if (prib->refresh)
        {
          /* Is in refresh state, associated with a refresh walker
           */
          rw = prib->walker ;
          ddl_del(rw->refresh_peers, prib, walk_list) ;

          if (!(rw->it.flags & rib_itf_update))
            {
              qassert(rw != prib->rib->walker) ;

              if (ddl_head(rw->refresh_peers) == NULL)
                bgp_rib_walker_discard(rw) ;
            } ;

          prib->refresh = false ;
        }
      else
        {
          /* Is not in refresh state, so must be one of the rib's
           * update_view_peers or update_peers -- remove it.
           */
          bgp_prib* p_base ;

          qassert((rw->it.flags & rib_itf_update) &&
                                                    (rw != prib->rib->walker)) ;
          if (prib->lc_id == lc_view_id)
            p_base = &prib->rib->update_view_peers ;
          else
            p_base = svec_get_p(prib->rib->update_peers, prib->lc_id) ;

          sdl_del(*p_base, prib, walk_list) ;
        } ;

      prib->walker = NULL ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Start a "refresh" rib walker for the given peer_rib.
 *
 * Detach the prib from its current walker, if any.  If is in the prib's
 * update_view_peers or update_peers, remove it.
 *
 * If there is a walker already queued at the start of the bgp_rib queue, then
 * join that and make sure it is going.
 *
 * Otherwise, create a new rib_it_walker, and set it going.
 *
 * Returns: address of the rib walker
 */
extern bgp_rib_walker
bgp_rib_walker_start_refresh(bgp_prib prib, wq_function func)
{
  bgp_rib        rib ;
  bgp_rib_walker rw ;
  bgp_rib_item   item ;

  bgp_rib_walker_detach(prib) ;

  rib = prib->rib ;     /* the bgp_rib for prib's address family, and for
                         * rib_main/rib_rs depending on the peer type.  */

  item = ddl_head(rib->queue_base) ;

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
typedef struct bgp_rib_extractor  bgp_rib_extractor_t ;
typedef struct bgp_rib_extractor* bgp_rib_extractor ;

struct bgp_rib_extractor
{
  prefix_rd_id_entry    rdie ;
  bgp_lc_id_t              lc ;
} ;

static bool bgp_rib_node_lc_select(const bgp_rib_node_c* p_a,
                                                        bgp_rib_extractor rex) ;
static bool bgp_rib_node_rd_select(const bgp_rib_node_c* p_a,
                                                        bgp_rib_extractor rex) ;

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
bgp_rib_extract(bgp_rib rib, bgp_lc_id_t lc, prefix_rd prd)
{
  bgp_rib_extractor_t  rex ;

  if ((rib == NULL) || (ihash_entry_count(rib->nodes_table) == 0))
    return vector_new(0) ;

  memset(&rex, 0, sizeof(rex)) ;
  rex.lc = lc ;

  if (prd == NULL)
    return ihash_table_extract(rib->nodes_table,
                       (ihash_select_test*)bgp_rib_node_lc_select, &rex, true,
                                            (ihash_sort_cmp*)bgp_rib_node_cmp) ;

  rex.rdie = prefix_rd_id_seek_entry(prd->val) ;
  if (rex.rdie == NULL)
    return NULL ;

  return ihash_table_extract(rib->nodes_table,
                      (ihash_select_test*)bgp_rib_node_rd_select, &rex, false,
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
 * Select bgp_rib_node entry if we have at least one route in the local context
 */
static bool
bgp_rib_node_lc_select(const bgp_rib_node_c* p_a, bgp_rib_extractor rex)
{
  bgp_rib_node_c  rn ;

  rn = *p_a ;

  if (rex->lc >= rn->local_context_count)
    return false ;

  return (*(rn->aroutes[rex->lc].base) != SVEC_NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Select bgp_rib_node entry if it matches the give Route Distinguisher, and
 *                               we have at least one route in the local context
 */
static bool
bgp_rib_node_rd_select(const bgp_rib_node_c* p_a, bgp_rib_extractor rex)
{
  if (bgp_rib_node_lc_select(p_a, rex))
    {
      prefix_id_entry pie ;

      pie = prefix_id_get_entry((*p_a)->pfx_id) ;

      return pie->pfx->rd_id == rex->rdie->id ;
    } ;

  return false ;
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
extern bgp_prib
peer_rib_new(bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
  bgp_rib  rib ;

  qassert(peer->prib[qafx] == NULL) ;

  prib = XCALLOC(MTYPE_BGP_PEER_RIB, sizeof(bgp_prib_t)) ;

  /* Zeroising has set:
   *
   *   * peer                 -- X        -- set below
   *
   *   * rib                  -- X        -- set below
   *
   *   * walker               -- NULL     -- none, yet
   *   * walk_list            -- NULLs    -- not on any walker's list, yet

   *   * qafx                 -- X        -- set below
   *   * i_afi                -- X        -- set below
   *   * i_safi               -- X        -- set below
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
   *   * pcount_recv          -- 0       )
   *   * pcount_in            -- 0       )   nothing yet
   *   * p_count_sent         -- 0       )
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
  prib->peer    = peer ;
  prib->qafx    = qafx ;
  prib->i_afi   = get_iAFI(qafx) ;
  prib->i_safi  = get_iSAFI(qafx) ;

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
  rib =  peer->bgp->rib[qafx] ;
  if (rib == NULL)
    rib = peer->bgp->rib[qafx] = bgp_rib_new(peer->bgp, qafx) ;
  prib->rib = rib ;

  rib->peer_count += 1 ;

  /* Set and return the new prib.
   */
  return peer->prib[qafx] = prib ;
} ;

/*------------------------------------------------------------------------------
 * Discard peer_rib structure.
 */
extern bgp_prib
peer_rib_free(bgp_prib prib)
{


  XFREE(MTYPE_BGP_PEER_RIB, prib) ;
  return NULL ;
} ;


#if 0
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
extern bgp_prib
peer_rib_set_rs(bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
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

  bgp_rib_walker_detach(prib) ;         /* stop if walking rib_main     */

  rib->peer_count -= 1 ;

  rib = peer->bgp->rib[qafx] ;
  if (rib == NULL)
    rib = peer->bgp->rib[qafx] = bgp_rib_new(peer->bgp, qafx) ;

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
extern bgp_prib
peer_rib_unset_rs(bgp_peer peer, qafx_t qafx)
{
  bgp_prib prib ;
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

#endif

