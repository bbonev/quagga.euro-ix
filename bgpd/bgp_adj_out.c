/* Peer-RIB Adj-Out handling -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#include "bgpd/bgp_common.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_run.h"
#include "bgpd/bgp_adj_out.h"
#include "bgpd/bgp_prun.h"
#include "bgpd/bgp_session.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_attr_store.h"

#include "list_util.h"
#include "qtime.h"
#include "vhash.h"
#include "ihash.h"
#include "pfifo.h"

/*==============================================================================
 *
 */
inline static pfifo_period_t bgp_adj_out_set_now(bgp_prib prib) ;
static void bgp_adj_out_unset_dispatcher(bgp_prib prib) ;
static void bgp_adj_out_delay_dispatcher(bgp_prib prib, pfifo_period_t dt) ;
static vhash_table bgp_attr_flux_hash_new(bgp_prib prib) ;
static vhash_table bgp_attr_flux_hash_delete(vhash_table af_hash) ;
static void bgp_attr_flux_hash_flush(vhash_table af_hash) ;
static void bgp_adj_out_dispatch(qtimer qtr, void* timer_info,
                                                            qtime_mono_t when) ;
static route_flux bgp_adj_out_unset(bgp_prib prib, adj_out_ptr_t ao,
                                                                   bool stale) ;
static void bgp_adj_out_add_batch(bgp_prib prib, route_flux rf,
                                        attr_set new_attr, prefix_id_t pfx_id) ;

/*------------------------------------------------------------------------------
 * Create new, empty adj_out elements for the given peer_rib.
 *
 * Requires the following peer_rib entries to be set:
 *
 *    peer
 *    qafx
 *    is_mpls
 *
 * Sets:
 *
 *    batch_delay        -- value depends on prun->sort -- see below
 *    batch_delay_extra  -- value depends on mrai
 *    announce_delay     -- value depends on prun->sort -- see below
 *    mrai_delay         -- from peer configuration
 *    mrai_delay_left    -- mrai_delay - batch_delay -- or zero

 *    period_origin      -- randomised origin;
 *    now                -- 0
 *
 *    adj_out            -- empty ihash
 *
 *    fifo_batch         -- empty pfifo
 *    fifo_mrai          -- empty pfifo
 *    announce_queue     -- empty pfifo
 *    withdraw_queue     -- empty list
 *
 *    attr_flux_hash     -- empty hash for attr_flux
 *
 *    dispatch_delay     -- 0
 *    dispatch_time      -- PFIFO_PERIOD_MAX
 *    dispatch_qtr       -- set to invoke bgp_adj_out_dispatch()
 */
extern void
bgp_adj_out_init(bgp_prib prib)
{
  pfifo_period_t periods ;

  /* Set up the various periods, depending on the prun->sort and its MRAI
   *
   *  * batch_delay          -- as set below
   *
   *    When a prefix changes, its schedule-time is set to now + batch_delay.
   *
   *  * batch_delay_extra    -- derived from peer's MRAI
   *
   *    This is the maximum *extra* delay that can be added to the original
   *    schedule-time when a prefix changes again.
   *
   *    So the total delay on the fifo_batch is batch_delay + batch_delay_extra.
   *
   *    If the peer's MRAI is less than the batch_delay, then batch_delay is
   *    used.
   *
   *  * announce_delay       -- as set below
   *
   *  * mrai_delay           -- copy of peer's MRAI
   *
   *  * mrai_delay_left      -- derived from peer's MRAI
   *
   *    This is the peer's MRAI *less* the batch_delay, or zero if the MRAI is
   *    less than the batch_delay.
   */
  prib->mrai_delay = qt_periods(QTIME(prib->prun->rp.mrai_secs), bgp_period_shift) ;
  if (prib->mrai_delay > aob_mrai_max)
    prib->mrai_delay = aob_mrai_max ;   /* clamp        */

  if (prib->prun->rp.sort == BGP_PEER_EBGP)
    {
      prib->batch_delay       = aob_batch_delay_ebgp ;
      prib->announce_delay    = aob_announce_delay_ebgp ;
    }
  else
    {
      prib->batch_delay       = aob_batch_delay_ibgp ;
      prib->announce_delay    = aob_announce_delay_ibgp ;
    } ;

  if (prib->mrai_delay > prib->batch_delay)
    {
      prib->batch_delay_extra = prib->mrai_delay ;
      prib->mrai_delay_left   = prib->mrai_delay - prib->batch_delay ;
    }
  else
    {
      prib->batch_delay_extra = prib->batch_delay ;
      prib->mrai_delay_left   = 0 ;
    } ;

  assert(prib->batch_delay       < aob_delay_max) ;
  assert(prib->batch_delay_extra < aob_delay_max) ;
  assert(prib->announce_delay    < aob_delay_max) ;
  assert(prib->mrai_delay        < aob_delay_max) ;
  assert(prib->mrai_delay_left   < aob_delay_max) ;

  /* The period_origin is different for each peer_rib, so that the timers are
   * not going off all in sync.
   *
   * We do not jitter the MRAI etc. because there is enough random perturbation
   * caused by the out of sync periods and general I/O and other delays.
   *
   * We make damn sure that the first period is at least 2, so that no P0
   * can ever be zero and so that the first possible pre-P0 period is 1 !
   * (noting that prib->dispatch_time == 0 is used to signal that the dispatch
   * timer is disabled).
   */
  prib->period_origin = qt_period_origin() ;
  while (bgp_adj_out_set_now(prib) < 2)
    prib->period_origin -= QTIME(1) ;

  /* Set up an empty adj_out -- indexed by prefix_id
   */
  prib->adj_out = ihash_table_new(200, 50) ;

  /* The pfifo_batch queue spans the batch_delay -- items may be rescheduled,
   * but only for batch_delay ahead of the current time.
   *
   * We then want some slack for processing delays, and to reduce number of
   * times the pfifo is reorganised, and a few extra for luck.
   *
   * We initialise P0 to be now -- which we guarantee is >= 2.
   *
   * While on the pfifo_batch queue, the dead-line may be at most
   * batch_delay_extra extra ahead of the current schedule time.  We know
   * that will fit in the aob_delta field.
   */
  periods = prib->batch_delay + aob_time_slack + 3 ;
  assert(periods < aob_index_max) ;
  assert(prib->batch_delay_extra < aob_delta_mask) ;

  prib->fifo_batch = pfifo_init_new(NULL, periods, aob_time_slack,
                                                offsetof(route_flux_t, list)) ;
  pfifo_take(prib->fifo_batch, prib->now, true /* set */) ;

  /* The pfifo fifo_mrai queue spans the full MRAI, if MRAI > batch_delay.
   * Generally, items are scheduled for mrai_delay_left (MRAI - batch_delay),
   * but an announce which arrives before mrai_delay_left will be rescheduled
   * to the full MRAI.
   *
   * We then want some slack for processing delays, and to reduce number of
   * times the pfifo is reorganised, and a few extra for luck.
   *
   * The MRAI is clamped so that the maximum delay is < aob_delay_max.
   *
   * We initialise P0 to be now -- which we guarantee is >= 2.
   *
   * While on the pfifo_mrai queue, the dead-line will be less than the full
   * MRAI -- since the dead-line is the full MRAI !
   */
  if (prib->mrai_delay_left > 0)
    {
      periods = prib->mrai_delay + aob_time_slack + 7 ;
      assert(periods < aob_index_max) ;
      assert(prib->mrai_delay < aob_delta_mask) ;

      prib->fifo_mrai = pfifo_init_new(NULL, periods, aob_time_slack,
                                                offsetof(route_flux_t, list)) ;
      pfifo_take(prib->fifo_mrai, prib->now, true /* set */) ;
    } ;

  /* The announce_queue queue spans the announce_delay.
   *
   * We initialise P0 to be now -- which we guarantee is >= 2.
   */
  periods = prib->announce_delay + aob_time_slack + 3 ;
  assert(periods < aob_index_max) ;

  prib->announce_queue = pfifo_init_new(NULL, periods, aob_time_slack,
                                                 offsetof(attr_flux_t, list)) ;
  pfifo_take(prib->announce_queue, prib->now, true /* set */) ;

  /* The withdraw_queue list is a simple ddl type list.
   */
  ddl_init(prib->withdraw_queue) ;

  /* Set up an empty vhash for the aggregation of prefixes by attributes.
   */
  prib->attr_flux_hash = bgp_attr_flux_hash_new(prib) ;

  /* Set up the dispatch timer -- not, yet, running.  By default will schedule
   * timer to run dispatch process as soon as first update is queued on the
   * batch_fifo.
   */
  prib->dispatch_delay = 0 ;
  prib->dispatch_time  = PFIFO_PERIOD_MAX ;
  prib->dispatch_qtr   = qtimer_init_new(NULL, re_nexus->pile,
                                                   bgp_adj_out_dispatch, prib) ;
} ;

/*------------------------------------------------------------------------------
 * Empty out all adj_out elements in the given peer_rib.
 *
 * NB: this is for use when the peer is being shut-down, at least for the
 *     AFI/SAFI in question.
 *
 * All update sending is halted and the data-structure emptied out and
 * everything is released.
 *
 * Must bgp_adj_out_init() if the peer_rib is to be used again.
 */
extern void
bgp_adj_out_discard(bgp_prib prib)
{
  ihash_walker_t walk[1] ;
  adj_out_ptr_t  ao ;

  /* Stop and discard the timer
   */
  bgp_adj_out_unset_dispatcher(prib) ;
  prib->dispatch_qtr = qtimer_free(prib->dispatch_qtr) ;

  /* Discard the pfifo's and list bases.
   *
   * Note that this does not affect any of the lists' contents, which are still
   * pointed to by the prib->adj_out.
   */
  prib->fifo_batch        = pfifo_free(prib->fifo_batch) ;
  prib->fifo_mrai         = pfifo_free(prib->fifo_mrai) ;
  ddl_init(prib->withdraw_queue) ;

  /* Now ream out the prib->adj_out
   */
  ihash_walk_start(prib->adj_out, walk) ;

  while ((ao.anon = ihash_walk_next(walk, (void*)&ao)) != NULL)
    {
      /* The walk returns all entries, even if the entry value is NULL.
       *
       * When we delete each entry we need to count down the prefix_id
       * reference count.
       */
      if (ao.anon != (void*)&ao)
        bgp_adj_out_unset(prib, ao, false /* not stale */) ;

      ihash_del_item(prib->adj_out, walk->self, NULL) ;
      prefix_id_dec_ref(walk->self) ;
    } ;

  /* And finally, discard the prib->attr_flux_hash, which should now be empty.
   */
  prib->announce_queue = pfifo_free(prib->announce_queue) ;
  prib->attr_flux_hash = bgp_attr_flux_hash_delete(prib->attr_flux_hash) ;
} ;

/*------------------------------------------------------------------------------
 * Set all adj_out elements in the given peer_rib as "stale".
 *
 * NB: this is for use in preparation for a route-refresh operation.
 *
 * All update sending is halted.  The data structures are flushed, and then
 * all prefixes which are not already withdrawn are added to the debounce
 * fifo as withdraws.  It is expected that the RIB will then be walked, and
 * a new update generated for all currently active prefixes, which will
 * replace the debounced withdraws.
 *
 * Once everything has been set stale, the current value of every route which
 * remains in the adj_out is set to the fictional 'bgp_attr_null', which is
 * neither a real attribute set, nor the withdrawn set.  The effect is to set
 * the current state "unknown", and not equal to any state which it will later
 * be set to.
 */
extern void
bgp_adj_out_set_stale(bgp_prib prib, uint delay)
{
  ihash_walker_t    walk[1] ;
  adj_out_ptr_t     ao ;

  /* Set the time now and stop the timer
   */
  bgp_adj_out_set_now(prib) ;
  bgp_adj_out_unset_dispatcher(prib) ;

  /* Empty the pfifo's and list bases.
   *
   * Note that this does not affect any of the lists' contents, which are still
   * pointed to by the prib->adj_out.
   */
  pfifo_flush_empty(prib->fifo_batch) ;
  pfifo_flush_empty(prib->fifo_mrai) ;
  ddl_init(prib->withdraw_queue) ;

  /* Walk the prib->adj_out, discarding any withdrawn entries, and converting
   * everything else to 'stale'.
   */
  ihash_walk_start(prib->adj_out, walk) ;

  while ((ao.anon = ihash_walk_next(walk, (void*)&ao)) != NULL)
    {
      /* The walk returns all entries, even if the entry value is NULL.
       *
       * Where we delete an entry (because the current state is withdrawn) we
       * need to count down the prefix_id reference count.
       *
       * Where we set the entry, and add it to the batch_fifo, we already have
       * a lock on the prefix_id, by virtue of the existing adj_out entry.
       */
      route_flux rf ;

      if (ao.anon == (void*)&ao)
        rf = NULL ;
      else
        rf = bgp_adj_out_unset(prib, ao, true /* stale */) ;

      if (rf != NULL)
        {
          rf->current = bgp_attr_lock(bgp_attr_null) ;
          bgp_adj_out_add_batch(prib, rf, NULL, walk->self) ;
        }
      else
        {
          ihash_del_item(prib->adj_out, walk->self, NULL) ;
          prefix_id_dec_ref(walk->self) ;
        } ;
    } ;

  /* The announce_queue fifo should now be empty, but we force it and
   * the related attr_flux hash table to be empty.
   */
  pfifo_flush_empty(prib->announce_queue) ;
  bgp_attr_flux_hash_flush(prib->attr_flux_hash) ;

  /* Set timer to start dispatching announcements after the given delay.
   */
  bgp_adj_out_delay_dispatcher(prib, prib->now +
                                   qt_periods(QTIME(delay), bgp_period_shift)) ;
} ;

/*------------------------------------------------------------------------------
 * Get the current period and set that in the prib.
 *
 * Truncates the current monotonic time to a pfifo_period.
 */
inline static pfifo_period_t
bgp_adj_out_set_now(bgp_prib prib)
{
  return prib->now = qt_period_fm(qt_get_monotonic(), prib->period_origin,
                                                             bgp_period_shift) ;
} ;

/*------------------------------------------------------------------------------
 * Get the adj_out entry for the given prefix.
 */
extern adj_out_ptr_t
bgp_adj_out_lookup(bgp_prib prib, prefix_id_t pfx_id)
{
  adj_out_ptr_t ao ;

  ao.anon = ihash_get_item(prib->adj_out, pfx_id, NULL) ;

  return ao ;
} ;

/*------------------------------------------------------------------------------
 * Get the current attributes associated with the given adj_out entry.
 */
extern attr_set
bgp_adj_out_attr(bgp_prib prib, adj_out_ptr_t ao)
{
  adj_out_type_t type ;

  if (ao.anon == NULL)
    return NULL ;           /* easy !               */

  /* If the entry is in steady-state, then we have the attributes in our
   * hand, or we have an MPLS entry.
   *
   * If the entry is not steady state, then the flux.current has what we
   * want, and we loop back !
   */
  type = (ao.anon->bits >> aob_type_shift) & aob_type_mask ;
  switch (type)
    {
      /* Not steady state.
       */
      case aob_flux:
        return ao.flux->current ;

      /* Steady state -- with simple attribute set.
       *
       * If the request is withdraw, exit now.  Otherwise continue and
       * schedule a change.
       */
      default:
        if (!(type & aob_attr_set))
          {
            /* Unrecognised type
             */
            qassert(false) ;
            return NULL ;           /* <<<< exit: safety            */
          } ;

        return ao.attr ;
    } ;
} ;

/*==============================================================================
 * The adj_out spaghetti.
 *
 *
 *   adj_out                                              attr_set
 *   *-->+->-------------------->+--->+------------------>+---------+
 *       |                       ^    |                   .         .
 *       |  route_flux           |    *--->NULL           .         .
 *       +->+---------+          |                        +---------+
 *          | current-|--------->+
 *          .         .                                   attr_set
 *          | pending-|--------->+--->+------------->+--->+---------+
 *          .         .          |    |              ^    .         .
 *          .         .          |    *--->NULL      |    .         .
 *     ...->|--list---|->...     |                   |    +---------+
 *          +---------+          |    attr_flux      |
 *                               +--->+---------+    |
 *                                    | attr----|--->+
 *                                    .         .
 *                               ...->|--list---|->...
 *                                    |  fifo---|->... list of route_flux
 *                                    +---------+
 *
 *
 *
 *
 *
 * Note that adj_out and rf->current are NULL for withdrawn (or never announced)
 * routes.
 *
 * In steady-state, the adj_out points at the attr_set, and owns a lock.
 *
 * When a route_flux is created, the adj_out attributes pointer is copied to
 * 'current', retaining the lock, to be replaced by the pointer to the
 * route_flux.
 *
 * When there is a new pending update, the 'pending' pointer points at an
 * attr_set, and owns a lock.
 *
 * When marshalling updates for the same attributes together, an attr_flux
 * object is created.  The pointer to the attributes moves from 'pending' into
 * the route_flux -- retaining the lock.
 *
 * Note that where we have a pending withdraw we may have:
 *
 *   a) rf->pending -> NULL                -- there is nothing else
 *
 *   b) rf->pending -> attr_set            -- there is an announce pending
 *
 *      In this case there is an announce pending after the withdraw is output.
 *      (This can happen once a withdraw has been dispatched.)
 *
 * The fifo_batch, withdraw_queue and fifo_mrai queues are queues of
 * route_flux objects.
 *
 * The announce_queue queue is a queue of attr_flux objects.  Each attr_flux
 * object has a queue of route_flux objects.
 *
 * The adj_out owns a lock on the current attr_set (if any) -- which it points
 * to either directly or via a route_flux.
 *
 * The rf->pending owns a lock on the pending attr_set (if any) -- which it
 * points to either directly or via an attr_flux.   Note that the attr_flux
 * does *not* have a lock.
 *
 * This means that when a route_flux object is created, the then adj_out
 * pointer can simply be moved to rf->current.  Similarly, when an update is
 * sent, rf->pending can be moved to rf->current, and when the route_flux is
 * discarded, rf->current becomes the adj_out pointer.
 *
 */
static void bgp_adj_out_update_again(bgp_prib prib, route_flux rf,
                                                                attr_set attr) ;
static void bgp_adj_out_update_revert(bgp_prib prib, route_flux rf,
                                                                 attr_flux af) ;
static void bgp_adj_out_set_steady(bgp_prib prib, route_flux rf) ;
static void bgp_adj_out_change_batch(bgp_prib prib, route_flux rf) ;
static void bgp_adj_out_change_announce(bgp_prib prib, route_flux rf,
                                                                 attr_flux af) ;

static void bgp_adj_out_mrai_withdraw(bgp_prib prib, route_flux rf) ;
static void bgp_adj_out_mrai_announce(bgp_prib prib, route_flux rf) ;
static void bgp_adj_out_mrai_revert(bgp_prib prib, route_flux rf) ;

static void bgp_adj_out_add_announce(bgp_prib prib, route_flux rf,
                                                            pfifo_period_t st) ;
static pfifo_period_t bgp_adj_out_del_announce(bgp_prib prib, route_flux rf,
                                                                 attr_flux af) ;

inline static pfifo_index_t bgp_adj_out_get_index(pfifo pf, adj_out ao) ;
static void bgp_adj_out_fix_ex(pfifo pf, adj_out ao) ;

inline static void bgp_adj_out_set_index(adj_out ao, pfifo_index_t i) ;
inline static void bgp_adj_out_set_index_dl(adj_out ao,
                                                     pfifo_index_t i, int dl) ;
inline static pfifo_period_t bgp_adj_out_get_dl(adj_out ao) ;

static void bgp_attr_flux_free(bgp_prib prib, attr_flux af) ;

static void bgp_adj_out_update_dispatcher(bgp_prib prib, pfifo_period_t dt) ;
static void bgp_adj_out_dispatch_queue(bgp_prib prib, route_flux rf_next,
                                                                     pfifo pf) ;

/*------------------------------------------------------------------------------
 * Update or set the adj_out for the given peer in the given node.
 *
 * For whatever reason, we have a new route for the given prefix, for the given
 * peer -- having completed any 'out' route-map etc.
 *
 * Schedules an update if required -- implementing MinRouteAdvertisementTimer
 * (MRAI).
 *
 * RFC4271 (9.2.1.1) specifies MinRouteAdvertisementTimer "per-destination"
 * and "per BGP peer", but goes on to weaken that to make implementation
 * easier.  The RFC does not distinguish between withdraw updates and announce
 * updates, but there is research which suggests that *not* delaying Withdraw
 * is a Good Idea.
 *
 * Applying MRAI to withdraws is generally known as WRATE, and not doing so is
 * NO-WRATE.  Quagga has, historically, implemented NO-WRATE.
 *
 * This Quagga implements "per-destination" MRAI.  It also implements a
 * batching system, which batches changes together, and absorbs very rapid
 * changes in a prefix.  There is then a further delay for announcements, to
 * aggregate those which use the same attributes.  Once an update for a given
 * prefix has been sent to a given peer, Quagga delays any further change for
 * the MRAI time less the batch-time, except where the prefix is withdrawn
 * within that time.
 *
 * The batching introduces a delay starting at the moment a prefix first
 * changes to the time that prefix is dispatched, in a batch with other
 * contemporary changes.  This is similar to the Juniper "out-delay" parameter.
 * The handling of MRAI is integrated with this batching mechanism.
 *
 * When a prefix has been unchanged for at least MRAI since the last update was
 * sent (if any), the prefix is in "steady state".  When a new update arrives
 * for a state prefix, this Quagga will:
 *
 *   * ignore updates which do not change the current state of the prefix.
 *
 *   * for withdraw: apply batch-delay (1.5 sec for iBGP & cBGP, 3 sec for eBGP)
 *     delay, then send the withdraw as quickly as I/O will allow.
 *
 *     This is a change from previous Quagga behaviour, where withdraws would
 *     be sent as soon as I/O delays would allow.
 *
 *     If an announce arrives, the pending change is updated and rescheduled.
 *     If the announce would restore the original attributes, the prefix
 *     reverts to steady state.
 *
 *   * for announce: apply the same batch-delay, then send the update after
 *     at most the aggregation-delay (1 sec for iBGP & cBGP, 2 sec for eBGP),
 *     plus any I/O delays.  The batching produces bursts of announcements,
 *     ~0.536 wide -- so any announcements with the same attributes in that
 *     burst will be aggregated.  The further aggregation-delay spreads the
 *     opportunity a little wider.
 *
 *     If an announce or withdraw arrives which restores the original state,
 *     the prefix reverts to steady state.
 *
 *     If a further announce or withdraw arrives, it is rescheduled.
 *
 *     This is also a change from previous Quagga behaviour, where the
 *     announcement process starts at MRAI after the start of the previous
 *     run, and outputs updates for all routes with uptimes of less than
 *     the start of the current run -- subject to I/O delays.  This means
 *     that from uptime to output is between 0 and MRAI -- so, on average,
 *     MRAI / 2, plus I/O delays.
 *
 *     For this Quagga, for iBGP batch-delay + aggregation-delay is 2.5 secs,
 *     which is MRAI/2 !  But for eBGP it is 5 secs, which is rather faster
 *     than 15 seconds.  In both cases the delay is more predictable, and the
 *     I/O delays are the same.
 *
 *     Note that there is some analysis which suggests that an MRAI of 30
 *     seconds is too long for eBGP and that 15 or less would be a reasonable
 *     alternative.
 *
 *   * Note that each further change causes the batch-delay to be restarted,
 *     until the total delay reaches MRAI + batch-delay, at which point the
 *     current state is dispatched, whatever it is.
 *
 *     This is consistent with the RFC, which requires a "constant upper bound"
 *     on the MRAI -- in this case MRAI * 2 (plus I/O delays).
 *
 * At this point, the two times associated with a scheduled item can be
 * described:
 *
 *   * schedule-time -- this is held in 0.268 second units, in 10 bits.
 *
 *     This uses the pfifo item index and the pfifo to manage the schedule
 *     time for items in the body of the pfifo.  Any item which has fallen
 *     out of the pfifo is deemed to have a schedule time of ????  TODO
 *
 *   * delta-time -- held in 0.268 second units, in 9 bits.
 *
 *     Adding this to the schedule-time gives the dead-line for items on the
 *     batch queue.
 *
 * The schedule-time and the next processing time work in 0.268 second
 * "periods".  The schedule-time is rounded up to the next period.  The next
 * processing time is the start of the first period with something in it.  When
 * the queue is processed, the current period and the next period are emptied.
 * This means that items are processed at most 0.268 seconds behind their true
 * schedule-time and at most 0.268 seconds ahead of it.  Consider four
 * schedule-times a, b, c and d which are:
 *
 *      p-n      p        p+1      p+2      p+3
 *      +--------+--------+--------+--------+--------+
 *      |        |a      b|c      d|        |        |
 *      +--------+--------+--------+--------+--------+
 *
 * that is, they are at the start and end of two consecutive periods.  They are
 * rounded up to be placed as A, B, C and D:
 *
 *      p        p+1      p+2      p+3
 *      +--------+--------+--------+--------+--------+
 *      |a      b|c      d|        |        |        |
 *      |        |AB      |CD      |        |        |
 *      +--------+--------+--------+--------+--------+
 *
 * Assuming nothing else is going on, the next processing time will be p+1,
 * at which point all of A, B, C & D will be processed.  Clearly b & c are
 * processed pretty much at the intended time.  While a is processed nearly
 * 0.268 seconds late, and d is processed nearly 0.268 secs early.
 *
 * The batch size is ~0.536 secs wide.  After processing, the next processing
 * time will be p+3 or later.  [To be precise, therefore, the batch-delay is
 * 1.608 secs +/- 0.268.  Note that for the batching to work, batch-delay must
 * be at least 0.268... otherwise when the time is p+1 the next processing run
 * can start, and c and d may not have been scheduled yet !]
 *
 * When an update is dispatched it is placed on one of two queues:
 *
 *   a) withdraw queue.
 *
 *      this is emptied by the I/O process, just as quickly as is possible.
 *
 *      Once an update reaches the withdraw queue, its fate is sealed.  If an
 *      announce rolls up, it is set pending -- unless that restores the
 *      original attribute state, in which case the prefix reverts to the
 *      steady state.  When the withdraw is actually output, any pending
 *      announce will sit in MRAI state.
 *
 *   b) announce queue
 *
 *      here we wish to aggregate updates which use the same attributes, for
 *      which there is a secondary scheduling process, based on the attributes.
 *
 *      The announce queue is populated by 'attr_flux' objects.  Each one has
 *      one or more prefixes attached to it, and those will appear together
 *      in an update message, if at all possible.  Each 'attr_flux' has a
 *      schedule-time, which is handled in the same way as for the batch
 *      queue.
 *
 *        aggregation-delay = ~1 sec for iBGP, cBGP
 *                            ~2 sec for eBGP
 *
 *      When the first route_flush with a given set of attributes is dispatched,
 *      an attr_flux object is created, and it is added to the announce queue,
 *      with a new schedule-time.
 *
 *      If a further route_flux with the same set of attributes is dispatched,
 *      it is added to the attr_flux, effectively inheriting the attr_flux's
 *      schedule-time.  So, having the same attributes as an earlier route_flux
 *      can accelerate, but not further delay, output.
 *
 * Now we get the fiddly cases, where the attributes for a route_flux change
 * once it is in the announce queue.  This is not something we expect,
 * particularly, but need to do something sensible in these cases:
 *
 *    * if the result is the original state, the prefix returns to steady
 *      state (!)
 *
 *    * if this is a withdraw, then the route_flux is moved to the withdraw
 *      queue -- and from that moment its fate is sealed, as above.
 *
 *    * if this is an announce for a set of attributes not in use already,
 *      creates a new attr_flux and queue it according to the current
 *      attr_flux's schedule-time.
 *
 *      So, further announcements cannot delay the output of an update for
 *      a prefix.
 *
 *    * if this is an announce for a set of attributes which are already
 *      queued, then:
 *
 *          i) if the schedule-time for that attr_flux is less than the
 *             schedule-time for the current attr_flux, then the route_flux
 *             inherits that shorter schedule.
 *
 *         ii) if the schedule-time for that attr_flux is greater than the
 *             schedule-time for the  current attr_flux, then the attr_flux's
 *             schedule-time is reduced.
 *
 *      Note that the schedule-time for an attr_flux can only go down.  The
 *      schedule-time for each route_flux is effectively the schedule-time for
 *      the attr_flux it is currently attached to, and may only go down if
 *      the attributes change.
 *
 *      If the previous attr_flux no longer has any associated prefixes, it is
 *      de-queued.
 *
 * When an update is sent, the prefix enters a cooling-off period -- the MRAI.
 * During MRAI a route_flux object sits on the batch queue, with a schedule-
 * time of the update time + MRAI - batch-delay, marked aob_mrai.  At the end
 * of the MRAI, the prefix will return to steady state, unless a change is
 * pending, in which case it will be re-queued with the batch-delay.  Note that
 * prefixes which have been withdrawn may already have a pending announce
 * attached to them when they enter MRAI.
 *
 * If a change arrives while awaiting MRAI:
 *
 *   * withdraw changes are rescheduled, for dispatch after batch-delay.
 *
 *     Ignored if the current state is withdrawn.
 *
 *     This is NO-WRATE in action.
 *
 *     The route_flux remains aob_mrai -- so if an announce arrives before the
 *     end of the batch-delay, it can be rescheduled as MRAI again.
 *
 *   * announce changes are stored up to the end of the MRAI period, including
 *     reverting to the current state.
 *
 *     If there is a pending withdraw, resets the schedule-time to the MRAI
 *     schedule.
 *
 * When the MRAI schedule time expires, the prefix either falls into steady
 * state, or is rescheduled for dispatch after batch-delay.
 *
 * Note that in MRAI state waits for the MRAI less the batch-delay, so that the
 * batch-delay overlays the tail end of MRAI.
 */
extern void
bgp_adj_out_update (bgp_prib prib, prefix_id_entry pie, attr_set attr)
{
  adj_out_ptr_t ao ;
  route_flux    rf ;
  adj_out_type_t type ;
  pfifo_period_t dt ;

  /* Set time now and look up the adj_out for this prefix
   */
  bgp_adj_out_set_now(prib) ;

  ao.anon = ihash_get_item(prib->adj_out, pie->id, (void*)&ao) ;

  /* Discover whether we are in steady state or in flux.
   *
   * If we are in steady state, prepare a new route_flux etc., and schedule it
   * on the fifo_batch.
   *
   * If not in steady state, update and reschedule the route_flux as required.
   */
  if ((ao.anon == NULL) || (ao.anon == (void*)&ao))
    {
      /* Steady state -- prefix withdrawn (or never announced).
       *
       * If the request is withdraw, exit now.  Otherwise continue and
       * schedule a change.
       */
      if (attr == NULL)
        return ;                        /* <<<< exit: no actual change  */

      if (ao.anon == (void*)&ao)
        {
          /* The prefix is not present in the adj_out, so will be making a
           * new entry below, which calls for a lock on the prefix.
           */
          prefix_id_entry_inc_ref(pie) ;
          ao.anon = NULL ;
        } ;
    }
  else
    {
      type = (ao.anon->bits >> aob_type_shift) & aob_type_mask ;
      switch (type)
        {
          /* Not steady state -- adjust the pending/dispatched state of the
           * route_flux etc.
           *
           * NB: xxx  ..................................................................
           */
          case aob_flux:
            qassert(ao.flux->pfx_id == pie->id) ;

            bgp_adj_out_update_again(prib, ao.flux, attr) ;

            return ;                    /* <<<< exit here               */

          /* Steady state
           *
           * If the request is withdraw, exit now.  Otherwise continue and
           * schedule a change.
           */
          default:
            if (!(type & aob_attr_set))
              {
                /* Unrecognised type
                 */
                qassert(false) ;
                return ;                /* <<<< exit: safety            */
              } ;

            if (ao.attr == attr)
              return ;                  /* <<<< exit: no actual change  */

            break ;                     /* steady state, announce change */
        } ;
    } ;

  /* We are in steady state and we need to change.
   *
   * At this point:  ao.attr -- NULL <=> previously withdrawn
   *                            otherwise: current attr_set
   *
   * Also: if attr == NULL then ao != NULL and vice versa.
   *       ie: both cannot be NULL together.
   *
   * We are going to need a route_flush object.
   */
  rf = XCALLOC(MTYPE_BGP_ROUTE_FLUX, sizeof(route_flux_t)) ;

  /* Zeroizing the route_flux object sets:
   *
   *  * current   -- NULL   -- set below
   *
   *  * pfx_id    -- X      -- set below
   *  * bits      -- X      -- set below
   *
   *  * pending   -- NULL   -- set as required, later
   *
   *  * list      -- NULLs
   */
  rf->current = ao.attr ;

  /* Now schedule on the fifo_batch and update the adj_out.
   */
  bgp_adj_out_add_batch(prib, rf, attr, pie->id) ;

  /* Now, if the first item in the fifo_batch has a schedule-time which is less
   * than the current dispatch_time, then may well need to reschedule the
   * dispatcher.
   *
   * Note that in this case -- starting from steady state -- the only queue
   * we have changed is the fifo_batch queue, and unless this is the first
   * update in a while, the dispatcher is probably running.
   */
  dt = pfifo_first_period(prib->fifo_batch) ;

  if (dt < prib->dispatch_time)
    bgp_adj_out_update_dispatcher(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Unset the given prib->adj_out entry -- where the entry is NOT NULL.
 *
 * NB: by the time we get here, all the pfifos and queues have been emptied out,
 *     except for the announce_queue.
 *
 *     So, where we have a route-flux, in rf_act_announce state, we unpick it
 *     from the attr-flux, and as the attr-flux empty out, they will be
 *     removed from the announce queue.
 *
 * If the entry is "in flux", then discard any pending update.
 *
 * In all cases, discard the current (steady) state of the route.
 *
 * For 'stale', if the current state is not withdrawn, set it to be "unknown",
 * by setting it to 'bgp_attr_null', and set a pending withdraw.  Return a
 * route_flux ready to be put into the adj_out and on to the batch_fifo.
 *
 * For not 'stale', or if the current state is in fact withdrawn, discards
 * the current state as well.
 *
 * Returns:  NULL <=> the adj_out entry is no more, and should now be deleted.
 *           otherwise, a route_flux to be set as the adj_out entry and to be
 *                      added to the batch_fifo.
 */
static route_flux
bgp_adj_out_unset(bgp_prib prib, adj_out_ptr_t ao, bool stale)
{
  route_flux        rf ;
  adj_out_type_t    type ;
  attr_set          attr ;

  qassert(ao.anon != NULL) ;

  type = (ao.anon->bits >> aob_type_shift) & aob_type_mask ;

  switch (type)
    {
      /* Not steady state --
       */
      case aob_flux:
        rf = ao.flux ;

        /* If there is a pending action, then now is the time to discard it.
         *
         * Note that all queue
         *
         * If we are setting the adj_out to stale, then set a pending withdraw.
         *
         * Otherwise, discard all parts of the pending action.
         */
        if (rf->pending.anon != NULL)
          {
            /* We have something pending, which we discard.
             */
            route_flux_action_t   action ;
            attr_set   attr_pending ;

            action = (rf->bits >> aob_action_shift) & aob_action_mask ;

            if (action != rf_act_announce)
              attr_pending = rf->pending.attr ;
            else
              {
                attr_flux  af_pending ;

                af_pending   = rf->pending.flux ;
                attr_pending = af_pending->attr ;
                bgp_adj_out_del_announce(prib, rf, af_pending) ;
              } ;

            if (attr_pending != NULL)
              bgp_attr_lock(attr_pending) ;

            rf->pending.anon = NULL ;
          } ;

        attr = rf->current ;
        if (attr != NULL)
          {
            /* We have a current value, which we no longer need.
             */
            bgp_attr_unlock(attr) ;

            /* If we are setting "stale", then we keep the current route-flux,
             * which will become a withdraw.
             */
            if (stale)
              {
                memset(rf, 0, sizeof(route_flux_t)) ;   /* tidy */
                return rf ;
              } ;
          } ;

        /* There were no advertised current attributes, or we are discarding
         * everything in any case.
         */
        XFREE(MTYPE_BGP_ROUTE_FLUX, rf) ;
        return NULL ;

      /* Steady state -- with an attribute set.
       *
       * If discard, then then we are done, once have unlocked the
       * attributes.  Otherwise, we need to set a "needs to be withdrawn"
       * route-flux.
       */
      default:
        if (!(type & aob_attr_set))
          {
            /* Unrecognised type
             */
            qassert(false) ;
            return NULL ;               /* <<<< exit: safety            */
          } ;

        /* We have a current, steady state value which we can now discard.
         *
         * If we are setting stale, need a new route flux !
         */
        bgp_attr_unlock(ao.attr) ;

        if (stale)
          return XCALLOC(MTYPE_BGP_ROUTE_FLUX, sizeof(route_flux_t)) ;
        else
          return NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Update arrived while not in steady state.
 *
 * What we have in our hands is a route_flux object.  That may be:
 *
 *   rf_act_batch    -- waiting for the batch-delay to expire
 *                      before we dispatch the route_flux.
 *
 *                      Revert to steady state if change sets current state,
 *                      except for .
 *
 *                      Do nothing if change is same as current pending.
 *
 *                      Otherwise, update the pending change and reschedule,
 *                      unless that would take us past the dead-line.
 *
 *   rf_act_withdraw -- waiting for the I/O to send a withdraw update
 *
 *                      Revert to steady state if change sets current state.
 *
 *                      Do nothing if change is withdraw.
 *
 *                      Do nothing if change is same as pending.
 *
 *                      Otherwise, set or update a pending announce, which
 *                      will now wait for MRAI (once the withdraw is actually
 *                      sent).
 *
 *   rf_act_announce -- waiting for the announce-delay to expire, or
 *                      for I/O to send an announce update.
 *
 *                      Revert to steady state if change sets current state.
 *
 *                      If change is withdraw, clear pending announce and
 *                      set rf_act_withdraw.
 *
 *                      Do nothing if change is same as current pending.
 *
 *                      Otherwise, update and reschedule pending announce.
 *
 *   rf_act_mrai     -- waiting for the MRAI to expire before we either
 *                      dispatch the route_flux or set it back to steady state.
 *
 *                      If this change is a withdraw:
 *
 *                        * do nothing if withdraw is pending.
 *
 *                        * otherwise, clear any other pending change and if
 *                          current state is not withdraw, set withdraw
 *                          pending, and reschedule.
 *
 *                      If this change is not a withdraw:
 *
 *                        * if a withdraw is pending reschedule to the MRAI.
 *
 *                        * discard any pending change if this change sets
 *                          current state.
 *
 *                        * update the pending state, otherwise.
 */
static void
bgp_adj_out_update_again(bgp_prib prib, route_flux rf, attr_set attr)
{
  route_flux_action_t action ;
  attr_flux     af ;

  /* Worry about the route_flux state and this change and decide whether:
   *
   *   * to do nothing at all
   *
   *     if the given attr is the same as the current pending update (if any),
   *     then nothing needs to be done.
   *
   *   * to revert to steady state or (for aob_mrai_wait) to waiting for MRAI.
   *
   *     ie. this update sets the current state of the prefix -- noting that
   *         for aob_mrai_wait that state may be withdrawn.
   *
   *   * to change the pending and/or other state
   *
   *     ie. this update changes the pending state of the prefix
   */
  action = (rf->bits >> aob_action_shift) & aob_action_mask ;
  af     = NULL ;               /* assume not rf_act_announce   */

  if (rf->pending.anon == NULL)
    {
      /* A withdraw (or possibly nothing, if rf_act_mrai) is pending.
       *
       *   rf_act_batch     -- waiting for delay schedule-time
       *
       *                       if is aob_
       *
       *   rf_act_withdraw  -- waiting for I/O
       *
       *   rf_act_announce  -- impossible !
       *
       *   rf_act_mrai      -- waiting for delay or MRAI
       *
       *                       if is not aob_mrai_wait, then attr_pending
       *                       of NULL means that a withdraw is pending, in
       *                       the usual way.
       *
       *                       if is aob_mrai_wait, then attr_pending of
       *                       NULL means that is waiting for the end of
       *                       MRAI period -- nothing is pending.
       */
      qassert(action != rf_act_announce) ;

      if ((attr == NULL) && !(rf->bits & aob_mrai_wait))
        return ;
    }
  else
    {
      /* An announce is pending -- in the case of rf_act_withdraw, that
       * may be pending the withdraw.
       *
       *   rf_act_batch     -- waiting for delay schedule-time
       *
       *   rf_act_withdraw  -- waiting for I/O
       *
       *                       has a an announce pending after the I/O
       *                       has sent the withdraw.
       *
       *   rf_act_announce  -- waiting for aggregation delay or I/O
       *
       *                       NB: rf->pending is an attr_flux.
       *
       *   rf_act_mrai      -- waiting for delay or MRAI
       *
       *                       NB: !aob_mrai_wait
       */
      attr_set attr_pending ;

      qassert(!(rf->bits & aob_mrai_wait)) ;

      if (action == rf_act_announce)
        {
          af = rf->pending.flux ;
          attr_pending = af->attr ;

          qassert(attr_pending != NULL) ;
        }
      else
        attr_pending = rf->pending.attr ;

      qassert(((adj_out)attr_pending)->bits & aob_attr_set) ;

      if (attr == attr_pending)
        return ;                /* no change !          */

      /* We are about to replace the current pending announcement.  We
       * have af -> attr_flux if there is one.  We no longer want the
       * attributes, and now is a good time to clear the pending stuff.
       */
      bgp_attr_unlock(attr_pending) ;
      rf->pending.anon = NULL ;
    } ;

  /* The new attributes are not the same as the previous pending ones, or
   * we are in mrai_wait state (which means there are no pending).
   *
   * If the attributes to be set are the same as the current (steady state)
   * then we revert to the current state.
   *
   * Note that for aob_mrai_wait, the current state is waiting on the mrai
   * queue.
   */
  if (attr == rf->current)
    return bgp_adj_out_update_revert(prib, rf, af) ;

  /* The new attributes require a new pending state to be set.
   */
  if (attr != NULL)
    rf->pending.attr = bgp_attr_lock(attr) ;
  else
    qassert(rf->pending.attr == NULL) ;

  /* We have updated the pending state, so now need to reschedule as
   * required.
   *
   * NB: to be here we must have a new pending state which is (a) not
   *     the previous pending state and (b) not the current state.
   */
  switch (action)
    {
      /* For stuff in the fifo_batch, we now reschedule if possible.
       */
      case rf_act_batch:
        bgp_adj_out_change_batch(prib, rf) ;
        break ;

      /* For dispatched withdraw, we have updated the pending state,
       * which will be dealt with once the withdraw is finally output.
       */
      case rf_act_withdraw:
        break ;

      /* For dispatched announce, we need to remove the route_flux from
       * its current attr_flux, and then reschedule as an announce or
       * as a withdraw.
       *
       * NB: the af attr_flux we have is the attr_flux for the *previous*
       *     pending announcement.  This tidies that up, using the *previous*
       *     schedule time for the announcement (which is why did not deal with
       *     the aattr_flux earlier).
       */
      case rf_act_announce:
        qassert(af != NULL) ;

        bgp_adj_out_change_announce(prib, rf, af) ;
        break ;

      /* For item in MRAI, we now have something pending, either withdraw
       * or announce.
       *
       * NB: absolutely requires the new state to be a *change* and not a
       *     *revert*.
       */
      case rf_act_mrai:
        rf->bits &= ~(adj_out_bits_t)aob_mrai_wait ;
                                            /* something pending    */
        if (attr == NULL)
          bgp_adj_out_mrai_withdraw(prib, rf) ;
        else
          bgp_adj_out_mrai_announce(prib, rf) ;

        break ;

      default:
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Revert the given not-steady-state prefix to its current (advertised) state.
 *
 * Requires that any pending state has been cleared already.
 *
 * If not MRAI and not Stale, this will send the prefix back to steady state.
 *
 * For Stale, the current state is not known but appears to be NULL: leaves
 * the route_flux on the fifo_batch, or the withdraw queue, NULL pending.
 *
 * For MRAI, will reschedule as required -- which generally means waiting to
 * the end of the MRAI period (less batch-delay), but may send the prefix back
 * to steady state.
 */
static void
bgp_adj_out_update_revert(bgp_prib prib, route_flux rf, attr_flux af)
{
  switch ((rf->bits >> aob_action_shift) & aob_action_mask)
    {
      /* Is waiting on the fifo_batch, so remove from there and set back
       * into steady state.
       *
       * May be reverting back to NULL, but in any case we have cleared out
       * whatever was pending.
       */
      case rf_act_batch:
        qassert(rf->pending.attr == NULL) ;

        pfifo_item_del(prib->fifo_batch, rf,
                         bgp_adj_out_get_index(prib->fifo_batch, (adj_out)rf)) ;
        bgp_adj_out_set_steady(prib, rf) ;
        break ;

      /* Is waiting on the withdraw_queue, so remove from there and set
       * back into steady state.
       *
       * NB: if we are reverting from withdraw queue, current MUST be NULL.
       *
       *     Not entirely clear how we get into this state.
       */
      case rf_act_withdraw:
        qassert(rf->current      == NULL) ;
        qassert(rf->pending.attr == NULL) ;

        ddl_del(prib->withdraw_queue, rf, list) ;
        bgp_adj_out_set_steady(prib, rf) ;
        break ;

      /* Is waiting on the announce_queue, so remove from there and set
       * back into steady state.
       *
       * The route-flux is still attached to the attr-flux, but the pending
       * pointer has been cleared and the lock on the af->attr owned by the rf
       * has been cleared.
       */
      case rf_act_announce:
        qassert(af               != NULL) ;
        qassert(rf->pending.flux == NULL) ;

        bgp_adj_out_del_announce(prib, rf, af) ;
        bgp_adj_out_set_steady(prib, rf) ;
        break ;

      /* Is waiting on the fifo_batch, for MRAI.
       *
       * The change reverts to the current state -- which is waiting for
       * MRAI to expire.  If that has now expired, drop to steady state.
       *
       *
       */
      case rf_act_mrai:
        qassert(rf->pending.attr == NULL) ;

        bgp_adj_out_mrai_revert(prib, rf) ;
        break ;

      default:
        qassert(false) ;
        break ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Send an End-of-RIB pseudo-update.
 *
 * Dispatches everything in the fifo_batch
 */
extern void
bgp_adj_out_eor(bgp_prib prib)
{
  route_flux  rf_first ;
  typedef struct dl_base_pair(attr_flux) dl_af ;
  dl_af* p_ex ;

  bgp_adj_out_set_now(prib) ;
  p_ex = (dl_af*)&prib->announce_queue->ex ;

  /* Cancel any pending End-of-RIB or create an empty one.
   */
  if (prib->eor != NULL)
    {
      ddl_del(*p_ex, prib->eor, list) ;
    }
  else
    {
      prib->eor = XCALLOC(MTYPE_BGP_ATTR_FLUX, sizeof(attr_flux_t)) ;
      confirm(aob_eor  == 0) ;
    } ;

  /* Dispatch everything from the fifo_batch.
   */
  rf_first = pfifo_flush(prib->fifo_batch) ;

  if (rf_first != NULL)
    bgp_adj_out_dispatch_queue(prib, rf_first, prib->fifo_batch) ;

  /* Dispatch everything from announce_queue
   *
   * This doesn't do very much, just arranges for all announces to sit on the
   * ex queue, whence they will be output.
   */
  pfifo_flush(prib->announce_queue) ;

  /* Add empty 'eor' attr_flux to the back of the announce_queue 'ex' queue
   */
  ddl_append(*p_ex, prib->eor, list) ;

  /* Prod the I/O
   */
} ;

/*------------------------------------------------------------------------------
 * Set steady state from given route_flux and delete the route_flux.
 *
 * Will have discarded any pending state -- so rf->pending == NULL
 *
 * NB: if is setting NULL, does NOT remove the adj_out entry -- garbage
 *     collection will do that later.
 */
static void
bgp_adj_out_set_steady(bgp_prib prib, route_flux rf)
{
  ihash_set_item(prib->adj_out, rf->pfx_id, rf->current) ;

  XFREE(MTYPE_BGP_ROUTE_FLUX, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Add a new rf_act_batch route_flux
 *
 * Overwrites any existing adj-out entry with the given route-flux, once filled
 * in and queued in the batch_delay pfifo.
 *
 * Requires:  rf = route-flux object with:
 *
 *             * current   -- set as required (copy of steady state)
 *
 *             * pfx_id    -- X      -- set below
 *             * bits      -- X      -- set below
 *             * pending   -- X      -- set below
 *             * list      -- X      -- set below
 *
 * Schedules the route_flux on the prib->fifo_batch and sets the adj_out entry.
 *
 * Note that we schedule one period ahead of the current period -- rounds up.
 */
static void
bgp_adj_out_add_batch(bgp_prib prib, route_flux rf, attr_set new_attr,
                                                             prefix_id_t pfx_id)
{
  pfifo_index_t i ;

  if (new_attr != NULL)
    bgp_attr_lock(new_attr) ;

  rf->pfx_id       = pfx_id ;
  rf->bits         = (rf_act_batch << aob_action_shift) | aob_flux ;
  rf->pending.attr = new_attr ;

  i = pfifo_item_add(prib->fifo_batch, rf, prib->now + prib->batch_delay + 1) ;
  bgp_adj_out_set_index_dl((adj_out)rf, i, prib->batch_delay_extra) ;

  ihash_set_item(prib->adj_out, rf->pfx_id, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Change an rf_act_batch route_flux
 *
 * Reschedules the route_flux, unless already 'ex' or unless already at the
 * dead-line.
 */
static void
bgp_adj_out_change_batch(bgp_prib prib, route_flux rf)
{
  pfifo_index_t   i ;

  i = bgp_adj_out_get_index(prib->fifo_batch, (adj_out)rf) ;

  if (i < aob_index_ex)
    {
      pfifo_period_t  nst, st, dl ;

      nst = prib->now + prib->batch_delay + 1 ;
      st  = pfifo_period_get(prib->fifo_batch, i) ;
      dl  = st + bgp_adj_out_get_dl((adj_out)rf) ;

      if (nst > dl)
        nst = dl ;              /* clamp to deadline    */

      if (nst != st)
        {
          i = pfifo_item_move(prib->fifo_batch, rf, i, nst) ;
          bgp_adj_out_set_index_dl((adj_out)rf, i, dl - nst) ;
        } ;
    } ;
} ;

/*==============================================================================
 * Adding, removing and changing attr_flux entries on the announce_queue
 * pfifo.
 */

/*------------------------------------------------------------------------------
 * Add given route_flux to attr_flux, creating attr_flux if required.
 *
 * If the attr_flux already exists, reschedule to schedule-time for the
 * route-flux, if the route_flux has an earlier schedule-time.
 *
 * Requires: rf   -- route_flux to be added
 *
 *                   rf->pending.attr == new (not NULL) attr !
 *
 *           st   -- schedule-time for the route_flux
 */
static void
bgp_adj_out_add_announce(bgp_prib prib, route_flux rf, pfifo_period_t st)
{
  pfifo_index_t i ;
  attr_flux     af ;
  bool          added ;

  qassert(rf->pending.attr != NULL) ;

  /* Find or create the required attr_flux.
   */
  added = false ;
  af = vhash_lookup(prib->attr_flux_hash, rf->pending.attr, &added) ;

  if (added)
    {
      /* The newly created attr_flux points at the attr.  Note that the
       * route_flux is the owner of a lock on the attr -- the attr_flux does
       * does not need one.
       *
       * The attr_flux is 'held' from a vhash perspective, until the fifo is
       * emptied...
       */
      af->attr = rf->pending.attr ;
      vhash_set_held(af) ;

      qassert(af->vhash.ref_count == aob_attr_flux) ;
    } ;

  /* Schedule or reschedule the attr_flux
   */
  if (ddl_head(af->fifo) != NULL)
    {
      pfifo_period_t ast ;

      i   = bgp_adj_out_get_index(prib->announce_queue, (adj_out)af) ;
      ast = pfifo_period_get(prib->announce_queue, i) ;

      if (ast > st)
        {
          i = pfifo_item_move(prib->announce_queue, af, i, st) ;
          bgp_adj_out_set_index((adj_out)af, i) ;
        } ;
    }
  else
    {
      i = pfifo_item_add(prib->announce_queue, af, st) ;
      bgp_adj_out_set_index((adj_out)af, i) ;
    } ;

  /* Set the route_flux or its associate route_mpls to point at the attr_flux
   * it is related to, and then add the route_flux to the attr_flux's list of
   * same.
   */
  rf->pending.flux = af ;
  ddl_append(af->fifo, rf, list) ;
} ;

/*------------------------------------------------------------------------------
 * Delete given route_flux from the given attr_flux.
 *
 * If the attr_flux empties out, remove it from the announce_queue queue and
 * *free* it.
 *
 * Returns:  the attr_flux's schedule.
 *
 * NB: this does not care about the state of rf->pending.  The caller may:
 *
 *       * already have copied the af->attr back to rf->pending.attr
 *
 *       * or undone the rf's lock on the af->attr and cleared rf->pending.
 *
 *     In any case, the caller is responsible for the attributes and the lock,
 *     and MUST NOT expected the attr_flux to still exist on return.
 */
static pfifo_period_t
bgp_adj_out_del_announce(bgp_prib prib, route_flux rf, attr_flux af)
{
  pfifo_index_t  i ;
  pfifo_period_t st ;

  ddl_del(af->fifo, rf, list) ;         /* take rf off the attr_flux    */

  i  = bgp_adj_out_get_index(prib->announce_queue, (adj_out)af) ;
  st = pfifo_period_get(prib->announce_queue, i) ;

  if (ddl_head(af->fifo) == NULL)
    {
      pfifo_item_del(prib->announce_queue, af, i) ;
      bgp_attr_flux_free(prib, af) ;
    } ;

  return st ;
} ;

/*------------------------------------------------------------------------------
 * Change an rf_act_announce route_flux
 *
 * This means that before the I/O can send the dispatched announce, or before
 * the aggregation-delay expires, we receive a change in what to announce,
 * or a withdraw.
 *
 * Requires:  rf   = route_flux, currently attached to given af
 *
 *                   BUT with rf->pending.attr set to the new attr (if any)
 *
 *            af   = attr_flux the route_flux is currently attached to
 *
 *                   this is used to schedule the new attr_flux, so that
 *                   rapid changes to a given prefix cannot indefinitely
 *                   delay updates !
 *
 * NB: the new state != old state
 *
 * Must remove from the current attr_flux, and reschedule either as announce or
 * as a withdraw.
 */
static void
bgp_adj_out_change_announce(bgp_prib prib, route_flux rf, attr_flux af)
{
  pfifo_period_t  st ;

  st = bgp_adj_out_del_announce(prib, rf, af) ;

  if (rf->pending.attr != NULL)
    bgp_adj_out_add_announce(prib, rf, st) ;
  else
    {
      rf->bits = (rf_act_withdraw << aob_action_shift) | aob_flux ;
      ddl_append(prib->withdraw_queue, rf, list) ;
    } ;
} ;






/*==============================================================================
 * MRAI pfifo handling.
 *
 * After sending an update for a given prefix it enters rf_act_mrai state,
 * where the prefix waits for (MRAI - batch_delay), before falling back to
 * steady state.  Note that does not wait for the full MRAI, so that if a
 * change rolls up immediately after returning to steady state, the batch_delay
 * it will then experience overlaps the end of the full MRAI.
 *
 * If the full MRAI is less than the batch_delay, then there is no MRAI pfifo,
 * and after sending an update the prefix immediately falls back to steady
 * state.
 *
 * So, on entry to MRAI we have:
 *
 *   (1)   |<------- Full MRAI -------->|
 *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
 *         *-------------------*--------*
 *         ^                   ^        ^
 *         |                   |        dead-line
 *         |                   schedule-time for return to steady state
 *         |                   MRAI-End
 *         update-time
 *
 * The route_flux has a NULL pending change, and aob_mrai_wait is set to
 * indicate that there is no change pending.
 *
 * Now, suppose a withdraw rolls up.  We want to do the NO-WRATE stuff... so
 * reschedule to the current time plus batch-delay so that, if the withdraw is
 * well before the MRAI-End, we have:
 *
 *   (2a)  |<---------- MRAI ---------->|
 *         |<--- MRAI - BD --->|<- BD ->|
 *         *----w--------+-----*--------*
 *         ^    ^<- BD ->^              ^
 *         |    |        |              dead-line
 *         |    |        schedule-time for withdraw
 *         |    withdraw
 *         update-time
 *
 * So that if nothing else happens, the withdraw can be dispatched after the
 * usual batch-delay.  But if something else does happen, the MRAI-End can be
 * be recovered from the dead-line.  While the withdraw is pending, is not
 * aob_mrai_wait.
 *
 * If a withdraw rolls up at any time up to but excluding MRAI-End, we have:
 *
 *   (2b)  |<---------- MRAI ---------->|
 *         |<--- MRAI - BD --->|<- BD ->|
 *         *---------------w---*----+---*
 *         ^               ^<- BD ->^   ^
 *         |               |        |   dead-line
 *         |               |        schedule-time for withdraw
 *         |               withdraw
 *         update-time
 *
 * There's actually no difference between (2a) and (2b).
 *
 * If the withdraw arrives at or after MRAI-End, then the prefix can be
 * rescheduled as rf_act_batch -- as if it had fallen back to steady state,
 * before the withdraw turned up.
 *
 * Now, suppose an announce rolls up.  We want the full MRAI to expire before
 * any announce, so we reschedule to the full MRAI.  So, if the announce is
 * any time up to but excluding MRAI-End, we have:
 *
 *   (3)   |<---------- MRAI ---------->|
 *         |<--- MRAI - BD --->|<- BD ->|
 *         *----a--------------*--------*
 *         ^    ^                       ^
 *         |    |                       dead-line
 *         |    |                       schedule-time for announce
 *         |    announce
 *         update-time
 *
 * Note that if enters MRAI after a withdraw is output, there may be an
 * announce pending, and in that case, starts in state (3).
 *
 * So now we have withdraw, announce or revert (return to current state) while
 * in state (2) or state (3):
 *
 *   2w: withdraw while withdraw pending -- no effect
 *
 *   2a: announce while withdraw pending.
 *
 *       If before MRAI-End, change to state (3).
 *
 *       If at or after MRAI-End, reschedule as rf_act_batch.
 *
 *   2r: revert while withdraw pending.
 *   3r: revert while announce pending
 *
 *       If before MRAI-End, reverts to state (1).
 *
 *       If at or after MRAI-End, fall back to steady state.
 *
 *   3w: withdraw while announce pending
 *
 *       If before MRAI-End, change to state (2).
 *
 *       If at or after MRAI-End, reschedule as rf_act_batch.
 *
 *   3a: announce while announce pending
 *
 *       Ignore if no change of announcement.
 *
 *       If before MRAI-End, update, but stay in state (3).
 *
 *       If at or after MRAI-End, reschedule as rf_act_batch.
 *
 * So... if the prefix bounces around before MRAI-End, it stays on the
 * fifo_mrai and the earliest it can be dispatched is after the full MRAI,
 * unless is withdrawn.  If change after MRAI-End, it will be scheduled
 * as rf_act_batch -- as if had gone to steady state before the change.
 */

/*------------------------------------------------------------------------------
 * Place the given route_flux into MRAI state -- after update sent.
 *
 * Sets the the current state from what was the pending state -- clearing the
 * previous current state.
 *
 * If the update was a withdraw, leave any now pending announce attributes.
 *
 * Enters state (1) or state (3) of MRAI.
 */
static void
bgp_adj_out_set_mrai(bgp_prib prib, route_flux rf, attr_set new_current_attr)
{
  pfifo_period_t  nst, dl ;
  pfifo_index_t   i ;
  adj_out_bits_t  bits ;

  bits = (rf_act_mrai << aob_action_shift) | aob_flux ;

  dl  = prib->now + prib->mrai_delay + 1 ;
  nst = dl - prib->batch_delay ;        /* state (1) schedule-time      */

  /* Whatever else, we can now update the current.
   */
  if (rf->current != NULL)
    bgp_attr_unlock(rf->current) ;

  rf->current = new_current_attr ;

  /* Deal with updating current and pending
   */
  if (new_current_attr != NULL)
    {
      /* After an announce, the new current is the previous pending, and we
       * have nothing pending -- so aob_mrai_wait.
       */
      rf->pending.attr = NULL ;
      bits |= aob_mrai_wait ;           /* state (1)                    */
    }
  else
    {
      /* After a withdraw, the current is NULL, and we may or may not have
       * something pending -- so may or may not be aob_mrai_wait.
       *
       * If we do have an announce pending, then set the schedule-time to the
       * end of the full MRAI -- ie as per state (3).
       */
      if (rf->pending.attr == NULL)
        bits |= aob_mrai_wait ;         /* state (1)                    */
      else
        nst = dl ;                      /* state (3) schedule-time      */
    } ;

  rf->bits = bits ;

  /* Whatever else is going on, we schedule the rf_act_mrai on the fifo_mrai,
   * setting the dead-line to the full MRAI time.
   */
  i = pfifo_item_add(prib->fifo_mrai, rf, nst) ;
  bgp_adj_out_set_index_dl((adj_out)rf, i, dl - nst) ;
} ;

/*------------------------------------------------------------------------------
 * Set pending MRAI withdraw.
 *
 * May be in state (1) or (3) -- in both cases the dead-line is full MRAI.
 *
 * Enters state (2) of MRAI or changes to rf_act_batch, with a withdraw.
 *
 * NB: must not already have a withdraw pending.
 *
 * NB: this can change the route_flux from rf_act_mrai to rf_act_batch.
 */
static void
bgp_adj_out_mrai_withdraw(bgp_prib prib, route_flux rf)
{
  pfifo_index_t   i ;
  pfifo_period_t  nst, dl ;

  nst = prib->now + prib->batch_delay + 1 ;

  i = bgp_adj_out_get_index(prib->fifo_mrai, (adj_out)rf) ;

  if (i < aob_index_ex)
    {
      /* The route_flux is in the body of the fifo_mrai, so we can get its
       * dead-line, which is the full MRAI time.
       *
       * If the new schedule-time is beyond the full MRAI dead-line, we drop
       * out of MRAI state and reschedule as ordinary batch delay.
       *
       * We have:
       *
       *         |<------- Full MRAI -------->|
       *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
       *         *---------------w---*----n---*
       *         ^               ^<- BD ->^   ^
       *         |               |        |   dead-line
       *         |               |        nst -- new schedule time
       *         |               withdraw (now)
       *         update-time
       */
      dl = pfifo_period_get(prib->fifo_mrai, i)
                                            + bgp_adj_out_get_dl((adj_out)rf) ;
    }
  else
    {
      /* The route_flux is in the 'ex' period, so we must be past MRAI-end, so
       * drop out of MRAI and reschedule as if from steady state.
       */
      dl = 0 ;
      qassert(nst > 0) ;
    } ;

  /* Reschedule as required.
   */
  if (nst > dl)
    {
      /* Reschedule as if had gone to steady state and is now being scheduled
       * from there -- so drop from rf_act_mrai to rf_act_batch, discarding
       * all flags -- in particular discards aob_mrai_wait.
       */
      pfifo_item_del(prib->fifo_mrai, rf, i) ;

      rf->bits = (rf_act_batch << aob_action_shift) | aob_flux ;
      i = pfifo_item_add(prib->fifo_batch, rf, nst) ;
      bgp_adj_out_set_index_dl((adj_out)rf, i, prib->batch_delay_extra) ;
    }
  else
    {
      /* Reschedule setting the new dead-line.
       *
       * The new dead-line is the full MRAI time wrt new schedule time.
       */
      i = pfifo_item_move(prib->fifo_mrai, rf, i, nst) ;
      bgp_adj_out_set_index_dl((adj_out)rf, i, dl - nst) ;

      rf->bits &= ~(adj_out_bits_t)aob_mrai_wait ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set pending MRAI announce.
 *
 * May be in state (1), (2) or (3) -- in all cases the dead-line is full MRAI.
 *
 * Enters state (3) of MRAI or changes to rf_act_batch, with an announce.
 *
 * NB: announcement must NOT be the same as any pending or the current state.
 *
 * NB: this can change the route_flux from rf_act_mrai to rf_act_batch.
 */
static void
bgp_adj_out_mrai_announce(bgp_prib prib, route_flux rf)
{
  pfifo_index_t   i ;
  pfifo_period_t  nst, dl ;

  nst = prib->now + prib->batch_delay + 1 ;

  i = bgp_adj_out_get_index(prib->fifo_mrai, (adj_out)rf) ;

  if (i < aob_index_ex)
    {
      /* The route_flux is in the body of the fifo_mrai, so we can get its
       * dead-line, which is the full MRAI time.
       *
       * If the new schedule-time is beyond the full MRAI dead-line, we drop
       * out of MRAI state and reschedule as ordinary batch delay.
       *
       * We have:
       *
       *         |<------- Full MRAI -------->|
       *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
       *         *---------------a---*----n---*
       *         ^               ^<- BD ->^   ^
       *         |               |        |   dead-line
       *         |               |        nst -- new schedule time
       *         |               now -- announce
       *         update-time
       */
      dl = pfifo_period_get(prib->fifo_mrai, i)
                                            + bgp_adj_out_get_dl((adj_out)rf) ;
    }
  else
    {
      /* The route_flux is in the 'ex' period, so we must be past MRAI-end, so
       * drop out of MRAI and reschedule as if from steady state.
       */
      dl = 0 ;
      qassert(nst > 0) ;
    } ;

  /* Reschedule as required.
   */
  if (nst > dl)
    {
      /* Reschedule as if had gone to steady state and is now being scheduled
       * from there -- so drop from rf_act_mrai to rf_act_batch, discarding
       * all flags -- in particular discards aob_mrai_wait.
       */
      pfifo_item_del(prib->fifo_mrai, rf, i) ;

      rf->bits = (rf_act_batch << aob_action_shift) | aob_flux ;
      i = pfifo_item_add(prib->fifo_batch, rf, nst) ;
      bgp_adj_out_set_index_dl((adj_out)rf, i, prib->batch_delay_extra) ;
    }
  else
    {
      /* Reschedule at the dead-line == full MRAI time
       *
       * The new dead-line, therefore, 0.
       */
      i = pfifo_item_move(prib->fifo_mrai, rf, i, dl) ;
      bgp_adj_out_set_index_dl((adj_out)rf, i, 0) ;

      rf->bits &= ~(adj_out_bits_t)aob_mrai_wait ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Revert MRAI to current state.
 *
 * May be in state (2) or (3) -- in both cases the dead-line is full MRAI.
 *
 * Enters state (1) of MRAI or drops to steady state.
 *
 * Will have discarded any pending state.
 *
 * NB: this can change prefix from rf_act_mrai to steady state -- discarding
 *     the route_flux.
 */
static void
bgp_adj_out_mrai_revert(bgp_prib prib, route_flux rf)
{
  pfifo_index_t   i ;
  pfifo_period_t  nst, dl ;

  qassert(rf->pending.anon == NULL) ;           /* nothing pending      */

  nst = prib->now + prib->batch_delay + 1 ;

  i = bgp_adj_out_get_index(prib->fifo_mrai, (adj_out)rf) ;

  if (i < aob_index_ex)
    {
      /* The route_flux is in the body of the fifo_mrai, so we can get its
       * dead-line, which is the full MRAI time.
       *
       * If the new schedule-time is beyond the full MRAI dead-line, we drop
       * out of MRAI state and reschedule as ordinary batch delay.
       *
       * We have:
       *
       *         |<------- Full MRAI -------->|
       *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
       *         *---------------r---*----n---*
       *         ^               ^        ^   ^
       *         |               |        |   dead-line
       *         |               |        nst -- new schedule time
       *         |               now -- revert
       *         update-time
       */
      dl = pfifo_period_get(prib->fifo_mrai, i)
                                            + bgp_adj_out_get_dl((adj_out)rf) ;
    }
  else
    {
      /* The route_flux is in the 'ex' period, so we must be past MRAI-end, so
       * drop out of MRAI and fall back to steady state.
       */
      dl = 0 ;
      qassert(nst > 0) ;
    } ;

  /* Reschedule or fall back to steady state as required.
   */
  if (nst > dl)
    {
      /* Drop to steady state.
       */
      pfifo_item_del(prib->fifo_mrai, rf, i) ;

      bgp_adj_out_set_steady(prib, rf) ;
    }
  else
    {
      /* Reschedule at the dead-line less batch-delay.
       */
      i = pfifo_item_move(prib->fifo_mrai, rf, i, dl - prib->batch_delay) ;
      bgp_adj_out_set_index_dl((adj_out)rf, i, prib->batch_delay) ;

      rf->bits |= aob_mrai_wait ;
    } ;
} ;

/*==============================================================================
 * Getting and setting index and delta values.
 */

/*------------------------------------------------------------------------------
 * Fix up the 'ex' list so that all indexes are 'ex'.
 *
 * Sets the aob_ex flag, so that does not repeat this.
 *
 * Zeroises the delta field.
 */
static void
bgp_adj_out_fix_ex(pfifo pf, adj_out ao)
{
  do
    {
      adj_out_bits_t bits ;

      bits = ao->bits & ~( (aob_index_mask << aob_index_shift) |
                           (aob_delta_mask << aob_delta_shift) ) ;
      ao->bits = bits | (aob_index_ex << aob_index_shift) | aob_ex ;

      ao = pfifo_pair_get(pf, ao)->prev ;
    }
  while ((ao != NULL) && !(ao->bits & aob_ex)) ;
} ;

/*------------------------------------------------------------------------------
 * Get the pfifo index from the given adj_out object
 *
 * If there are any 'ex' period items, then any which are not marked as
 * 'aob_ex' may have invalid indexes.  We know items are only ever appended to
 * the 'ex' period -- so we can scan from the back of the 'ex' list to fix
 * things up.
 *
 * Returns:  pfifo index for period or aob_index_mask (if in 'ex' period)
 */
inline static pfifo_index_t
bgp_adj_out_get_index(pfifo pf, adj_out ao)
{
  adj_out ao_tail ;

  ao_tail = pf->ex.tail ;
  if ((ao_tail != NULL) && !(ao_tail->bits & aob_ex))
    bgp_adj_out_fix_ex(pf, ao_tail) ;

  return (ao->bits >> aob_index_shift) & aob_index_mask ;
} ;

/*------------------------------------------------------------------------------
 * Set the pfifo index for the given adj_out object
 *
 * NB: will be PFIFO_INDEX_EX or aob_index_mask if is in the 'ex' period.
 */
inline static void
bgp_adj_out_set_index(adj_out ao, pfifo_index_t i)
{
  adj_out_bits_t bits ;

  confirm((PFIFO_INDEX_EX & aob_index_mask) == aob_index_ex) ;

  bits = ao->bits & ~(aob_index_mask << aob_index_shift) ;

  ao->bits = bits | ((i & aob_index_mask) << aob_index_shift) ;
} ;

/*------------------------------------------------------------------------------
 * Set the pfifo index and the deadline for the given adj_out object.
 *
 * If setting the index to aob_index_ex
 */
inline static void
bgp_adj_out_set_index_dl(adj_out ao, pfifo_index_t i, int dl)
{
  adj_out_bits_t bits ;

  confirm((PFIFO_INDEX_EX & aob_index_mask) == aob_index_mask) ;

  bits = ao->bits & ~( (aob_index_mask << aob_index_shift) |
                       (aob_delta_mask << aob_delta_shift) ) ;

  if ((dl > 0) && (i < aob_index_mask))
    {
      if (dl > aob_delta_mask)
        bits |= (aob_delta_mask << aob_delta_shift) ;
      else
        bits |= ((dl & aob_delta_mask) << aob_delta_shift) ;
    } ;

  ao->bits = bits | ((i & aob_index_mask) << aob_index_shift) ;
} ;

/*------------------------------------------------------------------------------
 * Get the dead-line from the given adj_out object
 *
 * The dead-line returned is a +ve offset from the current schedule-time.
 */
inline static pfifo_period_t
bgp_adj_out_get_dl(adj_out ao)
{
  return (ao->bits >> aob_delta_shift) & aob_delta_mask ;
} ;

/*==============================================================================
 * Dispatch Process.
 *
 * This timer driven process dispatches stuff from the fifo_batch to
 * withdraw_queue and announce_queue, and from the announce_queue to
 * its ex list.
 *
 *
 *
 */
static void bgp_adj_out_set_dispatcher(bgp_prib prib, pfifo_period_t dt) ;
static void bgp_adj_out_set_timer(bgp_prib prib, pfifo_period_t dt) ;

/*------------------------------------------------------------------------------
 * Set the dispatch process going for the given prib.
 */
static void
bgp_adj_out_start_dispatcher(bgp_prib prib)
{
  pfifo_period_t dt ;

  bgp_adj_out_set_now(prib) ;

  if (prib->withdraw_queue.head != NULL)
    dt = prib->now ;
  else
    {
      pfifo_period_t temp ;

      dt = pfifo_first_period(prib->fifo_batch) ;

      temp = pfifo_first_period(prib->announce_queue) ;
      if (dt > temp)
        dt = temp ;

      temp = pfifo_first_period(prib->fifo_mrai) ;
      if (dt > temp)
        dt = temp ;
    } ;

  bgp_adj_out_set_dispatcher(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Update the dispatch timer if the given dispatch time is less than the
 * current dispatch time.
 *
 * Note that when dispatch is being delayed, the current dispatch time is zero,
 * so this function has no effect !
 */
static void
bgp_adj_out_update_dispatcher(bgp_prib prib, pfifo_period_t dt)
{
  if (dt >= prib->dispatch_time)
    return ;

  bgp_adj_out_set_dispatcher(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Unset the dispatch timer
 */
static void
bgp_adj_out_unset_dispatcher(bgp_prib prib)
{
  bgp_adj_out_set_dispatcher(prib, PFIFO_PERIOD_MAX) ;
} ;

/*------------------------------------------------------------------------------
 * Set the dispatch time and clear any dispatch delay.
 *
 * If the given dispatch time is >= PFIFO_PERIOD_MAX, will stop the timer.
 */
static void
bgp_adj_out_set_dispatcher(bgp_prib prib, pfifo_period_t dt)
{
  prib->dispatch_time  = dt ;
  prib->dispatch_delay = 0 ;

  bgp_adj_out_set_timer(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Set the given time to delay dispatch to.
 *
 * While a delay is in place the timer is running, and bgp_adj_out_dispatch()
 * will be invoked when the delay expires.
 *
 * The delay is unset by:
 *
 *   * bgp_adj_out_start_dispatcher()
 *
 *   * bgp_adj_out_set_dispatcher()
 *
 * If the given dispatch time is >= PFIFO_PERIOD_MAX, will stop the timer.
 */
static void
bgp_adj_out_delay_dispatcher(bgp_prib prib, pfifo_period_t dt)
{
  prib->dispatch_time  = 0 ;
  prib->dispatch_delay = dt ;

  bgp_adj_out_set_timer(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Set or unset the prib->dispatch_qtr.
 *
 * Sets timer to the given 'dt' -- if that is >= PFIFO_PERIOD_MAX, will unset
 * the timer.
 */
static void
bgp_adj_out_set_timer(bgp_prib prib, pfifo_period_t dt)
{
  if (dt < PFIFO_PERIOD_MAX)
    qtimer_set(prib->dispatch_qtr,
                        qt_mono_fp(dt, prib->period_origin, bgp_period_shift),
                                                         bgp_adj_out_dispatch) ;
  else
    qtimer_unset(prib->dispatch_qtr) ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch from fifo_batch to withdraw_queue and announce_queue,
 * and move anything in announce_queue whose time has come, to its ex
 * list.
 *
 * Establish whether I/O processing is required.
 */
static void
bgp_adj_out_dispatch(qtimer qtr, void* timer_info, qtime_mono_t when)
{
  route_flux rf_next ;
  bgp_prib   prib ;
  pfifo_period_t dt, temp ;

  prib = timer_info ;
  qassert(qtr == prib->dispatch_qtr) ;

  bgp_adj_out_set_now(prib) ;

  /* Dispatch stuff from the fifo_batch.
   */
  rf_next = pfifo_take(prib->fifo_batch, prib->now + 1, true) ;

  if (rf_next != NULL)
    bgp_adj_out_dispatch_queue(prib, rf_next, prib->fifo_batch) ;

  dt = pfifo_first_not_ex_period(prib->fifo_batch) ;

  /* Dispatch stuff from the fifo_mrai.
   */
  rf_next = pfifo_take(prib->fifo_mrai, prib->now + 1, true) ;

  if (rf_next != NULL)
    bgp_adj_out_dispatch_queue(prib, rf_next, prib->fifo_mrai) ;

  temp = pfifo_first_not_ex_period(prib->fifo_mrai) ;
  if (dt > temp)
    dt = temp ;

  /* Dispatch stuff from announce_queue
   *
   * This doesn't do very much, just arranges for all announces whose
   * announce_delay has expired all sit on the ex queue, whence they will be
   * output.
   */
  pfifo_take(prib->announce_queue, prib->now + 1, true) ;

  temp = pfifo_first_not_ex_period(prib->announce_queue) ;
  if (dt > temp)
    dt = temp ;

  /* If I/O is required and the I/O process is not running, set it going
   */
  if ((prib->withdraw_queue.head != NULL) ||
                                    (prib->announce_queue->ex.head != NULL))
    bgp_session_kick_write(prib->prun) ;

  /* If required, schedule the next dispatch run
   */
  bgp_adj_out_set_dispatcher(prib, dt) ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch and empty rf_act_batch or rf_act_mrai 'ex' queue.
 *
 * NB: assumes there is at least one thing in the queue !
 */
static void
bgp_adj_out_dispatch_queue(bgp_prib prib, route_flux rf_next, pfifo pf)
{
  ddl_init(pf->ex) ;            /* empty the ex list    */

  do
    {
      route_flux   rf ;
      route_flux_action_t action ;

      rf      = rf_next ;
      rf_next = rf->list.next ;

      qassert(!(rf->bits & aob_attr_set) &&
                                 ((rf->bits & aob_type_mask) == aob_flux)) ;

      action = (rf->bits >> aob_action_shift) & aob_action_mask ;
      qassert((action == rf_act_batch) || (action == rf_act_mrai)) ;

      if (rf->pending.attr != NULL)
        {
          /* Dispatch to an attr_flux on the announce_queue.
           */
         rf->bits = (rf_act_announce << aob_action_shift) | aob_flux ;

         bgp_adj_out_add_announce(prib, rf,
                                         prib->now + prib->announce_delay + 1) ;
       }
      else if (rf->bits & aob_mrai_wait)
        {
          /* MRAI expired.
           */
          qassert(action == rf_act_mrai) ;
          bgp_adj_out_set_steady(prib, rf) ;
        }
      else
        {
          /* Dispatch to withdraw_queue queue.
           *
           * At this stage we don't have any pending announce to follow.
           */
          rf->bits = (rf_act_withdraw << aob_action_shift) | aob_flux ;
          ddl_append(prib->withdraw_queue, rf, list) ;
        } ;
    }
  while (rf_next != NULL) ;
} ;

/*==============================================================================
 * Interface for I/O -- pulling stuff from withdraw_queue and from
 * announce_queue and rescheduling for MRAI.
 *
 */
static route_out_parcel bgp_adj_out_ret_withdraw(bgp_prib prib,
                                       route_out_parcel parcel, route_flux rf) ;
static route_out_parcel bgp_adj_out_ret_announce(bgp_prib prib,
                         route_out_parcel parcel, attr_flux af, route_flux rf) ;
static route_out_parcel bgp_adj_out_ret_eor(bgp_prib prib,
                                                      route_out_parcel parcel) ;
static route_out_parcel bgp_adj_out_ret_next_announce(bgp_prib prib,
                                        route_out_parcel parcel, attr_flux af) ;

static route_out_parcel bgp_adj_out_announce_dequeue(bgp_prib prib,
                                                                 attr_flux af) ;

/*------------------------------------------------------------------------------
 * Update the announce_queue scheduling, to collect anything to now announce.
 *
 * So, when ready to do an announcement "run", get things ready for that.
 *
 * The expected use is:
 *
 *    bgp_adj_out_start_updates(prib) ;
 *    while (1)
 *      {
 *        parcel = bgp_adj_out_next_update(prib, &parcel_s) ;
 *        if (parcel == NULL)
 *          break ;
 *
 *          ... prepare withdraw/announce update or EoR.
 *          ... break out of loop if cannot output
 *
 *        withdraw:
 *          do
 *            {
 *              parcel = bgp_adj_out_done_withdraw(prib, &parcel_s) ;
 *              if (parcel != NULL)
 *                ... add prefix to withdraw if can
 *                ... break out of loop if cannot
 *            } ;
 *
 *        announce:
 *          do
 *            {
 *              parcel = bgp_adj_out_done_announce(prib, &parcel_s) ;
 *              if (parcel != NULL)
 *                ... add prefix to update if can
 *                ... break out of loop if cannot
 *            } ;
 *
 *         EoR:
 *           bgp_adj_out_done_eor(prib) ;
 *
 *         ship the withdraw/announce update or EoR.
 *      } ;
 *
 * ...where _done_announce returns another parcel iff it has the same
 * attributes as the first (and is not an EoR !).
 */
extern void
bgp_adj_out_start_updates(bgp_prib prib)
{
  bgp_adj_out_set_now(prib) ;
  pfifo_take(prib->fifo_batch, prib->now + 1, true) ;
} ;

/*------------------------------------------------------------------------------
 * Get next prefix to withdraw -- if any
 *
 * Does not require an bgp_adj_out_start_updates() first.
 *
 * Otherwise... see bgp_adj_out_next_update()
 *
 * Returns:  address of parcel (as given) -- NULL <=> no *withdraws* pending
 */
extern route_out_parcel
bgp_adj_out_next_withdraw(bgp_prib prib, route_out_parcel parcel)
{
  route_flux rf ;

  rf = prib->withdraw_queue.head ;

  if (rf != NULL)
    return bgp_adj_out_ret_withdraw(prib, parcel, rf) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get next prefix to withdraw, route to announce or EoR -- if any
 *
 * For after a bgp_adj_out_start_updates() up to when this returns NULL.
 *
 * The caller need not complete the action, the object remains pending in
 * the adj_out.  However, if the caller does complete the action it MUST do
 * so *before* any other change is made to the adj_out, and MUST call the
 * relevant bgp_adj_out_done_xxx() *before* any other change is made to the
 * adj_out.
 *
 * NB: any prefix_id returned in the parcel is *not* locked by the parcel
 *
 *     If the caller wishes to keep the prefix_id beyond the call of
 *     bgp_adj_out_done_xxx(), then they must obtain their own lock.
 *
 * NB: any attributes returned in the parcel are *not* locked by the parcel
 *
 *     If the caller wishes to keep the attributes beyond the call of
 *     bgp_adj_out_done_xxx(), then they must obtain their own lock.
 *
 * Returns:  address of parcel (as given) -- NULL <=> nothing pending
 */
extern route_out_parcel
bgp_adj_out_next_update(bgp_prib prib, route_out_parcel parcel)
{
  route_flux rf ;

  rf = prib->withdraw_queue.head ;

  if (rf != NULL)
    return bgp_adj_out_ret_withdraw(prib, parcel, rf) ;

  while (1)
    {
      attr_flux   af ;

      af = prib->announce_queue->ex.head ;

      if (af == NULL)
        return NULL ;

      rf = af->fifo.head ;
      if (rf != NULL)
        return bgp_adj_out_ret_announce(prib, parcel, af, rf) ;

      if (af == prib->eor)
        {
          qassert((af->attr == NULL) &&
                   (((((adj_out)af)->bits >> aob_type_shift) & aob_type_mask)
                                                                  == aob_eor)) ;
          return bgp_adj_out_ret_eor(prib, parcel) ;
        } ;

      /* The attr_flux fifo is empty, so we can de-queue and discard it.
       *
       * Not clear why we would have an empty attr_flux on the queue, but we
       * get rid of it, anyway.
       *
       * Note that the attr_flux does not have a lock on the attr, so no need
       * to worry about that.
       */
      bgp_adj_out_announce_dequeue(prib, af) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Return the given af/rf as the next route to withdraw.
 *
 * Returns parcel:
 *
 *   * attr                     -- NULL
 *
 *   * pfx_id                   -- from route_flux
 *
 *   * qafx                     -- from prib
 *   * action                   -- ra_out_withdraw
 */
static route_out_parcel
bgp_adj_out_ret_withdraw(bgp_prib prib, route_out_parcel parcel, route_flux rf)
{
  parcel->attr   = NULL ;
  parcel->pfx_id = rf->pfx_id ;
  parcel->qafx   = prib->qafx ;
  parcel->action = ra_out_withdraw ;

  return parcel ;
} ;

/*------------------------------------------------------------------------------
 * Return the given af/rf as the next route to announce.
 *
 * Returns parcel:
 *
 *   * attr                     -- from attr_flux
 *
 *   * pfx_id                   -- from route_flux
 *
 *   * qafx                     -- from prib
 *   * action                   -- ra_out_initial/ra_out_update
 */
static route_out_parcel
bgp_adj_out_ret_announce(bgp_prib prib, route_out_parcel parcel,
                                                    attr_flux af, route_flux rf)
{
  qassert(af->attr != NULL) ;

  parcel->qafx   = prib->qafx ;
  parcel->attr   = af->attr ;
  parcel->pfx_id = rf->pfx_id ;
  parcel->action = (rf->current == NULL) ? ra_out_initial
                                         : ra_out_update ;

  return parcel ;
} ;

/*------------------------------------------------------------------------------
 * Return an EoR parcel.
 *
 * Returns parcel:
 *
 *   * attr                     -- NULL
 *
 *   * pfx_id                   -- prefix_id_null
 *
 *   * qafx                     -- from prib
 *   * action                   -- ra_out_eor
 */
static route_out_parcel
bgp_adj_out_ret_eor(bgp_prib prib, route_out_parcel parcel)
{
  parcel->attr   = NULL ;
  parcel->pfx_id = prefix_id_null ;

  parcel->qafx   = prib->qafx ;
  parcel->action = ra_out_eor ;

  return parcel ;
} ;

/*------------------------------------------------------------------------------
 * Update prib because have just sent update for the current head of the
 * withdraw_queue queue -- return next withdrawn prefix, if any.
 *
 * See bgp_adj_out_ret_withdraw().
 *
 * Returns:  address of given route_out_parcel -- NULL <=> no withdraws pending
 *
 * So... updates prib and returns the next to be withdrawn.  The caller may
 * ignore the returned value.
 *
 * NB: does NOT require the given parcel to be the same as the last one
 *     given to either bgp_adj_out_ret_withdraw/_done_withdraw()
 */
extern route_out_parcel
bgp_adj_out_done_withdraw(bgp_prib prib, route_out_parcel parcel)
{
  route_flux rf ;

  rf = prib->withdraw_queue.head ;

  qassert(rf != NULL) ;
  if (rf == NULL)
    return NULL ;               /* no idea what else to do      */

  ddl_del_head(prib->withdraw_queue, list) ;
  bgp_adj_out_set_mrai(prib, rf, NULL) ;

  rf = prib->withdraw_queue.head ;

  if (rf == NULL)
    return NULL ;

  return bgp_adj_out_ret_withdraw(prib, parcel, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Update prib because have just sent update for the current head of the
 * announce_queue queue.
 *
 * Fills in and returns the given parcel iff there is another prefix to
 * announce with the same attributes as the one just done.
 *
 * Returns:  NULL => nothing else to announce with the same attributes.
 *       or: address of parcel with next thing to announce filled in
 *
 * NB: the given parcel may or may not be the same as the last one given to
 *     bgp_adj_out_next_update/_done_announce()
 */
extern route_out_parcel
bgp_adj_out_done_announce(bgp_prib prib, route_out_parcel parcel)
{
  attr_flux   af ;
  route_flux  rf ;

  af = prib->announce_queue->ex.head ;
  qassert(af != NULL) ;
  if (af == NULL)
    return NULL ;               /* no idea what else to do.     */

  rf = af->fifo.head ;
  if (rf != NULL)
    {
      /* There is at least one route_flux object associated with current head
       * of the announce_queue.
       *
       * So, that's assumed to be what we have just done announcing (!).
       *
       * Remove the route_flux object from the list, and stick it into mrai.
       *
       * The route_flux owns a lock on the attributes.  The attr_flux does not.
       * Having detached from the attr_flux, we set route_flux 'pending' to
       * point at the
       * 'pending' by the attr_set pointer.
       */
      ddl_del_head(af->fifo, list) ;

      bgp_adj_out_set_mrai(prib, rf, af->attr) ;
    }
  else
    {
      /* Since we claim we have just announced a prefix, really do NOT expect
       * either the af->fifo to be empty or for this to actually be an EoR !!
       *
       * (If it is EoR we are about to lose it !)
       */
      qassert(rf != NULL) ;
      qassert(af != prib->eor) ;
    } ;

  /* Now return the next announcement for this attr_flux or release it.
   */
  return bgp_adj_out_ret_next_announce(prib, parcel, af) ;
} ;

/*------------------------------------------------------------------------------
 * Update prib because have just sent EoR which is the current head of the
 * announce_queue queue.
 *
 * Returns:  NULL
 */
extern route_out_parcel
bgp_adj_out_done_eor(bgp_prib prib)
{
  attr_flux   af ;

  af = prib->announce_queue->ex.head ;
  qassert(af != NULL) ;
  if (af == NULL)
    return NULL ;                       /* no idea what else to do.     */

  qassert(af->fifo.head == NULL) ;
  qassert(af == prib->eor) ;
  qassert((af->attr == NULL) &&
                  (((((adj_out)af)->bits >> aob_type_shift) & aob_type_mask)
                                                                  == aob_eor)) ;

  pfifo_item_next_ex(prib->announce_queue) ;

  prib->eor_sent = true ;

  XFREE(MTYPE_BGP_ATTR_FLUX, prib->eor) ;       /* prib->eor = NULL     */

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Will never be able to announce the given route -- does not fit in an UPDATE.
 *
 * Treat as withdraw if ra_out_update.
 *
 * Fills in and returns the given parcel iff there is another prefix to
 * announce with the same attributes as the one just done.
 *
 * Returns:  NULL => nothing else to announce with the same attributes.
 *       or: address of parcel with next thing to announce filled in
 *
 * NB: the given parcel may or may not be the same as the last one given to
 *     bgp_adj_out_next_update/_done_announce()
 */
extern route_out_parcel
bgp_adj_out_done_no_announce(bgp_prib prib, route_out_parcel parcel)
{
  attr_flux   af ;
  route_flux  rf ;

  af = prib->announce_queue->ex.head ;
  qassert(af != NULL) ;
  if (af == NULL)
    return NULL ;               /* no idea what else to do.     */

  rf = af->fifo.head ;
  if (rf != NULL)
    {
      /* We need to treat the announcement as a withdraw.
       *
       * Clear the rf's reference to the af, and since we no longer need the
       * attributes, undo the lock on those.
       */
      ddl_del_head(af->fifo, list) ;
      bgp_attr_unlock(af->attr) ;

      rf->pending.anon = NULL ;

      /* Now withdraw or revert to steady (nothing announced) state.
       */
      if (rf->current != NULL)
        {
          rf->bits = (rf_act_withdraw << aob_action_shift) | aob_flux ;
          ddl_append(prib->withdraw_queue, rf, list) ;
        }
      else
        {
          bgp_adj_out_set_steady(prib, rf) ;
        } ;
    }
  else
    {
      /* Since we claim we have just tried to announce a prefix, really do NOT
       * expect either the af->fifo to be empty or for this to actually be an
       * EoR !!
       *
       * (If it is EoR we are about to lose it !)
       */
      qassert(rf != NULL) ;
      qassert(af != prib->eor) ;
    } ;

  /* Now return the next announcement for this attr_flux or release it.
   */
  return bgp_adj_out_ret_next_announce(prib, parcel, af) ;
} ;

/*------------------------------------------------------------------------------
 * If there is anything on the given attr_flux fifo, return it, otherwise
 *                                                        dequeue the attr_flux.
 *
 * NB: this is for attr_flux which is NOT an EoR !
 */
static route_out_parcel
bgp_adj_out_ret_next_announce(bgp_prib prib, route_out_parcel parcel,
                                                                   attr_flux af)
{
  route_flux rf ;

  rf = af->fifo.head ;
  if (rf != NULL)
    return bgp_adj_out_ret_announce(prib, parcel, af, rf) ;

  qassert(af != prib->eor) ;

  return bgp_adj_out_announce_dequeue(prib, af) ;
} ;

/*------------------------------------------------------------------------------
 * The attr_flux fifo is empty, so we can de-queue and discard it.
 *
 * Note that the attr_flux does not have a lock on the attr, so no need
 * to worry about that.
 *
 * Returns:  NULL
 */
static route_out_parcel
bgp_adj_out_announce_dequeue(bgp_prib prib, attr_flux af)
{
  attr_flux afx ;

  qassert(af->fifo.head == NULL) ;

  afx = pfifo_item_next_ex(prib->announce_queue) ;
  qassert(af == afx) ;

  bgp_attr_flux_free(prib, afx) ;

  return NULL ;
} ;

/*==============================================================================
 * The attr_flux objects are held in a vhash.  Each peer has a vhash, one
 * for each peer_rib in use.
 *
 * Each attr_flux holds a pointer to an attribute set.  Hung off the attr_flux
 * are all the route_flux objects for pending update advertisements that share
 * the attribute set.
 *
 * A attr_flux object exists only while there is a pending advertisement
 * which uses the attribute set it refers to.
 *
 * Note that no "orphan" function is required, because the attr_flux vhash
 * does not use any reference count.
 */
static vhash_hash_t bgp_attr_flux_hash(vhash_data_c data) ;
static int          bgp_attr_flux_equal(vhash_item_c item, vhash_data_c data) ;
static vhash_item   bgp_attr_flux_vhash_new(vhash_table table,
                                                            vhash_data_c data) ;
static vhash_item   bgp_attr_flux_vhash_free(vhash_item item,
                                                            vhash_table table) ;
static const vhash_params_t bgp_attr_flux_vhash_params =
{
    .hash       = bgp_attr_flux_hash,
    .equal      = bgp_attr_flux_equal,
    .new        = bgp_attr_flux_vhash_new,
    .free       = bgp_attr_flux_vhash_free,
    .orphan     = vhash_orphan_null,
    .table_free = vhash_table_free_simple,
} ;

/*------------------------------------------------------------------------------
 * Create a new attr_flux hash
 */
static vhash_table
bgp_attr_flux_hash_new(bgp_prib prib)
{
  return vhash_table_new(prib, 500 /* chain bases */,
                               200 /* % density   */,
                                                  &bgp_attr_flux_vhash_params) ;
} ;

/*------------------------------------------------------------------------------
 * Close an attr_flux_hash -- if any
 *
 * This is done when the owning peer's adj_out is being dismantled, *after*
 * the announce_queue queue has been emptied out.
 *
 * If the table is not empty, any items in it will be 'held', and that is
 * handled in bgp_attr_flux_vhash_free(), below: by leaving the object as an
 * orphan (but leaking memory).
 *
 * Once the table has been reset and the vhash table object freed, the pointer
 * to it must be set to NULL.  In the (impossible) event that any bgp_attr_flux
 * objects were to remain (as orphans), the NULL table pointer means that any
 * future attempt to free those would be safe (but empty, and leaking memory).
 *
 * The attr_flux_hash does not use the reference count, so it is also
 * "impossible" for orphans to be created by that means -- but the same would
 * apply to any such orphans.
 */
static vhash_table
bgp_attr_flux_hash_delete(vhash_table af_hash)
{
  return vhash_table_reset(af_hash) ;
} ;

/*------------------------------------------------------------------------------
 * Ensure attr_flux_hash is empty -- if any
 *
 * This is done when the owning peer's adj_out is being set 'stale', *after*
 * the announce_queue queue has been emptied out.
 *
 * This should be a null operation, but ensures that the table is emptied out,
 * even if that leaks a little memory.
 */
static void
bgp_attr_flux_hash_flush(vhash_table af_hash)
{
  vhash_table_ream(af_hash) ;
  vhash_table_reset_bases(af_hash, 0) ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: hash the given data
 *
 * The 'data' is the address of the attribute set in question.
 */
static vhash_hash_t
bgp_attr_flux_hash(vhash_data_c data)
{
  return vhash_hash_address(data) ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: is given item's data == the given data ?
 *
 * The 'item' is a attr_flux object.  The 'data' is an attribute set.
 */
static int
bgp_attr_flux_equal(vhash_item_c item, vhash_data_c data)
{
  attr_flux_c a = item ;
  attr_set_c  b = data ;

  return (a->attr == b) ? 0 : 1 ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: create a new item
 *
 * The 'data' is an attribute set.
 *
 * We create a new structure and set.
 */
static vhash_item
bgp_attr_flux_vhash_new(vhash_table table, vhash_data_c data)
{
  attr_flux  new ;

  new = XCALLOC(MTYPE_BGP_ATTR_FLUX, sizeof(attr_flux_t)) ;

  /* Zeroising has set:
   *
   *   * vhash            -- all zero, not that it matters
   *
   *   * attr             -- NULL   -- signals that this is a new item
   *
   *   * list             -- NULLs  -- not on any list, yet.
   *
   *   * fifo             -- NULLs  -- nothing on the fifo, yet
   */
  return new ;
} ;

/*------------------------------------------------------------------------------
 * vhash call-back: free an item
 *
 * The 'item' is a attr_flux object, which has been unset.
 *
 * This is done in bgp_attr_flux_free() only when the 'fifo' is empty.
 *
 * By the time vhash_table_reset() is called by bgp_attr_flux_hash_delete() the
 * vhash will have been emptied out, so this will not be called.
 *
 * So: in theory nothing can be pointing at the item which we are about to
 * free.  However, if the attr_flux object is still 'held' -- which it will
 * be if this is called during bgp_attr_flux_hash_delete() -- we do not
 * actually free the object.  This may leak memory, but will avoid being
 * tripped up by dangling reference(s).  Note that bgp_attr_flux_hash_delete()
 * frees the vhash table structure, so that any future "drop" of the object
 * is safe (but empty).
 *
 * The attr_flux object does not use the reference count, and in any case
 * this would not be called if the reference count were not zero.  But, we only
 * actually free the item if it is not 'held' and the reference count is zero.
 *
 * Returns:  NULL <=> the item has been freed
 *
 *
 */
static vhash_item
bgp_attr_flux_vhash_free(vhash_item item, vhash_table table)
{
  attr_flux af = item ;

  qassert(af->fifo.head == NULL) ;
  qassert(af->attr      == NULL) ;

  if (vhash_is_unused(item))
    XFREE (MTYPE_BGP_ATTR_FLUX, af) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Free the given attr_flux.
 */
static void
bgp_attr_flux_free(bgp_prib prib, attr_flux af)
{
  af->attr = NULL ;                     /* tidy                 */
  af->vhash.ref_count = aob_attr_flux ; /* discard times        */
  vhash_drop(af, prib->attr_flux_hash) ;
} ;
