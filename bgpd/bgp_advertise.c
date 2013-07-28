/* BGP advertisement and adjacency
   Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "thread.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer.h"
#include "bgpd/bgp_rib.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"

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
    .hash   = bgp_attr_flux_hash,
    .equal  = bgp_attr_flux_equal,
    .new    = bgp_attr_flux_vhash_new,
    .free   = bgp_attr_flux_vhash_free,
    .orphan = vhash_orphan_null,
} ;

/*------------------------------------------------------------------------------
 * Create a new adv_attr hash
 */
static vhash_table
bgp_attr_flux_hash_new(void)
{
  return vhash_table_new(NULL, 500 /* chain bases */,
                               200 /* % density   */,
                                                  &bgp_attr_flux_vhash_params) ;
} ;

/*------------------------------------------------------------------------------
 * Close an adv_attr_hash -- if any
 *
 * This is done when the owning peer is being dismantled, *after* the peer's
 * peer->adv_fifo[] has been emptied -- which means that the related
 * adv_attr_hash[qafx] *should* be empty by the time we get here.
 *
 * If the table is not empty, any items in it will be "set", and that is
 * handled in bgp_attr_flux_vhash_free(), below: by leaving the object as an
 * orphan (but leaking memory).
 *
 * Once the table has been reset and the vhash table object freed, the pointer
 * to it must be set to NULL.  In the (impossible) event that any bgp_attr_flux
 * objects were to remain (as orphans), the NULL table pointer means that any
 * future attempt to free those would be safe (but empty, and leaking memory).
 *
 * The adv_attr_hash does not use the reference count, so it is also
 * "impossible" for orphans to be created by that means -- but the same would
 * apply to any such orphans.
 */
static vhash_table
bgp_attr_flux_hash_delete(vhash_table adv_attr_hash)
{
  return vhash_table_reset(adv_attr_hash, free_it) ;
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
 * This is done in bgp_attr_flux_del() only when the 'fifo' is empty.
 *
 * By the time vhash_table_reset() is called by bgp_attr_flux_hash_delete() the
 * vhash will have been emptied out, so this will not be called.
 *
 * So: in theory nothing can be pointing at the item which we are about to
 * free.  However, if the attr_flux object is still "set" -- which it will
 * be if this is called during bgp_attr_flux_hash_delete() -- we do not
 * actually free the object.  This may leak memory, but will avoid being
 * tripped up by dangling reference(s).  Note that bgp_attr_flux_hash_delete()
 * frees the vhash table structure, so that any future "unset" of the object
 * is safe (but empty).
 *
 * The attr_flux object does not use the reference count, and in any case
 * this would not be called if the reference count were not zero.  But, we only
 * actually free the item if it is not "set" and the reference count is zero.
 *
 * Returns:  NULL <=> the item has been freed
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
 *
 * Returns:  the attribute set associated with the attr_flux.
 */
static attr_set
bgp_attr_flux_free(peer_rib prib, attr_flux af)
{
  attr_set attr ;

  attr = af->attr ;

  af->attr = NULL ;                     /* tidy                 */
  af->vhash.ref_count = aob_attr_flux ; /* discard times        */
  vhash_unset(af, prib->adv_attr_hash) ;

  return attr ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Add given route_flux to list of advertisements which share the given
 * attribute set.
 *
 * If required, creates a new attr_flux object to hang the route_flux object
 * on.
 *
 * If the attr_flux object's fifo is empty, append the attr_flux object to
 * the prib->fifo_announce.
 */
static attr_flux
bgp_attr_flux_add(peer_rib prib, route_flux rf, attr_set attr, route_mpls mpls)
{
  attr_flux  af ;
  bool       added ;

  added = false ;
  af = vhash_lookup(prib->adv_attr_hash, attr, &added) ;

  if (added)
    {
      /* The newly created attr_flux is now set to point at the attributes.
       *
       * which are, therefore, locked.
       */
      af->attr = bgp_attr_lock(attr) ;
      vhash_set(af) ;
    } ;

  if (ddl_head(af->fifo) == NULL)
    ddl_append(prib->fifo_announce, af, list) ;

  ddl_append(af->fifo, rf, list) ;

  return af ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given route_flux object from the list of advertisements which
 * share the same attribute set.
 *
 * If this bgp_adv object is the last to use the attribute set, unset the
 * pointer in the attr_flux object -- which will remove it from the hash.
 *
 * NB: unless the caller has their own lock on the attributes, there is an
 *     (outside) chance that the attribute set may suddenly and silently
 *     vanish.
 *
 * Returns:  NULL
 */
static attr_set
bgp_attr_flux_del(peer_rib prib, route_flux rf, attr_flux af)
{
  ddl_del(af->fifo, rf, list) ;

  if (ddl_head(af->fifo) == NULL)
    {
      ddl_del(prib->fifo_announce, af, list) ;
      af->attr = bgp_attr_unlock(af->attr) ;    /* tidy         */
      vhash_unset(af, prib->adv_attr_hash) ;
    } ;

  return NULL ;
} ;

/*==============================================================================
 *
 */
/*------------------------------------------------------------------------------
 * Create a new bgp_adv object in the given bgp_adj_out.
 *
 * Sets:   ao, type and qafx
 *
 * Leaves: aa & ri NULL
 *
 * Points 'parent' bgp_adj_out (ao) at the new bgp_adv.
 */
static bgp_adv
bgp_adv_new(bgp_adj_out ao, bgp_adv_type_t type, qafx_t qafx)
{
  bgp_adv adv ;

  adv = XCALLOC(MTYPE_BGP_ADV, sizeof(bgp_adv_t)) ;

  /* Zeroising has set:
   *
   *   * type           -- X       -- set below
   *   * qafx           -- X       -- set below
   *
   *   * fifo           -- NULLs   -- list pointers, tidy
   *
   *   * aa             -- NULL    -- no bgp_adv_attr
   *   * alist          -- NULLs   -- list pointers, tidy
   *
   *   * ao             -- X       -- set, below
   *
   *   * ri             -- NULL    -- no bgp_info set, yet
   */
  qassert((type < bgp_adv_count) && (qafx < qafx_count)) ;

  adv->type = type ;
  adv->qafx = qafx ;
  adv->ao   = ao ;

  qassert(ao->adv == NULL) ;

  return ao->adv = adv ;
} ;

/*------------------------------------------------------------------------------
 * Flush the given scheduled advertisement:
 *
 *   * if has bgp_adv_attr (aa), discard (removing the bgp_adv from the list
 *     of users of the attribute set.  It is possible that the bgp_adv_attr
 *     and the attribute set itself will now vanish.
 *
 *   * if has bgp_info (ri), discard
 *
 *     the ri pointer holds a lock on the bgp_info object, which is unlocked
 *     here.
 */
static void
bgp_adv_flush(bgp_adv adv)
{
  if (adv->aa != NULL)
    adv->aa = bgp_adv_attr_del(adv) ;

  if (adv->ri != NULL)
    adv->ri = bgp_info_unlock (adv->ri) ;
} ;

/*------------------------------------------------------------------------------
 * Change the given *existing* and *scheduled* bgp_adv:
 *
 *   * flushes the bgp_adv -- see above
 *
 *   * if is not of the required type:
 *
 *     move from the current peer->adv_fifo to the required peer->adv_fifo,
 *     and update the type.
 *
 * The effect is that any aa and ri are reset, but if an update was scheduled
 * for this prefix, a newer update will be scheduled at the same time as the
 * previous one.  TODO .... per peer/prefix update scheduling ???.....................
 */
static void
bgp_adv_change(bgp_adv adv, bgp_adv_type_t type)
{
  qassert((adv->ao != NULL) && (adv->ao->adv == adv)) ;

  bgp_adv_flush(adv) ;

  if (adv->type != type)
    {
      bgp_peer peer ;

      peer = adv->ao->peer ;

      bgp_adv_fifo_del(peer, adv) ;
      adv->type = type ;
      bgp_adv_fifo_add(peer, adv) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the next bgp_adv object on the list of those which share the same set
 * of attributes as the given bgp_adv.
 *
 * Returns:  a bgp_adv object if there is one
 *           NULL if there are no other bgp_adv with the same attributes
 */
extern bgp_adv
bgp_adv_next_by_attr(bgp_adv adv)
{
  bgp_adv  next ;

  next = ddl_next(adv, alist) ;

  if (next != NULL)
    return next ;

  next = ddl_head(adv->aa->abase) ;
  if (next != adv)
    return next ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Delete the given scheduled advertisement.
 *
 *   * flushes the bgp_adv -- see above
 *
 *   * remove from the peer->adv_fifo
 *
 *   * unlink from the related bgp_adj_out
 *
 *   * free the object
 *
 * Returns:  NULL
 */
extern bgp_adv
bgp_adv_delete(bgp_adv adv)
{
  bgp_adj_out ao ;

  ao = adv->ao ;

  qassert((ao != NULL) && (ao->adv == adv)) ;

  bgp_adv_flush(adv) ;

  bgp_adv_fifo_del(ao->peer, adv) ;

  XFREE(MTYPE_BGP_ADV, adv) ;

  return ao->adv = NULL ;
} ;

/*------------------------------------------------------------------------------
 * BGP adjacency keeps minimal advertisement information.
 *
 * Returns:  true <=> there is an outstanding 'update' announcement scheduled.
 *                 or we have sent an 'update'
 *
 *           false => there is no adj_out for this peer for the given prefix
 *                 or a 'withdraw' announcement has been scheduled
 *                 or a 'withdraw' announcement has been sent
 *                 or no announcement has ever been sent
 *
 * Generally, once a withdraw has been sent, and before any announcements have
 * been sent, there will be no bgp_adj_out object for the peer and prefix.
 */
extern bool
bgp_adj_out_lookup (bgp_peer peer, bgp_node rn)
{
  bgp_adj_out ao;

  ao = rn->adj_out;

  while (ao != NULL)
    {
      if (ao->peer == peer)
        {
          if (ao->adv != NULL)
            return (ao->adv->aa   != NULL) ;
          else
            return (ao->attr_sent != NULL) ;
        } ;

      ao = ao->adj.next ;
    } ;

  return false ;
} ;


#endif

/*==============================================================================
 * The adj_out spaghetti.
 *
 *   adj_out                                     attr_set
 *   *-->+->------------>+---+->------------>+-->+---------+
 *       |               ^   |               ^   |         |
 *       |  route_flux   |   |  route_mpls   |   .         .
 *       +->+---------+  |   +->+---------+  |   |         |
 *          | current-|->+   |  | atp-----|->+   +---------+
 *          .         .      |  |         |
 *          | pending-|->+   |  +---------+
 *          .         .  |   |
 *          +---------+  |   *->NULL
 *                       |                                       attr_set
 *                       +->------------>+---+->------------>+-->+---------+
 *                       |               |   |               ^   |         |
 *                       |  route_mpls   |   |  attr_flux    |   .         .
 *                       +->+---------+  |   +->+---------+  |   |         |
 *                          | atp-----|->+   |  | attr----|->+   +---------+
 *                          |         |      |  |         |
 *                          +---------+      |  +---------+
 *                                           |
 *                                           *->NULL
 *
 * Note that adj_out and rf->current are NULL for withdrawn (or never announced)
 * for ordinary and MPLS prefixes.  While rf->pending always points to a
 * route_mpls for MPLS, and its atp is NULL for withdraw pending.
 *
 * The fifo_batch and withdraw_queue queues are queues of route_flux objects.
 * The announce_queue queue is a queue of attr_flux objects.  Each attr_flux
 * object has a queue of route_flux objects.
 *
 * The adj_out owns a lock on the current attr_set (if any) -- which it points
 * to either directly or via a route_flux and/or route_mpls.
 *
 * The rf->pending owns a lock on the pending attr_set (if any) -- which it
 * points to either directly or via a route_mpls and/or attr_flux.   Note that
 * the attr_flux does *not* have a lock.
 *
 * This means that when a route_flux object is created, the then adj_out
 * pointer can simply be moved to rf->current.  Similarly, when an update is
 * sent, rf->pending can be moved to rf->current, and when the route_flux is
 * discarded, rf->current becomes the adj_out pointer.
 *
 */
static void bgp_adj_out_revert_batch(peer_rib prib, route_flux rf) ;
static void bgp_adj_out_revert_withdraw(peer_rib prib, route_flux rf) ;
static void bgp_adj_out_revert_announce(peer_rib prib, route_flux rf) ;
static void bgp_adj_out_set_steady(peer_rib prib, route_flux rf) ;

static void bgp_adj_out_change_batch(peer_rib prib, route_flux rf,
                                               attr_set attr, route_mpls mpls) ;
static void bgp_adj_out_change_withdraw(peer_rib prib, route_flux rf,
                                               attr_set attr, route_mpls mpls) ;
static void bgp_adj_out_change_announce(peer_rib prib, route_flux rf,
                                               attr_set attr, route_mpls mpls) ;
static void bgp_adj_out_change_mrai(peer_rib prib, route_flux rf,
                                               attr_set attr, route_mpls mpls) ;

static void bgp_adj_out_cancel_mrai_withdraw(peer_rib prib, route_flux rf) ;

static void bgp_adj_out_add_announce(peer_rib prib, route_flux rf,
                                               attr_set attr, route_mpls mpls) ;
static attr_set bgp_adj_out_del_announce(peer_rib prib, route_flux rf,
                                                                 attr_flux af) ;

inline static pfifo_period_t bgp_adj_out_set_now(peer_rib prib) ;

static pfifo_period_t bgp_adj_out_get_st(peer_rib prib, adj_out ao) ;
static void bgp_adj_out_set_st(adj_out ao, pfifo_period_t st,
                                                            pfifo_period_t dl) ;
static pfifo_period_t bgp_adj_out_get_dl(adj_out ao, pfifo_period_t st) ;
static void bgp_adj_out_set_dl(adj_out ao, pfifo_period_t dl,
                                                            pfifo_period_t st) ;










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
 * Where a prefix is unchanged for at least MRAI since the last update was
 * sent (if any) ("steady state"), this Quagga will:
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
 *     MRAI / 2.
 *
 *     For this Quagga, for iBGP batch-delay + aggregation-delay is 2.5 secs,
 *     which is MRAI/2 !  But for eBGP it is 5 secs, which is rather faster
 *     than 15 seconds.  In both cases the delay is more predictable.
 *
 *     Note that there is some analysis which suggests that an MRAI of 30
 *     seconds is too long for eBGP and that 15 or less would be a reasonable
 *     alternative.  There is also some analysis which suggests that WRATE
 *     is bad -- at least where the MRAI is too big.
 *
 *   * Note that each change causes the batch-delay to be restarted, until the
 *     total delay reaches MRAI + batch-delay, at which point the current state
 *     is dispatched, whatever it is.
 *
 *     This is consistent with the RFC, which requires a "constant upper bound"
 *     on the MRAI -- in this case MRAI * 2.
 *
 * At this point, the two times associated with a scheduled item can be
 * described:
 *
 *   * schedule-time -- this is held in 0.268 second units, in 12 bits.
 *
 *     When the schedule-time is set, it is simply the LS 12 bits of the
 *     current adj-out period timer, plus the required delay.
 *
 *     When a schedule-time is read, the MS bits of the current adj-out period
 *     timer are added to the 12 bit value, if the result is greater than the
 *     current adj-out period time, then 2^12 is subtracted.
 *
 *     12 bits at 0.268 periods is >18 minutes -- so if there is a very long
 *     delay in processing, then the schedule-times will be invalid.  The code
 *     checks for this, and flushes those queues if it has been >9 minutes
 *     since the last operation on the queue.
 *
 *   * delta-time -- held in 0.268 second units, in 8 bits.
 *
 *     Subtracting this from the schedule-time gives the start of the current
 *     schedule -- which can be used to reschedule an item.
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
 * Note that the batch-delay is fixed -- it does not restart if any further
 * changes occur.  Whatever the state is when the batch-delay expires, that is
 * the state which will be dispatched.  If the state changes again before the
 * update can be sent, then what is dispatched changes -- so the update
 * contains the latest state at that time.  It is tempting to consider a
 * rolling batch-delay -- so that a change is not dispatched until the prefix
 * has been stable for some time.  Apart from the complexity, it is not clear
 * whether that should be open-ended or subject to some maximum.  It cannot
 * be open ended, because
 *
 * When an update is dispatched its schedule-time is set to the then current
 * time plus aggregate-delay, and is placed on one of two queues:
 *
 *   a) withdraw queue.
 *
 *      this is emptied by the I/O process, just as quickly as is possible.
 *
 *      If an announce rolls up, it is moved to the announce queue, using the
 *      schedule-time -- unless that restores the original attribute state, in
 *      which case the prefix reverts to the steady state.
 *
 *   b) announce queue
 *
 *      here we wish to aggregate updates which use the same attributes, for
 *      which there is a secondary scheduling process, based on the attributes.
 *
 *      The announce queue is populated by 'attr_flux' objects.  Each one has
 *      one or more prefixes attached to it, and those will appear together
 *      in an update message, if at all possible.  Each one has a schedule-
 *      time, which is handled in the same way as for the batch queue.
 *
 *        aggregation-delay = ~1 sec for iBGP, cBGP
 *                            ~2 sec for eBGP
 *
 *      When the first route_flush with a given set of attributes is dispatched,
 *      an attr_flux object is created, and it is added to the announce queue,
 *      with the route_flush's schedule-time.
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
 *      queue.
 *
 *    * if this is an announce for a set of attributes not in use already,
 *      creates a new attr_flux and queue it according to the route_flux's
 *      schedule-time.
 *
 *    * if this is an announce for a set of attributes which are already
 *      queued, then:
 *
 *          i) if the schedule-time for that set is less than the
 *             schedule-time for the route_flux, then the route_flux
 *             effectively inherits the attr_flux's schedule-time.
 *
 *         ii) if the schedule-time for that set is greater than the
 *             schedule-time for the route_flux, then the attr_flux's
 *             schedule-time is reduced.
 *
 *      Note that the schedule-time for a route_flux or an attr_flux can only
 *      go down.  When or if a route_flux moves from one attr_flux to another,
 *      it might be nice if the attr_flux's schedule-time changed to the
 *      minimum of the remaining route_flux, but that requires potentially a
 *      lot of work -- if many prefixes share the same attributes.  This is
 *      a fringe case... so not worth more work.
 *
 *      If the previous attr_flux no longer has any associated prefixes, it is
 *      de-queued.
 *
 * When an update is sent, the prefix enters a cooling-off period -- the MRAI.
 * During MRAI a route_flux object sits on the batch queue, with a schedule-
 * time of the update time + MRAI - batch-delay, marked aob_mrai.  At the end
 * of the MRAI, the prefix will return to steady state, unless a change is
 * pending, in which case it will be re-queued with the batch-delay.  If a
 * change arrives while awaiting MRAI:
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
bgp_adj_out_update (bgp_peer peer, prefix_id_entry pie, attr_set attr,
                                                qafx_t qafx, mpls_tags_t tag)
{
  void*         ao ;
  peer_rib      prib ;
  route_flux    rf ;
  route_mpls    mpls ;
  attr_flux     af ;
  adj_out_type_t type ;
  route_out_action_t action ;
  attr_set      attr_pending ;
  bool          revert, change ;
  pfifo_period_t st ;

  /* Look up the relevant adj_out and set our current period
   */
  prib = peer->prib[qafx] ;

  if (prib == NULL)                     /* for safety ! */
    return ;

  qassert(prib->qafx == qafx) ;         /* hoho         */

  ao = ihash_get_item(prib->adj_out, pie->id) ;

  bgp_adj_out_set_now(prib) ;

  /* Discover whether we are in steady state or in flux.
   *
   * If we are in steady state, clear that -- but keep any route_mpls.  Fall
   * through to create new flux state.
   *
   * If not in steady state, ....
   */
  type = (ao != NULL) ? ((adj_out)ao)->bits & aob_type_mask : aob_null ;

  switch (type)
    {
      /* We are not in steady state.
       *
       * What we have in our hands is a route_flux object.  That may be:
       *
       *   ra_out_batch    -- waiting for the batch-delay to expire
       *                      before we dispatch the route_flux.
       *
       *   ra_out_withdraw -- waiting for the I/O to send a withdraw update
       *
       *   ra_out_announce -- waiting for the announce-delay to expire, or
       *                      for I/O to send an announce update.
       *
       *   ra_out_mrai     -- waiting for the MRAI to expire before we
       *                      either dispatch the route_flux or set it
       *                      back to steady state.
       *
       * NB: a attr_pending state of NULL <=> a withdraw is attr_pending, except when
       *     aob_mrai_wait -- which is set only in ra_out_mrai, and means that
       *     nothing is attr_pending, is just waiting for MRAI to expire.
       */
      case aob_flux:
        rf = ao ;
        action = (rf->bits >> aob_action_shift) & aob_action_mask ;

        mpls = NULL ;           /* assume not MPLS              */
        af   = NULL ;           /* assume not ra_out_announce   */

        if (!prib->is_mpls)
          {
            /* Not MPLS, so: rf->current is NULL or attr_set
             *               rf->attr_pending is NULL, or attr_set
             *                                    or attr_flux
             *
             * If we are in mrai, and no change is attr_pending, then rf->current
             * is NULL but aob_mrai_wait is set.
             */
            revert = attr == rf->current ;

            if (rf->bits & aob_withdraw)
              {
                qassert(rf->pending == NULL) ;

                attr_pending = NULL ;
                change  = (attr != NULL) || (rf->bits & aob_mrai_wait) ;
              }
            else
              {
                qassert(rf->pending != NULL) ;

                if (action == ra_out_announce)
                  {
                    af = (attr_flux)rf->pending ;
                    attr_pending = af->attr ;
                  }
                else
                  attr_pending = rf->pending ;

                change = attr != attr_pending ;
              } ;
          }
        else
          {
            /* is MPLS, so: rf->current is: route_mpls -> NULL
             *                                      or -> attr_set
             *                                      or -> attr_flux
             *              rf->attr_pending is: route_mpls -> NULL
             *                                      or -> attr_set
             *                                      or -> attr_flux
             *
             * If we are in mrai, and no change is attr_pending, then the route_mpls
             * points to NULL, is NULL but aob_mrai_wait is set.
             */
            qassert(rf->pfx_id == pie->id) ;

            mpls = rf->current ;
            revert = (attr == mpls->atp) && (tag == mpls->tag) ;

            mpls = rf->pending ;

            if (rf->bits & aob_withdraw)
              {
                qassert(mpls->atp == NULL) ;

                attr_pending = NULL ;
                change  = (attr != NULL) || (rf->bits & aob_mrai_wait) ;
              }
            else
              {
                qassert(mpls->atp != NULL) ;

                if (action == ra_out_announce)
                  {
                    af = (attr_flux)mpls->atp ;
                    attr_pending = af->attr ;
                  }
                else
                  attr_pending = mpls->atp ;

                change  = (attr != attr_pending) || (tag != mpls->tag) ;
              } ;
          } ;

        if (revert)
          {
            /* The requested change restores the prefix to its current
             * (advertised) state.
             *
             * Revert => change, but takes precedence !
             *
             * Discard any attr_pending state.
             *
             * If not MRAI, this will send the prefix back to steady state.
             *
             * For MRAI, leave where is, but set the aob_mrai_wait, which
             * indicates that is simply waiting for the MRAI to expire -- with
             * nothing attr_pending.
             */
            if (attr_pending != NULL)
              {
                qassert(((adj_out)attr_pending)->bits & aob_attr) ;

                if (af != NULL)
                  bgp_adj_out_del_announce(prib, rf, af) ;

                bgp_attr_unlock(attr_pending) ;
              } ;

            qassert(prib->is_mpls == (mpls != NULL)) ;

            if ((mpls != NULL) && (action != ra_out_mrai))
              XFREE(MTYPE_BGP_ROUTE_MPLS, mpls) ;       /* sets mpls NULL */

            switch (action)
              {
                case ra_out_batch:
                  bgp_adj_out_revert_batch(prib, rf) ;
                  break ;

                case ra_out_withdraw:
                  qassert(rf->bits & aob_withdraw) ;
                  bgp_adj_out_revert_withdraw(prib, rf) ;
                  break ;

                case ra_out_announce:
                  qassert(!(rf->bits & aob_withdraw)) ;
                  bgp_adj_out_revert_announce(prib, rf) ;
                  break ;

                case ra_out_mrai:
                  if (rf->bits & aob_withdraw)
                    bgp_adj_out_cancel_mrai_withdraw(prib, rf) ;

                  rf->bits |= aob_mrai_wait ;
                  break ;

                default:
                  break ;
              } ;
          }
        else if (change)
          {
            /* The requested change does change the attr_pending state.
             */
            if (attr_pending != NULL)
              {
                qassert(((adj_out)attr_pending)->bits & aob_attr) ;

                if (af != NULL)
                  bgp_adj_out_del_announce(prib, rf, af) ;

                bgp_attr_unlock(attr_pending) ;
              } ;

            qassert(prib->is_mpls == (mpls != NULL)) ;

            if (attr != NULL)
              bgp_attr_lock(attr) ;     /* about to save a copy of this */

            if (mpls != NULL)
              mpls->tag = tag ;         /* about to set this            */

            switch (action)
              {
                case ra_out_batch:
                  bgp_adj_out_change_batch(prib, rf, attr, mpls) ;
                  break ;

                case ra_out_withdraw:
                  bgp_adj_out_change_withdraw(prib, rf, attr, mpls) ;
                  break ;

                case ra_out_announce:
                  bgp_adj_out_change_announce(prib, rf, attr, mpls) ;
                  break ;

                case ra_out_mrai:
                  bgp_adj_out_change_mrai(prib, rf, attr, mpls) ;
                  break ;

                default:
                  break ;
              } ;
          } ;

          return ;

      /* Steady state -- with an mpls route
       *
       * If the request makes no difference, exit now.  Otherwise continue and
       * schedule a change.
       *
       * Note that in steady state we never have mpls->atp == NULL, because
       * that would imply a redundant route_mpls object !
       */
      case aob_mpls:
        qassert(prib->is_mpls) ;

        mpls = ao ;

        qassert(mpls->atp != NULL) ;
        qassert(((adj_out)mpls->atp)->bits & aob_attr) ;

        if ((mpls->atp == attr) && (mpls->tag == tag))
          return ;                      /* no actual change             */

        break ;

      /* Steady state -- prefix withdrawn (or never announced).
       *
       * If the request is withdraw, exit now.  Otherwise continue and
       * schedule a change.
       */
      case aob_null:
        if (attr == NULL)
          return ;                      /* no actual change             */

        break ;                         /* steady state, withdrawn      */

      /* Steady state -- with simple attribute set.
       *
       * If the request is withdraw, exit now.  Otherwise continue and
       * schedule a change.
       */
      default:
        if (!(type & aob_attr))
          {
            /* Unrecognised type
             */
            qassert(false) ;
            return ;                    /* safety                       */
          } ;

        qassert(!prib->is_mpls) ;

        if (ao == attr)
          return ;                      /* no actual change             */

        break ;                         /* steady state, announce change */
    } ;

  /* We are in steady state and we need to change.
   *
   * At this point:  ao    -- NULL <=> previously withdrawn
   *                          otherwise: either previous attr_set
   *                                         or previous route_mpls
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
   *  * list      -- NULLs
   *
   *  * pending   -- NULL   -- set as required, later
   */
  prefix_id_entry_inc_ref(pie) ;    /* About to store id in parcel  */

  rf->current = ao ;
  rf->pfx_id  = pie->id ;
  rf->bits    = (ra_out_batch << aob_action_shift) | aob_flux ;

  if (prib->is_mpls)
    {
      /* Zeroizing the route_mpls object sets:
       *
       *  * atp       -- NULL   -- set below, if not withdraw
       *  * tag       -- 0      -- set below, if not withdraw
       *  * bits      -- X      -- set below
       */
      mpls = XCALLOC(MTYPE_BGP_ROUTE_MPLS, sizeof(route_mpls_t)) ;

      if (attr == NULL)
        rf->bits |= aob_withdraw ;
      else
        {
          mpls->atp = bgp_attr_lock(attr) ;
          mpls->tag = tag ;
        } ;

      mpls->bits = aob_mpls ;

      rf->pending = mpls ;
    }
  else
    {
      if (attr == NULL)
        rf->bits |= aob_withdraw ;
      else
        rf->pending = bgp_attr_lock(attr) ;
    } ;

  /* Now schedule on the fifo_batch.
   *
   * Note that we schedule one period ahead of the current period -- rounds up.
   */
  st = prib->now + prib->batch_delay + 1 ;
  bgp_adj_out_set_st((adj_out)rf, st, prib->now + prib->batch_delay_max) ;
  pfifo_item_add(prib->fifo_batch, rf, st) ;

  /* Update the adj_out
   */
  ihash_set_item(prib->adj_out, pie->id, rf) ;

  return ;
} ;

/*------------------------------------------------------------------------------
 * Revert to steady state from the fifo_batch queue.
 */
static void
bgp_adj_out_revert_batch(peer_rib prib, route_flux rf)
{
  pfifo_item_del(prib->fifo_batch, rf, bgp_adj_out_get_st(prib, (adj_out)rf)) ;

  bgp_adj_out_set_steady(prib, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Revert to steady state from the withdraw_queue queue.
 */
static void
bgp_adj_out_revert_withdraw(peer_rib prib, route_flux rf)
{
  qassert(rf->current == NULL) ;

  ddl_del(prib->withdraw_queue, rf, list) ;

  bgp_adj_out_set_steady(prib, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Revert to steady state from the announce_queue queue.
 *
 * NB: already removed from the announce_queue queue by virtue of having
 *     discarded the pending announcement.
 */
static void
bgp_adj_out_revert_announce(peer_rib prib, route_flux rf)
{
  bgp_adj_out_set_steady(prib, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Set steady state from given route_flux and delete the route_flux.
 *
 * NB: if is setting NULL, does NOT remove the adj_out entry -- garbage
 *     collection will do that later.
 */
static void
bgp_adj_out_set_steady(peer_rib prib, route_flux rf)
{
  ihash_set_item(prib->adj_out, rf->pfx_id, rf->current) ;

  XFREE(MTYPE_BGP_ROUTE_FLUX, rf) ;
} ;

/*------------------------------------------------------------------------------
 * Change an ra_out_batch route_flux
 *
 * The rf->pending has been cleared, so can set that and then reschedule.
 *
 * NB: the given attr has been locked already, in preparation for this.
 *
 * NB: if mpls, then mpls->tag has been set already.
 */
static void
bgp_adj_out_change_batch(peer_rib prib, route_flux rf, attr_set attr,
                                                                route_mpls mpls)
{
  pfifo_period_t  nst, st, dl ;

  if (mpls == NULL)
    rf->pending = attr ;
  else
    {
      mpls->atp = attr ;
      rf->pending = mpls ;
    } ;

  nst = prib->now + prib->batch_delay + 1 ;
  st  = bgp_adj_out_get_st(prib, (adj_out)rf) ;
  dl  = bgp_adj_out_get_dl((adj_out)rf, st) ;

  if (nst > dl)
    nst = dl ;                          /* clamp to deadline    */

  if (nst != st)
    {
      pfifo_item_del(prib->fifo_batch, rf, st) ;
      bgp_adj_out_set_st((adj_out)rf, nst, dl) ;
      pfifo_item_add(prib->fifo_batch, rf, nst) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Change an ra_out_withdraw route_flux
 *
 * This means that before the I/O can send the dispatched withdraw, we get
 * an announcement to schedule instead !
 */
static void
bgp_adj_out_change_withdraw(peer_rib prib, route_flux rf, attr_set attr,
                                                                route_mpls mpls)
{
  qassert(attr != NULL) ;

  ddl_del(prib->withdraw_queue, rf, list) ;

  bgp_adj_out_add_announce(prib, rf, attr, mpls) ;
}

/*------------------------------------------------------------------------------
 * Change a ra_out_announce route_flux
 *
 * This means that before the I/O can send the dispatched announce, or before
 * the aggregation-delay expires, we receive a change in what to announce,
 * or a withdraw.
 *
 * NB: at this point, any previous pending announcement has been discarded.
 */
static void
bgp_adj_out_change_announce(peer_rib prib, route_flux rf, attr_set attr,
                                                                route_mpls mpls)
{
  if (attr == NULL)
    {
      rf->pending = mpls ;
      ddl_append(prib->withdraw_queue, rf, list) ;
    }
  else
    bgp_adj_out_add_announce(prib, rf, attr, mpls) ;
} ;

/*------------------------------------------------------------------------------
 * Change a ra_out_mrai route_flux
 *
 * This means that while we are waiting for the MRAI timer to expire, a change
 * arrives.
 *
 * There are three cases here:
 *
 *   1) a withdraw (must be nothing pending or announce pending)
 *
 *      We want to do the NO-WRATE stuff... so reschedule to the current
 *      time plus batch-delay so that, if the withdraw is well before the
 *      MRAI End, we have:
 *
 *         |<---------- MRAI ---------->|
 *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
 *         *--------w---a----+-*--------*
 *         ^        ^        ^ ^        ^
 *         |        |        | |        dead-line
 *         |        |        | MRAI end
 *         |        |        schedule-time for withdraw
 *         |        withdraw
 *         update-time
 *
 *      or, if the withdraw is within batch-delay of the MRAI End, we have:
 *
 *         |<---------- MRAI ---------->|
 *         |<--- MRAI - BD --->|<- BD ->|           (BD == batch-delay)
 *         *---------------w-a-*-b--+---*
 *         ^               ^   ^    ^   ^
 *         |               |   |    |   dead-line
 *         |               |   |    schedule-time for withdraw
 *         |               |   MRAI end
 *         |               withdraw
 *         update-time
 *
 *      So that if the schedule-time for withdraw arrives, the withdraw can be
 *      dispatched after the usual batch-delay.
 *
 *      If an announce arrives at 'a', that is, before the MRAI end, it the
 *      original MRAI end can be restored, and the announcement 'a' will be
 *      scheduled at MRAI end, as if the withdraw had never happened.
 *
 *      If an announce arrives at 'b', it can be scheduled in the usual way,
 *      as if the withdraw had not happened, and the announcement 'b' had
 *      occurred and the prefix had gone to steady state at MRAI end.
 *
 *   2) an announce when a withdraw is pending -- aob_mrai_withdraw
 *
 *      Extract the MRAI End from the dead-line, as described above.  If the
 *      announcement time is at or beyond the MRAI End, reschedule as at
 *      MRAI end.
 *
 *   3) announce when nothing or an announce is pending
 *
 * NB: at this point, any previous pending announcement has been discarded.
 */
static void
bgp_adj_out_change_mrai(peer_rib prib, route_flux rf, attr_set attr,
                                                                route_mpls mpls)
{
  /* Set the new pending value
   */
  if (mpls == NULL)
    rf->pending = attr ;
  else
    {
      mpls->atp = attr ;
      rf->pending = mpls ;
    } ;

  rf->bits &= ~aob_mrai_wait ;          /* have something pending       */

  /* If this is a withdraw -- schedule withdraw specially.
   *
   * If this is an announce --
   */
  if (attr == NULL)
    {
      /* Change to a withdraw -- cannot already be !
       *
       * We reschedule to now + batch-delay, unless that would be more than
       * or the same as the current mrai schedule.
       *
       *   nst = now + batch-delay + 1
       *   st  = current schedule-time (MRAI end)
       *   dl  = end of full MRAI
       *
       * Have set the new pending state, above.
       */
      pfifo_period_t  nst, st, dl ;

      qassert(!(rf->bits & aob_withdraw)) ;

      nst = prib->now + prib->batch_delay + 1 ;
      st  = bgp_adj_out_get_st(prib, (adj_out)rf) ;
      dl  = bgp_adj_out_get_dl((adj_out)rf, st) ; ;

      if (nst > dl)
        {
          /* This implies that the processing of the fifo_batch has fallen
           * behind, such that we are (literally) past MRAI.
           *
           * Reschedule as if had gone to steady state at the appointed time.
           */
          pfifo_item_del(prib->fifo_batch, rf, st) ;

          bgp_adj_out_batch_schedule(prib, rf, nst) ;
        }
      else
        {
          /* Reschedule, if required, setting the dead-line as the end of the
           * full MRAI delay.
           *
           * Mark as a pending withdraw while in MRAI.
           */
          if (nst != st)
            {
              pfifo_item_del(prib->fifo_batch, rf, st) ;
              bgp_adj_out_set_st((adj_out)rf, nst, dl) ;
              pfifo_item_add(prib->fifo_batch, rf, nst) ;
            } ;

          rf->bits |= aob_withdraw ;
        } ;
    }
  else
    {
      /* This is an announce -- not back to the advertised state.
       *
       * If there is a pending aob_mrai_withdraw, we cancel it and restore
       * the MRAI schedule-time.
       *
       * Have set the new pending state, above.
       */
      if (rf->bits & aob_withdraw)
        bgp_adj_out_cancel_mrai_withdraw(prib, rf) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Cancel pending MRAI withdraw.
 *
 * We reschedule to the original end of MRAI -- which we stored as the
 * dead-line, offset by the batch-delay.
 */
static void
bgp_adj_out_cancel_mrai_withdraw(peer_rib prib, route_flux rf)
{
  pfifo_period_t  nst, st, dl ;

  rf->bits &= ~aob_withdraw ;

  /* st  = schedule-time for the withdraw
   * dl  = end of full MRAI
   * nst = original end of MRAI
   */
  st  = bgp_adj_out_get_st(prib, (adj_out)rf) ;
  dl  = bgp_adj_out_get_dl((adj_out)rf, st) ;
  nst = dl - prib->batch_delay + 1 ;    /* rounding up  */

  pfifo_item_del(prib->fifo_batch, rf, st) ;
  bgp_adj_out_set_st((adj_out)rf, nst, dl) ;
  pfifo_item_add(prib->fifo_batch, rf, nst) ;
} ;

/*------------------------------------------------------------------------------
 * Add given route_flux to attr_flux, creating attr_flux if required.
 *
 * If the attr_flux already exists, reschedule to schedule-time for the
 * route-flux, if the route_flux has an earlier schedule-time.
 */
static void
bgp_adj_out_add_announce(peer_rib prib, route_flux rf, attr_set attr,
                                                                route_mpls mpls)
{
  pfifo_period_t  st ;
  attr_flux  af ;
  bool       added, schedule ;

  added = false ;
  af = vhash_lookup(prib->adv_attr_hash, attr, &added) ;

  if (added)
    {
      /* The newly created attr_flux points at the attr.  Note that the
       * route_flux is the owner of a lock on the attr -- the attr_flux does
       * does not need one.
       *
       * The attr_flux is "set" from a vhash perspective, until the fifo is
       * emptied...
       */
      af->attr = attr ;
      vhash_set(af) ;

      qassert(af->vhash.ref_count == aob_attr_flux) ;
    } ;

  st = bgp_adj_out_get_st(prib, (adj_out)rf) ;
  schedule = true ;

  if (ddl_head(af->fifo) != NULL)
    {
      pfifo_period_t ast ;

      ast = bgp_adj_out_get_st(prib, (adj_out)af) ;

      if (ast <= st)
        schedule = false ;
      else
        pfifo_item_del(prib->announce_queue, rf, ast) ;
    } ;

  if (schedule)
    {
      bgp_adj_out_set_st((adj_out)af, st, st) ;
      pfifo_item_add(prib->announce_queue, rf, st) ;
    } ;

  if (mpls == NULL)
    rf->pending = af ;
  else
    {
      qassert(rf->pending == mpls) ;
      mpls->atp = af ;
    } ;

  ddl_append(af->fifo, rf, list) ;
} ;

/*------------------------------------------------------------------------------
 * Delete given route_flux from the given attr_flux.
 *
 * If the attr_flux empties out, remove it from the announce_queue queue.
 *
 * Returns:  the attribute set associated with the route_flux.
 *
 * NB: the route_flux is the owner of a lock on the attribute set returned.
 */
static attr_set
bgp_adj_out_del_announce(peer_rib prib, route_flux rf, attr_flux af)
{
  pfifo_period_t ast ;

  ddl_del(af->fifo, rf, list) ;         /* take rf off the attr_flux    */

  if (ddl_head(af->fifo) != NULL)
    return af->attr ;

  ast = bgp_adj_out_get_st(prib, (adj_out)af) ;
  pfifo_item_del(prib->announce_queue, rf, ast) ;

  return bgp_attr_flux_free(prib, af) ;
} ;

/*------------------------------------------------------------------------------
 * Get the schedule-time from the given adj_out object
 */
static pfifo_period_t
bgp_adj_out_get_st(peer_rib prib, adj_out ao)
{
  pfifo_period_t period ;

  period = (prib->now & ~(pfifo_period_t)aob_time_mask) +
                                ((ao->bits >> aob_index_shift) & aob_time_mask) ;

  if (period > prib->now)
    period -= (pfifo_period_t)aob_time_mask + 1 ;

  return period ;
} ;

/*------------------------------------------------------------------------------
 * Get the dead-line from the given adj_out object
 *
 * The dead-line is the current (given) schedule-time plus the delta from the
 * adj_out object.
 */
static pfifo_period_t
bgp_adj_out_get_dl(adj_out ao, pfifo_period_t st)
{
  return st + ((ao->bits >> aob_delta_shift) & aob_delta_mask) ;
} ;

/*------------------------------------------------------------------------------
 * Set the schedule-time and dead-line in the given adj_out object
 */
static void
bgp_adj_out_set_st(adj_out ao, pfifo_period_t st, pfifo_period_t dl)
{
  adj_out_bits_t bits ;

  bits = ao->bits & ~( ((adj_out_bits_t)aob_time_mask  << aob_index_shift) |
                       ((adj_out_bits_t)aob_delta_mask << aob_delta_shift) ) ;

  bits = ao->bits & ~((adj_out_bits_t)aob_delta_mask << aob_delta_shift) ;

  if (dl > st)
    {
      pfifo_period_t delta ;

      delta = dl - st ;
      if (delta > aob_delta_mask)
        delta = aob_delta_mask ;

      bits |= (delta << aob_delta_shift) ;
    } ;

  ao->bits = bits | ((st & aob_time_mask) << aob_index_shift) ;
} ;

/*------------------------------------------------------------------------------
 * Set the dead-line in the given adj_out object.
 *
 * Stores the difference between the dead-line and the current (given)
 * schedule-time in the adj_out object delta.
 */
static void
bgp_adj_out_set_dl(adj_out ao, pfifo_period_t dl, pfifo_period_t st)
{
  adj_out_bits_t bits ;
  pfifo_period_t delta ;

  bits = ao->bits & ~((adj_out_bits_t)aob_delta_mask << aob_delta_shift) ;

  if (dl > st)
    {
      delta = dl - st ;
      if (delta > aob_delta_mask)
        delta = aob_delta_mask ;

      bits |= (delta << aob_delta_shift) ;
    } ;

  ao->bits = bits ;
} ;

/*==============================================================================
 * The adj_out timer(s), dispatch from fifo_batch and send updates from
 * withdraw_queue and announce_queue.
 *
 *
 *
 *
 *
 *
 */

static void bgp_adj_out_dispatch_withdraw(peer_rib prib, route_flux rf) ;
static void bgp_adj_out_dispatch_announce(peer_rib prib, route_flux rf) ;
static void bgp_adj_out_dispatch_batch(peer_rib prib, route_flux rf) ;

/*------------------------------------------------------------------------------
 * Dispatch from fifo_batch to withdraw_queue and announce_queue.
 *
 *
 */
extern void
bgp_adj_out_dispatch(peer_rib prib)
{
  route_flux rf_next ;

  /* set the
   *
   */
  bgp_adj_out_set_now(prib) ;

  rf_next = pfifo_take(prib->fifo_batch, prib->now + 1) ;

  if (rf_next != NULL)
    {
      route_flux rf ;

      ddl_init(prib->fifo_batch->ex) ;  /* empty the ex list    */

      do
        {
          rf      = rf_next ;
          rf_next = rf->list.next ;

          qassert(!(rf->bits & aob_attr) &&
                                     ((rf->bits & aob_type_mask) == aob_flux)) ;

          switch ((rf->bits >> aob_action_shift) & aob_action_mask)
            {
              /* If ra_out_batch, we are waiting:
               *
               *   * to be dispatched to withdraw_queue
               *
               *   * to be dispatched to announce_queue.
               */
              case ra_out_batch:
                if (rf->bits & aob_withdraw)
                  bgp_adj_out_dispatch_withdraw(prib, rf) ;
                else
                  bgp_adj_out_dispatch_announce(prib, rf) ;

                break ;

              /* If ra_out_mrai, we are waiting:
               *
               *   * to be dispatched to withdraw_queue
               *
               *   * to be rescheduled as ra_out_batch
               *
               *   * to be returned to steady state
               */
              case ra_out_mrai:
                if      (rf->bits & aob_withdraw)
                  bgp_adj_out_dispatch_withdraw(prib, rf) ;
                else if (rf->bits & aob_mrai_wait)
                  bgp_adj_out_set_steady(prib, rf) ;
                else
                  bgp_adj_out_dispatch_batch(prib, rf) ;

                break ;

              default:
                qassert(false) ;
                break ;
            } ;
        }
      while (rf_next != NULL) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch given route_flux to the withdraw_queue queue.
 *
 * We set schedule-time and dead-line, same like dispatch to announce_queue,
 * just in case an announce arrives before we have time to send the required
 * update (!).
 */
static void
bgp_adj_out_dispatch_withdraw(peer_rib prib, route_flux rf)
{
  pfifo_period_t st ;

  rf->bits = aob_flux | (ra_out_withdraw << aob_action_shift) ;

  st = prib->now + prib->announce_delay + 1 ;
  bgp_adj_out_set_st((adj_out)rf, st, st) ;

  ddl_append(prib->withdraw_queue, rf, list) ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch given route_flux to the announce_queue queue.
 *
 * Actually, dispatches to an attr_flux which is on the announce_queue
 * queue.
 *
 * We set schedule-time and dead-line, so can be rescheduled if changes while
 * waiting either for the end of the aggregation-delay, or for I/O.
 */
static void
bgp_adj_out_dispatch_announce(peer_rib prib, route_flux rf)
{
  attr_set       attr ;
  route_mpls     mpls ;
  pfifo_period_t st ;

  rf->bits = aob_flux | (ra_out_announce << aob_action_shift) ;

  st = prib->now + prib->announce_delay + 1 ;
  bgp_adj_out_set_st((adj_out)rf, st, st) ;

  if (prib->is_mpls)
    {
      mpls = rf->pending ;
      attr = mpls->atp ;
    }
  else
    {
      mpls = NULL ;
      attr = rf->pending ;
    } ;

  bgp_adj_out_add_announce(prib, rf, attr, mpls) ;
} ;

/*------------------------------------------------------------------------------
 * Dispatch given route_flux back to the fifo_batch queue.
 *
 * We set schedule-time and dead-line.
 */
static void
bgp_adj_out_dispatch_batch(peer_rib prib, route_flux rf)
{
  pfifo_period_t st ;

  rf->bits = aob_flux | (ra_out_batch << aob_action_shift) ;

  st = prib->now + prib->batch_delay + 1 ;
  bgp_adj_out_set_st((adj_out)rf, st, prib->now + prib->batch_delay_max) ;

  pfifo_item_add(prib->fifo_batch, rf, st) ;
} ;


/*==============================================================================
 * Interface for I/O -- pulling stuff from withdraw_queue and from
 * announce_queue and rescheduling for MRAI.
 *
 */

/*------------------------------------------------------------------------------
 * Get next prefix to withdraw and signal update sent for the previous prefix.
 *
 * The expected use is:
 *
 *    parcel = bgp_adj_out_next_withdraw(prib, &parcel_s) ;
 *
 *    while (parcel != NULL)
 *      {
 *        ... output withdraw update.
 *        ... break out of loop if cannot output
 *
 *        parcel = bgp_adj_out_done_withdraw(prib, &parcel_s)
 *      } ;
 *
 * Returns:  address of given route_out_parcel -- NULL <=> no withdraws pending
 *
 * NB: the prefix_id returned in the parcel is *not* locked.
 *
 *     If the caller wishes to keep the prefix_id beyond the call of
 *     bgp_adj_out_done_withdraw(), then they must obtain their own lock.
 *
 * NB: has NOT removed the returned prefix from the withdraw_queue queue.
 *
 *     So, if the caller is unable to send the required withdraw, can leave it
 *     for later -- though should not keep the route_out_parcel, because the
 *     route could change state.
 *
 * NB: having output the required update, bgp_adj_out_done_withdraw() MUST be
 *     called *immediately*, so that the prefix is taken off the
 *     withdraw_queue queue, and its state updated.
 *
 *     It is the callers responsibility to ensure that no other bgp_adj_out_xxx
 *     functions are called (for this peer_rib) between sending the update and
 *     updating the prib -- otherwise changes to the prefix may be lost !
 */
extern route_out_parcel
bgp_adj_out_next_withdraw(peer_rib prib, route_out_parcel parcel)
{
  route_flux rf ;

  rf = prib->withdraw_queue.head ;

  if (rf == NULL)
    return NULL ;

  memset(parcel, 0, sizeof(route_out_parcel_t)) ;

  parcel->pfx_id = rf->pfx_id ;
  parcel->qafx   = prib->qafx ;

  return parcel ;
} ;

/*------------------------------------------------------------------------------
 * Update prib because have just sent update for the current head of the
 * withdraw_queue queue -- return next withdrawn prefix, if any.
 *
 * See bgp_adj_out_next_withdraw().
 *
 * Returns:  address of given route_out_parcel -- NULL <=> no withdraws pending
 *
 * So... updates prib and returns the next to be withdrawn.  The caller may
 * ignore the returned value.
 *
 * NB: does NOT require the given parcel to be the same as the last one
 *     given to either bgp_adj_out_next_withdraw/_done_withdraw()
 */
extern route_out_parcel
bgp_adj_out_done_withdraw(peer_rib prib, route_out_parcel parcel)
{
  route_flux rf ;

  rf = prib->withdraw_queue.head ;

  if (rf == NULL)
    return NULL ;

  ddl_del_head(prib->withdraw_queue, list) ;
  bgp_adj_out_set_mrai(prib, rf) ;

  return bgp_adj_out_next_withdraw(prib, parcel) ;
} ;

/*------------------------------------------------------------------------------
 * Update the announce_queue scheduling, and return the first prefix
 * due for output -- if any.
 *
 * The expected use is:
 *
 *    parcel = bgp_adj_out_first_announce(prib, &parcel_s) ;
 *    attr   = NULL ;
 *    while (parcel != NULL)
 *      {
 *        ... output announce update -- with previous or new attributes.
 *        ... break out of loop if cannot output
 *
 *        parcel = bgp_adj_out_done_announce(prib, &parcel_s) ;
 *      } ;
 *
 * Returns:  address of given route_out_parcel -- NULL <=> no announce pending
 *
 * NB: the prefix_id and attr_set returned in the parcel are *not* locked.
 *
 *     If the caller wishes to keep the prefix_id and attr_set beyond the call
 *     of bgp_adj_out_done_announce(), then they must obtain their own locks.
 *
 * NB: has NOT removed the returned prefix from the announce_queue queue.
 *
 *     So, if the caller is unable to send the required update, can leave it
 *     for later -- though should not keep the route_out_parcel, because the
 *     prefix could change state.
 *
 * NB: having output the required update, bgp_adj_out_done_announce() MUST be
 *     called *immediately*, so that the prefix is taken off the
 *     announce_withdraw queue, and its state updated.
 *
 *     It is the callers responsibility to ensure that no other bgp_adj_out_xxx
 *     functions are called (for this peer_rib) between sending the update and
 *     updating the prib -- otherwise changes to the prefix may be lost !
 */
extern route_out_parcel
bgp_adj_out_first_announce(peer_rib prib, route_out_parcel parcel)
{
  bgp_adj_out_set_now(prib) ;

  pfifo_take(prib->fifo_batch, prib->now + 1) ;

  return bgp_adj_out_next_announce(prib, parcel) ;
} ;

/*------------------------------------------------------------------------------
 * Get next prefix to announce and signal update sent for the previous prefix.
 *
 * See bgp_adj_out_first_announce() above.
 *
 * If the given rf is not NULL, it MUST be the last rf to be returned by the
 * most recent call of bgp_adj_out_first_announce/_next_announce().
 *
 * Returns:  address of route_flux -- NULL <=> no announce pending
 */
extern route_out_parcel
bgp_adj_out_next_announce(peer_rib prib, route_out_parcel parcel)
{
  while (1)
    {
      attr_flux   af ;
      route_flux  rf ;

      af = prib->announce_queue->ex.head ;

      if (af == NULL)
        return NULL ;

      rf = af->fifo.head ;
      if (rf != NULL)
        {
          memset(parcel, 0, sizeof(route_out_parcel_t)) ;

          parcel->attr   = af->attr ;
          parcel->pfx_id = rf->pfx_id ;
          parcel->qafx   = prib->qafx ;

          if (prib->is_mpls)
            {
              route_mpls  mpls ;

              mpls = rf->pending ;
              qassert(mpls->atp == af) ;

              parcel->tag = mpls->tag ;
            }
          else
            {
              qassert(rf->pending == af) ;
            } ;

          return parcel ;
        } ;

      /* The attr_flux fifo is empty, so we can de-queue and discard it.
       *
       * Note that the attr_flux does not have a lock on the attr, so no need
       * to worry about that.
       */
      ddl_del_head(af->fifo, list) ;

      bgp_attr_flux_free(prib, af) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Update prib because have just sent update for the current head of the
 * announce_queue queue -- return next announced prefix, if any.
 *
 * See bgp_adj_out_next_announce().
 *
 * Returns:  address of given route_out_parcel -- NULL <=> no announce pending
 *
 * So... updates prib and returns the next to be announced.  The caller may
 * ignore the returned value.
 *
 * NB: does NOT require the given parcel to be the same as the last one
 *     given to bgp_adj_out_first_announce/_next_announce/_done_announce()
 */
extern route_out_parcel
bgp_adj_out_done_announce(peer_rib prib, route_out_parcel parcel)
{
  attr_flux   af ;
  route_flux  rf ;

  af = prib->announce_queue->ex.head ;

  if (af == NULL)
    return NULL ;

  rf = af->fifo.head ;

  if (rf != NULL)
    {
      ddl_del_head(af->fifo, list) ;
      bgp_adj_out_set_mrai(prib, rf) ;
    } ;

  return bgp_adj_out_next_announce(prib, parcel) ;
} ;

#if 0
/*------------------------------------------------------------------------------
 * Unset the adj_out for the given peer in the given node, if any.
 *
 * Note that we do not keep an adj_out we have withdrawn the ....
 *
 * The given 'ri' is the route selected for the given bgp_node.
 *
 * The given 'attr' are the attributes to be announced to the given peer, so
 * are the attributes after any 'out' route-map etc.
 *
 * Schedules an update advertisement.
 *
 * NB: even if the current ao->adj_out->attr is the same as the required
 *     attr, *will* schedule an advertisement.
 */
extern void
bgp_adj_out_withdraw (bgp_node rn, bgp_peer peer)
{
  bgp_adj_out ao;

  /* Lookup existing adjacency, if it is not there return immediately.
   */
  ao = rn->adj_out;
  while (1)
    {
      if (ao == NULL)
        return ;

      if (ao->peer == peer)
        break;

      ao = ao->adj.next ;
    } ;

  assert(rn == ao->rn) ;

  /* If is DISABLE_BGP_ANNONCE, then should not have an ngp_adj_out object, but
   * if we do, we can remove it now.
   */
  if (DISABLE_BGP_ANNOUNCE)
    return bgp_adj_out_delete(ao) ;

  /* Clear up previous advertisement, if any.
   */
  if (ao->attr_sent != NULL)
    {
      /* We have previously sent something to the peer, so must now schedule
       * a withdraw for it.
       */
      bgp_adv  adv ;

      adv = ao->adv ;
      if (adv != NULL)
        {
          /* Some advertisement is scheduled.
           *
           * If it is not a withdraw advertisement, reschedule as a withdraw.
           * In any case, unset any bgp_info (ri) and bgp_adv_attr (aa).
           */
          qassert(adv->ao == ao) ;
          bgp_adv_change(adv, bgp_adv_withdraw) ;
        }
      else
        {
          /* Create and schedule a withdraw advertisement.
           */
          adv = bgp_adv_new(ao, bgp_adv_withdraw, rn->qafx) ;
          bgp_adv_fifo_add(peer, adv) ;
        } ;

      /* Schedule flush of withdraws
       */
      bgp_withdraw_schedule(peer) ;
    }
  else
    {
      /* We haven't announced anything (though we were probably in the process
       * of doing so).
       *
       * Can now remove the bgp_adj_out and discard any scheduled advertisement.
       */
      bgp_adj_out_delete(ao) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * For whatever reason, delete the given bgp_adj_out and any bgp_adv.
 */
extern void
bgp_adj_out_delete (bgp_adj_out ao)
{
  bgp_node  rn ;

  rn = ao->rn ;

  /* If there are any attributes associated with this bgp_adj_out, we are
   * done with them now.
   */
  if (ao->attr_sent)
    ao->attr_sent = bgp_attr_unlock(ao->attr_sent);

  /* If there is an outstanding advertisement, we are done with that now.
   */
  if (ao->adv)
    ao->adv = bgp_adv_delete(ao->adv);

  /* Unhook from peer -- pointer to peer holds lock on it.
   */
  if (ao->route.next != NULL)
    ao->route.next->route.prev = ao->route.prev ;
  if (ao->route.prev != NULL)
    ao->route.prev->route.next = ao->route.next ;
  else
    ao->peer->adj_out_head[rn->qafx] = ao->route.next ;

  bgp_peer_unlock (ao->peer);

  /* Unhook from bgp_node -- pointer to node holds lock on it.
   */
  if (ao->adj.next != NULL)
    ao->adj.next->adj.prev = ao->adj.prev;
  if (ao->adj.prev != NULL)
    ao->adj.prev->adj.next = ao->adj.next;
  else
    rn->adj_out = ao->adj.next;

  bgp_unlock_node (rn);

  /* now can release memory.
   */
  XFREE (MTYPE_BGP_ADJ_OUT, ao);
}

/*------------------------------------------------------------------------------
 * Create and set adj_in for given node, peer and attribute set.
 */
static bgp_adj_in
bgp_adj_in_new(bgp_node rn, bgp_peer peer, attr_set attr)
{
  bgp_adj_in  ai;
  bgp_adj_in* adj_in_head ;

  ai = XCALLOC (MTYPE_BGP_ADJ_IN, sizeof(bgp_adj_in_t));

  /* Lock and set the attributes
   */
  ai->attr = bgp_attr_lock(attr);

  /* Add to list of adj-in in stuff for the peer
   */
  ai->peer = bgp_peer_lock (peer);

  adj_in_head = &(peer->adj_in_head[rn->qafx]) ;

  ai->route.next = *adj_in_head ;
  ai->route.prev = NULL ;
  if (*adj_in_head != NULL)
    (*adj_in_head)->route.prev = ai ;
  *adj_in_head = ai ;

  /* Add to list of adj-in stuff for the bgp_node
   */
  ai->rn = bgp_lock_node (rn);

  ai->adj.next = rn->adj_in ;
  ai->adj.prev = NULL ;
  if (rn->adj_in != NULL)
    rn->adj_in->adj.prev = ai ;
  rn->adj_in = ai ;

  return ai ;
} ;

/*------------------------------------------------------------------------------
 * Set adj_in for given node, peer and attribute set.
 *
 * NB: if there is an adj_in, does NOT change the adj->rs_in.
 *
 *     if there is no adj_in, the new adj_in will have a NULL rs_in.
 */
extern void
bgp_adj_in_set(bgp_node rn, bgp_peer peer, attr_set attr)
{
  bgp_adj_in ai;

  qassert((attr != NULL) && (attr->state == ats_stored)) ;

  ai = rn->adj_in ;

  while (1)
    {
      if (ai == NULL)
        {
          bgp_adj_in_new(rn, peer, attr) ;
          return ;
        } ;

      if (ai->peer == peer)
        {
          if (ai->attr != attr)
            {
              bgp_attr_unlock(ai->attr);
              ai->attr = bgp_attr_lock(attr);
            }

          return ;
        } ;

      ai = ai->adj.next ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Set adj_in with rs_in for given node, peer and attribute set.
 *
 * If there is no adj_in, creates it.
 */
extern void
bgp_adj_rs_in_set(bgp_node rn, bgp_peer peer, attr_set attr, attr_set rs_in)
{
  bgp_adj_in  ai;

  qassert((attr  != NULL) && (attr->state  == ats_stored)) ;
  qassert((rs_in != NULL) && (rs_in->state == ats_stored)) ;

  ai = rn->adj_in ;
  while (1)
    {
      if (ai == NULL)
        {
          ai = bgp_adj_in_new(rn, peer, attr) ;
          break ;
        }

      if (ai->peer == peer)
        {
          qassert(ai->attr == attr) ;
          break ;
        } ;

      ai = ai->adj.next ;
    } ;

  if (ai->rs_in != rs_in)
    {
      if (ai->rs_in != NULL)
        bgp_attr_unlock(ai->rs_in);

      ai->rs_in = bgp_attr_lock(rs_in);
    } ;
} ;

/*------------------------------------------------------------------------------
 * Remove given adj_in from its node and owning peer.
 *
 * Unlocks the attribute set and any rs-in set.
 */
extern void
bgp_adj_in_remove (bgp_node rn, bgp_adj_in ai)
{
  bgp_peer peer ;
  bgp_adj_in*  adj_in_head ;

  peer        = ai->peer ;
  adj_in_head = &(peer->adj_in_head[rn->qafx]) ;

  assert(rn == ai->rn) ;

  /* Done with this copy of attributes
   */
  ai->attr = bgp_attr_unlock(ai->attr);
  if (ai->rs_in != NULL)
    ai->rs_in = bgp_attr_unlock(ai->rs_in) ;

  /* Unhook from peer
   */
  if (ai->route.next != NULL)
    ai->route.next->route.prev = ai->route.prev ;
  if (ai->route.prev != NULL)
    ai->route.prev->route.next = ai->route.next ;
  else
    *adj_in_head = ai->route.next ;

  bgp_peer_unlock (peer);

  /* Unhook from bgp_node
   */
  if (ai->adj.next != NULL)
    ai->adj.next->adj.prev = ai->adj.prev;
  if (ai->adj.prev != NULL)
    ai->adj.prev->adj.next = ai->adj.next;
  else
    rn->adj_in = ai->adj.next;

  bgp_unlock_node (rn);

  /* now can release memory
   */
  XFREE (MTYPE_BGP_ADJ_IN, ai);
} ;

/*------------------------------------------------------------------------------
 * If there is an adj_in for the given peer in the given bgp_node, remove it.
 */
extern void
bgp_adj_in_unset (struct bgp_node *rn, bgp_peer peer)
{
  bgp_adj_in ai ;

  for (ai = rn->adj_in; ai != NULL ; ai = ai->adj.next)
    if (ai->peer == peer)
      {
        bgp_adj_in_remove (rn, ai) ;
        break ;
      } ;
} ;

/*------------------------------------------------------------------------------
 * If there is an adj_in for the given peer in the given bgp_node, unset any
 * rs_in it contains.
 */
extern void
bgp_adj_rs_in_unset (struct bgp_node *rn, bgp_peer peer)
{
  bgp_adj_in ai;

  for (ai = rn->adj_in; ai; ai = ai->adj.next)
    if (ai->peer == peer)
      {
        if (ai->rs_in != NULL)
          ai->rs_in = bgp_attr_unlock(ai->rs_in) ;
        break ;
      } ;
} ;

#endif

/*------------------------------------------------------------------------------
 * Make sure that all peer->adv_fifo[] are empty and that there are no
 * peer->adv_attr_hash[] (where are created as required.
 */
extern void
bgp_sync_init (bgp_peer peer)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_adv_type_t type ;

      for (type = 0 ; type < bgp_adv_count ; ++type)
        ddl_init(peer->adv_fifo[type][qafx]) ;

      peer->adv_attr_hash[qafx] = NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Empty out the peer->adv_fifo[] and dismantle all peer->adv_attr_hash[]
 */
extern void
bgp_sync_delete (struct peer *peer)
{
  qafx_t qafx ;

  for (qafx = qafx_first ; qafx <= qafx_last ; ++qafx)
    {
      bgp_adv_type_t type ;

      for (type = 0 ; type < bgp_adv_count ; ++type)
        {
          bgp_adv_base fifo ;
          bgp_adv      adv ;

          fifo = &peer->adv_fifo[type][qafx] ;

          while ((adv = ddl_head(*fifo)) != NULL)
            bgp_adv_delete(adv) ;
        } ;

      peer->adv_attr_hash[qafx] =
                           bgp_adv_attr_hash_delete(peer->adv_attr_hash[qafx]) ;
    } ;
} ;
