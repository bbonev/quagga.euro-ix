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
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_advertise.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_mplsvpn.h"

/*==============================================================================
 * Advertisment management
 *
 * The bgp_advertise (adv) object belongs to its related bgp_adj_out.  The adv
 * object lives on the peer's sync[afi][safi]->update or ->withdraw queue,
 * and represents the need to advertise a new state for the prefix.
 *
 * The bgp_advertise_attr (baa) belongs to the current set of adv objects
 * which share the same attr to be advertised.  The baa holds the pointer to
 * the interned attr, but does not itself hold a refcnt -- each adv which is
 * a member of the set owns their own refcnt.
 *
 * The baa also lives in a hash attached to the peer for the relevant afi/safi.
 *
 * The adv bgp_advertise (adv) structure owns a lock on:
 *
 *   * the bgp_node  -- so can get at the prefix and any route distinguisher.
 *
 *   * the bgp_info  -- so that cannot suddenly disappear, BUT it may be
 *                      cleared down between now and when the adv is actually
 *                      executed.
 *
 * NB: the bgp_advertise (adv) structure only exists while there is a related
 *     adj-out entry.
 *
 *     If the adj-out is changed (set or unset) the adv is removed from any
 *     advertisement scheduling.
 *
 *     When an advertisement is executed, it is discarded and unpicked from its
 *     adj-out.
 *
 *     So, there can be no dangling references.
 */
static struct bgp_adj_out* adj_out_calloc (void) ;
static void adj_out_free (struct bgp_adj_out *adj_out) ;
static struct bgp_advertise* adv_malloc(void) ;
static void adv_free (struct bgp_advertise *adv) ;
static struct bgp_advertise_attr* baa_calloc(void) ;
static void baa_free (struct bgp_advertise_attr *baa) ;

/*------------------------------------------------------------------------------
 * Allocate a new bgp_advertise_attr object, and copy in the given attr.
 *
 * For the bgp_advertise_attr hash, the data is the address of the attr
 * object referred to by the bgp_advertise_attr.
 */
static void *
baa_hash_alloc (const void *data)
{
  struct bgp_advertise_attr *baa;

  baa = baa_calloc ();          /* creates a zeroized bgp_advertise_attr  */

  baa->attr = miyagi(data) ;
  return baa;
}

/*------------------------------------------------------------------------------
 * Construct "key" for bgp_advertise_attr object's "data"
 *
 * For the bgp_advertise_attr hash, the data is the address of the attr
 * object referred to by the bgp_advertise_attr.
 */
static unsigned int
baa_hash_key (const void *data)
{
  return ((uintptr_t)data) % UINT_MAX ;
}

/*------------------------------------------------------------------------------
 * Compare value of given bgp_advertise_attr object with the given "data"
 *
 * For the bgp_advertise_attr hash, the data is the address of the attr
 * object referred to by the bgp_advertise_attr.
 */
static bool
baa_hash_equal (const void *obj, const void *data)
{
  const struct bgp_advertise_attr * baa  = obj ;
  const struct attr *               attr = data;

  return (baa->attr == attr) ;
}

/*------------------------------------------------------------------------------
 * Set adv structure (creating if required).
 *
 * Takes a lock on the bgp_node and any bgp_info.
 *
 * Places on the given fifo.
 *
 * Returns:  given or new bgp_advertise structure.
 *
 * NB: is on the given fifo, is attached to the adj, points at the rn and
 *     binfo (if any) complete with locks on same...
 *
 *     BUT: adv->baa   == NULL ) so looks like withdraw
 *     AND: adv->binfo == NULL )
 *
 *          it is the CALLERs responsibility to add the required baa and binfo
 *          if this has just been added to the update fifo !!
 */
static struct bgp_advertise *
bgp_advertise_set (struct bgp_advertise * adv, struct bgp_node* rn,
                  struct bgp_adj_out* adj, struct bgp_advertise_fifo_base* base)
{
  if (adv == NULL)
    adv = adv_malloc() ;        /* not zeroized         */

  memset(adv, 0, sizeof(struct bgp_advertise)) ;

  /* Zeroising has set:
   *
   *   * fifo                   -- X            -- set below
   *   * baa_list               -- NULLs
   *
   *   * rn                     -- X            -- set below
   *   * adj                    -- X            -- set below
   *
   *   * baa                    -- NULL         <=> withdraw !
   *   * binfo                  -- NULL         <=> withdraw !
   */
  adv->rn  = bgp_lock_node(rn) ;

  adv->adj = adj ;
  adj->adv = adv ;

  ddl_append(*base, adv, fifo) ;

  return adv ;
} ;

/*------------------------------------------------------------------------------
 * Annul the given adv:
 *
 *   - remove from the fifo it is on.
 *
 *   - clear pointer to bpp_info and lock on same, if any
 *
 *   - clear bgp_advertise_attr, if any
 *
 * NB: if an adv exists, it MUST be on the peer's withdraw or update fifo.
 *
 * The result is, effectively, an adv that can be scheduled as a withdraw.
 *
 * Still has:
 *
 *   * adv->rn and lock on same
 *
 *   * adv->adj and adj->adv still in place.
 *
 * BUT: is not on any fifo -- CALLER is responsible for either unsetting
 *      the adv->rn and adv->adj, or reusing the adv as a withdraw.
 *
 * Returns:  the (new) current head of the baa list of adv which share the
 *           same attr.  NULL if none (or no baa !).
 */
static struct bgp_advertise *
bgp_advertise_annul(struct bgp_advertise* adv, struct bgp_synchronize *sync)
{
  struct bgp_advertise_attr *baa;
  struct bgp_advertise *next ;
  struct attr *attr;

  qassert(adv->adj != NULL) ;
  qassert(adv      == adv->adj->adv) ;
  qassert(adv->rn  == adv->adj->rn) ;

  /* Unlink from withdraw or update FIFO.
   */
  baa = adv->baa ;

  if (baa == NULL)
    {
      /* This is a withdraw advertisement -- binfo must also be NULL but
       * we clear it in any case.
       *
       * Remove from the withdraw fifo, and we are done.
       */
      qassert(adv->binfo == NULL) ;

      if (adv->binfo != NULL)
        {
          bgp_info_unlock(adv->binfo) ;
          adv->binfo = NULL ;
        } ;

      qassert((ddl_prev(adv, fifo) != NULL) ||
                                            (ddl_head(sync->withdraw) == adv)) ;
      ddl_del(sync->withdraw, adv, fifo) ;

      return NULL ;
    } ;

  /* This is an update advertisement, so remove from the update fifo
   */
  qassert((ddl_prev(adv, fifo) != NULL) || (ddl_head(sync->update) == adv)) ;
  ddl_del(sync->update, adv, fifo) ;

  /* Forget the baa and remove from its list.
   */
  adv->baa = NULL ;
  ddl_del(baa->base, adv, baa_list) ;

  /* If we have a binfo, forget it and undo our lock on it.
   *
   * An update MUST have a binfo -- but we do the simple and safe thing here.
   */
  qassert(adv->binfo != NULL) ;
  if (adv->binfo != NULL)
    {
      bgp_info_unlock(adv->binfo) ;
      adv->binfo = NULL ;
    } ;

  /* Pick up the next adv which shares the attributes (and hence the baa),
   * and pick up the attr in question.
   *
   * If the baa has no other adv, then it must now be discarded.
   */
  qassert(baa->attr != NULL) ;

  next = ddl_head(baa->base) ;
  attr = baa->attr ;

  if (next == NULL)
    {
      struct bgp_advertise_attr *ret;

      ret = hash_release (sync->hash, attr);
      if (ret == baa)
        baa_free (baa);
      else
        {
          zlog_err("BUG: failed to find interned adv-attr -- found %s",
                         (ret == NULL) ? "nothing" : "something else") ;
        } ;
    } ;

  /* Drop our lock on the attr.
   *
   * Note that we do this after releasing and freeing the baa.  It doesn't
   * really make any difference -- but it avoids having a dangling reference
   * to the attr in the baa (for however brief a moment).
   */
  bgp_attr_unintern(attr) ;

  /* Done... if there are other adv with the same attributes, we here return
   *         the next one to consider.
   */
  return next ;
} ;

/*------------------------------------------------------------------------------
 * Discard the bgp_advertise (adv) object currently associated with
 *                                                  the given bgp_adj_out (adj).
 *
 * If there is a bgp_advertise_attr (baa) object associated with the adv object,
 * unpick it from there first.  If the baa becomes empty, that will be freed
 * automagically.
 *
 * If there is another adv associated with the baa (if any) return that (for
 * the benefit of the sending of updates).
 *
 * Release lock on the bgp_info (if any) and clear pointer to it.
 *
 * Release lock on the bgp_node, and clear pointer to it.
 *
 * If required, free the adv object, and set adj->adv NULL.  Otherwise, keep
 * the adv object, but unhook from the adj.
 *
 * Note: removes the adv from the fifo it is attached to.  So, if is about to
 *       advertise in a new way, that's a new advertisement, scheduled anew.
 *
 * Note: this has no effect on the adj->attr, which are not considered here.
 *
 * Returns:  the (new) current head of the baa list of adv which share the
 *           same attr.  NULL if none (or no baa !).
 */
extern struct bgp_advertise *
bgp_advertise_unset(struct bgp_advertise * adv, struct bgp_synchronize* sync,
                                                                 bool free_adv)
{
  struct bgp_advertise *next;
  struct bgp_adj_out *adj;

  next = bgp_advertise_annul(adv, sync) ;
  adj  = adv->adj ;

  qassert(adv == adj->adv) ;

  if (adv->rn != NULL)          /* should be there, but cope    */
    {
      qassert(adv->rn == adj->rn) ;

      bgp_unlock_node(adv->rn) ;
      adv->rn = NULL ;
    } ;

  /* Unhook from the adj, and free the adv if required.
   */
  adv->adj = NULL ;
  adj->adv = NULL ;

  if (free_adv)
    adv_free(adv);

  return next;
} ;

/*------------------------------------------------------------------------------
 * Take update adv and reinvent as a (real) withdraw.
 *
 * This takes the given adv off the update fifo, discards the bgp_info and the
 * the bgp_advertise_attr, and reschedules as a withdraw.
 *
 * Returns:  the (new) current head of the baa list of adv which share the
 *           same attr.  NULL if none (or no baa !).
 */
extern struct bgp_advertise*
bgp_advertise_redux(struct bgp_advertise * adv, struct bgp_synchronize* sync)
{
  struct bgp_advertise *next;

  qassert(adv->adj   != NULL) ;
  qassert(adv->rn    != NULL) ;
  qassert(adv->baa   != NULL) ;
  qassert(adv->binfo != NULL) ;

  /* Annul the update advertisement.
   *
   * The adv is left ready to be rescheduled as a withdraw.
   */
  next = bgp_advertise_annul(adv, sync) ;

  qassert(adv->adj   != NULL) ;
  qassert(adv->rn    != NULL) ;
  qassert(adv->baa   == NULL) ;
  qassert(adv->binfo == NULL) ;

  ddl_append(sync->withdraw, adv, fifo) ;

  /* The next returned by bgp_advertise_annul() is the next adv with the
   * same attributes (if any) as the adv we rode in on.
   */
  return next ;
} ;

/*==============================================================================
 * Adj-Out Handling
 *
 * The bgp_adj_out object lives on the related bgp_node (rn) rn->adj_out list,
 * and the peer's adj_out[afi][safi] list.  It represents the state of
 * any advertisement sent (in the most recent UPDATE message for the prefix)
 * for the peer for the prefix.
 *
 * If an advertisement is pending for the peer for the prefix, an adv object
 * is attached to the adj-out.
 */

/* BGP adjacency keeps minimal advertisement information.  */

extern bool
bgp_adj_out_lookup (struct peer *peer, struct prefix *p,
                    afi_t afi, safi_t safi, struct bgp_node *rn)
{
  struct bgp_adj_out *adj_out;

  for (adj_out = sdl_head(rn->adj_outs) ; adj_out != NULL;
                                          adj_out = sdl_next(adj_out, rn_list))
    if (adj_out->peer == peer)
      {
        if (adj_out->adv == NULL)
          return (adj_out->attr != NULL) ;      /* steady state, with attr */
        else
          return (adj_out->adv->baa != NULL) ;  /* in flux, with attr   */
      } ;

  return false ;
} ;

/*------------------------------------------------------------------------------
 * Set adj-out for the given bgp_node, peer, prefix, attributes, etc.
 *
 * Creates a new adj-out entry if required.
 *
 * If was scheduled for update or withdraw, remove from the relevant fifo,
 * and if was scheduled for update, remove from list of prefixes with the
 * same attributes.
 *
 * Schedule for update, adding to list of prefixes with the same attributes.
 *
 * NB: the given attributes MUST be interned, and the ref-count associated
 *     with those attributes is passed to the adv->baa.
 *
 *     So the adv->baa->attr is an interned set, and owns a ref-count, for each
 *     prefix which shares the same attributes.
 */
extern void
bgp_adj_out_set (struct bgp_node *rn, struct peer *peer, struct prefix *p,
                 struct attr *attr, afi_t afi, safi_t safi,
                 struct bgp_info *binfo)
{
  struct bgp_adj_out*        adj_out;
  struct bgp_advertise*      adv;
  struct bgp_advertise_attr* baa;
  struct bgp_synchronize*    sync ;

  assert(rn != NULL) ;
  assert((afi == rn->table->afi) && (safi == rn->table->safi)) ;
  assert(attr != NULL) ;

  if (qdebug)
    {
      bool rsclient ;

      qassert(bgp_attr_is_interned(attr)) ;

      rsclient = (peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT) ;

      switch (rn->table->type)
        {
          case BGP_TABLE_MAIN:
            qassert(!rsclient) ;
            break ;

          case BGP_TABLE_RSCLIENT:
            qassert(rsclient) ;
            break;

          default:
            qassert(false) ;
            break ;
        } ;
    } ;

  if (DISABLE_BGP_ANNOUNCE)
    {
      bgp_attr_unintern(attr) ;
      return;
    } ;

  /* Look for adjacency information.
   */
  for (adj_out = sdl_head(rn->adj_outs); adj_out != NULL;
                                         adj_out = sdl_next(adj_out, rn_list))
    if (adj_out->peer == peer)
      break;

  sync = peer->sync[afi][safi] ;

  if (adj_out != NULL)
    {
      /* We have an existing adjacency.
       *
       * If there is an advertisement already scheduled, unset that so can
       * reschedule whatever the new requirement is.  We preserve and reuse
       * the exiting adv structure.
       */
      adv = adj_out->adv ;

      if (adv != NULL)
        {
          /* The unset operation empties out everything, and undoes locks on
           * rn and binfo.
           */
          assert(adv->adj == adj_out) ;
          bgp_advertise_unset (adv, sync, false /* !free_adv */);
        } ;
    }
  else
    {
      adj_out = adj_out_calloc() ;

      /* Zeroizing has set:
       *
       *   * rn                 -- X            -- set below
       *   * rn_list            -- NULLs        -- set below
       *
       *   * peer               -- X            -- set below
       *   * peer_list          -- NULLs        -- set below
       *
       *   * attr               -- NULL         -- none, yet
       *   * adv                -- NULL         -- none, yet
       */
      adj_out->peer = bgp_peer_lock (peer);
      sdl_push(peer->adj_outs[afi][safi], adj_out, peer_list) ;

      adj_out->rn = bgp_lock_node (rn);
      sdl_push(rn->adj_outs, adj_out, rn_list) ;

      adv = NULL ;
    } ;

  /* The adj_out contains:  pointer to owner peer, and list pointers for same
   *                        pointer to parent bgp_node, and list pointers ditto
   *                        pointer to attributes (attr)
   *
   * The adj_out->attr are those actually sent to the peer, so we don't care
   * about them here -- if this is a new adj_out, then the attr have been set
   * NULL.  When the update is actually sent, will set/replace the
   * adj_out->attr.
   *
   * Now set/create the adv for the new update, this sets everything except
   * adv->binfo and adv->baa -- which are set NULL -- and dealt with below.
   *
   * This also sets adj_out->adv.
   */
  adv = bgp_advertise_set (adv, rn, adj_out, &sync->update) ;

  /* bgp_advertise_set() has put what looks like a withdraw onto the
   * update list.  Time to complete the update adv object:
   *
   *   * set pointer to the binfo and take lock
   *
   *   * find or create a baa for the attributes, and attach to same.
   */
  adv->binfo = bgp_info_lock (binfo) ;
  adv->baa   = baa = hash_get(sync->hash, attr, baa_hash_alloc) ;
  ddl_append(baa->base, adv, baa_list) ;
} ;

/*------------------------------------------------------------------------------
 * If there is an adj-out for this prefix for this peer, either schedule a
 *                                           withdraw, or remove it immediately.
 */
extern void
bgp_adj_out_unset (struct bgp_node *rn, struct peer *peer, struct prefix *p,
                   afi_t afi, safi_t safi)
{
  struct bgp_adj_out *adj_out;

  qassert((afi  == rn->table->afi)) ;
  qassert((safi == rn->table->safi)) ;

  if (qdebug)
    {
      bool rsclient ;

      rsclient = (peer->af_flags[afi][safi] & PEER_FLAG_RSERVER_CLIENT) ;

      switch (rn->table->type)
        {
          case BGP_TABLE_MAIN:
            qassert(!rsclient) ;
            break ;

          case BGP_TABLE_RSCLIENT:
            qassert(rsclient) ;
            break;

          default:
            qassert(false) ;
            break ;
        } ;
    } ;

  if (DISABLE_BGP_ANNOUNCE)
    return;

  /* Lookup existing adjacency, if it is not there return immediately.
   */
  adj_out = sdl_head(rn->adj_outs) ;
  while (1)
    {
      if (adj_out == NULL)
        return ;                /* nothing to remove    */

      if (adj_out->peer == peer)
        break ;                 /* found it             */

      adj_out = sdl_next(adj_out, rn_list) ;
    } ;

  assert(rn == adj_out->rn) ;

  /* Clear up previous advertisement, if any.
   */
  if (adj_out->attr == NULL)
    {
      /* Nothing actually advertised to the peer, so can simply discard the
       * adj-out -- discarding any pending advertisement.
       */
      bgp_adj_out_remove(adj_out, afi, safi) ;
    }
  else
    {
      /* We need to advertise a withdraw.
       *
       * Note that we don't change the adj->attr -- that's done when the
       * withdraw is actually sent.
       */
      struct bgp_advertise*   adv;
      struct bgp_synchronize* sync ;

      sync = peer->sync[afi][safi] ;

      adv = adj_out->adv ;
      if (adv != NULL)
        {
          assert(adv->adj == adj_out) ;
          bgp_advertise_unset (adv, sync, false /* !free_adv */);
        } ;

      /* Add adv for withdraw announcement
       *
       * Withdraws live on their own queue, but also adv->baa   == NULL
       *                                         and adv->binfo == NULL
       */
      bgp_advertise_set (adv, rn, adj_out, &sync->withdraw) ;

      /* Schedule flush of withdraws
       */
      bgp_withdraw_schedule(peer) ;
    }
}

/*------------------------------------------------------------------------------
 * Remove the given adj-out from the bgp_node and its peer.
 *
 * Discard any attributes known to have been sent to the peer.
 *
 * Discard and advertisement which may be scheduled for the prefix for the peer.
 *
 * This is done either when the session has gone down, or when a withdraw
 * has been sent, so the adjacency is now redundant.
 */
extern void
bgp_adj_out_remove (struct bgp_adj_out *adj_out, afi_t afi, safi_t safi)
{
  struct bgp_advertise *adv;
  bgp_peer peer ;

  qassert((afi  == adj_out->rn->table->afi)) ;
  qassert((safi == adj_out->rn->table->safi)) ;

  peer = adj_out->peer ;

  if (adj_out->attr != NULL)
    bgp_attr_unintern (adj_out->attr) ; /* about to discard the adj, so
                                         * don't care about ->attr      */
  adv = adj_out->adv;
  if (adv != NULL)
    {
      assert(adv->adj == adj_out) ;
      bgp_advertise_unset (adv, peer->sync[afi][safi], true /* free_adv */) ;
    } ;

  /* Unhook from peer
   */
  sdl_del(peer->adj_outs[afi][safi], adj_out, peer_list) ;
  bgp_peer_unlock (peer);

  /* Unhook from bgp_node
   */
  sdl_del(adj_out->rn->adj_outs, adj_out, rn_list) ;
  bgp_unlock_node (adj_out->rn);

  /* now can release memory.
   */
  adj_out_free(adj_out);
}

/*==============================================================================
 * Adj-In Stuff
 */

/*------------------------------------------------------------------------------
 * Add given attributes to the adj-in for the given bgp_node.
 *
 * The attributes are interned into the adj-in -- unless there is no change.
 */
extern void
bgp_adj_in_set (struct bgp_node *rn, struct peer *peer, struct attr *attr,
                                                               const uchar* tag)
{
  struct bgp_adj_in *adj_in;

  qassert(bgp_sub_attr_are_interned(attr)) ;

  for (adj_in = sdl_head(rn->adj_ins); adj_in != NULL;
                                       adj_in = sdl_next(adj_in, rn_list))
    {
      if (adj_in->peer == peer)
        {
          if (adj_in->attr != attr)
            {
              if (adj_in->attr != NULL)            /* paranoia     */
                bgp_attr_unintern (adj_in->attr);

              adj_in->attr = bgp_attr_intern (attr);
            }

          if (tag == NULL)
            memset(&adj_in->tag[0], 0, sizeof(adj_in->tag)) ;
          else
            memcpy(&adj_in->tag[0], tag, sizeof(adj_in->tag)) ;

          return;
        }
    }

  /* Need to create a brand new bgp_adj_in
   *
   * Zeroizing sets:
   *
   *   * rn             -- X            -- set below
   *   * rn_list        -- NULLs        -- set below
   *
   *   * peer           -- X            -- set below
   *   * peer_list      -- NULLs        -- set below
   *
   *   * attr           -- X            -- set below
   *   * tag            -- all zero     -- set if required
   */
  adj_in = XCALLOC (MTYPE_BGP_ADJ_IN, sizeof (struct bgp_adj_in));

  adj_in->peer = bgp_peer_lock (peer);
  sdl_push(peer->adj_ins[rn->table->afi][rn->table->safi], adj_in, peer_list) ;

  adj_in->rn = bgp_lock_node (rn);
  sdl_push(rn->adj_ins, adj_in, rn_list) ;

  /* Set the interned attributes and tag, if any.
   */
  adj_in->attr = bgp_attr_intern (attr);

  if (tag != NULL)
    memcpy(&adj_in->tag[0], tag, sizeof(adj_in->tag)) ;
  confirm(sizeof(adj_in->tag) == 3) ;
}

/*------------------------------------------------------------------------------
 * Remove the given adj-in from its respective rib-node and peer.
 */
extern void
bgp_adj_in_remove (struct bgp_adj_in *adj_in, afi_t afi, safi_t safi)
{
  qassert((afi  == adj_in->rn->table->afi)) ;
  qassert((safi == adj_in->rn->table->safi)) ;

  /* About to discard the adj-in entry, so don't care about adj_in->attr.
   * (Don't expect that to be NULL ... but don't really care it is !
   */
  if (adj_in->attr != NULL)
    bgp_attr_unintern (adj_in->attr);

  /* Unhook from peer
   */
  sdl_del(adj_in->peer->adj_ins[afi][safi], adj_in, peer_list) ;
  bgp_peer_unlock (adj_in->peer);

  /* Unhook from bgp_node
   */
  sdl_del(adj_in->rn->adj_ins, adj_in, rn_list) ;
  bgp_unlock_node (adj_in->rn);

  /* now can release memory.
   */
  XFREE (MTYPE_BGP_ADJ_IN, adj_in);
}

/*------------------------------------------------------------------------------
 * If there is an adj-in for the given peer in the given node, remove it.
 */
extern void
bgp_adj_in_unset (struct bgp_node *rn, struct peer *peer)
{
  struct bgp_adj_in *adj_in;

  adj_in = sdl_head(rn->adj_ins) ;

  while (1)
    {
      if (adj_in == NULL)
        return ;

      if (adj_in->peer == peer)
        break ;

      adj_in = sdl_next(adj_in, rn_list) ;
    }

  bgp_adj_in_remove (adj_in, rn->table->afi, rn->table->safi);
}

/*==============================================================================
 * Data structures for managing updates/withdraws.
 */
static void bgp_sync_new(struct peer *peer, afi_t afi, safi_t safi, bool afc) ;
static struct hash* bgp_sync_new_hash(afi_t afi, safi_t safi) ;
static void bgp_sync_reset(struct peer *peer, afi_t afi, safi_t safi,
                                                                     bool afc) ;
static void bgp_sync_clean(void* p) ;

/*------------------------------------------------------------------------------
 * Initialise the peer->sync and peer->hash structures for all address families.
 *
 * NB: does not create the hash for bgp_advertise_attr -- that is done by
 *     bgp_sync_start(), which is called when a session is established.
 */
extern void
bgp_sync_init (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_sync_new(peer, afi, safi, false /* not active */) ;
}

/*------------------------------------------------------------------------------
 * Reset the peer->sync structures for all active address families.
 *
 * This is done as a new session becomes established, so all the structures
 * should be empty.
 *
 * This makes sure everything which currently exists is empty, and creates
 * new empty structures for the now active/negotiated address families.
 */
extern void
bgp_sync_start(struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      bgp_sync_reset(peer, afi, safi, peer->afc[afi][safi]) ;
} ;

/*------------------------------------------------------------------------------
 * Discard the peer->sync and peer->hash structures.
 *
 * NB: assumes that any hashes for bgp_advertise_attr are, by now, empty.
 */
extern void
bgp_sync_delete (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
        if (peer->sync[afi][safi] != NULL)
          {
            bgp_sync_reset(peer, afi, safi, false /* not active*/) ;

            XFREE (MTYPE_BGP_SYNCHRONISE, peer->sync[afi][safi]);
                                /* sets peer->sync[afi][safi] = NULL    */
          } ;
      } ;
} ;

/*------------------------------------------------------------------------------
 * Create a new, empty sync object -- with hash if required.
 *
 * Sets the peer->sync[afi][safi].
 */
static void
bgp_sync_new(struct peer *peer, afi_t afi, safi_t safi, bool afc)
{
  struct bgp_synchronize* sync ;

  sync = XCALLOC (MTYPE_BGP_SYNCHRONISE, sizeof (struct bgp_synchronize)) ;

  ddl_init(sync->update);
  ddl_init(sync->withdraw);
#if 0
  ddl_init(sync->withdraw_low) ;
#endif

  if (afc)
    sync->hash = bgp_sync_new_hash(afi, safi) ;
  else
    sync->hash = NULL ;

  peer->sync[afi][safi] = sync ;
}

/*------------------------------------------------------------------------------
 * Create a new, empty sync hash for the given afi/safi
 *
 * Returns:  address of the hash
 */
static struct hash*
bgp_sync_new_hash(afi_t afi, safi_t safi)
{
  uint size ;

  size = 1024 ;                 /* default !    */

  switch (afi)
    {
      case AFI_IP:
        switch (safi)
          {
            case SAFI_UNICAST:
              size = 64 * 1024 ;
              break ;

            case SAFI_MULTICAST:
              break ;

            case SAFI_MPLS_VPN:
              break ;

            default:
              break ;
          } ;
        break ;

#if HAVE_IPV6
      case AFI_IP6:
        switch (safi)
          {
            case SAFI_UNICAST:
              size =  4 * 1024 ;
              break ;

            case SAFI_MULTICAST:
              break ;

            case SAFI_MPLS_VPN:
              break ;

            default:
              break ;
          } ;
#endif
       default:
         break ;
    } ;

  return hash_create_size(size, baa_hash_key, baa_hash_equal);
} ;

/*------------------------------------------------------------------------------
 * Reset the adj_out and the sync for the given peer in the given afi/safi
 *
 * When we get here, the adj_out and all related peer->sync stuff really
 * should be empty... but we ensure that it is here.
 *
 * If is "afc", then make sure we have a hash for marshalling updates.
 */
static void
bgp_sync_reset(struct peer *peer, afi_t afi, safi_t safi, bool afc)
{
  struct bgp_synchronize* sync ;
  struct hash* hash ;

  /* Worry about the state of the adj-out for the peer.
   *
   * Really should be empty... but if not, make it so !
   */
  qassert(sdl_head(peer->adj_outs[afi][safi]) == NULL) ;

  if (sdl_head(peer->adj_outs[afi][safi]) != NULL)
    {
      struct bgp_adj_out*  adj_out_next ;

      zlog_err("Adj-Out for peer %s (afi=%u/safi=%u)"
                 " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;

      adj_out_next = sdl_head(peer->adj_outs[afi][safi]) ;
      while (adj_out_next != NULL)
        {
          /* We start at the head of the list, and we depend on bgp_adj_out_remove()
           * removing that -- so that the current next becomes the head.
           *
           * We are in deep trouble if that is not the case.
           */
          struct bgp_adj_out*  adj_out ;

          adj_out      = adj_out_next ;
          adj_out_next = sdl_next(adj_out, peer_list) ;

          assert(sdl_prev(adj_out, peer_list) == NULL) ;
          assert(adj_out->peer == peer) ;

          bgp_adj_out_remove (adj_out, afi, safi) ;

          assert(adj_out_next == sdl_head(peer->adj_outs[afi][safi])) ;
        } ;
    } ;

  /* Allow for the entire sync object to be absent when the address family
   * is not in use.
   */
  sync = peer->sync[afi][safi] ;

  if (sync == NULL)
    {
      if (afc)
        bgp_sync_new(peer, afi, safi, afc /* active */) ;

      return ;
    } ;

  /* Now that the adj-out is empty, there really should be nothing
   * left in any fifo.
   *
   * If there is, then we annul same.
   */
  if (ddl_head(sync->update) != NULL)
    {
      struct bgp_advertise* adv ;

      zlog_err("sync->update for peer %s (afi=%u/safi=%u)"
                  " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;

      /* So empty out the fifo... the implication is that there are
       * somehow some adj_out objects lying around, which we've lost
       * track of... this at least tidies away advertisements which
       * the adj_out objects point to, and sets those into steady state.
       */
      while ((adv = ddl_head(sync->update)) != NULL)
        {
          assert(adv->baa != NULL) ;
          bgp_advertise_unset(adv, sync, true /* free */) ;
        } ;
    } ;

  if (ddl_tail(sync->update) != NULL)
    {
      zlog_err("sync->update.tail for peer %s (afi=%u/safi=%u)"
                  " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;
    } ;

  if (ddl_head(sync->withdraw ) != NULL)
    {
      struct bgp_advertise* adv ;

      zlog_err("sync->withdraw for peer %s (afi=%u/safi=%u)"
                  " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;

      /* as for update... at least make sure we clear out the
       * advertisements.
       */
      while ((adv = ddl_head(sync->withdraw)) != NULL)
        {
          assert(adv->baa == NULL) ;
          bgp_advertise_unset(adv, sync, true /* free */) ;
        } ;
    } ;

  if (ddl_tail(sync->withdraw ))
    {
      zlog_err("sync->withdraw.tail for peer %s (afi=%u/safi=%u)"
                  " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;
    } ;

  ddl_init(sync->update) ;              /* belt and...                  */
  ddl_init(sync->withdraw) ;            /* ...braces                    */

  /* Now worry about the hash.
   */
  hash = sync->hash ;

  if (hash != NULL)
    {
      /* The hash *really* should be empty by now... all known adv
       * objects have been destroyed, so all baa should have gone
       * with.
       */
      if (hash->count != 0)
        {
          zlog_err("sync->hash for peer %s (afi=%u/safi=%u)"
                   " is not empty when a new session becomes established",
                                                  peer->host, afi, safi) ;

          hash_clean (hash, bgp_sync_clean) ;
        } ;

      /* The hash is now empty...
       *
       * ...if peer is configured for the afi/safi, make sure it is
       *    empty -- in case hash->count is unreliable !
       *
       * ...otherwise, discard the hash.
       */
      if (afc)
        hash_reset(hash) ;
      else
        hash = hash_free(hash) ;
    }
  else
    {
      if (afc)
        hash = bgp_sync_new_hash(afi, safi) ;
    } ;

  sync->hash = hash ;
} ;

/*------------------------------------------------------------------------------
 * Discard bgp_advertise_attr structure, from the hash.
 */
static void
bgp_sync_clean(void* item)
{
  baa_free (item) ;
} ;

/*==============================================================================
 * Pools for bgp_advertise and bgp_advertise_attr structures.
 */
enum
{
  adj_out_pool_size = 1024,
  adv_pool_size     = 1024,
  baa_pool_size     = 1024
} ;

union adj_out_union
{
  struct bgp_adj_out    adj_out ;
  union  adj_out_union* next ;
} ;

struct adj_out_pool
{
  struct adj_out_pool* next ;
  union  adj_out_union adj_outs[adj_out_pool_size] ;
};

union adv_union
{
  struct bgp_advertise adv ;
  union  adv_union*    next ;
} ;

struct adv_pool
{
  struct adv_pool* next ;
  union  adv_union advs[adv_pool_size] ;
};

union baa_union
{
  struct bgp_advertise_attr baa ;
  union  baa_union*         next ;
} ;

struct baa_pool
{
  struct baa_pool* next ;
  union  baa_union baas[baa_pool_size] ;
};

struct adj_out_pool*  adj_out_pools = NULL ;
union  adj_out_union* adj_out_frees = NULL ;

struct adv_pool*   adv_pools = NULL ;
union  adv_union*  adv_frees = NULL ;

struct baa_pool*   baa_pools = NULL ;
union  baa_union*  baa_frees = NULL ;

static struct bgp_adj_out*
adj_out_calloc (void)
{
  union  adj_out_union* u ;

  u = adj_out_frees ;

  if (u == NULL)
    {
      struct adj_out_pool* pool ;
      uint i ;

      pool = XCALLOC(MTYPE_BGP_ADJ_OUT, sizeof(struct adj_out_pool)) ;

      pool->next = adj_out_pools ;
      adj_out_pools  = pool ;

      for (i = 0 ; i < adj_out_pool_size ; ++i)
        {
          u = &pool->adj_outs[i] ;

          u->next   = adj_out_frees ;
          adj_out_frees = u ;
        } ;
    } ;

  adj_out_frees = u->next ;

  memset(u, 0, sizeof(union adj_out_union)) ;
  confirm(sizeof(union adj_out_union) == sizeof(struct bgp_adj_out)) ;

  return &u->adj_out ;
} ;

static void
adj_out_free (struct bgp_adj_out *adj_out)
{
  union adj_out_union* u ;

  u = (void*)adj_out ;

  u->next   = adj_out_frees ;
  adj_out_frees = u ;
} ;

static struct bgp_advertise *
adv_malloc (void)
{
  union  adv_union* u ;

  u = adv_frees ;

  if (u == NULL)
    {
      struct adv_pool* pool ;
      uint i ;

      pool = XCALLOC(MTYPE_BGP_ADVERTISE, sizeof(struct adv_pool)) ;

      pool->next = adv_pools ;
      adv_pools  = pool ;

      for (i = 0 ; i < adv_pool_size ; ++i)
        {
          u = &pool->advs[i] ;

          u->next   = adv_frees ;
          adv_frees = u ;
        } ;
    } ;

  adv_frees = u->next ;

  return &u->adv ;
} ;

static void
adv_free (struct bgp_advertise *adv)
{
  union adv_union* u ;

  u = (void*)adv ;

  u->next   = adv_frees ;
  adv_frees = u ;
} ;

static struct bgp_advertise_attr *
baa_calloc (void)
{
  union  baa_union* u ;

  u = baa_frees ;

  if (u == NULL)
    {
      struct baa_pool* pool ;
      uint i ;

      pool = XCALLOC(MTYPE_BGP_ADVERTISE_ATTR, sizeof(struct baa_pool)) ;

      pool->next = baa_pools ;
      baa_pools  = pool ;

      for (i = 0 ; i < baa_pool_size ; ++i)
        {
          u = &pool->baas[i] ;

          u->next   = baa_frees ;
          baa_frees = u ;
        } ;
    } ;

  baa_frees = u->next ;

  memset(u, 0, sizeof(union baa_union)) ;
  confirm(sizeof(union baa_union) == sizeof(struct bgp_advertise_attr)) ;

  return &u->baa ;
} ;

static void
baa_free (struct bgp_advertise_attr *baa)
{
  union baa_union* u ;

  u = (void*)baa ;

  u->next   = baa_frees ;
  baa_frees = u ;
} ;

extern void
bgp_advertise_finish(void)
{
  struct adj_out_pool*  adj_out_p ;
  struct adv_pool*      adv_p ;
  struct baa_pool*      baa_p ;

  adj_out_frees = NULL ;

  while ((adj_out_p = adj_out_pools) != NULL)
    {
      adj_out_pools = adj_out_p->next ;

      XFREE(MTYPE_BGP_ADJ_OUT, adj_out_p) ;
    } ;

  adv_frees = NULL ;

  while ((adv_p = adv_pools) != NULL)
    {
      adv_pools = adv_p->next ;

      XFREE(MTYPE_BGP_ADVERTISE, adv_p) ;
    } ;

  baa_frees = NULL ;

  while ((baa_p = baa_pools) != NULL)
    {
      baa_pools = baa_p->next ;

      XFREE(MTYPE_BGP_ADVERTISE_ATTR, baa_p) ;
    } ;
} ;


