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
 * and represents the need to advertise a new state for the prefix.  Whenever
 * the bgp_adj_out changes, any related adv is dismantled and recreated as
 * necessary.
 *
 * The bgp_advertise_attr (baa) belongs to the current set of adv objects
 * which share the same attr to be advertised.  The baa holds the pointer to
 * the interned attr, but does not itself hold a refcnt -- each adv which is
 * a member of the set owns their own refcnt.
 */

/* BGP advertise attribute is used for pack same attribute update into
   one packet.  To do that we maintain attribute hash in struct
   peer.  */
static struct bgp_advertise_attr *
baa_new (void)
{
  return (struct bgp_advertise_attr *)
    XCALLOC (MTYPE_BGP_ADVERTISE_ATTR, sizeof (struct bgp_advertise_attr));
}

static void
baa_free (struct bgp_advertise_attr *baa)
{
  XFREE (MTYPE_BGP_ADVERTISE_ATTR, baa);
}

static void *
baa_hash_alloc (void *p)
{
  struct bgp_advertise_attr * ref = (struct bgp_advertise_attr *) p;
  struct bgp_advertise_attr *baa;

  baa = baa_new ();
  baa->attr = ref->attr;
  return baa;
}

static unsigned int
baa_hash_key (void *p)
{
  struct bgp_advertise_attr * baa = (struct bgp_advertise_attr *) p;

  return attrhash_key_make (baa->attr);
}

static int
baa_hash_cmp (const void *p1, const void *p2)
{
  const struct bgp_advertise_attr * baa1 = p1;
  const struct bgp_advertise_attr * baa2 = p2;

  return attrhash_cmp (baa1->attr, baa2->attr);
}

/* BGP update and withdraw information is stored in BGP advertise
   structure.  This structure is referred from BGP adjacency
   information.  */
static struct bgp_advertise *
bgp_advertise_new (void)
{
  return (struct bgp_advertise *)
    XCALLOC (MTYPE_BGP_ADVERTISE, sizeof (struct bgp_advertise));
}

static void
bgp_advertise_free (struct bgp_advertise *adv)
{
  if (adv->binfo)
    bgp_info_unlock (adv->binfo); /* bgp_advertise bgp_info reference */
  XFREE (MTYPE_BGP_ADVERTISE, adv);
}

static void
bgp_advertise_add (struct bgp_advertise_attr *baa,
                   bgp_advertise adv)
{
  bgp_advertise last ;

  if (baa->base.head == NULL)
    {
      last = NULL ;
      baa->base.head = adv ;
    }
  else
    {
      last = baa->base.tail ;
      last->adv_next = adv ;
    } ;

  adv->adv_next  = NULL ;
  adv->adv_prev  = last ;

  baa->base.tail = adv ;
}

static void
bgp_advertise_delete (struct bgp_advertise_attr *baa,
                      struct bgp_advertise *adv)
{
  if (adv->adv_next != NULL)
    adv->adv_next->adv_prev = adv->adv_prev;
  else
    baa->base.tail = adv->adv_prev ;

  if (adv->adv_prev != NULL)
    adv->adv_prev->adv_next = adv->adv_next;
  else
    baa->base.head = adv->adv_next;
}

/*------------------------------------------------------------------------------
 * Find or create a bgp_advertise_attr entry for the given attributes.
 *
 * NB: attributes must be interned already, and does NOT take another
 *     ref-count -- so the baa->attr inherits the ref-count.
 */
static struct bgp_advertise_attr *
bgp_advertise_intern (struct hash *hash, struct attr *attr)
{
  struct bgp_advertise_attr ref;
  struct bgp_advertise_attr *baa;

  qassert(bgp_attr_is_interned(attr)) ;

  ref.attr = attr ;
  baa = (struct bgp_advertise_attr *) hash_get (hash, &ref, baa_hash_alloc);
  baa->refcnt++;

  return baa;
}

/*------------------------------------------------------------------------------
 * Reduce references to the given baa.
 *
 * Releases the ref-count on the baa->attr which is owned by the reference to
 * the baa.
 */
static void
bgp_advertise_unintern (struct hash *hash, struct bgp_advertise_attr *baa)
{
  struct attr* attr ;

  attr = baa->attr ;

  if (baa->refcnt > 1)
    baa->refcnt -= 1 ;
  else
    {
      if (attr != NULL)
        {
          struct bgp_advertise_attr *ret;

          ret = hash_release (hash, baa);
          if (ret != baa)
            {
              zlog_err("BUG: failed to find interned adv-attr -- found %s",
                                 (ret == NULL) ? "nothing" : "something else") ;
              return ;  /* leaky but safer      */
            } ;
        } ;

      baa_free (baa);
    } ;

  if (attr != NULL)
    bgp_attr_unintern(attr) ;
} ;

struct bgp_advertise *
bgp_advertise_clean (struct peer *peer, struct bgp_adj_out *adj,
                     afi_t afi, safi_t safi)
{
  struct bgp_advertise *adv;
  struct bgp_advertise_attr *baa;
  struct bgp_advertise *next;

  adv = adj->adv;
  baa = adv->baa;
  next = NULL;

  if (baa)
    {
      /* Unlink myself from advertise attribute FIFO.  */
      bgp_advertise_delete (baa, adv);

      /* Fetch next advertise candidate. */
      next = baa->base.head ;

      /* Unintern BGP advertise attribute.  */
      bgp_advertise_unintern (peer->hash[afi][safi], baa);
    }

  /* Unlink myself from advertisement FIFO.  */
  bgp_advertise_fifo_del(adv);

  /* Free memory.  */
  bgp_advertise_free (adj->adv);
  adj->adv = NULL;

  return next;
}

/*==============================================================================
 * Adj-Out Handling
 *
 * The bgp_adj_out object lives on the related bgp_node (rn) rn->adj_out list,
 * and the peer's adj_out_head[afi][safi] list.  It represents the state of
 * any advertisement sent (in the most recent UPDATE message for the prefix)
 * for the peer for the prefix.
 *
 * If an advertisement is pending for the peer for the prefix, an adv object
 * is attached to the adj-out.
 */

/* BGP adjacency keeps minimal advertisement information.  */

int
bgp_adj_out_lookup (struct peer *peer, struct prefix *p,
                    afi_t afi, safi_t safi, struct bgp_node *rn)
{
  struct bgp_adj_out *adj;

  for (adj = rn->adj_out; adj; adj = adj->adj_next)
    if (adj->peer == peer)
      break;

  if (! adj)
    return 0;

  return (adj->adv
          ? (adj->adv->baa ? 1 : 0)
          : (adj->attr ? 1 : 0));
}

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
  struct bgp_adj_out*   adj = NULL;
  struct bgp_adj_out**  adj_out_head ;
  struct bgp_advertise *adv;

  assert(rn != NULL) ;
  assert((afi == rn->table->afi) && (safi == rn->table->safi)) ;
  assert(attr != NULL) ;

  if (qdebug)
    {
      bool rsclient ;

      qassert(attr != NULL) ;
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
    return;

  /* Look for adjacency information.
   */
  for (adj = rn->adj_out; adj; adj = adj->adj_next)
    if (adj->peer == peer)
          break;

  if (adj == NULL)
    {
      adj = XCALLOC (MTYPE_BGP_ADJ_OUT, sizeof (struct bgp_adj_out));

      /* Add to list of adj_out stuff for the peer
       */
      adj->peer = bgp_peer_lock (peer);

      adj_out_head = &(peer->adj_out_head[afi][safi]) ;

      adj->route_next = *adj_out_head ;
      adj->route_prev = NULL ;
      if (*adj_out_head != NULL)
        (*adj_out_head)->route_prev = adj ;
      *adj_out_head = adj ;

      /* Add to list of adj out stuff for the bgp_node
       */
      adj->rn = bgp_lock_node (rn);

      adj->adj_next = rn->adj_out ;
      adj->adj_prev = NULL ;
      if (rn->adj_out != NULL)
        rn->adj_out->adj_prev = adj ;
      rn->adj_out = adj ;
    } ;

  /* The adj_out contains:  pointer to owner peer, and list pointers for same
   *                        pointer to parent bgp_node, and list pointers ditto
   *                        pointer to bgp_advertise (adv)
   *                        pointer to attributes (attr)
   *
   * We here discard any current adv and make a new one, rescheduling
   * everything.
   *
   * The adj->attr are those actually sent to the peer, so we don't care about
   * those here.
   */
  if (adj->adv)
    bgp_advertise_clean (peer, adj, afi, safi);

  adj->adv = bgp_advertise_new ();

  adv = adj->adv;
  adv->rn = rn;

  assert (adv->binfo == NULL);
  adv->binfo = bgp_info_lock (binfo); /* bgp_info adj_out reference */

  if (attr)
    adv->baa = bgp_advertise_intern (peer->hash[afi][safi], attr);
  else
    adv->baa = baa_new ();
  adv->adj = adj;

  /* Add new advertisement to advertisement attribute list.
   */
  bgp_advertise_add (adv->baa, adv);

  /* Finally, add new advertisement to the peer's update list
   */
  bgp_advertise_fifo_add(&peer->sync[afi][safi]->update, adv);
}

void
bgp_adj_out_unset (struct bgp_node *rn, struct peer *peer, struct prefix *p,
                   afi_t afi, safi_t safi)
{
  struct bgp_adj_out *adj;
  struct bgp_advertise *adv;

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
  for (adj = rn->adj_out; adj; adj = adj->adj_next)
    if (adj->peer == peer)
      break;

  if (adj == NULL)
    return;

  assert(rn == adj->rn) ;

  /* Clear up previous advertisement.
   */
  if (adj->adv != NULL)
    bgp_advertise_clean (peer, adj, afi, safi);

  if (adj->attr != NULL)
    {
      /* We need advertisement structure.
       */
      adj->adv = bgp_advertise_new ();
      adv = adj->adv;
      adv->rn = rn;
      adv->adj = adj;

      /* Add to synchronization entry for withdraw announcement
       *
       * Withdraws live on their own queue, but also adv->baa   == NULL
       *                                         and adv->binfo == NULL
       */
      bgp_advertise_fifo_add(&peer->sync[afi][safi]->withdraw, adv);

      /* Schedule flush of withdraws
       */
      bgp_withdraw_schedule(peer) ;
    }
  else
    bgp_adj_out_remove(rn, adj, peer, afi, safi) ;
}

void
bgp_adj_out_remove (struct bgp_node *rn, struct bgp_adj_out *adj,
                    struct peer *peer, afi_t afi, safi_t safi)
{
  assert((rn == adj->rn) && (peer == adj->peer)) ;

  if (adj->attr)
    bgp_attr_unintern (adj->attr) ;     /* about to discard the adj, so
                                         * don't care about ->attr      */

  if (adj->adv)
    bgp_advertise_clean (peer, adj, afi, safi);

  /* Unhook from peer
   */
  if (adj->route_next != NULL)
    adj->route_next->route_prev = adj->route_prev ;
  if (adj->route_prev != NULL)
    adj->route_prev->route_next = adj->route_next ;
  else
    peer->adj_out_head[afi][safi] = adj->route_next ;

  bgp_peer_unlock (peer);

  /* Unhook from bgp_node
   */
  if (adj->adj_next)
    adj->adj_next->adj_prev = adj->adj_prev;
  if (adj->adj_prev)
    adj->adj_prev->adj_next = adj->adj_next;
  else
    rn->adj_out = adj->adj_next;

  bgp_unlock_node (rn);

  /* now can release memory.
   */
  XFREE (MTYPE_BGP_ADJ_OUT, adj);
}

void
bgp_adj_in_set (struct bgp_node *rn, struct peer *peer, struct attr *attr)
{
  struct bgp_adj_in *adj;
  struct bgp_adj_in**  adj_in_head ;

  for (adj = rn->adj_in; adj; adj = adj->adj_next)
    {
      if (adj->peer == peer)
        {
          if (adj->attr != attr)
            {
              if (adj->attr != NULL)            /* paranoia     */
                bgp_attr_unintern (adj->attr);
              adj->attr = bgp_attr_intern (attr);
            }
          return;
        }
    }

  /* Need to create a brand new bgp_adj_in                      */

  adj = XCALLOC (MTYPE_BGP_ADJ_IN, sizeof (struct bgp_adj_in));

  /* Set the interned attributes                                */
  adj->attr = bgp_attr_intern (attr);

  /* Add to list of adj in stuff for the peer                   */
  adj->peer = bgp_peer_lock (peer);

  adj_in_head = &(peer->adj_in_head[rn->table->afi][rn->table->safi]) ;

  adj->route_next = *adj_in_head ;
  adj->route_prev = NULL ;
  if (*adj_in_head != NULL)
    (*adj_in_head)->route_prev = adj ;
  *adj_in_head = adj ;

  /* Add to list of adj in stuff for the bgp_node               */
  adj->rn = bgp_lock_node (rn);

  adj->adj_next = rn->adj_in ;
  adj->adj_prev = NULL ;
  if (rn->adj_in != NULL)
    rn->adj_in->adj_prev = adj ;
  rn->adj_in = adj ;
}

void
bgp_adj_in_remove (struct bgp_node *rn, struct bgp_adj_in *bai)
{
  bgp_peer peer = bai->peer ;
  struct bgp_adj_in**  adj_in_head ;

  adj_in_head = &(peer->adj_in_head[rn->table->afi][rn->table->safi]) ;

  assert(rn == bai->rn) ;

  /* Done with this copy of attributes
   *
   * About to discard the adj-in entry, so don't care about bai->attr.
   */
  bgp_attr_unintern (bai->attr);

  /* Unhook from peer                                   */
  if (bai->route_next != NULL)
    bai->route_next->route_prev = bai->route_prev ;
  if (bai->route_prev != NULL)
    bai->route_prev->route_next = bai->route_next ;
  else
    *adj_in_head = bai->route_next ;

  bgp_peer_unlock (peer);

  /* Unhook from bgp_node                               */
  if (bai->adj_next)
    bai->adj_next->adj_prev = bai->adj_prev;
  if (bai->adj_prev)
    bai->adj_prev->adj_next = bai->adj_next;
  else
    rn->adj_in = bai->adj_next;

  bgp_unlock_node (rn);

  /* now can release memory.                            */
  XFREE (MTYPE_BGP_ADJ_IN, bai);
}

void
bgp_adj_in_unset (struct bgp_node *rn, struct peer *peer)
{
  struct bgp_adj_in *adj;

  for (adj = rn->adj_in; adj; adj = adj->adj_next)
    if (adj->peer == peer)
      break;

  if (! adj)
    return;

  bgp_adj_in_remove (rn, adj);
}

void
bgp_sync_init (struct peer *peer)
{
  afi_t afi;
  safi_t safi;
  struct bgp_synchronize *sync;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
        sync = XCALLOC (MTYPE_BGP_SYNCHRONISE,
                        sizeof (struct bgp_synchronize));
        bgp_advertise_fifo_init(&sync->update);
        bgp_advertise_fifo_init(&sync->withdraw);
        bgp_advertise_fifo_init(&sync->withdraw_low);
        peer->sync[afi][safi] = sync;
        peer->hash[afi][safi] = hash_create (baa_hash_key, baa_hash_cmp);
      }
}

void
bgp_sync_delete (struct peer *peer)
{
  afi_t afi;
  safi_t safi;

  for (afi = AFI_IP; afi < AFI_MAX; afi++)
    for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++)
      {
        if (peer->sync[afi][safi])
          XFREE (MTYPE_BGP_SYNCHRONISE, peer->sync[afi][safi]);
        peer->sync[afi][safi] = NULL;

        if (peer->hash[afi][safi])
          hash_free (peer->hash[afi][safi]);
        peer->hash[afi][safi] = NULL;
      }
}
