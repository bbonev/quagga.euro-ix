/* Periodic Fifo
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
#include <misc.h>

#include "pfifo.h"
#include "memory.h"

/*==============================================================================
 * Periodic Fifo.
 *
 * The periodic fifo is designed to provide a fifo where most of the time items
 * are added and removed in time order, but occasionally items are removed or
 * inserted out of time order.  This can (clearly) be achieved with priority
 * queue... but this is for when that is too expensive.
 *
 * The periodic fifo is implemented by:
 *
 *   a) a list pointer pair in each item -- so that items can be added/removed
 *      in the middle of the underlying list.
 *
 *   b) a set of auxiliary pointers -- one for each period.
 *
 *      At any given moment any item in the body of the pfifo is for a period
 *      p: P0 <= p < P0 + np -- where np is the number of periods in the pfifo.
 *
 *      When an item for period p is placed in an empty pfifo, P0 is set so
 *      that p = P0 + np - 1.
 *
 *      When an item for period p < P0 is placed in the pfifo it is not
 *      placed in the body of the pfifo, but in the pre-P0 'ex' period.
 *
 *      When an item for period p >= P0 + np is placed in the pfifo, P0 is
 *      advanced so that p = P0 + np - 1, and anything which was for a period
 *      less than P0 is moved to the now pre-P0 'ex' period.
 *
 *   c) a simple list of all pre-P0 items the 'ex' period.
 *
 * A priority queue would require a pointer and (possibly) a heap index.  Which
 * is possibly less memory -- unless the item requires a list pointer pair
 * for use at other times.  The cost of the priority queue for very large
 * fifos is the log(n) cost of maintaining the heap.
 *
 * The compromise implicit in the periodic fifo is that it is divided into
 * equal length periods, and that the order within each period is not
 * maintained for items which are inserted out of order.  Such items, are
 * inserted at the end of their respective period.
 *
 * Taking items from the head of the fifo is achieved by advancing P0.  All
 * items with a time less than the new P0 are moved to the pre-P0 period,
 * whence they can be removed.
 *
 * Note that the pfifo comprises two separate fifos, the pre-P0 and the
 * from P0 onwards.  The pre-P0 is a simple double linked list, and can be
 * emptied/added to in the usual way.
 *
 *------------------------------------------------------------------------------
 * The auxiliary f[] array is organised:
 *
 *        +------------+
 *      0 .            . <- Pb  -- base period
 *        . future     .
 *        .            .
 *        +------------+
 *        .            . <- P0  -- earliest period held in pfifo
 *        . past       .
 *        .            .
 *        +------------+
 *     fi | first @ Pf | <- Pf  -- first not empty period
 *        .            .
 *        .            .
 *        .            .
 *        | first @ Pl | <- Pl  -- last not empty period
 *        +------------+
 *     zi | last       | <- Pz  -- first period after last not empty
 *        .            .
 *        . future     .
 *        .            .
 *        +------------+
 *     np                      -- number of entries in f[]
 *
 * This can wrap round, but for any period p: P0 <= p < P0 + np we can
 * calculate the index for the period:
 *
 *    i = p - Pb ;
 *    if (i >= np)
 *      i -= np ;
 *
 * That is, if wrapped round:
 *
 *        +------------+
 *      0 .            . <- Pb  -- base period
 *        .            .
 *        | first @ Pl | <- Pl  -- last not empty period
 *        +------------+
 *     zi | last       | <- Pz  -- first period after last not empty
 *        .            .
 *        . future     .
 *        .            .
 *        . future     .
 *        .            .
 *        +------------+
 *        .            . <- P0  -- earliest period held in pfifo
 *        . past       .
 *        .            .
 *        +------------+
 *     fi | first @ Pf | <- Pf  -- first not empty period
 *        .            .
 *        .            .
 *        +------------+
 *     np                      -- number of entries in f[]
 *
 * We have: P0 - np < Pb <= P0  -- so, since Pz > (Pb + np) the calculation of
 * the index i works.
 *
 * The first and last periods may not be empty.  Will move fi up or zi down
 * to maintain that when items are removed.
 *
 * The entry at fi is the address of the first item in the pfifo, which will
 * have a prev pointer == NULL.
 *
 * The entry at zi is the address of the last item in the pfifo, which will
 * have a next pointer == NULL.
 *
 * When the pfifo is empty, will have Pz == Pf == 0.  At all other times,
 * Pz > Pf >= 0.
 *
 * For items > Pf and < Pz - 1 (ie all those between the first and last not
 * empty periods, the pointer is either the address of the first item in the
 * period, or, if the period is empty, the address of the first item in the
 * next not-empty period.
 *
 *------------------------------------------------------------------------------
 * To delete an item from the pfifo, or to move an item, or to find the period
 * associated with an item, the caller must preserve the pfifo_index_t
 * associated with the item.
 *
 * While in the pfifo an item's index does not change.  All items in the 'ex'
 * period nominally have the PFIFO_INDEX_EX index.
 *
 * As items are added or moved they are given a new index, and the add and move
 * functions return that -- returning PFIFO_INDEX_EX if the item ends up in the
 * 'ex' period.  As a side effect, P0 may move to accommodate the new item or
 * the new period for a moved item.
 *
 * The pfifo_take() and pfifo_flush() functions explicitly move items to the
 * 'ex' period as required.
 *
 * The caller has two basic options:
 *
 *   1) empty items out of the 'ex' period before doing anything which
 *      requires an item's index -- assuming the caller either marks items
 *      which are no longer the pfifo any more, or discards them so they are
 *      no longer of concern.
 *
 *   2) process the 'ex' queue to mark items which are no longer in the body
 *      of the pfifo.
 *
 *      This may be done by starting at the *tail* of the 'ex' queue, and
 *      working back to the start or the last previously marked item.
 *
 * In any event, it is the caller's responsibility to keep track of the index
 * of items in the body of the pfifo, and the 'ex'-ness of items which have
 * fallen off the back of the pfifo.
 *
 * Where a pfifo function takes an index, it will treat any value >= 'np' as
 * refering to the 'ex' period.
 */

/*------------------------------------------------------------------------------
 * Get next index
 */
inline static pfifo_index_t
pfifo_index_next(pfifo pf, pfifo_index_t i)
{
  return (i < pf->nx) ? i + 1 : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Get previous index
 */
inline static pfifo_index_t
pfifo_index_prev(pfifo pf, pfifo_index_t i)
{
  return (i > 0) ? i - 1 :  pf->nx ;
} ;

/*------------------------------------------------------------------------------
 * Get index from period p -- assuming:  P0 <= p < P0 + np  (number of periods)
 */
inline static pfifo_index_t
pfifo_index_fp(pfifo pf, pfifo_period_t p)
{
  pfifo_index_t i ;

  i = p - pf->pb ;
  if (i >= pf->np)
    i -= pf->np ;

  return i ;
} ;

/*==============================================================================
 * Creation and destruction of pfifo objects.
 */

/*------------------------------------------------------------------------------
 * Initialise a pfifo -- creating one if required.
 *
 * Requires: 'pf'           -- NULL => create new pfifo object
 *                             otherwise initialise the given structure.
 *           'i_max'        -- number of periods - 1:   1..PFIFO_INDEX_MAX
 *           'n_slack       -- number of slack periods: < i_max
 *           'offset'       -- offset of pfifo_pair_t in each pfifo_item.
 *
 * The n_slack MUST be < i_max.
 *
 * The i_max must be at most the maximum period index which the caller is
 * capable of storing.  So indexes in the pfifo body will be: 0..i_max.  For
 * the 'ex' period the "official" index is PFIFO_INDEX_EX, but anything greater
 * than i_max is deemed to mean the 'ex' period.
 *
 * The pfifo will support up to i_max periods from P0 to P0 + i_max - 1.
 *
 * As items are added to the pfifo, the P0 is advanced when required.  Each
 * time that happens, n_slack periods are added at the end of the fifo, beyond
 * the new period required for the current item.  This is so that as time
 * moves on, P0 does not have to be updated every time a new item is added
 * just ahead of the last period in the pfifo.
 *
 * So, if n_slack > 0, the number of periods supported is i_max - n_slack.
 *
 * (P0 is only advanced where required, so at any given moment there may be
 * upto i_max periods in the pfifo, but the minimum is i_max - n_slack.)
 *
 * NB: If pf != NULL, the i_max MUST be consistent with the size of the
 *     pfifo object provided -- the periods are held in a flexible array
 *     at the end of the object, so the space to allocate is:
 *
 *        offset_of(pfifo_t, f[i_max + 1])
 *
 * Returns:  address of initialised pfifo -- allocated if pf was NULL
 */
extern pfifo
pfifo_init_new(pfifo pf, uint i_max, uint n_slack, uint offset)
{
  uint size ;

  assert((i_max >= 1) && (i_max <= PFIFO_INDEX_MAX)) ;
  assert(n_slack < i_max) ;
  assert(offset <= USHRT_MAX) ;

  size = offsetof(pfifo_t, f[i_max + 1]) ;

  if (pf == NULL)
    pf = XCALLOC(MTYPE_PFIFO, size) ;
  else
    memset(pf, 0, size) ;

  pf->np      = i_max + 1 ;
  pf->nx      = i_max ;
  pf->n_slack = n_slack ;
  pf->off     = offset ;

  return pf ;
} ;

/*------------------------------------------------------------------------------
 * Free given dynamically allocated pfifo.
 *
 * It is the caller's responsibility to free any items which may be in the
 * pfifo.
 *
 * Calling pfifo_flush() will put everything onto the pre-T0 list, and
 * return the address of the first item -- which may be used to take control
 * of all the items in the pfifo.
 *
 * Returns:  NULL
 */
extern pfifo
pfifo_free(pfifo pf)
{
  if (pf != NULL)
    XFREE(MTYPE_PFIFO, pf) ;

  return NULL ;
} ;

/*==============================================================================
 * Adding, removing and moving pfifo items.
 *
 */
static void pfifo_advance(pfifo pf, pfifo_period_t new_p0, bool set) ;
static pfifo_index_t pfifo_append_ex(pfifo pf, pfifo_item frst,
                                               pfifo_item last) ;
inline static void pfifo_trim_leading(pfifo pf, pfifo_index_t i,
                                            pfifo_item item, pfifo_item next) ;
inline static void pfifo_trim_leading_empty(pfifo pf, pfifo_index_t ni,
                                           pfifo_period_t p, pfifo_item first) ;

/*------------------------------------------------------------------------------
 * Add item to pfifo
 *
 * Returns:  index for item -- PFIFO_INDEX_EX if period < current P0
 */
extern pfifo_index_t
pfifo_item_add(pfifo pf, pfifo_item item, pfifo_period_t p)
{
  pfifo_pair_t*  p_item_p ;
  pfifo_period_t pz ;

  uint i, zi ;

  pfifo_item    last ;
  pfifo_pair_t* p_last_p ;
  pfifo_item    next ;
  pfifo_pair_t* p_next_p ;

  p_item_p = pfifo_pair_get(pf, item) ;

  pz = p + 1 ;

  if (pz >= pf->pz)
    {
      if (pz == pf->pz)
        {
          /* Item belongs in the (not empty) last period -- majority case.
           *
           * Since the last period is guaranteed not empty, we can just append.
           *
           * The current last is the item which is to come before the new one.
           */
          zi = pf->zi ;                 /* index for pf->pz.            */

          last     = pf->f[zi] ;        /* insert after the last        */
          p_last_p = pfifo_pair_get(pf, last) ;

          qassert((last != NULL) && (p_last_p->next == NULL)) ;

          p_last_p->next = item ;
        }
      else
        {
          /* Item belongs beyond the current last period.
           *
           * Need to advance the last period, which may require P0 to be
           * advanced, which may move stuff to the 'ex' period.
           *
           * We have pz = new-Pz, where pz > Pz.
           *
           * The first thing to sort out is whether the new-Pz wraps around
           * and:
           *
           *   (a) is within the current "future".
           *
           *   (b) requires P0 to advance, but not affecting current periods
           *
           *   (c) requires P0 and Pf to advance, moving some current periods
           *       to the 'ex' period.
           *
           *   (d) empties out the current pfifo
           *
           *        +------------+
           *      0 .            . <- Pb  -- base period
           *   (a)->. future     .
           *        .            . <- max-Pz  == P0 + n - 1
           *        +------------+
           *        .            . <- P0  -- earliest period held in pfifo
           *   (b)->. past       .
           *        .            .
           *        +------------+
           *     fi | first @ Pf | <- Pf  -- first not empty period
           *        .            .
           *   (c)->.            .
           *        .            .
           *        | first @ Pl | <- Pl  -- last not empty period
           *        +------------+
           *     zi | last       | <- Pz  -- first period after last not empty
           *        .            .
           *   (d)->. future     .
           *        .            .
           *     nx |            |        -- number of entries in f[] - 1
           *        +------------+
           *     np                       -- number of entries in f[]
           */
          if (pz > (pf->p0 + pf->nx))
            {
              /* The new pz will wrap round past P0, so we need to adjust P0,
               * at least.
               *
               * If the new pz wraps around past Pf, we need to move some items
               * to 'ex', and adjust P0 and Pf together.  Note that this can
               * empty out the pfifo.
               *
               * As we do this we leave n_slack "spare" periods ahead of the
               * new-Pz, to cut down the number of times this has to be done
               * as Pz advances.
               *
               * When we have finished, the pfifo is either empty, or we have
               * Pf such that Pf..new-Pz lies withing the current bounds of the
               * pfifo.
               */
              pfifo_advance(pf, pz - pf->nx + pf->n_slack, true /* set P0 */) ;

              qassert((pf->pz == 0) || (pz <= (pf->pf + pf->nx))) ;
            } ;

          if (pf->pz == 0)
            {
              /* The pfifo is empty !
               *
               * Pz will become the given px, and Pf will become the given p.
               *
               * Need to set new P0 if (Pz - n - slack) > P0.
               *
               * Set Pb = P0.
               *
               * Set things up to add new last period, having set the new first
               * period (the same).
               */
              pfifo_period_t new_p0 ;

              if (pz < (pfifo_period_t)(pf->np - pf->n_slack))
                new_p0 = 0 ;
              else
                new_p0 = pz - (pf->np - pf->n_slack) ;

              if (new_p0 < pf->p0)
                new_p0 = pf->p0;

              pf->pb = new_p0 ;
              pf->p0 = new_p0 ;

              i = p - new_p0 ;
              pf->fi = i ;
              pf->pf = p ;
              pf->f[i] = item ;         /* start of new first period    */

              qassert(i < (pf->nx)) ;
              zi = i + 1 ;
              last = NULL ;
            }
          else
            {
              /* The pfifo is not empty, and we need to add zero or more
               * empty periods, before adding the new last period.
               *
               * Append the new item to the current last one.
               *
               * Pz will become the given pz, and Pf will become the given p.
               *
               * Need to set new P0 if (Pz - n - slack) > P0.
               *
               * Set Pb = P0.
               */
              uint a ;

              zi       = pf->zi ;       /* currently                    */
              last     = pf->f[zi] ;    /* insert after the last        */
              p_last_p = pfifo_pair_get(pf, last) ;

              qassert((last != NULL) && (p_last_p->next == NULL)) ;

              p_last_p->next = item ;

              qassert(pz > pf->pz) ;

              a  = pz - pf->pz ;        /* number of periods to add including
                                         * the new last one             */
              do
                {
                  i = zi ;
                  pf->f[i] = item ;     /* start of new period          */

                  zi = pfifo_index_next(pf, i) ;

                  a -= 1 ;
                }
              while (a > 0) ;
            } ;

          pf->zi = zi ;                 /* update                       */
          pf->pz = pz ;
        } ;

      pf->f[zi] = item ;                /* new last item                */

      p_item_p->next = NULL ;
      p_item_p->prev = last ;

      return zi ;
    }
  else if (p < pf->pf)
    {
      /* The item to be added is somewhere before the first not empty period.
       */
      uint a ;

      if (p < pf->p0)
        {
          /* The item to be added is somewhere before P0 -- so add to 'ex'
           *
           * Returns PFIFO_INDEX_EX
           */
          return pfifo_append_ex(pf, item, item) ;
        } ;

      /* The item to be added is somewhere after or at P0, but before pf
       * (the first not empty) -- so need to move pf back to this item's p,
       * filling empty periods as we do so.
       */
      i        = pf->fi ;       /* currently                    */
      next     = pf->f[i] ;     /* insert after the last        */
      p_next_p = pfifo_pair_get(pf, next) ;

      qassert((next != NULL) && (p_next_p->prev == NULL)) ;

      p_next_p->prev = item ;

      a  = pf->pf - p ;         /* number of periods to add including
                                 * the new first one            */
      while (1)
        {
          i = pfifo_index_prev(pf, i) ;
          a -= 1 ;
          if (a == 0)
            break ;

          pf->f[i] = next ;     /* start of new empty period    */
        } ;

      pf->fi   = i ;            /* new first period             */
      pf->pf   = p ;
      pf->f[i] = item ;

      p_item_p->next = next ;
      p_item_p->prev = NULL ;

      return i ;
    } ;

  /* We have p >= pf->pf and p < pf->pz -- so inserting in the body of the
   * pfifo, at or after the first not-empty and before the last not-empty.
   *
   * If we add to an empty period, this becomes the first in that period.  If
   * there are empty periods preceding this one, need to update them, too.
   */
  i = pfifo_index_fp(pf, p) ;   /* index of period to add to    */

  next     = pf->f[pfifo_index_next(pf, i)] ;   /* insert before here    */
  qassert(next != NULL) ;
  p_next_p = pfifo_pair_get(pf, next) ;
  qassert(p_next_p->prev != NULL) ;

  last     = p_next_p->prev ;       /* last of target period */
  qassert(last != NULL) ;
  p_last_p = pfifo_pair_get(pf, last) ;

  qassert(p_last_p->next == next) ;

  p_last_p->next = item ;
  p_next_p->prev = item ;
  p_item_p->next = next ;
  p_item_p->prev = last ;

  if (pf->f[i] == next)
    {
      /* The current period was empty -- cannot be the first period, by rule.
       */
      uint pi ;

      pi = i ;
      do
        {
          /* It should be impossible to get (pf->f[pi] == item) when
           * pi == fi -- but we avoid falling into an infinite loop
           * here.
           */
          if (pi == pf->fi)
            {
              qassert(false) ;
              break ;
            } ;

          pf->f[pi] = item ;
          pi = pfifo_index_prev(pf, pi) ;
        }
      while (pf->f[pi] == next) ;
    } ;

  return i ;
} ;

/*------------------------------------------------------------------------------
 * Delete item from pfifo
 *
 * It is the caller's responsibility to present the same index as was returned
 * when the item was added.  It is also the caller's responsibility to ensure
 * that the item is in the pfifo !
 *
 * Note that this does not place the item in the 'ex' period.
 */
extern void
pfifo_item_del(pfifo pf, pfifo_item item, pfifo_index_t i)
{
  pfifo_pair_t*  p_item_p ;
  pfifo_item    prev ;
  pfifo_item    next ;

  p_item_p = pfifo_pair_get(pf, item) ;

  /* Cut from the underlying fifo
   */
  next = p_item_p->next ;
  prev = p_item_p->prev ;

  if (next != NULL)
    {
      pfifo_pair_get(pf, next)->prev = prev ;
      p_item_p->next = NULL ;
    } ;

  if (prev != NULL)
    {
      pfifo_pair_get(pf, prev)->next = next ;
      p_item_p->prev = NULL ;
    } ;

  /* Now worry about the effect on the period that the item was in.
   */
  if (i < pf->np)
    {
      /* Now worry about:
       *
       *   a) updating the pointer to the first item in the current period.
       *
       *   b) updating the pointer to the last item in the fifo if we have
       *      just removed the last item.
       *
       *   c) collapsing down empty periods if we have just emptied the first
       *      or the last period
       */
      if (next == NULL)
        {
          /* We are removing the last item, which must be the last item
           * in the last period !
           *
           * We are, by rule, not allowed to have an empty last period,
           * so we track back, deleting empty periods.
           */
          qassert(pfifo_index_next(pf, i) == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          if (prev == NULL)
            {
              /* We have just emptied out the fifo -- set Pz = Pf = 0
               */
              qassert(i == pf->fi) ;

              pf->pz = pf->pf = 0 ;
            }
          else
            {
              /* prev is the new last item in the pfifo -- which is not empty.
               *
               * Track back across any empty periods.
               *
               * If there is only one period, we have:
               *
               *  (1)   +------------+
               *  i, fi | first      | <- Pf  -- first & last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == Pf + 1
               *        .            .
               *
               * where first != item because the pfifo is not empty after
               * removing one item.
               *
               * If first == prev, we end up with:
               *
               *        +------------+
               *  i, fi | first=prev | <- Pf  -- first & last not empty period
               *        +------------+
               *     zi | prev=first | <- Pz  -- Pz == Pf + 1
               *        .            .
               *
               * ie: a pfifo with one item in it, which is fine.
               *
               * We know that the pfifo is not empty, after removing the item,
               * so first != item.  So we set f[zi] = prev, and we are done.
               *
               * If there is more than one period, we have:
               *
               *  (2)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | q          | <- p   -- last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * If q != item, and we can simply set f[zi] = prev, so that
               * we end up with:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | q != prev  | <- p   -- last not empty period
               *        +------------+
               *     zi | prev       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * If q == prev, we end up with:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | q=prev     | <- p   -- last not empty period
               *        +------------+
               *     zi | prev=q     | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * ie: a last period with one item in it, which is fine.  (So, if
               * f[i] != item, we can set f[zi] = prev.)
               *
               * So... for all cases where f[i] != item, we can simply set
               * f[zi] = prev.
               *
               * But... if f[i] == item we had just one item in the last
               * period:
               *
               *  (3)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * So we are about to empty the last period, so we need to track
               * back, discarding empty periods, and reduce Pz and zi.  Note
               * that as we track back we will find either another not-empty
               * period or the first period -- so we stop on case (1) or (2),
               * above.
               */
              pfifo_index_t zi ;

              zi = pf->zi ;

              if (pf->f[i] == item)
                {
                  /* Track back and update Pz and zi.
                   */
                  pfifo_period_t pz ;

                  pz = pf->pz ;
                  do
                    {
                      /* It should be impossible to get (pf->f[i] == item) when
                       * i == fi -- but we avoid falling into an infinite loop
                       * here.
                       */
                      if (i == pf->fi)
                        {
                          qassert(false) ;
                          break ;
                        } ;

                      pz -= 1 ;
                      zi  = i ;
                      i   = pfifo_index_prev(pf, i) ;
                    }
                  while (pf->f[i] == item) ;

                  pf->zi = zi ;
                  pf->pz = pz ;
                } ;

              pf->f[zi] = prev ;
            } ;
        }
      else
        {
          /* Something follows the item we just removed -- pfifo is not empty.
           */
          if (prev == NULL)
            {
              /* We have removed the first item of the first period.
               */
              pfifo_trim_leading(pf, i, item, next) ;
            }
          else if (pf->f[i] == item)
            {
              /* We have removed the first item of some period other than the
               * first.
               *
               * We need to update the pointer for the current period.
               *
               * If the previous period is empty, we need to update its
               * pointer too, and back to the first not empty period (which
               * there must be).
               *
               * We know that:
               *
               *   * there is at least one earlier item (prev != NULL), so
               *     the first period cannot now be empty.
               *
               *     Also, i != fi -- so there are at least 2 periods.
               *
               *   * there is at least one later item (next != NULL), so the
               *     last period cannot now be empty.
               *
               * And hence, the number of periods is not going to change.
               *
               * The first step is to update the pointer for the current
               * period, and there are two cases:
               *
               *  (1)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        +------------+
               *     zi | last       | <- Pz  -- Pz = p + 1
               *
               * We set f[i] = next.  If next == last, we now have one item
               * left in the last period.
               *
               *  (2)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        | q          |
               *        .            .
               *        +------------+
               *     zi | last       | <- Pz
               *
               * We set f[i] = next.  If next == q, we have just set the
               * current period empty.
               *
               * So... we can set f[i] = next in all cases.
               *
               * If the preceding period was empty (so cannot be the first
               * period) we have:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *        | item       |        -- empty period
               *      i | next       | <- p   -- last not empty period
               *        .            .
               *
               * So, we need to update the previous periods, too.  And all
               * preceding empty periods.  Noting that first != item.
               */
              do
                {
                  /* It should be impossible to get (pf->f[i] == next) when
                   * i == fi -- but we avoid falling into an infinite loop
                   * here.
                   */
                  if (i == pf->fi)
                    {
                      qassert(false) ;
                      break ;
                    } ;

                  pf->f[i] = next ;
                  i = pfifo_index_prev(pf, i) ;
                }
              while (pf->f[i] == item) ;
            } ;
        } ;
    }
  else
    {
      /* The index is for the 'ex' period.
       *
       * NB: we treat any index which is out of range as the 'ex' period.
       */
      if (next == NULL)
        {
          /* We have just removed the last item, which was last item of ex.
           */
          qassert(pf->ex.tail == item) ;

          pf->ex.tail = prev ;
        } ;

      if (prev == NULL)
        {
          /* We have just removed the first item.
           */
          qassert(pf->ex.head == item) ;

          pf->ex.head = next ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Move an item in the pfifo from its current period to a new one.
 *
 * It is the caller's responsibility to present the same index as was returned
 * when the item was added.  It is also the caller's responsibility to ensure
 * that the item is in the pfifo !
 *
 * NB: does nothing if the target period is the same as the current period.
 *
 *     This means that the item's order wrt other items in its current period
 *     is not affected.  In particular, if the item is in the 'ex' period,
 *     and the target is < P0, the item does not move.
 *
 * NB: treats all indexes i >= pf->np as being the 'ex' period.
 */
extern pfifo_index_t
pfifo_item_move(pfifo pf, pfifo_item item, pfifo_index_t i, pfifo_period_t p)
{
  pfifo_period_t pi ;
  pfifo_pair_t*  p_item_p ;
  pfifo_item     prev ;
  pfifo_item     next ;

  /* If the item is not known to be in the body of the pfifo, then do nothing
   * at all.
   */
  if (i > pf->nx)
    {
      /* The index is for the 'ex' period.
       *
       * NB: we treat any index which is out of range as the 'ex' period.
       */
      if (p >= pf->p0)
        {
          pfifo_item_del(pf, item, i) ;
          return pfifo_item_add(pf, item, p) ;
        } ;

      return PFIFO_INDEX_EX ;
    } ;

  /* If the given index is not a currently valid one, then we are stumped, and
   * return without changing anything.
   *
   * If the new period is the current one, then we need do nothing also.
   */
  pi = pfifo_period_fi(pf, i) ;
  if ((pi < pf->pf) || (pi >= pf->pz))
    {
      qassert(false) ;
      return i ;
    } ;

  if (p == pi)
    return i ;

  /* If the new period is < P0, we can simply delete the item and add it to
   * the 'ex' period -- returning PFIFO_INDEX_EX.
   */
  if (p < pf->p0)
    {
      pfifo_item_del(pf, item, i) ;
      return pfifo_append_ex(pf, item, item) ;
    } ;

  /* If the new period requires a change of Pf, we also do the operation the
   * simple minded way: deleting and inserting the item.
   *
   * This reduces the number of cases we try to optimise.
   */
  if (p >= (pf->pf + pf->nx))
    {
      pfifo_item_del(pf, item, i) ;
      return pfifo_item_add(pf, item, p) ;
    } ;

  /* So far, so good... the item to move is:
   *
   *   * in the current pfifo:  P0 <= p < (Pf + nx)
   *
   *     may need to change P0, but NOT Pf.
   *
   *   * the new period is not current one
   *
   * Prepare to cut the item and reinsert it.
   */
  p_item_p = pfifo_pair_get(pf, item) ;

  next = p_item_p->next ;
  prev = p_item_p->prev ;

  /* If we are not about to remove the first item of its period, we can simply
   * cut it from the list and re-insert -- looking out for removing the last
   * item in the pfifo
   *
   * Now, if we are about to remove the first item of its period, then we may
   * be creating an empty period.  What we want to avoid is collapsing down
   * leading or trailing empty periods, only to build them up again.  Or to
   * update a run of empty periods on delete, only to change them a second
   * time on addition.
   */
  if (item != pf->f[i])
    {
      /* We are not about to remove the first item of its period.
       */
      qassert(prev != NULL) ;

      if (next == NULL)
        {
          /* We are removing the last item in the pfifo, but not emptying the
           * last period.
           *
           * So, update f[zi] and proceed to cut the item from the list and
           * re-insert it.
           */
          qassert(pfifo_index_next(pf, i) == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          pf->f[pf->zi] = prev ;
        }
      else
        {
          /* This is easy -- we are not removing the first item in any period,
           * nor are we removing the last item in the pfifo.
           *
           * So, proceed to cut the item from the list and re-insert it.
           */
          pfifo_pair_get(pf, next)->prev = prev ;
        } ;

      pfifo_pair_get(pf, prev)->next = next ;
    }
  else
    {
      /* We are about to remove the first item of its period...
       */
      pfifo_item_del(pf, item, i) ;

#if 0
      pfifo_index_t ni ;

      ni = pfifo_index_next(pf, i) ;

      if (next == NULL)
        {
          /* We have emptied the last period
           */
          qassert(ni   == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          if (prev == NULL)
            {
              /* Special case -- have just removed the only item in the pfifo.
               *
               * So just set it empty and then add back in the usual way.
               */
              pf->pz = pf->pf = 0 ;
            }
          else
            {
              /* Have emptied the last period, but not the pfifo.
               *
               * We have:
               *
               *        +------------+
               *      0 .            . <- Pb  -- base period
               *   (a)->. future     .
               *        .            .
               *        +------------+
               *        .            . <- P0  -- earliest period in pfifo
               *   (b)->. past       .
               *        .            .
               *        +------------+
               *        | first      | <- Pf  -- first not empty period
               *        .            .
               *   (c)->.            .
               *        .            .
               *      i | item       | <- Pl  -- now empty period !
               *        +------------+
               *     ni | item       | <- Pz
               *        .            .
               *   (d)->. future     .
               *        .            .
               *        +------------+
               *     np                       -- number of entries in f[]
               *
               * We know that p != Pl, and that: PO <= p < (Pf + np - 1)
               *
               * And the four cases:
               *
               *   (a) the new period is well ahead of the now empty last
               *       period, but we don't have to change P0.
               *
               *       Need to fill empty periods upto the new last period,
               *       and then fill in the new last period.
               *
               *   (b) the new period is further ahead of the now empty last
               *       period, and we have to change P0.
               *
               *       We change P0 so that the new period is the last
               *       possible period -- ie. we change P0 by the minimum
               *       necessary.
               *
               *       Then treat as (a).
               *
               *   (c) the new period is before the now empty last period.
               *
               *       Track back, looking for the first not-empty period
               *       (there will be one), or the new period.  Then:
               *
               *         * if find a not-empty period before getting to the
               *           new period,
               *
               *
               *           pdate Pz, zi and f[zi], and then add the item
               *           in the usual way.
               *
               *         * if the new period is at now the last not-empty one,
               *           insert the new last item (appending back on fifo) and
               *         update Pz, zi and f[zi].
               *
               *
               *   (d) the new period is ahead of the last now not-empty
               *       period, and we don't have to change P0.
               *
               *       Treat as (a).
               *
               *   * if the new period is behind the last period: p < Pz
               *
               *  * if the new period is ahead of the last period: p >= Pz
               *
               *    move forwards setting empty periods, insert the new last
               *    item (appending back on fifo) and update Pz, zi and f[zi].
               *
               */
              pfifo_period_t pz ;

              pz = pf->pz ;
              qassert(pz != (p + 1)) ;  /* new period != old one        */

              if (pz >)

              do
                {
                  /* It should be impossible to get (pf->f[i] == item) when
                   * i == fi -- but we avoid falling into an infinite loop
                   * here.
                   */
                  if (i == pf->fi)
                    {
                      qassert(false) ;
                      break ;
                    } ;

                  pz -= 1 ;
                  zi  = i ;
                  i   = pfifo_index_prev(pf, i) ;
                }
              while (pf->f[i] == item) ;

              /* We have found the now last not-empty period, or the period we
               * want to set, and it is empty.
               *
               * May need to adjust P0, but NOT Pf.
               *
               * We have:
               *
               *        +------------+
               *      0 .            . <- Pb  -- base period
               *   (a)->. future     .
               *        .            .
               *        +------------+
               *        .            . <- P0  -- earliest period in pfifo
               *   (b)->. past       .
               *        .            . <- max-Pz  == P0 + n - 1
               *        +------------+
               *        | first      | <- Pf  -- first not empty period
               *        .            .
               *   (c)->.            .
               *        .            .
               *      i | q          | <-     -- now last not empty period
               *        +------------+
               *     zi | ????       | <- pz
               *        .            .
               *   (d)->. future     .
               *        .            .
               *        +------------+
               *     np                       -- number of entries in f[]
               *
               * And the four cases:
               *
               *   (a) the new period is well ahead of the now last not-empty
               *       period, but we don't have to change P0.
               *
               *   (b) the new period is further ahead of the now last not-empty
               *       period, and we have to change P0.
               *
               *       We change P0 so that the new period is the last
               *       possible period -- ie. we change P0 by the minimum
               *       necessary.
               *
               *   (c) the new period is at or before the now last not-empty,
               *       so we set the new last item, and insert the item in
               *       the usual way.
               *
               *   (d) the new period is ahead of the last now not-empty
               *       period, and we don't have to change P0.
               *
               * Or we have:
               *
               *        +------------+
               *        | first      | <- Pf  -- first not empty period
               *        .            .
               *        .            .
               *        .            .
               *      i | item       | <- p   -- now last not empty period
               *        +------------+
               *     zi | ????       | <- pz
               *
               * Which means we have found the period to be set, and it was
               * empty -- so we can go ahead and fill in f[zi], Pz and zi.
               */
              if (pz <= (p + 1))
                {
                  if (p >= (pf->p0 + pf->nx))
                    {
                      pf->p0 = p - pf->nx ;
                      qassert(p->p0 <= pf->pf) ;
                    } ;

                  while (pz < (p + 1)) ;
                    {
                      i   = zi ;
                      pf->f[i] = item ;

                      zi  = pfifo_index_prev(pf, i) ;
                      pz += 1 ;
                    } ;

                  pfifo_pair_get(pf, prev)->next = item ;
                  p_item_p->next = NULL ;
                  p_item_p->prev = prev ;

                  pf->f[zi] = item ;
                  pf->zi = zi ;
                  pf->pz = pz ;

                  return i ;
                } ;

              /* The new period is behind the now last not-empty, so
               */
              pf->zi = zi ;
              pf->pz = pz ;
              pf->f[zi] = prev ;
            } ;
        }
      else if (pf->f[ni] == next)
        {
          /* We have emptied the current period.
           */
          if (prev == NULL)
            {
              /* We have emptied the first period
               *
               */
            }
          else
            {
              /* We have emptied some period which is neither the first, nor
               * the last.
               */


            } ;
        }
      else
        {
          /* We have not emptied the current period.
           *
           * So, update the first item in the period, and proceed to add the
           * item back in the usual way.
           */
          pf->f[i] = next ;
        } ;
#endif
    } ;

  /* By the time we get to here, the item has been removed from the pfifo, as
   * if by pfifo_item_del(), and it can now be added back in the usual way.
   */
  return pfifo_item_add(pf, item, p) ;

#if 0
  /*
   *
   */
  if (p < pi)
    {
      /* We are inserting in some period earlier than the current one, but
       * at a period >= P0.
       *
       *   P0 <= p < pi < Pz
       */
      ni = pfifo_index_fp(pf, p) ;
      qassert(ni != i) ;

      if (next == NULL)
        {
          /* We have just removed the last item, and what we intend to add
           * belongs in an earlier period.
           *
           * If we have emptied out the pfifo, then we can add the item
           * to a new first and last period.
           *
           * If the last period is empty, we need to track back, discarding
           * empty periods -- but can stop if we reach the new period.
           *
           * If the last period is not now empty, then we can go ahead and
           * simply add the new item.
           */
          pfifo_index_t zi ;

          qassert(pfifo_index_next(pf, i) == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          if (prev == NULL)
            {
              /* We have just emptied the fifo -- so put the item back in its
               * new place.
               *
               * Which we know we can do without adjusting P0.
               */
              qassert(i == pf->fi) ;
              qassert((pf->p0 <= p) && (p < (pf->p0 + pf->n))) ;

              pf->pf = p ;
              pf->pz = p + 1 ;

              zi = pfifo_index_next(pf, ni) ;

              pf->fi = ni ;
              pf->zi = zi ;

              pf->f[ni] = item ;
              pf->f[zi] = item ;

              return ni ;
            }
          else if (pf->f[i] == item)
            {
              /* The pfifo is not empty, but the last period is.
               *
               * We have to track back, removing any trailing empty
               * periods, until we:
               *
               *   * find that the new item is now the last item.
               *
               *   * find a not empty period beyond where we need to add the
               *     current one, in which case we update the end of the
               *     pfifo, and insert the item in the usual way.
               */
              uint a ;

              a = 0 ;
              do
                {
                  a += 1 ;
                  zi = i ;
                  i = pfifo_index_prev(pf, i) ;

                  if (ni == i)
                    {
                      /* While stepping back over empty tailing periods, we
                       * have reached the period in which the item now
                       * belongs.  So the item is now the last item, and
                       * we can put it back on the end and update Pz and zi.
                       */
                      qassert(pf->f[zi] == item) ;

                      pfifo_pair_get(pf, prev)->next = item ;

                      qassert(p_item_p->prev == prev) ;
                      qassert(p_item_p->next == NULL) ;

                      qassert((pf->pz - a) == (p + 1)) ;

                      pf->zi = zi ;
                      pf->pz = p + 1 ;

                      return ni ;
                    } ;
                }
              while ((pf->f[i] == item) && (i != ni)) ;

              /* Trim off the trailing empty periods.  The item's new period
               * is somewhere earlier than the current last period.
               */
              pf->zi  = zi ;
              pf->pz -= a ;
            } ;

          return pfifo_item_add(pf, item, p) ;
        }
      else if (item == pf->f[i])
        {
          /* We have not removed the last item -- so the pfifo is not
           * empty and the last period is not empty.  But we have removed the
           * first item in its period.
           *
           * We wish to reinsert the item in some earlier period.
           *
           *
           *
           * If we have taken the first item of its period, then we need to
           * update its pointer.  If that....
           *
           *
           *
           *
           *
           * If we have emptied out the pfifo, then we can add the item
           * to a new first and last period.
           *
           * If the last period is empty, we need to track back, discarding
           * empty periods -- but can stop if we reach the new period.
           *
           * If the last period is not now empty, then we can go ahead and
           * simply add the new item.
           */
          pfifo_index_t zi ;

          qassert(pfifo_index_next(pf, i) == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          if (prev == NULL)
            {
              /* We have just emptied the fifo -- so put the item back in its
               * new place.
               *
               * Which we know we can do without adjusting P0.
               */
              qassert(i == pf->fi) ;
              qassert((pf->p0 <= p) && (p < (pf->p0 + pf->n))) ;

              pf->pf = p ;
              pf->pz = p + 1 ;

              zi = pfifo_index_next(pf, ni) ;

              pf->fi = ni ;
              pf->zi = zi ;

              pf->f[ni] = item ;
              pf->f[zi] = item ;

              return ni ;
            }
          else if (pf->f[i] == item)
            {
              /* The pfifo is not empty, but the last period is.
               *
               * We have to track back, removing any trailing empty
               * periods, until we:
               *
               *   * find that the new item is now the last item.
               *
               *   * find a not empty period beyond where we need to add the
               *     current one, in which case we update the end of the
               *     pfifo, and insert the item in the usual way.
               */
              uint a ;

              a = 0 ;
              do
                {
                  a += 1 ;
                  zi = i ;
                  i = pfifo_index_prev(pf, i) ;

                  if (ni == i)
                    {
                      /* While stepping back over empty tailing periods, we
                       * have reached the period in which the item now
                       * belongs.  So the item is now the last item, and
                       * we can put it back on the end and update Pz and zi.
                       */
                      qassert(pf->f[zi] == item) ;

                      pfifo_pair_get(pf, prev)->next = item ;

                      qassert(p_item_p->prev == prev) ;
                      qassert(p_item_p->next == NULL) ;

                      qassert((pf->pz - a) == (p + 1)) ;

                      pf->zi = zi ;
                      pf->pz = p + 1 ;

                      return ni ;
                    } ;
                }
              while ((pf->f[i] == item) && (i != ni)) ;

              /* Trim off the trailing empty periods.  The item's new period
               * is somewhere earlier than the current last period.
               */
              pf->zi  = zi ;
              pf->pz -= a ;
            } ;

          return pfifo_item_add(pf, item, p) ;
        }


    }





















  /* If we have just removed the first item in its period....
   *
   */


  if (pf->f[i] == item)
    {
      /* We have removed the first item in its period.
       *
       *
       *
       *
       */


    } ;


  pz = p + 1 ;

  if (pz >= pf->pz)
    {
      if (pz == pf->pz)
        {
          /* Item belongs in the (not empty) last period -- majority case.
           *
           * Since the last period is guaranteed not empty, we can just append.
           *
           * The current last is the item which is to come before the new one.
           */
          zi = pf->zi ;                 /* index for pf->pz.            */

          last     = pf->f[zi] ;        /* insert after the last        */
          p_last_p = pfifo_pair_get(pf, last) ;

          qassert((last != NULL) && (p_last_p->next == NULL)) ;

          p_last_p->next = item ;
        }
      else
        {
          /* Item belongs beyond the current last period.
           *
           * Need to advance the last period, which may require P0 to be
           * advanced, which may move stuff to the 'ex' period.
           *
           * We have pz = new-Pz, where pz > Pz.
           *
           * The first thing to sort out is whether the new-Pz wraps around
           * and:
           *
           *   (a) is within the current "future".
           *
           *   (b) requires P0 to advance, but not affecting current periods
           *
           *   (c) requires P0 and Pf to advance, moving some current periods
           *       to the 'ex' period.
           *
           *   (d) empties out the current pfifo
           *
           *        +------------+
           *      0 .            . <- Pb  -- base period
           *   (a)->. future     .
           *        .            . <- max-Pz  == P0 + n - 1
           *        +------------+
           *        .            . <- P0  -- earliest period held in pfifo
           *   (b)->. past       .
           *        .            .
           *        +------------+
           *     fi | first @ Pf | <- Pf  -- first not empty period
           *        .            .
           *   (c)->.            .
           *        .            .
           *        | first @ Pl | <- Pl  -- last not empty period
           *        +------------+
           *     zi | last       | <- Pz  -- first period after last not empty
           *        .            .
           *   (d)->. future     .
           *        .            .
           *        +------------+
           *     np                       -- number of entries in f[]
           */
          pfifo_period_t pz_max ;

          pz_max = pf->p0 + pf->nx ;    /* max-Pz without affecting P0    */

          if (pz_max < pz)
            pfifo_advance(pf, pz - (pf->np - pf->n_slack), true /* set P0 */) ;

          if (pf->pz == 0)
            {
              /* The pfifo is empty !
               *
               * Pz will become the given px, and Pf will become the given p.
               *
               * Need to set new P0 if (Pz - n - slack) > P0.
               *
               * Set Pb = P0.
               *
               * Set things up to add new last period, having set the new first
               * period (the same).
               */
              pfifo_period_t new_p0 ;

              if (pz < (pfifo_period_t)(pf->np - pf->n_slack))
                new_p0 = 0 ;
              else
                new_p0 = pz - (pf->np - pf->n_slack) ;

              if (new_p0 < pf->p0)
                new_p0 = pf->p0;

              pf->pb = new_p0 ;
              pf->p0 = new_p0 ;

              i = p - new_p0 ;
              pf->fi = i ;
              pf->pf = p ;
              pf->f[i] = item ;         /* start of new first period    */

              qassert(i < (pf->nx)) ;
              zi = i + 1 ;
              last = NULL ;
            }
          else
            {
              /* The pfifo is not empty, and we need to add zero or more
               * empty periods, before adding the new last period.
               *
               * Append the new item to the current last one..
               *
               * Pz will become the given px, and Pf will become the given p.
               *
               * Need to set new P0 if (Pz - n - slack) > P0.
               *
               * Set Pb = P0.
               */
              uint a ;

              zi       = pf->zi ;       /* currently                    */
              last     = pf->f[zi] ;    /* insert after the last        */
              p_last_p = pfifo_pair_get(pf, last) ;

              qassert((last != NULL) && (p_last_p->next == NULL)) ;

              p_last_p->next = item ;

              qassert(pz > pf->pz) ;

              a  = pz - pf->pz ;        /* number of periods to add including
                                         * the new last one             */
              do
                {
                  i = zi ;
                  pf->f[i] = item ;     /* start of new period          */

                  zi = pfifo_index_next(pf, i) ;

                  a -= 1 ;
                }
              while (a > 0) ;
            } ;

          pf->zi   = zi ;               /* update                       */
          pf->pz   = pz ;
        } ;

      pf->f[zi] = item ;                /* new last item                */

      p_item_p->next = NULL ;
      p_item_p->prev = last ;

      return i ;
    }
  else if (p < pf->pf)
    {
      /* The item to be added is somewhere before the first not empty period.
       */
      uint a ;

      if (p < pf->p0)
        {
          /* The item to be added is somewhere before P0 -- so add to 'ex'
           */
          pfifo_append_ex(pf, item, item) ;
          return PFIFO_INDEX_EX ;
        } ;

      /* The item to be added is somewhere after or at P0, but before pf
       * (the first not empty) -- so need to move pf back to this item's p,
       * filling empty periods as we do so.
       */
      i        = pf->fi ;       /* currently                    */
      next     = pf->f[i] ;     /* insert after the last        */
      p_next_p = pfifo_pair_get(pf, next) ;

      qassert((next != NULL) && (p_next_p->prev == NULL)) ;

      p_next_p->prev = item ;

      a  = pf->pf - p ;         /* number of periods to add including
                                 * the new first one            */
      while (1)
        {
          i = pfifo_index_prev(pf, i) ;
          a -= 1 ;
          if (a == 0)
            break ;

          pf->f[i] = next ;     /* start of new empty period    */
        } ;

      pf->fi   = i ;            /* new first period             */
      pf->pf   = p ;
      pf->f[i] = item ;

      p_item_p->next = next ;
      p_item_p->prev = NULL ;

      return i ;
    } ;

  /* We have p >= pf->pf and p < pf->pz -- so inserting in the body of the
   * pfifo, at or after the first not-empty and before the last not-empty.
   *
   * If we add to an empty period, this becomes the first in that period.  If
   * there are empty periods preceding this one, need to update them, too.
   */
  i = pfifo_index_fp(pf, p) ;   /* index of period to add to    */

  next     = pf->f[pfifo_index_next(pf, i)] ;   /* insert before here    */
  qassert(next != NULL) ;
  p_next_p = pfifo_pair_get(pf, next) ;
  qassert(p_next_p->prev != NULL) ;

  last     = p_next_p->prev ;       /* last of target period */
  qassert(last != NULL) ;
  p_last_p = pfifo_pair_get(pf, last) ;

  qassert(p_last_p->next == next) ;

  p_last_p->next = item ;
  p_next_p->prev = item ;
  p_item_p->next = next ;
  p_item_p->prev = last ;

  if (pf->f[i] == next)
    {
      /* The current period was empty -- cannot be the first period, by rule.
       */
      uint pi ;

      pi = i ;
      do
        {
          /* It should be impossible to get (pf->f[pi] == item) when
           * pi == fi -- but we avoid falling into an infinite loop
           * here.
           */
          if (pi == pf->fi)
            {
              qassert(false) ;
              break ;
            } ;

          pf->f[pi] = item ;
          pi = pfifo_index_prev(pf, pi) ;
        }
      while (pf->f[pi] == next) ;
    } ;

  return i ;
























  /* Now worry about the effect on the period that the item was in.
   */
  if (i < pf->np)
    {
      /* Now worry about:
       *
       *   a) updating the pointer to the first item in the current period.
       *
       *   b) updating the pointer to the last item in the fifo if we have
       *      just removed the last item.
       *
       *   c) collapsing down empty periods if we have just emptied the first
       *      or the last period
       */
      if (next == NULL)
        {
          /* We are removing the last item, which must be the last item
           * in the last period !
           *
           * We are, by rule, not allowed to have an empty last period,
           * so we track back, deleting empty periods.
           */
          qassert(pfifo_index_next(pf, i) == pf->zi) ;
          qassert(item == pf->f[pf->zi]) ;

          if (prev == NULL)
            {
              /* We have just emptied out the fifo -- set Pz = Pf = 0
               */
              qassert(i == pf->fi) ;

              pf->pz = pf->pf = 0 ;
            }
          else
            {
              /* prev is the new last item in the pfifo -- which is not empty.
               *
               * Track back across any empty periods.
               *
               * If there is only one period, we have:
               *
               *  (1)   +------------+
               *  i, fi | first      | <- Pf  -- first & last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == Pf + 1
               *        .            .
               *
               * where first != item because the pfifo is not empty after
               * removing one item.
               *
               * If first == prev, we end up with:
               *
               *        +------------+
               *  i, fi | first      | <- Pf  -- first & last not empty period
               *        +------------+
               *     zi | first      | <- Pz  -- Pz == Pf + 1
               *        .            .
               *
               * ie: a pfifo with one item in it, which is fine.
               *
               * We know that the pfifo is not empty, after removing the item,
               * so first != item.  So we set f[zi] = prev, and we are done.
               *
               * If there is more than one period, we have:
               *
               *  (2)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | q          | <- p   -- last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * If q != item, and we can simply set f[zi] = prev.
               * If q == prev, we end up with:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | prev       | <- p   -- last not empty period
               *        +------------+
               *     zi | prev       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * ie: a last period with one item in it, which is fine.  (So, if
               * f[i] != item, we cab set f[zi] = prev.)
               *
               * If q == item we had just one item in the last period:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        +------------+
               *     zi | item       | <- Pz  -- Pz == p + 1
               *        .            .
               *
               * So we are about to empty the last period, so we need to track
               * back, discarding empty periods, and reduce Pz and zi.  Note
               * that as we track back we will find either another not-empty
               * period or the first period -- so we stop on case (1) or (2),
               * above.
               */
              pfifo_index_t zi ;

              zi = pf->zi ;

              if (pf->f[i] == item)
                {
                  /* Track back and update Pz and zi.
                   */
                  uint a ;

                  a = 0 ;
                  do
                    {
                      /* It should be impossible to get (pf->f[i] == item) when
                       * i == fi -- but we avoid falling into an infinite loop
                       * here.
                       */
                      if (i == pf->fi)
                        {
                          qassert(false) ;
                          break ;
                        } ;

                      a += 1 ;
                      zi = i ;
                      i  = pfifo_index_prev(pf, i) ;
                    }
                  while (pf->f[i] == item) ;

                  pf->zi  = zi ;
                  pf->pz -= a ;
                } ;

              pf->f[zi] = prev ;
            } ;
        }
      else
        {
          /* Something follows the item we just removed -- pfifo is not empty.
           */
          if (prev == NULL)
            {
              /* We have removed the first item of the first period.
               */
              pfifo_trim_leading(pf, i, item, next) ;
            }
          else if (pf->f[i] == item)
            {
              /* We have removed the first item of some period other than the
               * first.
               *
               * We need to update the pointer for the current period.
               *
               * If the previous period is empty, we need to update its
               * pointer too, and back to the first not empty period (which
               * there must be).
               *
               * We know that:
               *
               *   * there is at least one earlier item (prev != NULL), so
               *     the first period cannot now be empty.
               *
               *     Also, i != fi -- so there are at least 2 periods.
               *
               *   * there is at least one later item (next != NULL), so the
               *     last period cannot now be empty.
               *
               * And hence, the number of periods is not going to change.
               *
               * The first step is to update the pointer for the current
               * period, and there are two cases:
               *
               *  (1)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        +------------+
               *     zi | last       | <- Pz  -- Pz = p + 1
               *
               * We set f[i] = next.  If next == last, we now have one item
               * left in the last period.
               *
               *  (2)   +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *      i | item       | <- p   -- last not empty period
               *        | q          |
               *        .            .
               *        +------------+
               *     zi | last       | <- Pz
               *
               * We set f[i] = next.  If next == q, we have just set the
               * current period empty.
               *
               * So... we can set f[i] = next in all cases.
               *
               * If the preceding period was empty (so cannot be the first
               * period) we have:
               *
               *        +------------+
               *     fi | first      | <- Pf  -- first not empty period
               *        .            .
               *        | item       |        -- empty period
               *      i | next       | <- p   -- last not empty period
               *        .            .
               *
               * So, we need to update the previous periods, too.  And all
               * preceding empty periods.  Noting that first != item.
               */
              do
                {
                  /* It should be impossible to get (pf->f[i] == next) when
                   * i == fi -- but we avoid falling into an infinite loop
                   * here.
                   */
                  if (i == pf->fi)
                    {
                      qassert(false) ;
                      break ;
                    } ;

                  pf->f[i] = next ;
                  i = pfifo_index_prev(pf, i) ;
                }
              while (pf->f[i] == item) ;
            } ;
        } ;
    } ;
#endif
} ;

/*------------------------------------------------------------------------------
 * Get address of current head of pfifo.
 *
 * Returns the first pre-P0 ('ex') or the first P0 or beyond.
 *
 * Returns:  address of head item.  NULL if pfifo completely empty.
 *
 * One strategy for pulling stuff from the fifo is to check the head, and if
 * that item's time has come, take it out of the fifo by pfifo_item_next().
 * But see pfifo_advance().
 */
extern pfifo_item
pfifo_item_head(pfifo pf)
{
  pfifo_item  item ;

  item = pf->ex.head ;

  if ((item == NULL) && (pf->pz != 0))
    item = pf->f[pf->fi] ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Pull the next item from the given pfifo.
 *
 * Empties out the pf->ex list first, then the periods, in order.
 *
 * Returns:  address of next item.  NULL if none left.
 */
extern pfifo_item
pfifo_item_next(pfifo pf)
{
  pfifo_item  item ;
  pfifo_item  next ;

  item = pf->ex.head ;

  if (item != NULL)
    {
      /* pf->ex item, straightforward double linked list.
       */
      next = pfifo_pair_get(pf, item)->next ;

      pf->ex.head = next ;
      if (next == NULL)
        pf->ex.tail = NULL ;
    }
  else if (pf->pz != 0)
    {
      /* No ex, and pfifo not empty, so pf->f[fi] is the first item in the
       * pfifo.
       */
      uint i ;
      pfifo_pair_t*  p_item_p ;

      i    = pf->fi ;
      item = pf->f[i] ;
      qassert(item != NULL) ;

      p_item_p = pfifo_pair_get(pf, item) ;
      qassert(p_item_p->prev == NULL) ;

      next = p_item_p->next ;

      if (next != NULL)
        {
          /* The pfifo still has something in it.
           */
          pfifo_trim_leading(pf, i, item, next) ;
        }
      else
        {
          /* The pfifo is now empty.
           */
          pf->pz = pf->pf = 0 ;
        } ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Pull the next item from the pf->ex list of the given pfifo.
 *
 * Returns:  address of next item.  NULL if none left.
 */
extern pfifo_item
pfifo_item_next_ex(pfifo pf)
{
  pfifo_item  item ;

  item = pf->ex.head ;

  if (item != NULL)
    {
      pfifo_item  next ;

      next = pfifo_pair_get(pf, item)->next ;

      pf->ex.head = next ;
      if (next == NULL)
        pf->ex.tail = NULL ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Transfer contents of all periods upto but excluding 'p' to the ex list.
 *
 * This is provided so that a pfifo may be used to schedule items which have
 * a "not before time t" associated with them.  Items which are ready are moved
 * to the ex list, whence they may be processed.
 *
 * If required, set P0 to the given value (if it is greater than the current).
 *
 * Returns:  address of first item of the pf->ex list, if any.
 */
extern pfifo_item
pfifo_take(pfifo pf, pfifo_period_t p, bool set)
{
  if (p > pf->p0)
    pfifo_advance(pf, p, set) ;

  return pf->ex.head ;
} ;

/*------------------------------------------------------------------------------
 * Flush contents of pfifo onto the pf->ex list.
 *
 * Returns:  address of first item of the pf->ex list, if any.
 */
extern pfifo_item
pfifo_flush(pfifo pf)
{
  if (pf->pz != 0)
    {
      pfifo_item  frst, last ;

      qassert(pf->pz > pf->pf) ;

      frst = pf->f[pf->fi] ;    /* first item to add to pf->ex  */
      last = pf->f[pf->zi] ;    /* last item to add to pf->ex   */

      qassert((frst != NULL) && (last != NULL)) ;

      pfifo_append_ex(pf, frst, last) ;

      pf->pz = pf->pf = 0 ;     /* set empty                    */
    } ;

  return pf->ex.head ;
} ;

/*------------------------------------------------------------------------------
 * Flush contents of pfifo onto a single list, and empty it completely.
 *
 * Returns:  address of first item of the list
 */
extern pfifo_item
pfifo_flush_empty(pfifo pf)
{
  pfifo_item head ;

  head = pfifo_flush(pf) ;
  ddl_init(pf->ex) ;

  return head ;
} ;

/*------------------------------------------------------------------------------
 * Get the period of the first item in the pfifo.
 *
 * Returns:  p0 - 1 if there is something on the pf->ex list
 *           pn     if there is something in the pfifo (and nothing pf->ex)
 *           PFIFO_PERIOD_MAX otherwise.
 */
extern pfifo_period_t
pfifo_first_period(pfifo pf)
{
  if (pf->ex.head != NULL)
    return pf->p0 - 1 ;

  return pfifo_first_not_ex_period(pf) ;
} ;

/*------------------------------------------------------------------------------
 * Get the period of the first item in the body of the pfifo -- ignoring 'ex'.
 *
 * Returns:  pn     if there is something in the body of the pfifo
 *           PFIFO_PERIOD_MAX otherwise.
 */
extern pfifo_period_t
pfifo_first_not_ex_period(pfifo pf)
{
  if (pf->pz != 0)
    return pf->pf ;

  return PFIFO_PERIOD_MAX ;
} ;

/*------------------------------------------------------------------------------
 * Transfer contents of all periods upto but excluding 'new-P0' to the ex list.
 *
 * If required, set P0 to the new-P0
 *
 * NB: the new-P0 MUST be greater than current P0.
 *
 * NB: we append stuff to the 'ex' period.  This is required behaviour, so that
 *     the caller knows that any new items in the 'ex' period follow any
 *     items already in that period -- see above.
 */
static void
pfifo_advance(pfifo pf, pfifo_period_t new_p0, bool set)
{
  qassert(new_p0 > pf->p0) ;

  if      (new_p0 >= pf->pz)
    {
      /* The pfifo is empty, or contains nothing before the new_p0.
       *
       * Empty everything out.  Then, if we are about to change P0, we must
       * also set Pb.
       */
      pfifo_flush(pf) ;

      if (set)
        pf->pb = new_p0 ;
    }
  else if (new_p0 > pf->pf)
    {
      /* We have to move periods Pf..new_p0-1 to the ex list.
       *
       * NB: we are leaving at least one period -- since new_p0 < Pz -- so
       *     the pfifo cannot end up empty.
       */
      uint fi, i ;
      pfifo_item     keep, frst, last, next ;
      pfifo_pair_t*  p_keep_p ;

      /* Move stuff to the 'ex' period.
       */
      fi = pf->fi ;
      i  = pfifo_index_fp(pf, new_p0) ;

      keep     = pf->f[i] ;             /* first item to be kept        */
      qassert(keep != NULL) ;
      p_keep_p = pfifo_pair_get(pf, keep) ;

      frst     = pf->f[fi] ;            /* first item to move           */
      last     = p_keep_p->prev ;       /* last item to move            */
      p_keep_p->prev = NULL ;           /* cut items from first to keep */

      qassert(last != NULL) ;
      qassert(frst != NULL) ;

      pfifo_append_ex(pf, frst, last) ;

      /* Now we need to update fi.  In general, what we have is:
       *
       *        .            .
       *        +------------+
       *     fi | first @ Pf | <- Pf  -- first not empty period
       *        .            .
       *      i | keep       | <- new_p0
       *        .            .
       *        | first @ Pl | <- Pl  -- last not empty period
       *        +------------+
       *     zi | last       | <- Pz  -- first period after last not empty
       *        .            .
       *
       * Which we update to:
       *
       *        .            .
       *        +------------+
       *     fi | keep       | <- Pf == new_p0
       *      i | next       |
       *        .            .
       *        | first @ Pl | <- Pl  -- last not empty period
       *        +------------+
       *     zi | last       | <- Pz  -- first period after last not empty
       *        .            .
       *
       * If keep == next then the period at fi is now empty, which by rule
       * is invalid, so we need to trim off leading empty periods.
       *
       * We have not emptied the pfifo (since new_p0 < Pz), so the limiting
       * case is:
       *
       *        .            .
       *        +------------+
       *     fi | keep       | <- Pf == new_p0
       *      i | next       | <- Pl  -- last not empty period
       *        +------------+
       *     zi | last       | <- Pz  -- first period after last not empty
       *        .            .
       */
      qassert(new_p0 < (pf->pz - 1)) ;

      fi   = i ;
      i    = pfifo_index_next(pf, fi) ;
      next = pf->f[i] ;

      if (keep == next)
        pfifo_trim_leading_empty(pf, i, new_p0, next) ;
      else
        {
          pf->fi = fi ;
          pf->pf = new_p0 ;
        } ;
    } ;

  /* Set new P0 as required, and return the (now) first 'ex' item.
   */
  if (set)
    pf->p0 = new_p0 ;
} ;

/*------------------------------------------------------------------------------
 * Append frst..last to pf->ex -- if any
 *
 * Returns:  PFIFO_INDEX_EX
 */
static pfifo_index_t
pfifo_append_ex(pfifo pf, pfifo_item frst, pfifo_item last)
{
  if (frst != NULL)
    {
      pfifo_item tail ;

      qassert(last != NULL) ;

      tail = pf->ex.tail ;

      pfifo_pair_get(pf, frst)->prev = tail ;
      pfifo_pair_get(pf, last)->next = NULL ;

      if (tail == NULL)
        {
          /* Make new ex list
           */
          pf->ex.head = frst ;
        }
      else
        {
          /* Append to existing list.
           */
          pfifo_pair_t*  p_tail_p ;

          p_tail_p = pfifo_pair_get(pf, tail) ;
          qassert(p_tail_p->next == NULL) ;

          p_tail_p->next = frst ;
        } ;

      pf->ex.tail    = last ;
    } ;

  return PFIFO_INDEX_EX ;
} ;

/*------------------------------------------------------------------------------
 * Trim any leading empty periods from pfifo, after:
 *
 *   a) removing the first item of the first period.
 *
 *   b) NOT emptying the pfifo
 *
 * A period is empty if it points to the same item as the next period.
 *
 * If the first period is now empty, we need to deal with that, since by rule
 * that is not allowed.
 *
 * By rule, the last period may not be empty.  The pfifo is not empty, so the
 * last period is still not empty, even if it is also the first period.
 *
 * Where there is only one period, we have:
 *
 *        +------------+
 *     fi | item       | <- Pf  -- first & last not empty period
 *        +------------+
 *     zi | last       | <- Pz  -- Pz == Pf + 1
 *
 * The pfifo is not empty after removing item, so we can simply
 * set f[fi] = next.  That may leave if next == last:
 *
 *        +------------+
 *     fi | last       | <- Pf  -- first & last not empty period
 *        +------------+
 *     zi | last       | <- Pz
 *
 * which is fine.  Note that when looking at the last period, next == last does
 * NOT mean the last period is empty.
 *
 * Where there are two periods, we have:
 *
 *        +------------+
 *     fi | item       | <- Pf  -- first not empty period
 *        | q          |
 *        +------------+
 *     zi | last       | <- Pz  -- Pz == Pf + 2
 *
 * If q != next, the first period is not now empty, so we can simply set f[fi]
 * the the new first item.
 *
 * If q == next, the first period is now empty, so we need to advance
 * both fi and Pf:
 *
 *        +------------+
 *        | item       |
 *     fi | next       | <- Pf  -- first not empty period
 *        +------------+
 *     zi | last       | <- Pz  -- Pz == Pf + 1
 *
 * Where there are more than two periods, we have:
 *
 *        +------------+
 *     fi | item       | <- Pf  -- first not empty period
 *        | q          |
 *        | qq         |
 *        . ?          .
 *        +------------+
 *     zi | last       | <- Pz  -- Pz == Pf + ?
 *
 * If q != next, the first period is not now empty, so we can simply set f[fi]
 * the the new first item.
 *
 * If q == next, the first period is now empty, so we need to advance both
 * fi and Pf.  If qq == next, need to step past that to and any further empty
 * periods until reach a not empty period, which may be the last one.
 */
inline static void
pfifo_trim_leading(pfifo pf, pfifo_index_t i, pfifo_item item, pfifo_item next)
{
  pfifo_index_t ni ;

  qassert(item != next) ;
  qassert(next != NULL) ;
  qassert((i == pf->fi) && (pf->f[i] == item)) ;

  ni = pfifo_index_next(pf, i) ;

  if ((pf->f[ni] == next) && (ni != pf->zi))
    {
      /* First period is now empty.
       *
       * First period is not the last, and hence only, period, because the
       * pfifo is not empty.
       *
       * Step past this and any subsequent empty periods, and then update the
       * first period index and period.
       */
      pfifo_trim_leading_empty(pf, ni, pf->pf, next) ;
    }
  else
    {
      /* First period is not empty, but since we took the first
       * item, we need to update it.
       *
       * Here the first period may be the same as the last one.
       */
      pf->f[i] = next ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * First period is now empty -- but the pfifo is not.
 *
 * First period is not the last, and hence only, period.
 *
 * Step past this and any subsequent empty periods, and then update the
 * first period index and period.
 *
 * Requires:  ni    -- index of item just after current fi
 *            p     -- current pf->pf
 *            first -- address of new first item in the pfifo
 */
inline static void
pfifo_trim_leading_empty(pfifo pf, pfifo_index_t ni, pfifo_period_t p,
                                                               pfifo_item first)
{
  pfifo_index_t i ;

  qassert(first != NULL) ;

  do
    {
      /* Note that in this case we may get (pf->f[ni] == next)
       * when (ni == pf->zi) -- when the last period has just
       * one item in it.
       */
      p += 1 ;
      i  = ni ;
      ni = pfifo_index_next(pf, ni) ;
    }
  while ((pf->f[ni] == first) && (ni != pf->zi)) ;

  pf->fi = i ;
  pf->pf = p ;
} ;
