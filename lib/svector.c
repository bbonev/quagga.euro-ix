/* "Small Vector"
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#include "svector.h"
#include "memory.h"

/*==============================================================================
 * A "Small Vector" is a collection of up to some 65,000 items.
 *
 * The principle objective of a "Small Vector" -- svec --  is to map an index,
 * 1..65000, to the address of some item.  The index for an item is stable from
 * the moment the item is added to the svec up to the moment it is deleted.
 *
 * NB: it is the caller's responsibility to deal with any pthread issues !
 *
 * NB: the first index value is '1' -- not '0' -- so that '0' can be used
 *     as "NULL".
 *
 * The base "Small Vector" object contains the first SVEC_EMBEDDED items
 *
 *
 */
/*==============================================================================
 * Initialisation, allocation, reset etc.
 */


/*------------------------------------------------------------------------------
 * Initialise an svec -- assuming that it has never been kissed.
 */
Private void
_svec_init(svec sv, svec_index_t e)
{
  memset(sv, 0, offsetof(svec_t, body[e + 1])) ;
} ;

/*------------------------------------------------------------------------------
 * Reset an svec -- preserving any existing extended body.
 *
 * Clears the embedded 'base' svec-list.
 *
 * NB: it is the caller's responsibility to ensure that the items are no
 *     longer required.
 *
 * NB: reconstructs the free list, so that will allocate in ascending index
 *     order.  This touches every entry.
 */
Private void
_svec_reset(svec sv, svec_index_t e)
{
  if (sv->body[SVEC_EXT_BODY] == NULL)
    {
      qassert((sv->last == 0) || (sv->last == e)) ;

      _svec_init(sv, e) ;
    }
  else
    {
      svec_item* p_item ;
      svec_index_t i ;

      qassert(sv->last > e) ;

      svl_init(sv->base) ;
      sv->free = 1 ;
      confirm(SVEC_FIRST == 1) ;

      p_item = &sv->body[1] ;
      for (i = 1 ; i <= e ; ++i)
        p_item[i - 1] = (void*)(uintptr_t)(i + 1) ;

      p_item = (svec_item*)(sv->body[SVEC_EXT_BODY]) ;
      for (i = (e + 1) ; i < sv->last ; ++i)
        p_item[i - (e + 1)] = (void*)(uintptr_t)(i + 1) ;

      p_item[sv->last - (e + 1)] = SVEC_NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Clear out an svec -- free any extended body and leave empty.
 *
 * NB: it is the caller's responsibility to ensure that the items are no
 *     longer required.
 */
Private void
_svec_clear(svec sv, svec_index_t e)
{
  XFREE(MTYPE_SVEC_EXT_BODY, sv->body[SVEC_EXT_BODY]) ;
  _svec_init(sv, e) ;
} ;

/*==============================================================================
 * Add/Delete items.
 */

/*------------------------------------------------------------------------------
 * Add item to svec -- extending the body, if required.
 *
 * Returns:  index at which the item has been added.
 */
Private svec_index_t
_svec_add(svec sv, svec_item item, svec_index_t e)
{
  svec_item*   p_item ;
  svec_index_t i, f ;

  /* If we don't have a free entry, better create some.
   *
   * NB: when an svec is initialised, it has sv->last == sv->free == 0, which
   *     we here patch up if there are 1 or more embedded items.
   */
  i = sv->free ;

  if (i != SVEC_NULL)
    {
      /* Simple -- use the first item on the free list
       */
      p_item = _svec_get_p(sv, i, e) ;
      f      = (uintptr_t)*p_item ;
    }
  else
    {
      svec_index_t l ;
      uint      n ;

      /* We appear to have no free items
       */
      l = sv->last ;                    /* last index in svec   */

      if (l < e)
        {
          /* We have an empty svec with at least one embedded entry, which
           * we can now use.
           */
          qassert((l == 0) && (sv->body[SVEC_EXT_BODY] == NULL)) ;
          n = 0 ;                       /* extended body item count     */
          i = 1 ;                       /* index of item to add         */
        }
      else
        {
          /* We need an extended body or a larger one.
           *
           * Calculate 'n' as the size of the extended part, then allocate or
           * reallocate.
           */
          n = l - e ;                   /* length of extended part      */
          i = l + 1 ;                   /* index of item to add         */

          if (n == 0)
            {
              /* We have yet to allocate an extended body -- calculate 'n',
               * the number of items for the new extended body.
               */
              qassert(sv->body[SVEC_EXT_BODY] == NULL) ;

              if (e < SVEC_EXT_SIZE_MIN)
                n = SVEC_EXT_SIZE_MIN ;
              else
                n = e ;
            }
          else
            {
              /* We have an extended body -- calculate 'n', the number of items
               * for the extended extended body.
               */
              assert(l <= SVEC_LAST) ;  /* simply cannot get bigger     */

              if (n < SVEC_EXT_DOUBLE_MAX)
                n = n + n ;
              else
                n = n + SVEC_EXT_DOUBLE_MAX ;

              if ((n + e) > SVEC_LAST)
                n = SVEC_LAST - e ;
            } ;

          sv->body[SVEC_EXT_BODY] = XREALLOC(MTYPE_SVEC_EXT_BODY,
                                                     sv->body[SVEC_EXT_BODY],
                                                        n * sizeof(svec_item)) ;

        } ;

      /* Update the new last index
       */
      sv->last = l = n + e ;            /* new last index               */

      /* Fill in the free chain.
       *
       * Start by getting the address of the item we are about to use.
       *
       * Finish with f == next free item index.
       *
       * NB: to keep life simple, we fill in the entire free chain, even
       *     though we are about to recalculate the address of the first
       *     free and remove it from the list.
       */
      p_item = _svec_get_p(sv, i, e) ;

      if (i == l)
        {
          /* This covers the obscure case of an empty svec with a single
           * embedded item.
           */
          qassert((e == 1) && (l == 1) && (sv->body[SVEC_EXT_BODY] == NULL)) ;

          f = SVEC_NULL ;
        }
      else
        {
          /* We have at least one free item in addition to the one we are
           * about to use.
           *
           * Start at the end of the new free list, setting that entry NULL,
           * and then moving up to entry i + 1.
           *
           * We end up with f == i + 1.  If there is only one free item, that's
           * the value we start with !
           *
           * Note that whether we are in the embedded or the extended body,
           * we hav p_item is address of item with index 'i'.
           */
          qassert(i < l) ;

          f = l ;                       /* Start at the end     */
          p_item[f - i] = SVEC_NULL ;   /* Set terminator       */

          while (f > (i + 1))
            {
              p_item[f - 1 - i] = (svec_item)(uintptr_t)f ;
              f -= 1 ;
            } ;
        } ;
    } ;

  /* Use the first free item on the list.
   */
  sv->free = f ;
  *p_item  = item ;
  return i ;
} ;

/*------------------------------------------------------------------------------
 * Delete item from svec -- has no effect on the body.
 *
 * Returns:  address of the item has just deleted.
 *
 * NB: it is the caller's responsibility to free the item itself as required.
 */
Private svec_item
_svec_del(svec sv, svec_index_t i, svec_index_t e)
{
  svec_item     item ;
  svec_item*    p_item ;

  p_item  = _svec_get_p(sv, i, e) ;
  item    = *p_item ;
  *p_item = (svec_item)(uintptr_t)(sv->free) ;
  sv->free = i ;

  return item ;
} ;

/*==============================================================================
 * Double Link Base -- List Functions -- _svl_xxx()
 *
 * Note that macros are provided a front-ends to all these, to help arrange
 * the required arguments.
 */
#define _svl_p(item, off) \
  ((svl_list)((void*)((char*)item + off)))

/*------------------------------------------------------------------------------
 * Prepend item at index 'i' to the given svl-list
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svl list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 * Returns:  address of the item
 */
Private svec_item
_svl_prepend(svl_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list      item_p ;
  svec_index_t  in ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = base->head ;
  if (in == SVEC_NULL)
    base->tail = i ;
  else
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;

      next_p = _svl_p(next, off) ;
      next_p->prev = i ;
    } ;

  base->head   = i ;
  item_p->next = in;
  item_p->prev = SVEC_NULL ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Append item at index 'i' to the given svl-list
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svl list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 * Returns:  address of the item
 */
Private svec_item
_svl_append(svl_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list      item_p ;
  svec_index_t  ip ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  ip = base->tail ;
  if (ip == SVEC_NULL)
    base->head = i ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev = _svec_get(sv, ip, e) ;

      prev_p = _svl_p(prev, off) ;
      prev_p->next = i ;
    } ;

  base->tail   = i ;
  item_p->next = SVEC_NULL ;
  item_p->prev = ip ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Insert item before the given item, or at the *tail* of given svl-list.
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svl list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *            ib       -- index of item to add before
 *
 * If 'ib' is SVEC_NULL the item is inserted at the tail -- "append".
 * (This is consistent with, say, insert before first larger on list.)
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 *       * item 'ib' was NOT on the list (if not SVEC_NULL)
 *
 * Returns:  address of the item
 */
Private svec_item
_svl_in_before(svl_base base, svec sv,
                    svec_index_t i, size_t off, svec_index_t e, svec_index_t ib)
{
  svec_item     item, before ;
  svec_index_t  ip ;
  svl_list      item_p, before_p ;

  if (ib == SVEC_NULL)
    return _svl_append(base, sv, i, off, e) ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  before   = _svec_get(sv, ib, e) ;
  before_p = _svl_p(before, off) ;

  ip = before_p->prev ;
  before_p->prev = i ;

  item_p->next = ib ;
  item_p->prev = ip ;

  if (ip == SVEC_NULL)
    base->head = i ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev = _svec_get(sv, ip, e) ;

      prev_p = _svl_p(prev, off) ;
      prev_p->next = i ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Insert item after the given item, or at the *head* of given svl-list.
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svl list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *            ia       -- index of item to add after
 *
 * If 'ia' is SVEC_NULL the item is inserted at the head -- "prepend".
 * (This is consistent with, say, insert after last smaller or equal.)
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 *       * item 'ia' was NOT on the list (if not SVEC_NULL)
 *
 * Returns:  address of the item
 */
Private svec_item
_svl_in_after(svl_base base, svec sv,
                    svec_index_t i, size_t off, svec_index_t e, svec_index_t ia)
{
  svec_item     item, after ;
  svec_index_t  in ;
  svl_list      item_p, after_p ;

  if (ia == SVEC_NULL)
    return _svl_prepend(base, sv, i, off, e) ;

  item    = _svec_get(sv, i, e) ;
  item_p  = _svl_p(item, off) ;

  after   = _svec_get(sv, ia, e) ;
  after_p = _svl_p(after, off) ;

  in = after_p->next ;
  after_p->next = i ;

  item_p->next = in ;
  item_p->prev = ia ;

  if (in == SVEC_NULL)
    base->tail = i ;
  else
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;

      next_p = _svl_p(next, off) ;
      next_p->prev = i ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete and return head of given svl-list
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            off      -- offset of the svl list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * off were incorrect !
 *
 * Returns:  address of item from head of list -- NULL if none
 */
Private svec_item
_svl_del_head(svl_base base, svec sv, size_t off, svec_index_t e)
{
  svec_index_t  i, in ;
  svec_item     item ;
  svl_list      item_p ;

  i = base->head ;
  if (i == SVEC_NULL)
    return NULL ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = item_p->next ;
  if (in == SVEC_NULL)
    base->tail = in ;
  else
    {
      svec_item next ;
      svl_list  next_p ;

      next   = _svec_get(sv, in, e) ;
      next_p = _svl_p(next, off) ;

      next_p->prev = SVEC_NULL ;
    } ;

  base->head = in ;
  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete and return tail of given svl-list
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            off      -- offset of the svl list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * off were incorrect !
 *
 * Returns:  address of item from tail of list -- NULL if none
 */
Private svec_item
_svl_del_tail(svl_base base, svec sv, size_t off, svec_index_t e)
{
  svec_index_t  i, ip ;
  svec_item     item ;
  svl_list      item_p ;

  i = base->tail ;
  if (i == SVEC_NULL)
    return NULL ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  ip = item_p->prev ;
  if (ip == SVEC_NULL)
    base->head = ip ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev   = _svec_get(sv, ip, e) ;
      prev_p = _svl_p(prev, off) ;

      prev_p->prev = SVEC_NULL ;
    } ;

  base->tail = ip ;
  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete item at index 'i' from given svl-list
 *
 * Requires:  base     -- pointer to the svl base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            off      -- offset of the svl list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item 'i' was not on the list
 *
 *       * off were incorrect !
 *
 * Returns:  address of the item
 */
Private svec_item
_svl_del(svl_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list    item_p ;
  svec_index_t  in, ip ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = item_p->next ;
  ip = item_p->prev ;

  if (in == SVEC_NULL)
    base->tail  = ip ;
  else
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;
      next_p = _svl_p(next, off) ;
      next_p->prev = ip ;
    } ;

  if (ip == SVEC_NULL)
    base->head = in ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev = _svec_get(sv, ip, e) ;
      prev_p = _svl_p(prev, off) ;
      prev_p->next = in ;
    } ;

  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

/*==============================================================================
 * Single Link Base -- List Functions -- _svs_xxx()
 *
 */
/*------------------------------------------------------------------------------
 * Prepend item at index 'i' to the given svs-list
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svec list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 * Returns:  address of the item
 */
Private svec_item
_svs_prepend(svs_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list      item_p ;
  svec_index_t  in ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = *base ;
  if (in != SVEC_NULL)
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;

      next_p = _svl_p(next, off) ;
      next_p->prev = i ;
    } ;

  *base        = i ;
  item_p->next = in ;
  item_p->prev = SVEC_NULL ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Append item at index 'i' to the given svs-list
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svec list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *
 * NB: has to chase down the list looking for the tail.
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 * Returns:  address of the item
 */
Private svec_item
_svs_append(svs_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list      item_p ;
  svec_index_t  ip ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  ip = *base ;
  if (ip == SVEC_NULL)
    *base = i ;
  else
    {
      svec_item    prev ;
      svl_list     prev_p ;

      while (1)
        {
          svec_index_t in ;

          prev   = _svec_get(sv, ip, e) ;
          prev_p = _svl_p(prev, off) ;

          in = prev_p->next ;
          if (in == SVEC_NULL)
            break ;

          ip = in ;
        } ;

      prev_p->next = i ;
    } ;

  item_p->next = SVEC_NULL ;
  item_p->prev = ip ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Insert item before the given item, or at the *tail* of given svs-list.
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svs list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *            ib       -- index of item to add before
 *
 * If 'ib' is SVEC_NULL the item is inserted at the tail -- "append".
 * (This is consistent with, say, insert before first larger on list.)
 *
 * NB: append has to chase down the list looking for the last item !
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 *       * item 'ib' was NOT on the list (if not SVEC_NULL)
 *
 * Returns:  address of the item
 */
Private svec_item
_svs_in_before(svs_base base, svec sv,
                    svec_index_t i, size_t off, svec_index_t e, svec_index_t ib)
{
  svec_item     item, before ;
  svec_index_t  ip ;
  svl_list      item_p, before_p ;

  if (ib == SVEC_NULL)
    return _svs_append(base, sv, i, off, e) ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  before   = _svec_get(sv, ib, e) ;
  before_p = _svl_p(before, off) ;

  ip = before_p->prev ;
  before_p->prev = i ;

  item_p->next = ib ;
  item_p->prev = ip ;

  if (ip == SVEC_NULL)
    *base = i ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev = _svec_get(sv, ip, e) ;

      prev_p = _svl_p(prev, off) ;
      prev_p->next = i ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Insert item after the given item, or at the *head* of given svs-list.
 *
 * Requires:  base     -- pointer to the svs base-pair for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            item_p   -- pointer to the svs list-pair in item 'i' (NB !)
 *            e        -- index of the last embedded item in the svec
 *            ia       -- index of item to add after
 *
 * If 'ia' is SVEC_NULL the item is inserted at the head -- "prepend".
 * (This is consistent with, say, insert after last smaller or equal.)
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item_p were not the list-pair in item 'i'
 *
 *       * item 'i' was already on the list
 *
 *       * item 'ia' was NOT on the list (if not SVEC_NULL)
 *
 * Returns:  address of the item
 */
Private svec_item
_svs_in_after(svs_base base, svec sv,
                    svec_index_t i, size_t off, svec_index_t e, svec_index_t ia)
{
  svec_item     item, after ;
  svec_index_t  in ;
  svl_list      item_p, after_p ;

  if (ia == SVEC_NULL)
    return _svs_prepend(base, sv, i, off, e) ;

  item    = _svec_get(sv, i, e) ;
  item_p  = _svl_p(item, off) ;

  after   = _svec_get(sv, ia, e) ;
  after_p = _svl_p(after, off) ;

  in = after_p->next ;
  after_p->next = i ;

  item_p->next = in ;
  item_p->prev = ia ;

  if (in != SVEC_NULL)
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;

      next_p = _svl_p(next, off) ;
      next_p->prev = i ;
    } ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete and return head of given svs-list
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            off      -- offset of the svs list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * off were incorrect !
 *
 * Returns:  address of item from head of list -- NULL if none
 */
Private svec_item
_svs_del_head(svs_base base, svec sv, size_t off, svec_index_t e)
{
  svec_index_t  i, in ;
  svec_item     item ;
  svl_list      item_p ;

  i = *base ;
  if (i == SVEC_NULL)
    return NULL ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = item_p->next ;
  if (in != SVEC_NULL)
    {
      svec_item next ;
      svl_list  next_p ;

      next   = _svec_get(sv, in, e) ;
      next_p = _svl_p(next, off) ;

      next_p->prev = SVEC_NULL ;
    } ;

  *base        = in ;
  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete and return tail of given svs-list
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            off      -- offset of the svs list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: has to chase down the list looking for the last item !
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * off were incorrect !
 *
 * Returns:  address of item from tail of list -- NULL if none
 */
Private svec_item
_svs_del_tail(svs_base base, svec sv, size_t off, svec_index_t e)
{
  svec_index_t  i, in ;
  svec_item     item ;
  svl_list      item_p ;

  i = *base ;
  if (i == SVEC_NULL)
    return NULL ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = item_p->next ;
  if (in == SVEC_NULL)
    *base = in ;
  else
    {
      svl_list  prev_p ;

      do
        {
          prev_p = item_p ;

          item   = _svec_get(sv, in, e) ;
          item_p = _svl_p(item, off) ;

          in = item_p->next ;
        }
      while (in != SVEC_NULL) ;

      prev_p->next = in ;
    } ;

  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

/*------------------------------------------------------------------------------
 * Delete item at index 'i' from given svs-list
 *
 * Requires:  base     -- pointer to the svs base for the list.
 *            sv       -- the svec in question -- *generic*.
 *            i        -- index of item to prepend
 *            off      -- offset of the svs list-pair in items
 *            e        -- index of the last embedded item in the svec
 *
 * NB: it would be a very sad mistake indeed if:
 *
 *       * item 'i' did not exist.
 *
 *       * item 'i' was not on the list
 *
 *       * off were incorrect !
 *
 * Returns:  address of the item
 */
Private svec_item
_svs_del(svs_base base, svec sv, svec_index_t i, size_t off, svec_index_t e)
{
  svec_item     item ;
  svl_list    item_p ;
  svec_index_t  in, ip ;

  item   = _svec_get(sv, i, e) ;
  item_p = _svl_p(item, off) ;

  in = item_p->next ;
  ip = item_p->prev ;

  if (in != SVEC_NULL)
    {
      svec_item next ;
      svl_list  next_p ;

      next = _svec_get(sv, in, e) ;
      next_p = _svl_p(next, off) ;
      next_p->prev = ip ;
    } ;

  if (ip == SVEC_NULL)
    *base = in ;
  else
    {
      svec_item prev ;
      svl_list  prev_p ;

      prev = _svec_get(sv, ip, e) ;
      prev_p = _svl_p(prev, off) ;
      prev_p->next = in ;
    } ;

  item_p->next = item_p->prev = SVEC_NULL ;
  return item ;
} ;

