/* List Utilities
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include "misc.h"
#include "list_util.h"
#include "heap.h"

/*==============================================================================
 * Single Base, Single Link
 */

/*------------------------------------------------------------------------------
 * Deleting item
 *
 * Have to chase down list to find item.
 *
 * Note that p_prev:
 *
 *   * starts as pointer to the base pointer and thereafter is a pointer to
 *     the "next" pointer in the current item.
 *
 *     In the macro we cast &base to (void**) before passing it as p_prev.
 *
 *     The compiler has a tendency to throw a wobbly complaining about aliasing,
 *     which is a complete mystery.  But this all works OK, provided the
 *     ssl_del_func() is not inlined -- go figure.
 *
 *   * as steps along the list p_prev points to the "next" pointer in the
 *     previous item.
 *
 *     The _sl_p_next() macro adds the offset of the "next" pointer to the
 *     address of the given item, and returns a (void**).
 *
 *   * at the end, assigns the item's "next" pointer to the "next" pointer
 *     field pointed at by p_prev.
 *
 * Returns: true  => removed item from list
 *          false => item not found on list (or item == NULL)
 */
extern bool
ssl_del_func(void** prev_p, void* item, void** item_p)
{
  size_t offset ;
  void*  prev ;

  if (item == NULL)
    return false ;

  offset = (char*)item_p - (char*)item ;

  while ((prev = *prev_p) != item)
    {
      if (prev == NULL)
        return false ;

      prev_p = sl_list_ptr_make(prev, offset) ;
    } ;

  *prev_p = *item_p ;

  return true ;
} ;

/*------------------------------------------------------------------------------
 * Appending item
 *
 * Have to chase down list to find item to insert after.
 *
 * See notes on p_prev above.
 */
extern void
ssl_append_func(void** prev_p, void* item, void** item_p)
{
  size_t offset ;
  void* prev ;

  offset = (char*)item_p - (char*)item ;

  while ((prev = *prev_p) != NULL)
    prev_p = sl_list_ptr_make(prev, offset) ;

  *prev_p = item ;
  *item_p = NULL ;
} ;

/*==============================================================================
 * Double Base, Single Link
 */

/*------------------------------------------------------------------------------
 * Deleting item
 *
 * Have to chase down list to find item.
 *
 * Returns: true  => removed item from list
 *          false => item not found on list (or item == NULL)
 */
extern bool
dsl_del_func(dl_base_pair_v base, void* item, void** item_p)
{
  void*  this ;
  void** this_p ;
  size_t offset ;

  if (item == NULL)
    return false ;

  this_p = &base->head ;
  offset = (char*)item_p - (char*)item ;

  while ((this = *this_p) != item)
    {
      if (this == NULL)
        return false ;

      this_p = sl_list_ptr_make(this, offset) ;
    } ;

  *this_p = *item_p ;

  if (item == base->tail)
    base->tail = *item_p ;

  return true ;
} ;

/*==============================================================================
 * List sorting functions.
 *
 *
 */

/*------------------------------------------------------------------------------
 * Sort the given double linked list.
 */
extern void
_dl_sort(vp* base, dl_list_pair_v item_p, sort_cmp* cmp, bool double_base)
{
} ;

/*------------------------------------------------------------------------------
 * Insert given item in (ascending) order into the given list.
 *
 * Assumes, of course, that the list is already sorted !
 */
extern void
_ddl_insert(dl_base_pair_v base, vp item, dl_list_pair_v item_p,
                                                                 sort_cmp* cmp)
{
  vp  head, prev, next ;
  dl_list_pair_v prev_p, next_p ;
  size_t offset ;

  /* Deal with the trivial cases of: (1) empty list
   *                                 (2) greater than last item
   *                                 (3) less than first item
   */
  head = base->head ;
  if (head == NULL)
    {
      /* List is empty -- trivial !
       */
      base->head   = base->tail   = item ;
      item_p->next = item_p->prev = NULL ;
      return ;
    } ;

  offset = (char*)item_p - (char*)item ;

  prev   = base->tail ;
  prev_p = dl_list_ptr_make(prev, offset) ;
  if (cmp((const cvp*)&prev, (const cvp*)&item) <= 0)
    {
      /* Tail item is less than or equal to the new one -- trivial !
       */
      item_p->next = NULL ;
      item_p->prev = prev ;

      base->tail = prev_p->next = item ;

      return ;
    } ;

  if ((prev == head) || (cmp((const cvp*)&head, (const cvp*)&item) > 0))
    {
      /* Head item is greater than the new one -- trivial.
       */
      dl_list_pair_v head_p ;

      head_p = dl_list_ptr_make(head, offset) ;

      item_p->next = head ;
      item_p->prev = NULL ;

      base->head = head_p->prev = item ;

      return ;
    } ;

  /* Now we know item belongs after the head, and before the tail.
   *
   * We work back from the tail, in the hope that we are roughly adding stuff
   * in order -- but doesn't make any difference if not.
   */
  while (1)
    {
      /* Step back so that we have: prev/prev_p pointing at item to consider
       *                            next/next_p pointing at item after that
       */
      next   = prev ;
      next_p = prev_p ;

      prev   = prev_p->prev ;
      prev_p = dl_list_ptr_make(prev, offset) ;

      if (prev == head)
        break ;                 /* we know head is <= item      */

      if (cmp((const cvp*)&prev, (const cvp*)&item) <= 0)
        break ;                 /* prev is now <= item          */
    } ;

  /* Now belongs after prev and before next.
   */
  item_p->next = next ;
  item_p->prev = prev ;

  prev_p->next = item ;
  next_p->prev = item ;
} ;

