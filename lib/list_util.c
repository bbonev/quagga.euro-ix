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

