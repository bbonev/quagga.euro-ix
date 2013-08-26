/* List Utilities -- header
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

#ifndef _ZEBRA_LIST_UTIL_H
#define _ZEBRA_LIST_UTIL_H

#include "misc.h"

/*------------------------------------------------------------------------------
 * Note that the following fell foul of "strict-aliasing":
 *
 *    #define ssl_del_head(base, next) \
 *      ssl_del_head_func_i((void**)&(base), _lu_off(base, next))
 *
 *    Inline void*
 *    ssl_del_head_func_i(void** p_base, size_t link_offset)
 *    {
 *      void* item = *p_base ;
 *
 *      if (item != NULL)
 *        *p_base = _sl_next(item, link_offset) ;
 *
 *      return item ;
 *    } ;
 *
 * the assignment to *p_base is, apparently, unacceptable.  This works
 * perfectly well as an ordinary function.  Using a GNUC extension it is
 * possible to avoid the function call... hence the ugly skips.
 */
#ifdef __GNUC__
#define __GNUC__LIST_UTIL
#endif

/*==============================================================================
 * These utilities provide for linked lists of items, where the list pointers
 * are fields in the items.
 *
 * This is a little less general that the linklist stuff, but carries less
 * overhead.
 *
 * The items will be structures of some sort, and are described here as being
 * of type "struct item".  Pointers to those items will be of type
 * "struct item*".
 *
 * Most of these utilities are implemented as macros.
 *
 *------------------------------------------------------------------------------
 * Links and Bases.
 *
 * For a singly linked list, the item declaration is straightforward:
 *
 *   struct item
 *   {
 *     ....
 *     struct item*  foo_next ;
 *     ....
 *   }
 *
 * The item can live on more than one list, all that is required is that each
 * list has its next pointer.
 *
 * For double linked lists, the item may be declared:
 *
 *   struct item
 *   {
 *     ....
 *     struct dl_list_pair(struct item*) foo_list ;
 *     ....
 *   } ;
 *
 * A single base is straighforward:
 *
 *   struct item* foo_base ;
 *
 * and that may be a variable or a structure field.
 *
 * A double base may be declared:
 *
 *   struct dl_base_pair(struct item*) foo_base ;
 *
 * Various ways to construct structures or structure types:
 *
 *   typedef struct dl_list_pair(struct foo*) foo_list ;
 *
 *   struct foo_list dl_list_pair(struct foo*) ;
 *
 *   struct foo_base dl_base_pair(struct foo*) ;
 */
#define dl_base_pair(ptr_t)  { ptr_t head ; ptr_t tail ; }
#define dl_list_pair(ptr_t)  { ptr_t next ; ptr_t prev ; }

#define INIT_DL_BASE_PAIR    { NULL, NULL }

typedef struct dl_base_pair(void*) dl_base_pair_vt ;
typedef struct dl_list_pair(void*) dl_list_pair_vt ;

typedef dl_base_pair_vt* dl_base_pair_v ;
typedef dl_list_pair_vt* dl_list_pair_v ;

#define dl_list_ptr_make(item, offset) \
  ((dl_list_pair_v)((void*)((char*)item + offset)))

#define sl_list_ptr_make(item, offset) \
  ((void*)((char*)item + (offset)))

#define _lu_off(obj, field) ((char*)&((obj)->field) - (char*)(obj))

/*==============================================================================
 * Single Base, Single Link
 *
 * To insert item must chase down list to find the tail.
 *
 * To delete item must chase down list to find it.
 *
 * Supports:
 *
 *   ssl_init(base)                 -- initialise base
 *
 *     An empty list has a NULL base.
 *
 *   ssl_push(base, item, next)     -- add at head of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   ssl_append(base, item, next)   -- add at tail of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   ssl_insert(base, after, item, next)  -- insert after given item
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Inserts at head of list if after is NULL.
 *
 *   ssl_del(base, item, next)      -- delete from list
 *
 *     Treat as function returning bool.  Does nothing if the item is NULL.
 *
 *     Returns: true  => removed item from list
 *              false => item not found on list (or item was NULL)
 *
 *   ssl_del_head(base, next)       -- delete head of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   ssl_pop(&dst, base, next)      -- pop head of list, if any
 *
 *     Treat as function returning void*.
 *
 *     Returns old head in dst and as return from "function".
 *
 *     Returns NULL and sets dst == NULL if list is empty.
 *
 *   ssl_head(base)                 -- return head of list
 *
 *     Treat as function returning void*.
 *
 *   ssl_next(item, next)           -- step to next item, if any
 *
 *     Treat as function returning void*.  Returns NULL if item is NULL.
 *
 * Note that ssl_del() and ssl_pop() do NOT affect the item->next pointer.
 *
 * Where:
 *
 *   "base" to be an r-value of type struct item*
 *
 *   "item" to be an l-value of type struct item*
 *
 *   "dst"  to be an r-value of type struct item*
 *
 *   "next" to be the name of a field in struct item, with type struct item*
 *
 *------------------------------------------------------------------------------
 * For example:
 *
 *   struct item                       // definition for list items
 *   {
 *     ...
 *     struct item*  bar_next ;
 *     ...
 *   } ;
 *
 *   static struct item* bar_base ;    // declaration of the list base
 *
 *   // create item and add to list (adds at front)
 *   struct item* q = calloc(1, sizeof(struct item)) ;
 *   ssl_push(bar_base, q, bar_next) ;
 *
 *   // remove item from list
 *   ssl_del(bar_base, q, bar_next) ;
 *
 *   // walk a list
 *   struct item* t = ssl_head(bar_base) ;
 *   while (t != NULL)
 *     {
 *       ....
 *       t = ssl_next(t, bar_next) ;
 *     }
 *
 *   // walk and empty out a list -- removing item before processing
 *   struct item* t ;
 *   while (ssl_pop(&t, bar_base, bar_next) != NULL)
 *     {
 *       ....  // t points to old head of list
 *     }
 *
 *   // walk and empty out a list -- removing after processing
 *   struct item* t ;
 *   while ((t = ssl_head(bar_base) != NULL)
 *     {
 *       ....
 *       ssl_del_head(bar_base, bar_next) ;
 *     }
 *
 * And for example:
 *
 *   struct parent_item                 // parent structure containing list
 *   {
 *      ....
 *      struct item* bar_base ;
 *      ....
 *   }
 *
 *   void footle(struct parent_item* parent, struct item* item)
 *   {
 *     ....
 *     ssl_push(parent->bar_base, item, bar_next) ;
 *     ....
 *   }
 */

#define ssl_init(base)                                          \
  ((base) = NULL)

#define ssl_push(base, item, next)                              \
  do { (item)->next = (base) ;                                  \
       (base) = item ;                                          \
  } while (0)

Private void ssl_append_func(void** prev_p, void* item, void** item_p) ;

#define ssl_append(base, item, next)                            \
  ssl_append_func((void**)(&(base)), item, (void**)&(item)->next)

#define ssl_insert(base, after, item, next)                     \
  do { if ((after) == NULL)                                     \
         ssl_push(base, item, next) ;                           \
       else                                                     \
         { (item)->next  = (after)->next ;                      \
           (after->next) = item ;  } ;                          \
  } while (0)

Private bool ssl_del_func(void** prev_p, void* item, void** item_p) ;

#define ssl_del(base, item, next)                               \
  ssl_del_func((void**)(&(base)), item, (void**)&(item)->next)

#define ssl_del_head(base, next)                                \
  do { if ((base) != NULL)                                      \
       (base) = (base)->next ;                                  \
  } while (0)

#define ssl_pop(dst, base, next)                                \
  ((*(dst) = (base)) != NULL ? ((base) = (base)->next, *(dst)) : NULL)

#define ssl_head(base) (base)

#define ssl_next(item, next)                                    \
  ((item) != NULL ? (item)->next : NULL)

/*   _sl_p_next(item, off) -- pointer to next pointer at given offset
 *   _sl_next(item, off)   -- contents of next pointer at given offset
 */

#define _sl_p_next(item, off)                                   \
  ((void**)( (char*)(item) + (off) ))

#define _sl_next(item, off)                                     \
  *_sl_p_next(item, off)

/*==============================================================================
 * Single Base, Double Link
 *
 * Can delete entry directly.
 *
 * Supports:
 *
 *   sdl_init(base)                 -- initialise base
 *
 *     An empty list has a NULL base.
 *
 *   sdl_push(base, item, list)     -- add at head of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   sdl_del(base, item, list)      -- delete from list
 *
 *     Treat as void function.  Does nothing if the item is NULL.
 *
 *     Undefined if item is not on the list.
 *
 *   sdl_del_head(base, next)       -- delete head of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   sdl_pop(&dst, base, next)      -- pop head of list, if any
 *
 *     Treat as function returning void*.
 *
 *     Returns old head in dst and as return from "function".
 *
 *     Returns NULL and sets dst == NULL if list is empty.
 *
 *   sdl_head(base)                 -- return head of list
 *
 *     Treat as function returning void*.
 *
 *   sdl_next(item, next)           -- step to next item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 *   sdl_prev(item, next)           -- step to prev item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 * Note that sdl_del() and sdl_pop() do NOT affect the item->list.next
 * or item->list.prev pointers.
 *
 * Where:
 *
 *   "base" to be an r-value of type: struct base_pair(struct item*)*
 *
 *          That is... a variable or field which is a pointer to
 *
 *   "item" to be an l-value of type struct item*
 *
 *   "dst"  to be an r-value of type struct item*
 *
 *   "list" to be the name of a field in struct item
 *          of type: struct list_pair(struct item*)
 *
 *------------------------------------------------------------------------------
 * For example:
 *
 *   struct item                       // definition for list items
 *   {
 *     ...
 *     struct list_pair(struct item*)  bar_list ;
 *     ...
 *   } ;
 *
 *   static struct base_pair(struct item*) bar_base ;
 *                                    // declaration of the list base
 *
 *   // create item and add to list (adds at front)
 *   struct item* q = calloc(1, sizeof(struct item)) ;
 *   sdl_push(bar_base, q, bar_list) ;
 *
 *   // remove item from list
 *   sdl_del(bar_base, q, bar_list) ;
 *
 *   // walk a list
 *   struct item* t = sdl_head(bar_base) ;
 *   while (t != NULL)
 *     {
 *       ....
 *       t = sdl_next(t, bar_list) ;
 *     }
 *
 *   // walk and empty out a list -- removing item before processing
 *   struct item* t ;
 *   while (sdl_pop(&t, bar_base, bar_list) != NULL)
 *     {
 *       ....  // t points to old head of list
 *     }
 *
 *   // walk and empty out a list -- removing after processing
 *   struct item* t ;
 *   while ((t = sdl_head(bar_base) != NULL)
 *     {
 *       ....
 *       sdl_del_head(bar_base, bar_list) ;
 *     }
 *
 * And for example:
 *
 *   struct parent_item                 // parent structure containing list
 *   {
 *      ....
 *      struct base_pair(struct item*) bar_base ;
 *      ....
 *   }
 *
 *   void footle(struct parent_item* parent, struct item* item)
 *   {
 *     ....
 *     sdl_push(parent->bar_base, item, bar_list) ;
 *     ....
 *   }
 */

#define sdl_init(base)                                                  \
  ((base) = NULL)

#define sdl_push(base, item, list)                                      \
  do { confirm(_lu_off(base, list.next) == _lu_off(item, list.next)) ;  \
       confirm(_lu_off(base, list.prev) == _lu_off(item, list.prev)) ;  \
       (item)->list.next = (base) ;                                     \
       (item)->list.prev = NULL ;                                       \
       if ((base) != NULL)                                              \
         (base)->list.prev = (item) ;                                   \
       (base) = (item) ;                                                \
  } while (0)

#define sdl_del(base, item, list)                                       \
  do { confirm(_lu_off(base, list.next) == _lu_off(item, list.next)) ;  \
       confirm(_lu_off(base, list.prev) == _lu_off(item, list.prev)) ;  \
       if ((item) != NULL)                                              \
         {                                                              \
           if ((item)->list.next != NULL)                               \
             (item)->list.next->list.prev = (item)->list.prev ;         \
           if ((item)->list.prev != NULL)                               \
             (item)->list.prev->list.next = (item)->list.next ;         \
           else                                                         \
             (base) = (item)->list.next ;                               \
         } ;                                                            \
  } while (0)

#define sdl_del_head(base, list)                                        \
  do { if ((base) != NULL)                                              \
         {                                                              \
           (base) = (base)->list.next ;                                 \
           if ((base) != NULL)                                          \
             (base)->list.prev = NULL ;                                 \
         }                                                              \
  } while (0)

#define sdl_pop(dst, base, list)                                        \
  ((*(dst) = (base)) != NULL                                            \
    ? ( ((base) = (base)->list.next) != NULL                            \
      ? ( (base)->list.prev = NULL, *(dst) ) : *(dst) ) : NULL)

#define sdl_head(base) (base)

#define sdl_next(item, list)                                            \
  ((item) != NULL ? (item)->list.next : NULL)

#define sdl_prev(item, list)                                            \
  ((item) != NULL ? (item)->list.prev : NULL)

/*   _dl_p_next(obj, off)   -- pointer to next pointer at given offset
 *   _dl_next(obj, off)     -- contents of next pointer at given offset
 *   _dl_p_prev(obj, off)   -- pointer to prev pointer at given offset
 *   _dl_prev(obj, off)     -- contents of prev pointer at given offset
 */
#define _dl_p_next(obj, off)                                            \
  ( (void**)( (char*)(obj) + (off) + 0 ) )

#define _dl_next(obj, off)                                              \
  *_dl_p_next(obj, off)

#define _dl_p_prev(obj, off)                                            \
  ( (void**)( (char*)(obj) + (off) _ sizeof(void*) ) )

#define _dl_prev(obj, off)                                              \
  *_dl_p_next(obj, off)

/*==============================================================================
 * Double Base, Double Link
 *
 * Can delete entry directly.  Can insert and remove at tail.
 *
 * Supports:
 *
 *   ddl_init(base)                 -- initialise base
 *
 *     An empty list has *both* head and tail pointers NULL.
 *
 *     NB: confusion will arise if only one of these pointers is NULL.
 *
 *   ddl_init_pair(item, list)      -- initialise pointer pair
 *
 *     Sets both pointers NULL -- not strictly necessary, but tidy.
 *
 *   ddl_push(base, item, list)     -- insert at head of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   ddl_append(base, item, list)   -- insert at tail of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   ddl_in_after(after, base, item, list)   -- insert after
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     If after == NULL, insert item at the head of the current list.  So, can
 *     insert in order by searching backwards for first "smaller" item or start
 *     of list !  This works equally for empty lists.
 *
 *     Undefined if item is already on any list (including this one), or if
 *     after is not on the list.
 *
 *   ddl_in_before(before, base, item, list) -- insert before
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     If before == NULL, insert item at the tail of the current list.  So, can
 *     insert in order by searching forwards for first "larger" item or end
 *     of list !  This works equally for empty lists.
 *
 *     Undefined if item is already on any list (including this one), or if
 *     before is not on the list.
 *
 *   ddl_pop(&dst, base, next)      -- pop head of list, if any
 *
 *     Treat as function returning void*.
 *
 *     Returns old head in dst and as return from "function".
 *
 *     Returns NULL and sets dst == NULL if list is empty.
 *
 *   ddl_crop(&dst, base, next)     -- crop tail of list, if any
 *
 *     Treat as function returning void*.
 *
 *     Returns old tail in dst and as return from "function".
 *
 *     Returns NULL and sets dst == NULL if list is empty.
 *
 *   ddl_del(base, item, list)      -- delete from list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is not on the list.
 *
 *   ddl_replace(base, item, list, new) -- replace item by new one
 *
 *     Treat as void function.  The item and the new one may *not* be NULL.
 *
 *     Undefined if item is not on the list (or if new already is !).
 *
 *   ddl_del_head(base, next)       -- delete head of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   ddl_del_tail(base, next)       -- delete tail of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   ddl_head(base)                 -- return head of list
 *
 *     Treat as function returning void*.
 *
 *   ddl_tail(base)                 -- return tail of list
 *
 *     Treat as function returning void*.
 *
 *   ddl_next(item, next)           -- step to next item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 *   ddl_prev(item, next)           -- step to prev item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 *   ddl_slice(base, sub, list)     -- remove sublist from given list
 *
 *     Treat as void function.  Does nothing if the sublist is empty.
 *
 *     sub is a base pair, but need not be a valid list (its head->list.prev
 *     and tail->list.next will not be NULL, unless is the complete list.)
 *
 *     The resulting sub *is* a valid list (its head->list.prev and
 *     tail->list.next will be NULL).
 *
 *   ddl_splice_after(after, base, sub, list)
 *                                  -- insert sublist after given item
 *
 *     Treat as void function.  Does nothing if the sublist is empty.
 *
 *     If after == NULL, insert sublist at the end of the current list
 *     (ie append).
 *
 *     sub is a base pair, but need not be a valid list (its head->list.prev
 *     and tail->list.next need not be NULL)
 *
 *     sub is unchanged by this operation -- but its head->list.prev and
 *     and tail->list.next may well be.
 *
 *   ddl_splice_before(before, base, sub, list)
 *                                  -- insert sublist before given item
 *
 *     Treat as void function.  Does nothing if the sublist is empty.
 *
 *     If before == NULL, insert sublist at the start of the current list
 *     (ie prepend).
 *
 *     sub is a base pair, but need not be a valid list (its head->list.prev
 *     and tail->list.next need not be NULL)
 *
 *     sub is unchanged by this operation -- but its head->list.prev and
 *     and tail->list.next may well be.
 *
 *   ddl_append_list(base, sub, list) -- append sub list to base list
 *
 *     Treat as void function.
 *
 *     sub is a base pair, but need not be a valid list (its head->list.prev
 *     and tail->list.next need not be NULL)
 *
 *     sub is unchanged by this operation -- but its head->list.prev and
 *     and tail->list.next may well be.
 *
 *   ddl_prepend_list(base, sub, list) -- prepend sub list to base list
 *
 *     Treat as void function.
 *
 *     sub is a base pair, but need not be a valid list (its head->list.prev
 *     and tail->list.next need not be NULL)
 *
 *     sub is unchanged by this operation -- but its head->list.prev and
 *     and tail->list.next may well be.
 *
 * Note that ddl_del() and ddl_pop() do NOT affect the item->list.next
 * or item->list.prev pointers.
 *
 * Where:
 *
 *   "base" to be an r-value of type: struct base_pair(struct item*)*
 *
 *          That is... a variable or field which is a pointer pair.
 *
 *   "item" to be an l-value of type struct item*
 *
 *   "dst"  to be an r-value of type struct item*
 *
 *   "list" to be the name of a field in struct item
 *          of type: struct list_pair(struct item*)
 *
 *   "sub"  to be an r-value of type: struct base_pair(struct item*)*
 *
 *          That is... a variable or field which is a pointer pointer pair,
 *          *but* where the head->list.prev and tail->list.next need not be
 *          NULL and may well not be.
 *
 *------------------------------------------------------------------------------
 * For example:
 *
 *   struct item                       // definition for list items
 *   {
 *     ...
 *     struct list_pair(struct item*)  bar_list ;
 *     ...
 *   } ;
 *
 *   static struct base_pair(struct item*) bar_base ;
 *                                    // declaration of the list base
 *
 *   // create item and add to list (adds at front)
 *   struct item* q = calloc(1, sizeof(struct item)) ;
 *   ddl_push(bar_base, q, bar_list) ;
 *
 *   // remove item from list
 *   ddl_del(bar_base, q, bar_list) ;
 *
 *   // walk a list
 *   struct item* t = ddl_head(bar_base) ;
 *   while (t != NULL)
 *     {
 *       ....
 *       t = ddl_next(t, bar_list) ;
 *     }
 *
 *   // walk and empty out a list -- removing item before processing
 *   struct item* t ;
 *   while (ddl_pop(&t, bar_base, bar_list) != NULL)
 *     {
 *       ....  // t points to old head of list
 *     }
 *
 *   // walk and empty out a list -- removing after processing
 *   struct item* t ;
 *   while ((t = ddl_head(bar_base) != NULL)
 *     {
 *       ....
 *       ddl_del_head(bar_base, bar_list) ;
 *     }
 *
 * And for example:
 *
 *   struct parent_item                 // parent structure containing list
 *   {
 *      ....
 *      struct base_pair(struct item*) bar_base ;
 *      ....
 *   }
 *
 *   void footle(struct parent_item* parent, struct item* item)
 *   {
 *     ....
 *     ddl_push(parent->bar_base, item, bar_list) ;
 *     ....
 *   }
 */
#define ddl_init(base)                                                  \
  ((base).head = (base).tail = NULL)

#define ddl_init_pair(item, list)                                       \
  ((item)->list.next = (item)->list.prev = NULL)

#define ddl_push(base, item, list) ddl_prepend(base, item, list)

#define ddl_prepend(base, item, list)                                   \
  do { (item)->list.next = (base).head ;                                \
       (item)->list.prev = NULL ;                                       \
       if ((base).head != NULL)                                         \
         (base).head->list.prev = (item) ;                              \
       else                                                             \
         (base).tail = (item) ;                                         \
       (base).head = (item) ;                                           \
  } while (0)

#define ddl_append(base, item, list)                                    \
  do { (item)->list.next = NULL ;                                       \
       (item)->list.prev = (base).tail ;                                \
       if ((base).tail != NULL)                                         \
         (base).tail->list.next = (item) ;                              \
       else                                                             \
         (base).head = (item) ;                                         \
       (base).tail = (item) ;                                           \
  } while (0)

#define ddl_in_after(after, base, item, list)                           \
  do { if (after != NULL)                                               \
         {                                                              \
           (item)->list.next = (after)->list.next ;                     \
           (item)->list.prev = (after) ;                                \
           if ((after)->list.next != NULL)                              \
             (after)->list.next->list.prev = (item) ;                   \
           else                                                         \
             (base).tail = (item) ;                                     \
           (after)->list.next = (item) ;                                \
         }                                                              \
       else                                                             \
         ddl_prepend(base, item, list) ;                                \
  } while (0)

#define ddl_in_before(before, base, item, list)                         \
  do { if (before != NULL)                                              \
         {                                                              \
           (item)->list.next = (before) ;                               \
           (item)->list.prev = (before)->list.prev ;                    \
           if ((before)->list.prev != NULL)                             \
             (before)->list.prev->list.next = (item) ;                  \
           else                                                         \
             (base).head = (item) ;                                     \
           (before)->list.prev = (item) ;                               \
         }                                                              \
       else                                                             \
         ddl_append(base, item, list) ;                                 \
  } while (0)

#define ddl_del(base, item, list)                                       \
  do { if ((item)->list.next != NULL)                                   \
         (item)->list.next->list.prev = (item)->list.prev ;             \
       else                                                             \
         (base).tail = (item)->list.prev ;                              \
       if ((item)->list.prev != NULL)                                   \
         (item)->list.prev->list.next = (item)->list.next ;             \
       else                                                             \
         (base).head = (item)->list.next ;                              \
  } while (0)

#define ddl_replace(base, item, list, new)                              \
  do { (new)->list.next = (item)->list.next ;                           \
       if ((new)->list.next != NULL)                                    \
         (new)->list.next->list.prev = (new) ;                          \
       else                                                             \
         (base).tail = (new) ;                                          \
       (new)->list.prev = (item)->list.prev ;                           \
       if ((new)->list.prev != NULL)                                    \
         (new)->list.prev->list.next = (new) ;                          \
       else                                                             \
         (base).head = (new) ;                                          \
  } while (0)

#define ddl_del_head(base, list)                                        \
  do { if ((base).head != NULL)                                         \
         {                                                              \
           (base).head = (base).head->list.next ;                       \
           if ((base).head != NULL)                                     \
             (base).head->list.prev = NULL ;                            \
           else                                                         \
             (base).tail = NULL ;                                       \
         }                                                              \
  } while (0)

#define ddl_del_tail(base, list)                                        \
  do { if ((base).tail != NULL)                                         \
         {                                                              \
           (base).tail = (base).tail->list.prev ;                       \
           if ((base).tail != NULL)                                     \
             (base).tail->list.next = NULL ;                            \
           else                                                         \
             (base).head = NULL ;                                       \
         }                                                              \
  } while (0)

#define ddl_pop(dst, base, list)                                        \
  ((*(dst) = (base).head) != NULL                                       \
    ? ( ((base).head = (base).head->list.next) != NULL                  \
          ? ( (base).head->list.prev = NULL, *(dst) )                   \
          : ( (base).tail            = NULL, *(dst) ) )                 \
    : NULL)

#define ddl_crop(dst, base, list)                                       \
  ((*(dst) = (base).tail) != NULL                                       \
    ? ( ((base).tail = (base).tail->list.prev) != NULL                  \
          ? ( (base).tail->list.next = NULL, *(dst) )                   \
          : ( (base).head            = NULL, *(dst) ) )                 \
    : NULL)

#define ddl_head(base) ((base).head)

#define ddl_tail(base) ((base).tail)

#define ddl_next(item, list)                                            \
  ((item) != NULL ? (item)->list.next : NULL)

#define ddl_prev(item, list)                                            \
  ((item) != NULL ? (item)->list.prev : NULL)

#define ddl_slice(base, sub, list)                                      \
  do { if ((sub).head != NULL)                                          \
         {                                                              \
            if ((sub).head->list.prev != NULL)                          \
              (sub).head->list.prev->list.next = (sub).tail->list.next ; \
            else                                                        \
              {                                                         \
                qassert((sub).head == (base).head) ;                    \
                (base).head = (sub).tail->list.next ;                   \
              } ;                                                       \
                                                                        \
            if ((sub).tail->list.next != NULL)                          \
              (sub).tail->list.next->list.prev = (sub).head->list.prev ; \
            else                                                        \
              {                                                         \
                qassert((sub).tail == (base).tail) ;                    \
                (base).tail = (sub).head->list.prev ;                   \
              } ;                                                       \
                                                                        \
            (sub).head->list.prev = NULL ;                              \
            (sub).tail->list.next = NULL ;                              \
         }                                                              \
  } while (0)

#define ddl_splice_after(after, base, sub, list)                        \
  do { if ((sub).head != NULL)                                          \
         {                                                              \
           if ((after) != NULL)                                         \
             {                                                          \
               (sub).head->list.prev = (after) ;                        \
               (sub).tail->list.next = (after)->list.next ;             \
               if ((after)->list.next != NULL)                          \
                 (after)->list.next->list.prev = (sub).tail ;           \
               else                                                     \
                 (base).tail = (sub).tail ;                             \
               (after)->list.next = (sub).head ;                        \
             }                                                          \
           else                                                         \
             ddl_append_list(base, sub, list) ;                         \
         }                                                              \
  } while (0)

#define ddl_splice_before(before, base, sub, list)                      \
  do { if ((sub).head != NULL)                                          \
         {                                                              \
           if ((before) != NULL)                                        \
             {                                                          \
               (sub).tail->list.next = (before) ;                       \
               (sub).head->list.prev = (before)->list.prev ;            \
               if ((before)->list.prev != NULL)                         \
                 (before)->list.prev->list.next = (sub).head ;          \
               else                                                     \
                 (base).head = (sub).head ;                             \
               (before)->list.prev = (sub).tail ;                       \
             }                                                          \
           else                                                         \
             ddl_prepend_list(base, sub, list) ;                        \
         }                                                              \
  } while (0)

#define ddl_append_list(base, sub, list)                                \
  do { if ((sub).head != NULL)                                          \
         {                                                              \
          (sub).head->list.prev = (base).tail ;                         \
          (sub).tail->list.next = NULL ;                                \
           if ((base).head != NULL)                                     \
             {                                                          \
               (base).tail->list.next = (sub).head ;                    \
               (base).tail = (sub).tail ;                               \
             }                                                          \
           else                                                         \
             {                                                          \
               qassert((base).tail == NULL) ;                           \
               (base) = (sub) ;                                         \
             } ;                                                        \
         }                                                              \
  } while (0)

#define ddl_prepend_list(base, sub, list)                               \
  do { if ((sub).head != NULL)                                          \
         {                                                              \
          (sub).head->list.prev = NULL ;                                \
          (sub).tail->list.next = (base).head ;                         \
           if ((base).head != NULL)                                     \
             {                                                          \
               (base).head->list.prev = (sub).tail ;                    \
               (base).head = (sub).head ;                               \
             }                                                          \
           else                                                         \
             {                                                          \
               qassert((base).tail == NULL) ;                           \
               (base) = (sub) ;                                         \
             } ;                                                        \
         }                                                              \
  } while (0)

/*==============================================================================
 * Double Base, Single Link
 *
 * To delete entry must chase down list to find it.  Can insert at tail, but
 * not remove (except by chasing down list).
 *
 * Supports:
 *
 *   dsl_init(base)                 -- initialise base
 *
 *     An empty list has *both* head and tail pointers NULL.
 *
 *     NB: confusion will arise if only one of these pointers is NULL.
 *
 *   dsl_push(base, item, next)     -- insert at head of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   dsl_append(base, item, next)   -- insert at tail of list
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one).
 *
 *   dsl_in_after(after, base, item, next)   -- insert after
 *
 *     Treat as void function.  The after & item may *not* be NULL.
 *
 *     Undefined if item is already on any list (including this one), or if
 *     after is not on the list.
 *
 *   dsl_pop(&dst, base, next)      -- pop head of list, if any
 *
 *     Treat as function returning void*.
 *
 *     Returns old head in dst and as return from "function".
 *
 *     Returns NULL and sets dst == NULL if list is empty.
 *
 *   dsl_del(base, item, next)      -- delete from list
 *
 *     Treat as void function.  Does nothing if the item is NULL.
 *
 *     Undefined if item is not on the list.
 *
 *   dsl_del_head(base, next)       -- delete head of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   dsl_del_tail(base, next)       -- delete tail of list
 *
 *     Treat as void function.  Does nothing if the list is empty.
 *
 *   dsl_head(base)                 -- return head of list
 *
 *     Treat as function returning void*.
 *
 *   dsl_tail(base)                 -- return tail of list
 *
 *     Treat as function returning void*.
 *
 *   dsl_next(item, next)           -- step to next item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 * Note that dsl_del() and dsl_pop() do NOT affect the item->next pointer.
 *
 * Where:
 *
 *   "base" to be an r-value of type: struct base_pair(struct item*)*
 *
 *          That is... a variable or field which is a pointer to
 *
 *   "item" to be an l-value of type struct item*
 *
 *   "dst"  to be an r-value of type struct item*
 *
 *   "next" to be the name of a field in struct item of type struct item*
 *
 *------------------------------------------------------------------------------
 * For example:
 *
 *   struct item                       // definition for list items
 *   {
 *     ...
 *     struct item*  bar_next ;
 *     ...
 *   } ;
 *
 *   static struct base_pair(struct item*) bar_base ;
 *                                    // declaration of the list base
 *
 *   // create item and add to list (adds at front)
 *   struct item* q = calloc(1, sizeof(struct item)) ;
 *   dsl_push(bar_base, q, bar_next) ;
 *
 *   // remove item from list
 *   dsl_del(bar_base, q, bar_next) ;
 *
 *   // walk a list
 *   struct item* t = dsl_head(bar_base) ;
 *   while (t != NULL)
 *     {
 *       ....
 *       t = dsl_next(t, bar_next) ;
 *     }
 *
 *   // walk and empty out a list -- removing item before processing
 *   struct item* t ;
 *   while (dsl_pop(&t, bar_base, bar_next) != NULL)
 *     {
 *       ....  // t points to old head of list
 *     }
 *
 *   // walk and empty out a list -- removing after processing
 *   struct item* t ;
 *   while ((t = dsl_head(bar_base) != NULL)
 *     {
 *       ....
 *       dsl_del_head(bar_base, bar_next) ;
 *     }
 *
 * And for example:
 *
 *   struct parent_item                 // parent structure containing list
 *   {
 *      ....
 *      struct base_pair(struct item*) bar_base ;
 *      ....
 *   }
 *
 *   void footle(struct parent_item* parent, struct item* item)
 *   {
 *     ....
 *     dsl_push(parent->bar_base, item, bar_next) ;
 *     ....
 *   }
 */

#define dsl_init(base)                                                  \
  ((base).head = (base).tail = NULL)

#define dsl_push(base, item, next)                                      \
  do { (item)->next = (base).head ;                                     \
       if ((base).tail == NULL)                                         \
         (base).tail = (item) ;                                         \
       (base).head = (item) ;                                           \
  } while (0)

#define dsl_append(base, item, next)                                    \
  do { (item)->next = NULL ;                                            \
       if ((base).tail != NULL)                                         \
         (base).tail->next = (item) ;                                   \
       else                                                             \
         (base).head = (item) ;                                         \
       (base).tail = (item) ;                                           \
  } while (0)

#define dsl_in_after(after, base, item, next)                           \
  do { (item)->next = (after)->next ;                                   \
       (after)->next = (item) ;                                         \
       if ((base).tail == (after))                                      \
         (base).tail = (item) ;                                         \
  } while (0)

Private bool dsl_del_func(dl_base_pair_v p_base, void* item, void** item_p) ;
#define dsl_del(base, item, next)                                       \
  dsl_del_func((dl_base_pair_v)&(base), item, (void**)&(item)->next)

#define dsl_del_head(base, next)                                        \
  do { if ((base).head != NULL)                                         \
         {                                                              \
           (base).head = (base).head->next ;                            \
           if ((base).head == NULL)                                     \
             (base).tail = NULL ;                                       \
         }                                                              \
  } while (0)

#define dsl_pop(dst, base, next)                                        \
  ((*(dst) = (base).head) != NULL                                       \
    ? ( ((base).head = (base).head->next) == NULL                       \
          ? ( (base).tail = NULL, *(dst) )                              \
          :                       *(dst) )                              \
    : NULL)

#define dsl_head(base) ((base).head)

#define dsl_tail(base) ((base).tail)

#define dsl_next(item, next)                                            \
  ((item) != NULL ? (item)->next : NULL)

/*------------------------------------------------------------------------------
 * Append given item to dsl.
 *
 * Call as:  p = _dsl_pop(base, item, (void**)&base->head->list)
 */
Inline void*
_dsl_append(dl_base_pair_v base, void* item, void** item_p)
{
  void* next ;

  next = base->head ;

  if (next == NULL)
    base->head = item ;
  else
    {
      void** next_p ;

      next_p  = sl_list_ptr_make(next, (char*)item_p - (char*)item) ;
      *next_p = item ;
    } ;

  base->tail = item ;
  *item_p = NULL ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Pop item from head of dsl.
 *
 * Call as:  p = _dsl_pop(base, (void**)&base->head->list)
 */
Inline void*
_dsl_pop(dl_base_pair_v base, void** item_p)
{
  void* head ;

  head = base->head ;

  if (head != NULL)
    {
      void* next ;

      next = *item_p ;

      base->head = next ;
      if (next == NULL)
        base->tail = NULL ;
    } ;

  return head ;
} ;

/*------------------------------------------------------------------------------
 * Push item onto head of dsl.
 *
 * Call as:  p = _dsl_push(base, item, (void**)&base->head->list)
 */
Inline void*
_dsl_push(dl_base_pair_v base, void* item, void** item_p)
{
  void* next ;

  next = base->head ;

  base->head = item ;
  if (next == NULL)
    base->tail = item ;

  *item_p = next ;

  return item ;
} ;

/*==============================================================================
 * Ring, Double Link
 *
 * On this ring all items are connected forwards and backwards.  The head
 * of a ring points to one of the items.
 *
 * Supports:
 *
 *   rdl_init(base)                 -- initialise base
 *
 *     An empty ring has a NULL base.
 *
 *   rdl_clear(item, ring)          -- clear the ring pointer pair
 *
 *     Sets both pointers NULL.
 *
 *     NB: unlike a list, when an item is on a ring neither ring.next nor
 *         ring.prev are NULL.  So, if the pointers are cleared, this may be
 *         used to tell whether the item is on the ring or not.
 *
 *   rdl_is_on(item, ring)          -- is item on its ring ?
 *   rdl_is_off(item, ring)         -- is item not on its ring ?
 *
 *     Treat as function returning bool
 *
 *     NB: this depends on the CALLER ensuring that the ring pointer pair
 *         is cleared when the item is not on its ring.
 *
 *   rdl_head(base)                 -- return head of ring
 *
 *     Treat as function returning void*.
 *
 *   rdl_tail(base)                 -- return tail of ring
 *
 *     Treat as function returning void*.
 *
 *   rdl_next(item, ring)           -- step to next item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 *   rdl_prev(item, ring)           -- step to prev item, if any
 *
 *     Treat as function returning void*.  Returns NULL if the item is NULL.
 *
 *   rdl_append(base, item, ring)   -- insert at tail of ring
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any ring (including this one).
 *
 *   rdl_prepend(base, item, ring)  -- insert at head of ring
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is already on any ring (including this one).
 *
 *   rdl_del(base, item, ring)      -- delete from ring
 *
 *     Treat as void function.  The item may *not* be NULL.
 *
 *     Undefined if item is not on the ring.
 *
 *   rdl_del_head(base, ring)       -- delete head of ring
 *
 *     Treat as function returning previous head.
 *
 *     Does nothing if the ring is empty.
 *
 * Note that rdl_del() and rdl_del_head() set the ring.next and
 * ring.prev pointers to NULL.
 *
 * Where:
 *
 *   "base" to be an r-value of type: struct item*
 *
 *          That is... a variable or field which points to an item.
 *
 *   "item" to be an l-value of type struct item*
 *
 *   "ring" to be the name of a field in struct item
 *          of type: struct dl_list_pair(struct item*)
 *
 */
#define rdl_init(base)                                                  \
  ((base) = NULL)

#define rdl_clear(item, ring) \
  _rdl_clear((dl_list_pair_v)&((item)->ring))

#define rdl_is_on(item, ring) \
  _rdl_is_on((dl_list_pair_v)&((item)->ring))

#define rdl_is_off(item, ring) \
  (!_rdl_is_on((dl_list_pair_v)&((item)->ring)))

#define rdl_head(base) \
  _rdl_head((void**)&(base))

#define rdl_tail(base, ring) \
  _rdl_tail((void**)&(base), (dl_list_pair_v)&((base)->ring))

#define rdl_next(item, ring) \
  _rdl_next(item, (dl_list_pair_v)&((item)->ring))

#define rdl_prev(item, ring) \
  _rdl_prev(item, (dl_list_pair_v)&((item)->ring))

#define rdl_append(base, item, ring) \
  _rdl_append((void**)&base, item, (dl_list_pair_v)&((item)->ring))

#define rdl_prepend(base, item, ring) \
  _rdl_prepend((void**)&base, item, (dl_list_pair_v)&((item)->ring))

#define rdl_del(base, item, ring) \
  _rdl_del((void**)&base, item, (dl_list_pair_v)&((item)->ring))

#define rdl_del_head(base, ring) \
  _rdl_del_head((void**)&base, (dl_list_pair_v)&((base)->ring))

/*------------------------------------------------------------------------------
 * Clear rdl pair.
 */
Inline void
_rdl_clear(dl_list_pair_v item_p)
{
  item_p->next = item_p->prev = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Is the rdl pair next != NULL
 *
 * Returns:  true <=> next != NULL
 */
Inline bool
_rdl_is_on(dl_list_pair_v item_p)
{
  qassert((item_p->next != NULL) == (item_p->prev != NULL)) ;

  return (item_p->next != NULL) ;
} ;

/*------------------------------------------------------------------------------
 * Get next item on ring -- returns NULL iff item is NULL
 *
 * NB: next may be the same item -- caller must check is cares.
 */
Inline void*
_rdl_next(void* item, dl_list_pair_v item_p)
{
  if (item != NULL)
    item = item_p->next ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Get previous item on ring -- returns NULL iff item is NULL
 *
 * NB: next may be the same item -- caller must check is cares.
 */
Inline void*
_rdl_prev(void* item, dl_list_pair_v item_p)
{
  if (item != NULL)
    item = item_p->prev ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Get head of rdl ring (if any)
 */
Inline void*
_rdl_head(void** base)
{
  return *base ;
} ;

/*------------------------------------------------------------------------------
 * Get tail of rdl ring (if any)
 *
 * We are passed: base_pair = &((*base)->ring.
 */
Inline void*
_rdl_tail(void** base, dl_list_pair_v item_p)
{
  void* item ;

  item = *base ;
  return _rdl_prev(item, item_p) ;
} ;

/*------------------------------------------------------------------------------
 * Append given item to rdl.
 */
Inline void
_rdl_append(void** base, void* item, dl_list_pair_v item_p)
{
  void* next ;

  next = *base ;

  if (next == NULL)
    {
      *base = item_p->next = item_p->prev = item ;
    }
  else
    {
      size_t         offset ;
      dl_list_pair_v next_p ;
      dl_list_pair_v prev_p ;
      void*          prev ;

      offset = (char*)item_p - (char*)item ;

      next_p = dl_list_ptr_make(next, offset) ;
      prev   = next_p->prev ;
      prev_p = dl_list_ptr_make(prev, offset) ;

      qassert(prev_p->next == next_p->prev) ;

      item_p->next = next ;
      item_p->prev = prev ;

      next_p->prev = item ;
      prev_p->next = item ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Prepend given item to rdl.
 */
Inline void
_rdl_prepend(void** base, void* item, dl_list_pair_v item_p)
{
  _rdl_append(base, item, item_p) ;
  *base = item ;
} ;

/*------------------------------------------------------------------------------
 * Delete given item from rdl.
 *
 * NB: item MUST be on the rdl !!
 */
Inline void
_rdl_del(void** base, void* item, dl_list_pair_v item_p)
{
  void* next ;
  void* prev ;

  qassert(*base != NULL) ;

  next = item_p->next ;
  prev = item_p->prev ;

  if (next == item)
    {
      /* Ring contains just the one item !
       */
      qassert((*base == item) && (next == prev)) ;
     *base = NULL ;
    }
  else
    {
      dl_list_pair_v next_p ;
      dl_list_pair_v prev_p ;
      size_t         offset ;

      offset = (char*)item_p - (char*)item ;

      next_p = dl_list_ptr_make(next, offset) ;
      prev_p = dl_list_ptr_make(prev, offset) ;

      next_p->prev = prev ;
      prev_p->next = next ;

      if (*base == item)
        *base = next ;
    } ;

  item_p->next = item_p->prev = NULL ;
} ;

/*------------------------------------------------------------------------------
 * Delete head of rdl (if any) and return address of same.
 */
Inline void*
_rdl_del_head(void** base, dl_list_pair_v item_p)
{
  void* item ;

  item = *base ;
  if (item != NULL)
    _rdl_del(base, item, item_p) ;

  return item ;
} ;

#endif /* _ZEBRA_LIST_UTIL_H */
