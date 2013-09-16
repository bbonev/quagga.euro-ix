/* "Small Vector" -- Header.
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
#ifndef _ZEBRA_SVECTOR_H
#define _ZEBRA_SVECTOR_H

#include "misc.h"

/*------------------------------------------------------------------------------
 * types and struct for vector
 *
 * NB: an entirely zero structure represents an entirely empty vector.
 */
typedef void*     svec_item ;
typedef uint16_t  svec_index_t ;

enum
{
  /* The first usable "index" for an svec is '1', because we reserve '0'
   * for NULL.
   *
   * The last usable "index" is limited by using a UINT16_MAX.
   *
   * Note that because the "index" is 1-origin, the index of the last item is
   * the same as the maximum number of items the svec can hold at any time.
   */
  SVEC_NULL         = 0,

  SVEC_FIRST        = 1,
  SVEC_LAST         = UINT16_MAX,

  SVEC_INDEX_FIRST  = SVEC_FIRST,
  SVEC_INDEX_MAX    = SVEC_LAST,

  SVEC_EXT_BODY   = 0,
} ;

/*------------------------------------------------------------------------------
 * Support for double base and link lists, where the "pointers" are svec_index_t.
 */
typedef struct svl_base  svl_base_t ;
typedef struct svl_base* svl_base ;

struct svl_base
{
  svec_index_t  head ;
  svec_index_t  tail ;
} ;

typedef struct svl_list  svl_list_t ;
typedef struct svl_list* svl_list ;

struct svl_list
{
  svec_index_t  next ;
  svec_index_t  prev ;
} ;

/*------------------------------------------------------------------------------
 * Support for single base and double link lists, where the "pointers" are
 * svec_index_t.
 */
typedef svec_index_t  svs_base_t ;
typedef svec_index_t* svs_base ;

typedef svl_list_t svs_list_t ;
typedef svl_list   svs_list ;

/*------------------------------------------------------------------------------
 * Generator for small-vector types and various "standard" instances of same.
 *
 * There is a svec-list base-pair embedded in the svec, which may be used by
 * the caller to, for example, keep a creation order list of items.
 */
#define svecN(n) svec##n \
  { \
    svec_index_t  free ;  \
    svec_index_t  last ;  \
    svl_base_t    base[1] ; \
    void*         body[n + 1] ; \
  }

/* When malloc() we may expect some overhead -- perhaps 16 bytes.
 *
 * As shown here, can create a custom small-vector with as many 'embedded'
 * entries as desired.  When passed to any svec function, the svec is cast to
 * the generic 'svec'.
 */
struct svecN( 0) ;      /* struct svec0                 */
struct svecN( 4) ;      /* struct svec4 --  48 bytes    */
struct svecN( 8) ;      /* struct svec8 --  80 bytes    */
struct svecN(12) ;      /* struct svec12-- 112 bytes    */

typedef struct svec0   svec_t ;
typedef struct svec0*  svec ;

typedef struct svec4   svec4_t ;
typedef struct svec4*  svec4 ;

typedef struct svec8   svec8_t ;
typedef struct svec8*  svec8 ;

typedef struct svec12  svec12_t ;
typedef struct svec12* svec12 ;

/* Setting a vector object to all zeros is enough to initialise it to
 * an empty vector.
 */
enum
{
  SVEC_INIT_ALL_ZEROS = true
} ;

#define SVEC_INIT_EMPTY  { 0 }

/*------------------------------------------------------------------------------
 * Values that control the allocation of the extended small-vector body.
 *
 * NB: these must all be powers of 2.
 */
enum
{
  /* When an extended body is first allocated, it will either match the size
   * of the embedded part, or be this big (whichever is the larger).
   */
  SVEC_EXT_SIZE_MIN       = 4,

  /* When an external body grows, it doubles in size, until it is this big.
   * After that it grows in units of this much.
   */
  SVEC_EXT_DOUBLE_MAX     = 64,
} ;

CONFIRM(IS_POW_OF_2(SVEC_EXT_SIZE_MIN)) ;
CONFIRM(IS_POW_OF_2(SVEC_EXT_DOUBLE_MAX)) ;

/*==============================================================================
 * Prototypes/Macros
 *
 * All functions involved in operating on an svec need to have the embedded
 * count as an argument.  To make that simple, all the functions have a
 * macro form, which creates the extra, "hidden" argument automatically.
 *
 * NB: this depends on the *type* of the svec argument.
 *
 */
#define svec_embedded(sv) ((sizeof(*sv) - sizeof(svec_t)) / sizeof(void*))
CONFIRM(svec_embedded((svec4)NULL) == 4) ;

/* Initialisation/Destruction.
 *
 *   * svec_init(sv)          -- initialise from scratch
 *
 *                               sv is address of an svec object.
 *
 *                               No different from zeroizing !
 *
 *   * svec_reset(sv)         -- set empty, retaining any extended body.
 *
 *   * svec_clear(sv)         -- set empty, freeing any extended body
 */
#define svec_init(sv) _svec_init((svec)sv, svec_embedded(sv))
#define svec_reset(sv) _svec_reset((svec)sv, svec_embedded(sv))
#define svec_clear(sv) _svec_clear((svec)sv, svec_embedded(sv))

Private void _svec_init(svec sv, svec_index_t e) ;
Private void _svec_reset(svec sv, svec_index_t e) ;
Private void _svec_clear(svec sv, svec_index_t e) ;

/* The basic add/del/get operations.
 *
 *   * svec_add(sv, item)     -- add given item to the svec
 *
 *                               NB: item may be NULL.
 *
 *                               Returns: index of the item.
 *
 *   * svec_del(sv, i)        -- remove item at the given index from the svec.
 *
 *                               Returns: item removed.
 *
 *   * svec_get(sv, i)        -- get address of item at the given index.
 *
 *                               Returns: item
 *
 *   * svec_set(sv, i)        -- set address of item at the given index.
 *
 *                               Returns: item
 *
 *   * svec_get_(sv, i)       -- get pointer to address of item at the given
 *                               index.
 *
 *                               Returns: pointer to item
 *
 * NB: the svec_get() in particular is "light-weight" -- no checking is done
 *     on the index, the state of the svec or anything else.
 */
#define svec_add(sv, item) _svec_add((svec)sv, item, svec_embedded(sv))
#define svec_del(sv, i) _svec_del((svec)sv, i, svec_embedded(sv))
#define svec_get(sv, i) _svec_get((svec)sv, i, svec_embedded(sv))
#define svec_set(sv, i, item) _svec_set((svec)sv, i, item, svec_embedded(sv))
#define svec_get_p(sv, i) _svec_get_p((svec)sv, i, svec_embedded(sv))

Private svec_index_t _svec_add(svec sv, svec_item item, svec_index_t e) ;
Private svec_item _svec_del(svec sv, svec_index_t i, svec_index_t e) ;
Inline svec_item _svec_get(svec sv, svec_index_t i, svec_index_t e) ;
Inline svec_item _svec_set(svec sv, svec_index_t i, svec_item item,
                                                               svec_index_t e) ;
Inline svec_item _svec_get_p(svec sv, svec_index_t i, svec_index_t e) ;

/*==============================================================================
 * The inline functions:
 */

/*------------------------------------------------------------------------------
 * Basic "get item".
 *
 * Returns:  item -- NULL if i == SVEC_NULL or i > sv->last
 *
 * NB: 'e' is the index of the last embedded item.
 */
Inline svec_item
_svec_get(svec sv, svec_index_t i, svec_index_t e)
{
  qassert(e <= sv->last) ;

  if (i <= e)
    {
      if (i > SVEC_NULL)
        return sv->body[i] ;
      else
        return NULL ;
    }
  else
    {
      if (i <= sv->last)
        return ((void**)(sv->body[SVEC_EXT_BODY]))[i - e - 1] ;
      else
        return NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Basic get pointer to item -- ie address of the svec entry.
 *
 * Returns:  address of pointer to item
 *
 * NB: if i == SVEC_NULL, returns address of pointer to SVEC_EXT_BODY !!
 *
 * NB: if i > sv->last, returns bogus address !!
 *
 * NB: 'e' is the index of the last embedded item.
 */
Inline svec_item
_svec_get_p(svec sv, svec_index_t i, svec_index_t e)
{
  qassert((i != SVEC_NULL) && (i <= sv->last) && (e <= sv->last)) ;

  if (i <= e)
    return &sv->body[i] ;
  else
    return &((void**)(sv->body[SVEC_EXT_BODY]))[i - e - 1] ;
} ;

/*------------------------------------------------------------------------------
 * Basic "set item".
 *
 * Returns:  item as given
 *
 * NB: will go BADLY WRONG if the given index is invalid !!
 *
 * NB: 'e' is the index of the last embedded item.
 */
Inline svec_item
_svec_set(svec sv, svec_index_t i, void* item, svec_index_t e)
{
  qassert((i != SVEC_NULL) && (i <= sv->last) && (e <= sv->last)) ;

  if (i <= e)
    return sv->body[i] = item ;
  else
    return ((void**)(sv->body[SVEC_EXT_BODY]))[i - e - 1] = item ;
} ;

/*==============================================================================
 * Double Link Base -- List Functions.
 *
 * These "functions" are (mostly) macro front ends to actual functions.  The
 * macros generate offsets and establish the embedded count and so on, and
 * pass same to the actual functions.  The arguments are:
 *
 *   * base     -- type == svl_base     -- address of base pair
 *
 *   * list     -- type == svl_list     -- address of list pair
 *
 *   * sv       -- type == svecXX       -- address of some svec object
 *
 *   * i        -- type == svec_index_t -- index of item in the svec.
 *   * ia, ib   -- similarly
 *
 *   * it_t     -- type of the items in the svec
 *   * lp       -- type == svl_list_t   -- field in it_t which is a list pair
 *
 * Suppose we have items of item_t:
 *
 *   typedef struct item item_t ;
 *   struct item
 *     {
 *       ....
 *       svl_list_t  list ;
 *       ....
 *     } ;
 *
 * we can push item 'i' onto a given list by:
 *
 *   svl_push(base, sv, item_t, list) ;
 *
 * And similarly for most of the other list operations.
 *
 * The "functions" are:
 *
 *   * svl_init_base(base)       -- clear the given base pair
 *
 *   * svl_init_list(list)       -- clear the given list pair
 *
 *   * svl_head(base, sv)        -- get item which is head of given list
 *   * svl_tail(base, sv)        -- get item which is tail of the the given list
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_next(list, sv)        -- get item which follows in list
 *   * svl_prev(list, sv)        -- get item which precedes in list
 *
 *     So... if have:
 *
 *       struct item
 *       {
 *         ...
 *         svl_list_t  list ;
 *         ...
 *       }
 *
 *     Then given a pointer to such an item:
 *
 *       p_item = svl_next(&p_item->list, the_svec) ;
 *
 *     will return the next item.
 *
 *   * svl_prepend(base, sv, i, it_t, lp)   -- place item on front of list
 *   * svl_push(base, sv, i, it_t, lp)
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *   * svl_append(base, sv, i, it_t, lp)    -- place item on tail of list
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *   * svl_in_before(ib, base, sv, i, it_t, lp) -- place item before given one
 *   * svl_in_after(ia, base, sv, i, it_t, lp)  -- place item after given one
 *
 *     If ib == SVEC_NULL, append to list.
 *     If ia == SVEC_NULL, prepend.
 *
 *     Consider a list in some ascending order.  A loop searching for the
 *     first item greater than some new value may run off the end of the list.
 *     Hence, for svl_in_before it makes sense to treat SVEC_NULL as append.
 *     For svl_in_after() the same logic applies, assuming working backwards
 *     along a sorted list.
 *
 *     If the list is empty, 'ib' and 'ia' can only be SVEC_NULL, and it
 *     matters not whether the operation is append or prepend !
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     It is also *vital* that items 'ia' and 'ib' exist are on the list !
 *
 *   * svl_del_head(base, sv, it_t, lp) -- remove and return head of list
 *   * svl_pop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_del_tail(base, sv, it_t, lp) -- remove and return tail of list
 *   * svl_crop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *   * svl_del(base, sv, i, it_t, lp)   -- remove item from list
 *
 *     It is *vital* that item 'i' exists in the given sv, and is on the list.
 */
#define svl_init(base) \
  ((base)->head = (base)->tail = SVEC_NULL)

#define svl_init_p(item_p) \
  ((item_p)->next = (item_p)->prev = SVEC_NULL)

#define svl_head(base, sv) ((base)->head == SVEC_NULL \
                           ? NULL : svec_get(sv, (base)->head))

#define svl_tail(base, sv) ((base)->tail == SVEC_NULL \
                           ? NULL : svec_get(sv, (base)->tail))

#define svl_next(list, sv) ((list)->next == SVEC_NULL \
                           ? NULL : svec_get(sv, (list)->next))

#define svl_prev(list, sv) ((list)->prev == SVEC_NULL \
                           ? NULL : svec_get(sv, (list)->prev))

#define svl_prepend(base, sv, i, it_t, lp) \
  _svl_prepend(base, (svec)sv, i, offsetof(i_t, lp), svec_embedded(sv))

#define svl_push(base, sv, i, it_t, lp) \
  svl_prepend(base, sv, i, it_t, lp)

#define svl_append(base, sv, i, it_t, lp) \
  _svl_append(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv))

#define svl_in_before(ib, base, sv, i, it_t, lp) \
  _svl_in_before(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv), ib)

#define svl_in_after(ia, base, sv, i, it_t, lp) \
  _svl_in_after(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv), ia)

#define svl_del_head(base, sv, it_t, lp) \
  _svl_del_head(base, (svec)sv, offsetof(it_t, lp), svec_embedded(sv))

#define svl_pop(base, sv, it_t, lp) \
  svl_del_head(base, sv, it_t, lp)

#define svl_del_tail(base, sv, it_t, lp) \
  _svl_del_head(base, (svec)sv, offsetof(it_t, lp), svec_embedded(sv))

#define svl_crop(base, sv, it_t, lp) \
  svl_del_tail(base, sv, it_t, lp)

#define svl_del(base, sv, i, it_t, lp) \
  _svl_del(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv))

Private svec_item _svl_prepend(svl_base base, svec sv,
                                   svec_index_t i, size_t off, svec_index_t e) ;
Private svec_item _svl_append(svl_base base, svec sv,
                                   svec_index_t i, size_t off, svec_index_t e) ;
Private svec_item _svl_in_before(svl_base base, svec sv,
                  svec_index_t i, size_t off, svec_index_t e, svec_index_t ib) ;
Private svec_item _svl_in_after(svl_base base, svec sv,
                  svec_index_t i, size_t off, svec_index_t e, svec_index_t ia) ;
Private svec_item _svl_del_head(svl_base base, svec sv,
                                                   size_t off, svec_index_t e) ;
Private svec_item _svl_del_tail(svl_base base, svec sv,
                                                   size_t off, svec_index_t e) ;
Private svec_item _svl_del(svl_base base, svec sv, svec_index_t i,
                                                   size_t off, svec_index_t e) ;

/*==============================================================================
 * Single Link Base -- List Functions.
 *
 * These are almost the same as the Double Link Base functions, above, except
 * for:
 *
 *   * base     -- type == svs_base     -- address of the svec_index
 *
 * The "functions" are:
 *
 *   * svs_init_base(base)       -- clear the given base
 *
 *   * svs_init_list(list)       -- clear the given list pair
 *
 *   * svs_head(base, sv)        -- get item which is head of given list
 *   * svs_tail(base, sv)        -- get item which is tail of the the given list
 *
 *     If the list is empty these return NULL.
 *
 *     NB: svs_tail() has to chase down the list looking for the tail !
 *
 *   * svs_next(list, sv)        -- get item which follows in list
 *   * svs_prev(list, sv)        -- get item which precedes in list
 *
 *     So... if have:
 *
 *       struct item
 *       {
 *         ...
 *         svs_list_t  list ;
 *         ...
 *       }
 *
 *     Then given a pointer to such an item:
 *
 *       p_item = svs_next(&p_item->list, the_svec) ;
 *
 *     will return the next item.
 *
 *   * svs_prepend(base, sv, i, it_t, lp)   -- place item on front of list
 *   * svs_push(base, sv, i, it_t, lp)
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     These (and other) macros take a *type* and a *field* as arguments, where
 *     the field is the svs_list_t pair, so that the offset of that field
 *     can be calculated by: offsetof(it_t, lp).
 *
 *     Suppose we have items of item_t:
 *
 *       typedef struct item item_t ;
 *       struct item
 *         {
 *           ....
 *           svs_list_t  list ;
 *           ....
 *         } ;
 *
 *     we can push item 'i' onto a given list by:
 *
 *       svs_push(base, sv, item_t, list) ;
 *
 *     And similarly for most of the other list operations.
 *
 *   * svs_append(base, sv, i, it_t, lp)    -- place item on tail of list
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     NB: this has to chase down to the tail in order to insert.
 *
 *   * svs_in_before(ib, base, sv, i, it_t, lp) -- place item before given one
 *   * svs_in_after(ia, base, sv, i, it_t, lp)  -- place item after given one
 *
 *     If ib == SVEC_NULL, append to list -- NB: chases down list !!
 *     If ia == SVEC_NULL, prepend.
 *
 *     Consider a list in some ascending order.  A loop searching for the
 *     first item greater than some new value may run off the end of the list.
 *     Hence, for svs_in_before it makes sense to treat SVEC_NULL as append.
 *     For svs_in_after() the same logic applies, assuming working backwards
 *     along a sorted list.
 *
 *     However, since the append operation has to chase down the list looking
 *     for the end, this is probably not a good way to go !
 *
 *     If the list is empty, 'ib' and 'ia' can only be SVEC_NULL, and it
 *     matters not whether the operation is append or prepend !
 *
 *     It is *vital* that item 'i' exists in the given sv, but is NOT on any
 *     list (including not on the given one).
 *
 *     It is also *vital* that items 'ia' and 'ib' exist are on the list !
 *
 *   * svs_del_head(base, sv, it_t, lp) -- remove and return head of list
 *   * svs_pop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *   * svs_del_tail(base, sv, it_t, lp) -- remove and return tail of list
 *   * svs_crop(base, sv, it_t, lp)
 *
 *     If the list is empty these return NULL.
 *
 *     NB: has to chase down list to find the tail item.
 *
 *   * svs_del(base, sv, i, it_t, lp)   -- remove item from list
 *
 *     It is *vital* that item 'i' exists in the given sv, and is on the list.
 */
#define svs_init(base) \
  (*(base) = SVEC_NULL)

#define svs_init_p(item_p) \
  ((item_p)->next = (item_p)->prev = SVEC_NULL)

#define svs_head(base, sv) (*(base) == SVEC_NULL \
                           ? NULL : svec_get(sv, *(base)))

#define svs_tail(base, sv) (*(base) == SVEC_NULL \
                           ? NULL : _svs_tail(sv, *(base)))

#define svs_next(list, sv) ((list)->next == SVEC_NULL \
                           ? NULL : svec_get(sv, (list)->next))

#define svs_prev(list, sv) ((list)->prev == SVEC_NULL \
                           ? NULL : svec_get(sv, (list)->prev))

#define svs_prepend(base, sv, i, it_t, lp) \
  _svs_prepend(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv))

#define svs_push(base, sv, i, it_t, lp) \
  svs_prepend(base, sv, i, it_t, lp)

#define svs_append(base, sv, i, it_t, lp) \
  _svs_append(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv))

#define svs_in_before(ib, base, sv, i, it_t, lp) \
  _svs_in_before(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv), ib)

#define svs_in_after(ia, base, sv, i, it_t, lp) \
  _svs_in_after(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv), ia)

#define svs_del_head(base, sv, it_t, lp) \
  _svs_del_head(base, (svec)sv, offsetof(it_t, lp), svec_embedded(sv))

#define svs_pop(base, sv, it_t, lp) \
  svs_del_head(base, sv, it_t, lp)

#define svs_del_tail(base, sv, it_t, lp) \
  _svs_del_head(base, (svec)sv, offsetof(it_t, lp), svec_embedded(sv))

#define svs_crop(base, sv, it_t, lp) \
  svs_del_tail(base, sv, it_t, lp)

#define svs_del(base, sv, i, it_t, lp) \
  _svs_del(base, (svec)sv, i, offsetof(it_t, lp), svec_embedded(sv))

Private svec_item _svs_prepend(svs_base base, svec sv,
                                   svec_index_t i, size_t off, svec_index_t e) ;
Private svec_item _svs_append(svs_base base, svec sv,
                                   svec_index_t i, size_t off, svec_index_t e) ;
Private svec_item _svs_in_before(svs_base base, svec sv,
                  svec_index_t i, size_t off, svec_index_t e, svec_index_t ib) ;
Private svec_item _svs_in_after(svs_base base, svec sv,
                  svec_index_t i, size_t off, svec_index_t e, svec_index_t ia) ;
Private svec_item _svs_del_head(svs_base base, svec sv,
                                                   size_t off, svec_index_t e) ;
Private svec_item _svs_del_tail(svs_base base, svec sv,
                                                   size_t off, svec_index_t e) ;
Private svec_item _svs_del(svs_base base, svec sv, svec_index_t i,
                                                   size_t off, svec_index_t e) ;

#endif /* _ZEBRA_SVECTOR_H */
