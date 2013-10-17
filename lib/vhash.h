/* Value Hash Table structure -- header
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_VHASH_H
#define _ZEBRA_VHASH_H

#include "misc.h"
#include "vector.h"

/*==============================================================================
 * Value Hash Table definitions
 *
 * Note that count things in uint -- which is known to be at least 32 bits.
 *
 * Expect to run out of memory before really challenge that assumption !  (At
 * 8 bytes to a pointer, 4G of pointers is already 32G.)
 */
CONFIRM(sizeof(uint) >= 4) ;

enum
{
  /* When extending the chain bases, the number will:
   *
   *   * double if is      <= VHASH_TABLE_BASES_DOUBLE_MAX
   *
   *   * grow by 50% if is <= VHASH_TABLE_BASES_ADD_HALF_MAX
   *
   *   * grow by 25% otherwise -- when changing the number of chain bases,
   *     will allocate enough to increase the number of entries by 25%, before
   *     it hits the threshold again.
   */
  VHASH_TABLE_BASES_DOUBLE_MAX   =  4000,
  VHASH_TABLE_BASES_ADD_HALF_MAX = 20000,

  /* Minimum and maximum number of vhash table bases.
   *
   * Something has gone tragically wrong if we hit the maximum !
   *
   * The maximum is such that: (a) total size of chain bases cannot overflow
   *                               size_t.
   *
   *                           (b) does not exceed UINT_MAX.
   *
   *                           (c) is definitely odd
   */
  VHASH_TABLE_BASES_MIN     = 10,
#if (SIZE_MAX / SIZEOF_VOIDP) > UINT_MAX
  VHASH_TABLE_BASES_MAX     = (UINT_MAX - 1) | 1,
#else
  VHASH_TABLE_BASES_MAX     = ((SIZE_MAX / SIZEOF_VOIDP) - 1) | 1,
#endif

  VHASH_TABLE_THRESHOLD_MAX = UINT_MAX,

  /* Default density
   */
  VHASH_TABLE_DENSITY_DEFAULT   =   2*100,      /*   2.00 entries/base  */
  VHASH_TABLE_DENSITY_MIN       =     100/2,    /*   0.50 entries/base  */
  VHASH_TABLE_DENSITY_MAX       = 500*100,      /* 500.00 entries/base  */
} ;

/*------------------------------------------------------------------------------
 * Structures defined below.
 */
struct vhash_table ;
struct vhash_node ;

typedef uint32_t vhash_hash_t ;
typedef uint     vhash_ref_count_t ;

typedef struct vhash_table*  vhash_table ;
typedef struct vhash_table   vhash_table_t ;

typedef struct vhash_walker* vhash_walker ;
typedef struct vhash_walker  vhash_walker_t ;

typedef struct vhash_node*   vhash_node ;
typedef struct vhash_node    vhash_node_t ;

typedef struct vhash_params* vhash_params ;
typedef struct vhash_params  vhash_params_t ;

typedef const struct vhash_params* vhash_params_c ;
typedef const struct vhash_params  vhash_params_ct ;

/*------------------------------------------------------------------------------
 * A vhash_item is some arbitrary structure, which encloses a vhash_node.
 *
 * The vhash_node MUST be the FIRST object in the vhash_item -- so the vhash
 * code does not really distinguish the two.
 */
typedef void*       vhash_item ;
typedef const void* vhash_item_c ;

typedef void*       vhash_data ;
typedef const void* vhash_data_c ;

enum
{
  vhash_node_offset = 0         /* offset of vhash node in vhash item   */
} ;

/*------------------------------------------------------------------------------
 * Parameters for a Value Hash Table
 *
 * The 'hash', 'equal', 'new' and 'free' functions MUST be set.
 *
 * There are null methods for 'free', 'orphan' and 'table_free', which do
 * very little.
 *
 * Each vhash_table has a pointer to a *const* set of the table's parameters.
 *
 * The 'equal function must return: 0 <=> item value == given value.  Anything
 * else <=> not equal -- so ordinary cmp function will do the job.
 */
typedef vhash_hash_t vhash_hash_func(vhash_data_c data) ;
typedef int          vhash_equal_func(vhash_item_c item, vhash_data_c data) ;
typedef vhash_item   vhash_new_func(vhash_table table, vhash_data_c data) ;
typedef vhash_item   vhash_free_func(vhash_item item, vhash_table table) ;
typedef vhash_item   vhash_orphan_func(vhash_item item, vhash_table table) ;
typedef vhash_table  vhash_table_free_func(vhash_table table, bool on_reset) ;

struct vhash_params
{
  vhash_hash_func*     hash ;   /* hash given data -- for lookup        */
  vhash_equal_func*    equal ;  /* item equal to data ? -- for lookup   */
  vhash_new_func*      new ;    /* to add an item to the table          */
  vhash_free_func*     free ;   /* when item is not in table and
                                 * ref count == 0 (may be 'held')       */
  vhash_orphan_func*   orphan ; /* when item is not in table, but the
                                 * ref count != 0 (may also be 'held')  */
  vhash_table_free_func*
                       table_free ;
} ;

/*------------------------------------------------------------------------------
 * Value Hash Table.
 */
struct vhash_table
{
  void*    parent ;             /* to identify the table.               */

  vhash_node* bases ;           /* ref:array of chain bases             */
  uint     base_count ;         /* number of chain bases                */

  uint     entry_count ;        /* number of entries in the table       */
  uint     max_index ;          /* maximum index in the table           */
  uint     extend_thresh ;      /* when to extend the hash table        */

  vhash_ref_count_t ref_count ; /* references and 'held' state          */

  uint16_t density ;            /* entries per chain base * 100         */
  uint16_t init_base_count ;    /* initial number of chain bases        */

  vhash_params_c params ;       /* pointer to the methods, etc          */
} ;

/*------------------------------------------------------------------------------
 * Value Hash Node.
 *
 * Note that the nodes live on single-link lists hung off the table's chain
 * bases.  This does mean that when removing an item from a table, it is
 * necessary to scan along the list to find it.  A double-linked list is
 * not used because:
 *
 *   - the extra pointer would add 8 bytes to each item, where the node is
 *     only 16 (with the single pointer).
 *
 *   - removal operations are expected to be infrequent.
 *
 *   - the lists are expected to be kept short if performance is critical.
 *
 *     The main cost of long lists is most likely to be when looking up
 *     items -- where a double-linked list would not help.
 *
 *     Some or all of the saving of 8 bytes per item can be spent on more
 *     chain bases, where the return is better -- since both lookup and
 *     removal operations benefit.  Further, consider a table of 'n' items,
 *     where we expect an average of 8 items per chain base.  Using a
 *     double-link list would cost n * 8 bytes.  Adding chain-bases to
 *     reduce the average to 2 items per chain base would cost n * (3/8) * 8
 *     bytes -- so a little *under* half as much !
 *
 * The lookup implements move-to-the-front -- which does not require a
 * double-linked list, either.  So, if memory really is critical, then the cost
 * of long lists is mitigated as much as possible for look-up.  But the cost
 * when removing an item is part of the trade-off.
 *
 * A copy of the item's hash value is kept in the node.  Inter alia, this is
 * used:
 *
 *  1. during look-up: so that when comparing each item with the sought for
 *     value, the hash values can be compared first -- short-circuiting most
 *     comparisons.  (In general the actual value comparison will only ever
 *     be used as final confirmation that the item has been found.)
 *
 *  2. during table reorganisation: when the chain-bases for a table are
 *     extended, every item in the table must be moved to a new chain base,
 *     for which its hash is required (and would otherwise have to be
 *     recalculated).
 *
 *     Use (1) above is the compelling reason for storing the hash in each
 *     node.  This is an additional benefit.
 *
 *  3. when removing items: so the relevant chain-base can be found without
 *     having to recalculate the hash value.
 *
 *     This is also an additional rather than a compelling benefit.
 */
struct vhash_node
{
  vhash_node    next ;          /* single-link list             */

  vhash_hash_t  hash ;          /* set when put into a table    */

  vhash_ref_count_t ref_count ; /* references and 'held' state  */
} ;

enum { VHASH_NODE_INIT_ALL_ZEROS = true } ;

/* The ref_count actually counts in 2's.  The LS bit is the 'held' bit.
 *
 * While the 'held' bit is set, the ref_count field is not zero !
 */
enum vhash_ref_count
{
  vhash_ref_count_increment = 2,
  vhash_ref_count_held      = 1
} ;

/*------------------------------------------------------------------------------
 * Value Hash Walk Iterator
 */
struct vhash_walker
{
  vhash_table table ;           /* table we are working in              */
  vhash_node  next ;            /* next node to return (if any)         */
  vhash_node* base ;            /* next chain base to process (if any)  */
  uint        base_count ;      /* count of chain bases left to process */
} ;

/*==============================================================================
 * Value Hash Table Operations.
 */
extern vhash_table vhash_table_new(void* parent, uint base_count,
                                          uint density, vhash_params_c params) ;
extern void vhash_table_init(vhash_table table, void* parent, uint base_count,
                                          uint density, vhash_params_c params) ;

extern vhash_item vhash_orphan_null(vhash_item item, vhash_table table) ;
extern vhash_item vhash_free_null(vhash_item item, vhash_table table) ;

extern vhash_table vhash_table_free_simple(vhash_table table, bool on_reset) ;
extern vhash_table vhash_table_free_parent(vhash_table table, bool on_reset) ;
extern vhash_table vhash_table_free_null(vhash_table table, bool on_reset) ;
extern vhash_table vhash_table_free(vhash_table table) ;

extern void  vhash_table_set_parent(vhash_table table, void* parent) ;
extern void* vhash_table_get_parent(vhash_table table) ;

extern void vhash_table_ream(vhash_table table) ;
extern vhash_table vhash_table_reset(vhash_table table) ;
extern void vhash_table_reset_bases(vhash_table table, uint base_count) ;

extern vhash_item vhash_lookup(vhash_table table, vhash_data_c data,
                                                                bool* p_added) ;
Inline vhash_item vhash_set_held(vhash_item item) ;
Inline vhash_item vhash_clear_held(vhash_item item) ;
extern vhash_item vhash_drop(vhash_item item, vhash_table table) ;
extern vhash_item vhash_drop_delete(vhash_item item, vhash_table table) ;
extern vhash_item vhash_delete(vhash_item item, vhash_table table) ;

Inline vhash_item vhash_inc_ref(vhash_item item) ;
Inline vhash_item vhash_dec_ref(vhash_item item, vhash_table) ;
Inline vhash_item vhash_dec_ref_simple(vhash_item item) ;
Private vhash_item vhash_ref_final(vhash_item item, vhash_table table) ;

Inline bool vhash_has_references(vhash_item item) ;
Inline bool vhash_is_set(vhash_item item) ;
Inline bool vhash_is_unused(vhash_item item) ;

extern void vhash_walk_start(vhash_table table, vhash_walker walk) ;
extern vhash_item vhash_walk_next(vhash_walker walk) ;

typedef bool vhash_select_test(const vhash_item_c*, vhash_data_c data) ;
typedef int vhash_sort_cmp(const vhash_item_c* a, const vhash_item_c* b) ;

extern vector vhash_table_extract(vhash_table table,
                                   vhash_select_test* select,
                                   vhash_data_c data,
                                   bool most,
                                   vhash_sort_cmp* sort) ;

extern vhash_hash_t vhash_hash_string(const void* string) ;
extern vhash_hash_t vhash_hash_string_cont(const void* string, vhash_hash_t h) ;
extern vhash_hash_t vhash_hash_bytes(const void* bytes, size_t len) ;
extern vhash_hash_t vhash_hash_bytes_cont(const void* bytes, size_t len,
                                                               vhash_hash_t h) ;
Inline vhash_hash_t vhash_hash_word(uint32_t w) ;
Inline vhash_hash_t vhash_hash_word_cont(uint32_t w, vhash_hash_t h) ;

Inline vhash_hash_t vhash_hash_address(const void* a) ;
Inline vhash_hash_t vhash_hash_address_cont(const void* a, vhash_hash_t h) ;

/*==============================================================================
 * The Inline stuff.
 */

/*------------------------------------------------------------------------------
 * Set the 'held' state for the given item
 *
 * Returns:  the item
 */
Inline vhash_item
vhash_set_held(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  ((vhash_node)item)->ref_count |= vhash_ref_count_held ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Clear the 'held' state for the given item
 *
 * The item may then be ready to be freed, but is NOT freed at this time.
 * (Contrast with vhash_drop.)
 *
 * A later call of vhash_unset() will proceed to free the item, if the
 * reference count is zero.
 *
 * The 'held' state is expected to be used to signal that some "owner" of the
 * item has it in their hands and/or that the value of the item is 'held'.
 * When the "owner" is about to release an item and/or its value is about to
 * be dismantled, the 'held' state can be cleared to signal that.
 *
 * NB: a later call of vhash_dec_ref() could also free the item... so, to be
 *     completely certain of holding onto the item once it is unset:
 *
 *        vhash_inc_ref()
 *        vhash_clear_set()
 *
 *        ....
 *
 *        vhash_dec_ref()       // which may then free the item
 *
 * Returns:  the item
 */
Inline vhash_item
vhash_clear_held(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  ((vhash_node)item)->ref_count &= ~(vhash_ref_count_t)vhash_ref_count_held ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Increment item reference count.
 *
 * Returns:  the item
 */
Inline vhash_item
vhash_inc_ref(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  ((vhash_node)item)->ref_count += vhash_ref_count_increment ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Decrement item reference count:
 *
 * If the reference count is not zero, decrement it.
 *
 * Then:
 *
 *   * if the reference count is not zero, or the item is 'held'
 *
 *     Returns the item.
 *
 *   * if the reference count is zero, and the item is not 'held'
 *
 *     vhash_delete() the item -- ie remove it from the table (if it is there)
 *                                and then free() it (if possible).
 *
 *     Returns NULL
 *
 *     (To be more precise, returns whatever the table's free() function
 *      returns -- which will be NULL, unless something "special" is going
 *      on, which the vhash code knows nothing about.
 *
 *      If table is NULL, cannot actually free the item, but pretends that
 *      it did.)
 *
 * For the avoidance of doubt: it is probably an error to attempt to decrement
 * a zero reference count.  What this does is:
 *
 *   * ignore the decrement if the item is 'held'
 *
 *   * vhash_delete() the item if it is not 'held'
 *
 * Returns:  NULL if the item has been freed (or would have been freed, but
 *                                                                table is NULL)
 *           the original item, otherwise.
 */
Inline vhash_item
vhash_dec_ref(vhash_item item, vhash_table table)
{
  confirm(vhash_node_offset == 0) ;

  if (((vhash_node)item)->ref_count > vhash_ref_count_increment)
    {
      ((vhash_node)item)->ref_count -= vhash_ref_count_increment ;
      return item ;
    } ;

  return vhash_ref_final(item, table) ;
} ;

/*------------------------------------------------------------------------------
 * Decrement item reference count, if possible:
 *
 * If the reference count is not zero, decrement it.  Nothing else.
 *
 * NB: if the reference count becomes zero, or is already zero, this has no
 *     effect.
 *
 *     This is the same as vhash_dec_ref() when the item is 'held'.
 *
 *     BUT, if the item is not 'held', it will remain in the hash with a
 *     zero reference count.  (This is not illegal, but is unusual where the
 *     reference count is used.)
 *
 * Returns:  the original item.
 */
Inline vhash_item
vhash_dec_ref_simple(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  if (((vhash_node)item)->ref_count > vhash_ref_count_increment)
    ((vhash_node)item)->ref_count -= vhash_ref_count_increment ;

  return item ;
} ;

/*------------------------------------------------------------------------------
 * Test whether there are any references.
 *
 * Note that for this purpose, the 'held' state does not count
 */
Inline bool
vhash_has_references(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  return (((vhash_node)item)->ref_count >= vhash_ref_count_increment) ;
} ;

/*------------------------------------------------------------------------------
 * Test the 'held' state
 */
Inline bool
vhash_is_set(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  return ((vhash_node)item)->ref_count & vhash_ref_count_held ;
} ;

/*------------------------------------------------------------------------------
 * Test for not 'held' and no references
 */
Inline bool
vhash_is_unused(vhash_item item)
{
  confirm(vhash_node_offset == 0) ;

  return ((vhash_node)item)->ref_count == 0 ;
} ;

/*------------------------------------------------------------------------------
 * Standard vhash integer hash function.
 *
 * Simple approach -- treat as seed for random number !
 *
 * Given that the number of chain bases is always odd, testing suggests that
 * it doesn't make much difference how the integer is hashed !  There is
 * no evidence that jhash() does a better job than this -- and is clearly
 * slower !
 */
Inline vhash_hash_t
vhash_hash_word(uint32_t w)
{
  return ((w ^ 3141592653) * 2650845021u) + 5 ; /* See Knuth 3.3.4      */
} ;

/*------------------------------------------------------------------------------
 * Standard vhash integer hash function, continuing.
 */
Inline vhash_hash_t
vhash_hash_word_cont(uint32_t w, vhash_hash_t h)
{
  return ((w ^ h) * 2650845021u) + 5 ;          /* See Knuth 3.3.4      */
} ;

/*------------------------------------------------------------------------------
 * Standard vhash address hash function.
 *
 * Simple approach -- xor ls 32 bits with ms 32, then treat as integer.
 *
 * If (when) addresses exceed 64 bits, will need to review this.
 */
Inline vhash_hash_t
vhash_hash_address(const void* a)
{
  confirm(sizeof(void*) <= 8) ;

  if (sizeof(void*) <= sizeof(vhash_hash_t))
    return vhash_hash_word((uintptr_t)a) ;
  else
    return vhash_hash_word((uintptr_t)a ^ ((uintptr_t)a >> 32)) ;
} ;

/*------------------------------------------------------------------------------
 * Standard vhash address hash function, continuing.
 */
Inline vhash_hash_t
vhash_hash_address_cont(const void* a, vhash_hash_t h)
{
  return vhash_hash_word_cont(vhash_hash_address(a), h) ;
} ;

#endif /* _ZEBRA_VHASH_H */
