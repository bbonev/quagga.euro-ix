/* Value Hash Table structure -- functions
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
#include "misc.h"

#include "vhash.h"
#include "memory.h"

/*==============================================================================
 * A Value Hash Table maps some data to some structure containing or referring
 * to that data.
 *
 * This is used to map a "name" to a value.
 *
 * This is also used for "content addressable" store for unique copies of a
 * piece of data.
 *
 * A vhash_table comprises:
 *
 *   * vhash_table structure             -- containing all "red-tape"
 *   * array of chain-bases              -- for the hash table
 *   * vhash_items enclosing vhash_nodes -- each containing an item related
 *                                          to some vhash_data.
 *
 * The vhash_table structure may be dynamically allocated or may be embedded
 * in another structure.
 *
 * A vhash_table may point to its "parent".  The vhash_table code does not
 * use or need this -- it is for the convenience of the caller.
 *
 * The vhash_item and the vhash_data may be anything at all.  As far as the
 * vhash table is concerned these are is defined by the vhash_params:
 *
 *   * vhash_hash_func*   hash
 *
 *     This takes a vhash_data value, and returns the hash value for it.
 *
 *     This is used when searching for, and possibly adding, an item.
 *
 *   * vhash_equal_func*  equal
 *
 *     This takes a vhash_item value and a vhash_data value, and returns
 *     0 <=> the vhash_item data == the give vhash_data.
 *
 *     This is called when searching for an item with the given data -- but
 *     only when the hash for the item and the hash for the data match.
 *
 *   * vhash_new_func*    new
 *
 *     This takes the vhash_table and a vhash_data value, and returns the
 *     address of a new vhash_item.
 *
 *     This is called when adding an item.
 *
 *     Note that the new() does not need to worry about the vhash_node part of
 *     the item -- in particular, it is not required to zeroize it.
 *
 *     If the item holds a pointer to the table, then vhash_table_inc_ref()
 *     can/should be used to avoid that pointer becoming a dangling pointer.
 *
 *   * vhash_free_func*   free
 *
 *     This is called when an item has been removed from the table and the
 *     item's reference count is zero -- the item may or may not be "set".
 *     (The item may be an orphan, so have been removed from the table some
 *     time ago.)
 *
 *     The expected action is that the item, and any value it may have, will be
 *     freed.  If vhash_table_inc_ref() was called when the item was created,
 *     the vhash_table_dec_ref() will be required.  The function should
 *     return NULL.
 *
 *     If (for whatever, bizarre) reason the item is not freed, the free()
 *     function may elect to return the item or NULL.
 *
 *     In any case, it is a mistake to call vhash_unset() in the free()
 *     function, because that will recurse.
 *
 *   * vhash_orphan_func* orphan
 *
 *     This is called when an item is removed from the table and the item's
 *     reference count is not zero -- the item may or may not be "set".
 *
 *     The expected action is that the item's value will be cleared, and any
 *     "set" state cleared with it.  At a minimum, the "set" state should be
 *     cleared, so that when the reference count is reduced to zero, the
 *     item will then be freed.  The function should return the item.
 *
 *     It is a mistake to fiddle with the reference count in the orphan()
 *     function, because that may recurse or cause free() to be called.
 *
 *     The orphan() function may call vhash_unset() -- subject to the caveat re
 *     fiddling with the reference count.
 *
 *     If the "set" state is not clear when orphan() returns, then the
 *     application must clear it at some other time (if the item is to be
 *     freed).  The vhash_orphan_null() does nothing other than clear "set".
 *
 *     If (for whatever, really, bizarre) reason the item is freed, the
 *     orphan() function must return NULL.
 *
 * The array of chain-bases is dynamically allocated and will grow to maintain
 * an approximate given maximum number of items per chain base.  This density
 * is set when the vhash table is initialised.  The array does not
 * automatically reduce in size.
 *
 * The number of chain bases is always odd.  The hash function returns an
 * unsigned value, which is mapped to the chain bases modulo their number.
 * Since that is odd, it is co-prime with the hash, so contributes to the hash
 * process.
 *
 * The reference counting and "set" state work as follows:
 *
 *   * an item which is marked as "set" is not freed when the reference count
 *     is zero, but it may be deleted from the table -- which clears the "set"
 *     state.
 *
 *     The intent is that there may be "users" of an item, who are counted by
 *     the reference count, and one "owner" of an item who holds the "set" flag
 *     while the item has a (or any) value.
 *
 *   * when saving/discarding the address of an item, the "user" can
 *     increment/decrement the reference count to register/unregister their
 *     interest in the item.
 *
 *     Decrementing the reference count to zero (or when it is zero) will
 *     cause the item to be deleted, unless it is "set".
 *
 *   * the owner of an item may clear the "set" state, and the item will
 *     be freed immediately or when its reference count reduces to zero.
 *
 *   * an item may be deleted from the table -- it is expected that only the
 *     "owner" will do this, and that the "set" will be cleared at the same
 *     time.
 *
 *     If the item has a zero reference count, it will be freed immediately.
 *
 *     Otherwise, the item becomes an orphan -- that is, not in the table and
 *     not "set".  All "users" of the item will still have a valid pointer to
 *     it -- though the item may be marked empty in some way (noting that the
 *     "set" state may be used for that purpose).  If the table structure
 *     remains valid, the item may be freed when its reference count is
 *     reduced to zero.
 *
 *     Note that once an item has been orphaned, a new item with the same
 *     "name" can be created, and that is entirely separate from the orphaned
 *     item.
 *
 * The reference count and "set" state are used by the following functions:
 *
 *   * vhash_set()     -- sets the "set" state
 *
 *   * vhash_unset()   -- clears the "set" state (if it was set)
 *
 *                        if the reference count is zero, removes the item from
 *                        the table and frees it.
 *
 *   * vhash_inc_ref() -- increments the reference count
 *
 *   * vhash_dec_ref() -- decrements the reference count (if not already zero)
 *
 *                        if the resulting reference count is zero, and the
 *                        item is not "set", removes it from the table and
 *                        frees it.
 *
 *   * vhash_unset_delete()  -- combined vhash_unset()/vhash_delete()
 *
 *   * vhash_delete()  -- removes item from the table, then:
 *
 *                          if the reference count is zero, call free()
 *
 *                          if the reference count is not zero, call orphan()
 *
 *                        NB: in this case, when free() or orphan() are called
 *                            the item may still be "set".
 *
 *                            Generally, only the "owner" of an item will
 *                            vhash_delete() it, so the "set" state signals
 *                            that any value is still present, and may (well)
 *                            need to be discarded.
 *
 * Note that vhash_delete() can create orphan items, which are covered below.
 *
 *------------------------------------------------------------------------------
 * Orphan items etc.
 *
 * When an item which has a non-zero reference count (irrespective of whether
 * it is "set" or not) is deleted by vhash_delete() it becomes an orphan.
 * During the delete operation the table's orphan() function is called to
 * signal that fact.
 *
 * It is likely that when an item becomes an orphan its value will be cleared,
 * but that is a matter outside the scope of the vhash_table.  At the same time,
 * if the item is "set", it is likely to be unset.
 *
 * It is expected that each "user" of the item will, in due course, call
 * vhash_dec_ref().  When the reference count becomes zero, the item will be
 * freed.
 *
 * Once an item is an orphan: vhash_inc_ref() will work as you might expect;
 * vhash_set() and vhash_unset() will also work, but what they mean is not
 * clear -- an orphan is not likely to have a value; vhash_delete() has no
 * effect.
 *
 * The related vhash_table_reset() and vhash_table_ream() functions implicitly
 * vhash_delete() every item in the table.
 *
 * Callers of vhash_dec_ref() et al need the address of the relevant table.
 * Provided they have access to the current address, all is well.  How that is
 * achieved depends on the application, but may include:
 *
 *   * static allocation of the vhash table structure -- which finesses the
 *     problem completely.
 *
 *   * static allocation of a pointer to the vhash table structure.
 *
 *   * some other means to lookup a pointer to the relevant table.
 *
 * When a table is freed, the pointer must be set NULL.  If any of
 * vhash_dec_ref() et al is called, the reference count etc. will be updated.
 * If the item should be freed, then since there is no known table there is
 * no free() function, so nothing is done and the item is quietly forgotten.
 * This may leak memory, but is at least safe.  In particular, at termination
 * time, it is best to delay deleting the table structure to the last possible
 * moment -- but it is not fatal if one or two orphans still exist.
 *
 * However, where the application is more dynamic, it may be necessary to keep
 * in each item a pointer to the vhash table in which it belongs.  To avoid
 * dangling references to the vhash table we have an additional mechanism,
 * the vhash table's 'ref_count', which is much like the ref_count for each
 * item.  When a vhash table is created it is "set".  When it is reset and
 * freed, the "set" state is cleared, but if the reference count is not
 * zero, the vhash table structure is not freed.  The vhash_table_inc_ref() and
 * vhash_table_def_ref() functions may be used to register/de-register an
 * interest in the vhash table.  This may be used:
 *
 *   * in the new() and free() functions to prevent the vhash table structure
 *     being deleted while the item exists and points at it.
 *
 *   * to protect a pointer to a vhash table structure which is used for
 *     vhash_dec_ref() et al -- and which will remain valid after a
 *     table has been reset and freed.
 *
 *     Where many dynamic vhash tables are created and destroyed, it might be
 *     useful to keep a single "dummy" vhash table structure for use by
 *     orphan items.
 *
 * Note that the free() function is only called when the item's reference
 * count is zero.  The "set" state may signal that the item has a value, which
 * needs to be freed.  But whatever the "set" state, the expectation is that
 * the item will be freed and that free() will return NULL.
 *
 * The orphan() function is only called when the items's reference count is
 * not zero.  It is also only called when the item becomes an orphan, that is
 * at the time it is removed from the table.  The "set" state may signal that
 * the item has a value, which needs to be freed.  But in any case, since the
 * item is being deleted, it is likely that any value will be discarded at
 * this point, and any "set" state cleared.
 */

 /*------------------------------------------------------------------------------
  * Null orphan() function -- clear any "set" state, but otherwise do nothing
  * and return the item.
  *
  * If no action is required when an item is orphaned, the table's orphan()
  * function may be set to this.
  */
extern vhash_item
vhash_orphan_null(vhash_item item, vhash_table table)
{
  ((vhash_node)item)->ref_count &= ~(vhash_ref_count_t)vhash_ref_count_set ;

  return item ;
} ;

/*==============================================================================
 * Value Hash Table Operations
 */
static void vhash_table_free_bases(vhash_table table) ;
static void vhash_table_new_bases(vhash_table table, uint new_base_count) ;
static void vhash_table_extend_bases(vhash_table table) ;
static vhash_item vhash_reap(vhash_node node, vhash_table table,
                                                           vhash_node* p_prev) ;

inline static uint vhash_base_index(vhash_table table, vhash_hash_t hash) ;

/*------------------------------------------------------------------------------
 * Allocate and initialise a new vhash table.
 *
 * Requires:
 *
 *   parent   -- address of some parent or other higher level data structure.
 *
 *               This is not used by the vhash table code and may be NULL if
 *               the caller has no use for it.
 *
 *   bases    -- number of list bases to start the vhash table at.
 *
 *               The vhash table grows as required, but can set initial size if
 *               have some expectations and wish to avoid growth steps.
 *
 *               A minimum of VHASH_TABLE_BASES_MIN will be allocated when the
 *               time comes.  A limit of UINT16_MAX is imposed on this (!).
 *
 *   density  -- %-age of items/bases.   0 => use default.
 *                                     150 => 1.50 entries/base (for example)
 *
 *               When the time comes, the density will be clamped to
 *               VHASH_TABLE_DENSITY_MIN..VHASH_TABLE_DENSITY_MAX
 *
 *   params   -- see above
 *
 *               NB: this pointer to the parameters for the vhash is copied to
 *                   the table structure.
 *
 *                   So: a vhash parameters structure MUST have a lifetime at
 *                       least as long as the tables in which it is used
 *                       (noting that a table may live beyond a call of
 *                        vhash_table_reset() if the ref_count requires it).
 *
 *                   It is expected that the parameters will be const, which
 *                   trivially satisfies this requirement !
 *
 *               NB: all methods MUST be defined -- there is no such thing
 *                   as a NULL or empty method.
 *
 * Note that does not allocate any chain bases, and leaves the processing of
 * the base_count and the density settings until they are needed -- see
 * vhash_table_new_bases().
 *
 * Returns:  address of new vhash table
 */
extern vhash_table
vhash_table_new(void* parent, uint base_count, uint density,
                                                          vhash_params_c params)
{
  vhash_table table ;

  table = XMALLOC(MTYPE_VHASH_TABLE, sizeof (vhash_table_t)) ;

  vhash_table_init(table, parent, base_count, density, params) ;

  return table ;
} ;

/*------------------------------------------------------------------------------
 * Initialise a new vhash table.
 *
 * See vhash_table_new() for the arguments.
 */
extern void
vhash_table_init(vhash_table table, void* parent, uint base_count, uint density,
                                                          vhash_params_c params)
{
  assert(base_count <= VHASH_TABLE_BASES_MAX) ;

  memset(table, 0, sizeof(vhash_table_t)) ;

  /* The memset(0) sets:
   *
   *   parent          -- X     -- set below, per argument
   *
   *   bases           -- NULL  -- does not allocate bases until required
   *   base_count      -- 0     -- ditto
   *
   *   entry_count     -- 0     -- table is empty !
   *   max_index       -- 0     -- table is empty !
   *   extend_thresh   -- 0     -- set when chain bases are allocated
   *
   *   ref_count       -- X     -- is "set", below.
   *
   *   density         -- X     -- set below, per argument
   *   init_base_count -- X     -- set below, per argument
   *
   *   params          -- X     -- set below
   */
  table->parent          = parent ;

  table->ref_count       = vhash_ref_count_set ;

  if (base_count > UINT16_MAX)
    base_count = UINT16_MAX ;

  if (density > UINT16_MAX)
    density = UINT16_MAX ;

  table->init_base_count = base_count ;
  table->density         = density ;

  qassert(params->hash  != NULL) ;      /* must have            */
  qassert(params->equal != NULL) ;      /* must have            */
  qassert(params->new   != NULL) ;      /* must have            */
                                        /* rest optional        */
  table->params = params ;
} ;


/*------------------------------------------------------------------------------
 * Set "parent" of vhash table.
 */
extern void
vhash_table_set_parent(vhash_table table, void* parent)
{
  table->parent = parent ;
} ;

/*------------------------------------------------------------------------------
 * Get "parent" of vhash table.
 */
extern void*
vhash_table_get_parent(vhash_table table)
{
  return table->parent ;
} ;

/*------------------------------------------------------------------------------
 * Ream out given vhash_table --  vhash_delete() everything in the table.
 *
 * Does nothing if the table is NULL.
 *
 * This preserves the current table and chain bases.
 *
 * NB: vhash_delete() can do pretty much anything it likes with the table,
 *     short of freeing the table structure -- up to and including
 *     freeing the chain bases (!).
 */
extern void
vhash_table_ream(vhash_table table)
{
  bool rescan ;

  if (table == NULL)
    return ;

  rescan = false ;
  while ((table->entry_count != 0) && (table->bases != NULL))
    {
      uint index ;
      vhash_node  node ;
      vhash_node* p_base ;

      /* We have some chain bases, so the base_count should be > 0,
       * and hence:
       */
      qassert(table->max_index < table->base_count) ;

      /* Hunt for a non-NULL chain base entry, starting from the current
       * max_index.
       */
      index = table->max_index ;
      while (1)
        {
          p_base = &table->bases[index] ;
          node = *p_base ;

          if (node != NULL)
            break ;                     /* we have another item */

          if (index == 0)
            {
              /* This is unexpected... either the table->entry_count is wrong,
               * or the table->max_index was.  In case it is the later, will
               * rescan once, starting from the end.
               *
               * Note that adding items to the table changes table->max_index
               * if required -- so this is not a mechanism for dealing with
               * that case.
               */
              qassert(false) ;

              if (rescan)
                return ;                /* give up              */

              rescan = true ;
              index  = table->base_count ;      /* the very end */
            } ;

          index -= 1 ;
        } ;

      /* We have found a not-empty chain base -- reap the current first
       * entry in the chain.
       */
      table->max_index = index ;        /* keep up to date      */

      vhash_reap(node, table, p_base) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Ream out given table (if any), free the chain bases and (if required) free
 * the table.
 *
 * All items in the table are deleted as if by vhash_delete().
 *
 * If the table is not freed, then can continue to use it (!) and if a new
 * item is added to the table, will create a new set of chain bases.
 *
 * If the table is to be freed, clears the "set" state for the table, and
 * free it if the reference count is zero.  If the reference count is not zero,
 * the table is not freed, but will be when the reference count is reduced
 * to zero.
 *
 * NB: once the table is no longer "set", it is a mistake to look up items in
 *     the table, and especially a mistake to try to add anything to it.
 *
 * Returns:  table if not 'free_table'
 *           NULL if 'table_free'
 */
extern vhash_table
vhash_table_reset(vhash_table table, free_keep_b free_table)
{
  if (table != NULL)
    {
      vhash_table_ream(table) ;

      vhash_table_free_bases(table) ;

      if (free_table)
        {
          table->ref_count &= ~(vhash_ref_count_t)vhash_ref_count_set ;
          if (table->ref_count == 0)
            XFREE(MTYPE_VHASH_TABLE, table) ;

          table = NULL ;
        } ;
    } ;

  return table ;
} ;

/*------------------------------------------------------------------------------
 * Unless the "set" state is set, clear the reference count to zero, then
 * do vhash_table_reset(table, free_it)
 *
 * Returns: the original table, if is "set"
 *          otherwise: NULL
 */
Private vhash_table
vhash_table_ref_final(vhash_table table)
{
  if (table->ref_count & vhash_ref_count_set)
    return table ;

  table->ref_count = 0 ;
  return vhash_table_reset(table, free_it) ;
} ;

/*------------------------------------------------------------------------------
 * Reset number of bases in given table, if any.
 *
 * This is for use when a table has grown and then shrunk, and it is felt to
 * be essential to recover space by reducing the number of chain bases.
 *
 * Sets the new number of bases to the number given, or such that the threshold
 * for the next reorganisation is about 1.25 * number of items currently have,
 * whichever is the greater.
 *
 * If the table is empty, and the number of bases requested is zero, then will
 * free any existing bases.  [A lookup will create a new set of bases according
 * to the table->init_base_count.]
 */
extern void
vhash_table_reset_bases(vhash_table table, uint base_count)
{
  if ((table->entry_count != 0) || (base_count != 0))
    vhash_table_new_bases(table, base_count) ;
  else
    vhash_table_free_bases(table) ;
} ;

/*------------------------------------------------------------------------------
 * Free the vhash chain bases, if any.
 */
static void
vhash_table_free_bases(vhash_table table)
{
  qassert(table->entry_count == 0) ;

  XFREE(MTYPE_VHASH_BASES, table->bases) ;      /* sets NULL    */

  table->base_count    = 0 ;    /* => use default       */
  table->entry_count   = 0 ;
  table->max_index     = 0 ;
  table->extend_thresh = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Extend the existing array of list bases.
 *
 * To be called when the number of entries exceeds the threshold.
 */
static void
vhash_table_extend_bases(vhash_table table)
{
  uint new_base_count ;

  qassert((table->bases != NULL) && (table->base_count != 0)) ;

  /* Should be here because the number of entries in the table has exceeded
   * the threshold.
   *
   * Depending on how big the table is, we either double it or add 50% as
   * much, or leave it to vhash_table_new_bases() to set the number of bases
   * (to allow for 25% more items before needing to do this again.)
   */
  new_base_count = (table->base_count | 1) - 1 ; /* trim enforced odd-ness */

  if      (new_base_count <= VHASH_TABLE_BASES_DOUBLE_MAX)
    {
      confirm((VHASH_TABLE_BASES_DOUBLE_MAX * 2) < VHASH_TABLE_BASES_MAX) ;
      new_base_count *= 2 ;
    }
  else if (new_base_count <= VHASH_TABLE_BASES_ADD_HALF_MAX)
    {
      confirm( ( VHASH_TABLE_BASES_ADD_HALF_MAX
              + (VHASH_TABLE_BASES_ADD_HALF_MAX / 2)) < VHASH_TABLE_BASES_MAX) ;
      new_base_count += (new_base_count / 2) ;
    } ;

  /* Do the hard work of rearranging the bases
   */
  vhash_table_new_bases(table, new_base_count) ;
} ;

/*------------------------------------------------------------------------------
 * Create and set new chain bases and threshold for next extension.
 *
 * Ensures that the base count used is at least the minimum and is odd.
 *
 * The minimum is the larger of the absolute VHASH_TABLE_BASES_MIN, or enough
 * for the number of entries to grow by 25% before the new threshold will be
 * exceeded.
 *
 * The resulting new base count may be less than the current.  (Passing in
 * a new_base_count == 0 is a request for the, current, minimum number of
 * chain bases -- which is at least VHASH_TABLE_BASES_MIN.)
 *
 * If there is an existing set of chain bases, transfers node from old to new
 * chain bases, and frees the old bases.
 *
 * If there are no existing chain bases, simply allocates and initialises
 * a new set.
 */
static void
vhash_table_new_bases(vhash_table table, uint new_base_count)
{
  vhash_node* old_bases ;
  uint        old_base_count ;
  uint        old_entry_count ;
  urlong      temp, density ;

  confirm(sizeof(urlong) > sizeof(uint)) ;

  /* Decide how many chain bases we want.
   *
   * We fret about the table->density here... so that could be changed, and
   * because this is where we *really* need the right value.
   *
   * Use of urlong intermediate values avoid the (remote) possibility that
   * could overflow a uint (!).
   */
  density = table->density ;

  if      (density < VHASH_TABLE_DENSITY_MIN)
    {
      if (density == 0)
        density = VHASH_TABLE_DENSITY_DEFAULT ;
      else
        density = VHASH_TABLE_DENSITY_MIN ;

      table->density = density ;
    }
  else if (density > VHASH_TABLE_DENSITY_MAX)
    {
      density = VHASH_TABLE_DENSITY_MAX ;
      table->density = density ;
    } ;

  temp = ((urlong)table->entry_count * (urlong)125) / density  ;

  if (temp >= VHASH_TABLE_BASES_MAX)
    new_base_count = VHASH_TABLE_BASES_MAX ;    /* already odd  */
  else
    {
      uint new_minimum ;

      new_minimum = temp ;      /* will be < VHASH_TABLE_BASES_MAX      */

      if (new_minimum < VHASH_TABLE_BASES_MIN)
        new_minimum = VHASH_TABLE_BASES_MIN ;

      if (new_base_count < new_minimum)
        new_base_count = new_minimum ;

      new_base_count |= 1 ;     /* ENSURE is odd -- could (just)
                                 *       reach VHASH_TABLE_BASES_MAX !  */
    } ;

  /* Create the new set of chain bases.
   *
   * Note that VHASH_TABLE_BASES_MAX is such that the size of the array of
   * pointers cannot exceed size_t.
   *
   * Note also that if the number of bases has hit the maximum, we set the
   * threshold to VHASH_TABLE_THRESHOLD_MAX -- which will prevent any
   * further attempts to extend the number of bases.
   */
  old_bases       = table->bases ;
  old_base_count  = table->base_count ;
  old_entry_count = table->entry_count ;

  table->bases = XCALLOC(MTYPE_VHASH_BASES,
                                  (size_t)new_base_count * sizeof(vhash_node)) ;
  table->base_count = new_base_count ;

  temp = ((urlong)new_base_count * density) / (urlong)100 ;
  if ((temp >= VHASH_TABLE_THRESHOLD_MAX) ||
                                      (new_base_count >= VHASH_TABLE_BASES_MAX))
    table->extend_thresh = VHASH_TABLE_THRESHOLD_MAX ;
  else
    table->extend_thresh = temp ;

  table->max_index     = 0 ;
  table->entry_count   = 0 ;

  /* Finished if have just allocated the first set of bases.
   */
  if (old_bases == NULL)
    return ;

  /* Rehome everything on the new chain bases.
   *
   * The old table may be empty -- see vhash_table_reset_bases(), but we scan
   * the entire table anyway, so can check the count is correct.
   */
  qassert(old_base_count != 0) ;

  while (old_base_count--)
    {
      vhash_node  next ;
      next = old_bases[old_base_count] ;
      while (next != NULL)
        {
          vhash_node  this ;
          uint        index ;
          vhash_node* base ;

          this = next ;
          next = this->next ;

          index = vhash_base_index(table, this->hash) ;
          base  = &table->bases[index] ;
          this->next = *base ;
          *base = this ;

          if (index > table->max_index)
            table->max_index = index ;
          ++table->entry_count ;
        } ;
    } ;

  qassert(table->entry_count == old_entry_count) ;

  /* Release the old chain bases, and we're done
   */
  XFREE(MTYPE_VHASH_BASES, old_bases) ;
} ;

/*------------------------------------------------------------------------------
 * Return chain base index for given hash value.
 */
inline static uint
vhash_base_index(vhash_table table, vhash_hash_t hash)
{
  return hash % table->base_count ;
} ;

/*==============================================================================
 * Item operations
 */
static vhash_item vhash_remove(vhash_item item, vhash_table table) ;

/*------------------------------------------------------------------------------
 * Look-up 'data' in given vhash_table.  Add if required.
 *
 * If the p_added argument is NULL, do not add.
 *
 * If the p_added argument is not NULL, add item if required and set true if
 * added or false if item found.
 *
 * Returns:  NULL if not found and not required to add (or table is not "set").
 *           otherwise: address of item found or added
 *
 * The data argument is passed, verbatim, to:
 *
 *   * the table's hash function
 *
 *   * the table's equal function
 *
 *   * the table's new function -- iff adding item
 *
 * NB: creates chain bases if there are none.  So can reset a table and then
 *     start using it again.
 *
 * NB: if the table has been vhash_table_reset(table, free_it), then the table
 *     SHOULD NOT be being added to -- it only continues to exist be
 */
extern vhash_item
vhash_lookup(vhash_table table, vhash_data_c data, bool* p_added)
{
  vhash_node   this, prev ;
  vhash_node*  base ;
  uint         index ;
  vhash_hash_t hash ;

  qassert(table != NULL) ;

  /* The bases are allocated when/if they are needed.
   */
  if (table->bases == NULL)
    {
      qassert(table->ref_count & vhash_ref_count_set) ;

      if ((p_added == NULL) || !(table->ref_count & vhash_ref_count_set))
        return NULL ;

      vhash_table_new_bases(table, table->init_base_count) ;
    } ;

  /* Do the search
   *
   * If find, move to the front and return.
   */
  hash  = table->params->hash(data) ;
  index = vhash_base_index(table, hash) ;
  base  = &(table->bases[index]) ;
  this  = *base ;
  prev  = NULL ;
  while (this != NULL)
    {
      confirm(vhash_node_offset == 0) ;

      if ((this->hash == hash)
                        && (table->params->equal((vhash_item)this, data) == 0))
        {
          if (prev != NULL)
            {
              prev->next = this->next ;
              this->next = *base ;
              *base      = this ;
            } ;

          if (p_added != NULL)
            *p_added = false ;

          return (vhash_item)this ;
        } ;

      prev = this ;
      this = this->next ;
    } ;

  /* Not found -- quit now if not required to add, otherwise set added
   */
  if (p_added == NULL)
    return NULL ;

  *p_added = true ;

  /* Adding: first, get a new, empty vhash_item
   *
   * Note that the vhash node part of the item is fully initialised below.  The
   * vhash_new_func() does not need to worry about this - in particular, is
   * not required to zeroize it.
   */
  confirm(vhash_node_offset == 0) ;

  this = (vhash_node)(table->params->new(table, data)) ;

  /* Second, if required, extend the array of list bases.  We extend if
   * we have a collision *and* we exceed threshold of number of entries
   * (*and* the threshold is not already the maximum !).
   *
   * Once extended, recalculate the index and select new base.
   */
  if ((*base != NULL) && (table->entry_count > table->extend_thresh)
                      && (table->extend_thresh < VHASH_TABLE_THRESHOLD_MAX))
    {
      vhash_table_extend_bases(table) ;

      index = vhash_base_index(table, hash) ;
      base  = &table->bases[index] ;
    } ;

  /* Third, chain in and complete the new node.
   *
   * This initialises all fields in the vhash_node part of the item.
   */
  this->next      = *base ;
  this->hash      = hash ;
  this->ref_count = 0 ;
  *base = this ;

  /* Finally, count the new entry and update the max_index.
   */
  if (index > table->max_index)
    table->max_index = index ;

  ++table->entry_count ;

  confirm(vhash_node_offset == 0) ;

  return (vhash_item)this ;
} ;

/*------------------------------------------------------------------------------
 * Clear the "set" state.
 *
 * If the reference count is zero do vhash_remove()
 *
 * Returns: the original item, if reference count != 0
 *          otherwise: see vhash_remove()
 */
extern vhash_item
vhash_unset(vhash_item item, vhash_table table)
{
  confirm(vhash_node_offset == 0) ;

  ((vhash_node)item)->ref_count &= ~(vhash_ref_count_t)vhash_ref_count_set ;

  if (((vhash_node)item)->ref_count != 0)
    return item ;

  return vhash_remove(item, table) ;
} ;

/*------------------------------------------------------------------------------
 * Clear the "set" state and delete given vhash_item (if any).
 *
 * This is the same as vhash_delete(), except that clears the "set" state,
 * before doing vhash_remove().
 *
 * If the "set" state is significant for the free() or orphan() functions,
 * then this may be used to clear the state and then delete the item.
 * (Unlike vhash_delete(), which leaves the "set" state.)
 *
 * This could be done by vhash_unset() followed by vhash_delete(), except that
 * would need to check the reference count and only do the vhash_delete() if
 * it was not zero -- before the vhash_unset().
 */
extern vhash_item
vhash_unset_delete(vhash_item item, vhash_table table)
{
  if (item == NULL)
    return NULL ;               /* assume already freed !       */

  confirm(vhash_node_offset == 0) ;

  ((vhash_node)item)->ref_count &= ~(vhash_ref_count_t)vhash_ref_count_set ;

  return vhash_remove(item, table) ;
} ;

/*------------------------------------------------------------------------------
 * Delete vhash_item (if any) from vhash_table (if any).
 *
 * Returns: see vhash_remove()
 */
extern vhash_item
vhash_delete(vhash_item item, vhash_table table)
{
  if (item == NULL)
    return NULL ;               /* assume already freed !       */

  return vhash_remove(item, table) ;
} ;

/*------------------------------------------------------------------------------
 * Unless the "set" state is set, clear the reference count to zero, then
 * do vhash_remove()
 *
 * Returns: the original item, if is "set"
 *          otherwise: see vhash_remove() -- NULL unless free() is bizarre
 */
Private vhash_item
vhash_ref_final(vhash_item item, vhash_table table)
{
  if (((vhash_node)item)->ref_count & vhash_ref_count_set)
    return item ;

  ((vhash_node)item)->ref_count = 0 ;
  return vhash_remove(item, table) ;
} ;

/*------------------------------------------------------------------------------
 * Remove vhash_item from vhash_table and either free() it or orphan() it.
 *
 * If the table is NULL (the item must be an orphan):
 *
 *   This means that the table has been freed and the item is an orphan.  There
 *   is no free() function to be called, so:
 *
 *     * if the reference count is zero (irrespective of the "set" state)
 *
 *       returns NULL, as if free() had freed it
 *
 *     * otherwise
 *
 *       returns the item.
 *
 * If the item is an orphan:
 *
 *   This means that the item has already been removed from the table.
 *
 *     * if the reference count is zero (irrespective of the "set" state)
 *
 *       calls free() to free the item and returns what it returns.
 *
 *       NB: it is possible that the table will wink out of existence during
 *           the free() -- if the free() function does vhash_table_dec_ref() !
 *
 *     * otherwise
 *
 *       returns the item.
 *
 * Otherwise :
 *
 *   This means that the item was in the table.  So, we now remove it from the
 *   table and:
 *
 *     * if the reference count is zero (irrespective of the "set" state)
 *
 *       call free() to free the item and return the result.
 *
 *     * otherwise
 *
 *       call orphan() to signal a *new* orphan item and return the result.
 *
 * Note that orphan() is only called when the the item is first removed from
 * the table.
 */
static vhash_item
vhash_remove(vhash_item item, vhash_table table)
{
  confirm(vhash_node_offset == 0) ;

  /* Do the actual removal from the table -- if required.
   */
  if ((table != NULL) && (table->bases != NULL))
    {
      vhash_node  node ;
      vhash_node* p_prev ;
      uint index ;

      index = vhash_base_index(table, ((vhash_node)item)->hash) ;
      p_prev = &table->bases[index] ;

      while (1)
        {
          node = *p_prev ;

          if (node == (vhash_node)item)
            return vhash_reap(node, table, p_prev) ;

          if (node == NULL)
            break ;

          p_prev = &node->next ;
        } ;
    } ;

  /* The item is not in the table -- which may be because the table is
   * not there -- so the item is (already) an orphan
   *
   * If the reference count is zero, should free() the item.  If the table
   * has gone before, we pretend the item has been freed.
   *
   * If the reference count is not zero, then the orphan lives on.
   */
  if (((vhash_node)item)->ref_count < vhash_ref_count_increment)
    {
      if (table != NULL)
        return table->params->free(item, table) ;

      return NULL ;     /* as if free() were called     */
    } ;

  return item ;         /* the orphan                   */
} ;

/*------------------------------------------------------------------------------
 * Have just removed an item from the given table.
 *
 * Adjust the entry_count and tidy up the node.
 *
 * If the reference count is zero (irrespective of the "set" state):
 *
 *   call the table's free() and return what it returns.
 *
 * Otherwise:
 *
 *   call the table's orphan() and return what it returns.
 *
 * Note that orphan() is only called when the the item is first removed from
 * the table.
 */
static vhash_item
vhash_reap(vhash_node node, vhash_table table, vhash_node* p_prev)
{
  *p_prev = node->next ;

  table->entry_count -= 1 ;

  node->next = NULL ;           /* tidy         */
  node->hash = 0 ;              /* ditto        */

  confirm(vhash_node_offset == 0) ;

  if (node->ref_count < vhash_ref_count_increment)
    return table->params->free((vhash_item)node, table) ;
  else
    return table->params->orphan((vhash_item)node, table) ;
} ;

/*==============================================================================
 * Walking a vhash table
 *
 * Simple walk: visits all entries in the table, in the order they are hashed
 *              to.  Simple iterator.
 *
 * Extract:     makes vector of pointers to selected entries, and sorts that
 *              vector as required.
 */

/*------------------------------------------------------------------------------
 * Walk the given vhash_table.
 *
 * Usage:
 *
 *   vhash_walker_t walker ;
 *   vhash_item     item ;
 *   ....
 *   vhash_walk_start(table, walker) ;
 *   while ((item = vhash_walk_next(walker)) != NULL)
 *     ....
 *
 * where table == NULL is treated as an empty table.
 *
 * NB: it is possible to delete the current item during the walk, directly
 *     by vhash_delete(), or indirectly by vhash_unset() or vhash_dec_ref()
 *     etc.
 *
 *     Any other changes to the table must NOT be attempted.
 */
extern void
vhash_walk_start(vhash_table table, vhash_walker walk)
{
  assert(walk != NULL) ;

  walk->table      = table ;
  walk->next       = NULL ;
  if (table != NULL)
    {
      walk->base       = table->bases ;
      walk->base_count = table->base_count ;
    }
  else
    {
      walk->base       = NULL ;
      walk->base_count = 0 ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Walk to next item to consider
 *
 * NB: if walk->next is NULL and walk->base_count == 0, does not use the
 *     walk->table -- so can set up a vhash_walker for a NULL table, and this
 *     will return NULL.
 */
extern vhash_item
vhash_walk_next(vhash_walker walk)
{
  vhash_node this = walk->next ;

  while (this == NULL)
    {
      if (walk->base_count == 0)
        return NULL ;

      --walk->base_count ;
      this = *(walk->base++) ;
    } ;

  walk->next = this->next ;

  confirm(vhash_node_offset == 0) ;
  return (vhash_item)this ;
} ;

/*------------------------------------------------------------------------------
 * Extract vhash_items from given vhash_table (if any).
 *
 * Walk vhash table and select items to add to a new vector.  Then sort the
 * vector, if required.  Takes:
 *
 *  -- selector: NULL => select all
 *  -- p_val:    pointer is passed to the select function (if any)
 *  -- most:     if there is a select function, this flag hints that most of
 *               the items will be selected -- so it is worth preallocating
 *               a vector big enough for all of them.
 *  -- sort:     NULL => no sort (!)
 *
 * Returns:  address of new vector -- which may be empty, but is never NULL.
 *
 * NB: it is the caller's responsibility to discard the vector when it is done
 *     with.
 *
 * NB: the vector contains pointers to the selected items.  It is the
 *     caller's responsibility to avoid deleting any item whose pointer
 *     in the vector they expect to rely on !
 */
extern vector
vhash_table_extract(vhash_table table,
                     vhash_select_test* selector, const void* p_val, bool most,
                                                          vhash_sort_cmp* sort)
{
  vector      extract ;
  vhash_node* base ;
  uint        count, n ;
  vhash_node  node ;

  if ((table == NULL) || ((n    = table->entry_count) == 0)
                      || ((base = table->bases)       == NULL))
    return vector_new(0) ;

  if ((selector != NULL) && !most && (n > 64))
    n = n / 8 ;

  extract = vector_init_new(NULL, n) ;

  count = table->base_count ;
  while (count--)
    {
      node = *base++ ;
      while (node != NULL)
        {
          confirm(vhash_node_offset == 0) ;

          if ((selector == NULL) || selector((vhash_item)node, p_val))
            vector_push_item(extract, (vhash_item)node) ;

          node = node->next ;
        } ;
    } ;

  /* Sort the vhash_items as required.
   */
  if (sort != NULL)
    vector_sort(extract, (vector_sort_cmp*)sort) ;

  return extract ;
} ;

/*==============================================================================
 * Simple hashing functions.
 *
 * The hash functions provided here use CRC32 as a hash.
 *
 * CRC32 is not intended as a hash function, and is not a perfect one.
 * However it is fast -- requiring a few simple operations per byte.  Taken
 * with the secondary effect of using the hash produced modulo an odd number,
 * experience suggests this is sufficient.
 */
static u_int32_t crc_table[] ;

/*------------------------------------------------------------------------------
 * Simple hash function for '\0' terminated strings.
 *
 * Can be used directly in a struct vhash_funcs.
 */
extern vhash_hash_t
vhash_hash_string(const void* string)
{
  return vhash_hash_string_cont(string, 0xA5A5A5A5) ;
} ;

/*------------------------------------------------------------------------------
 * Simple hash function for '\0' terminated strings.
 *
 * Continue from the given hash value.
 */
extern vhash_hash_t
vhash_hash_string_cont(const void* string, vhash_hash_t h)
{
  const uint8_t* p ;

  confirm(sizeof(vhash_hash_t) == 4) ;         /* it's a uint32_t !    */

  h ^= 0x31415927 ;

  p = string ;
  while (*p != '\0')
    h = crc_table[(h & 0xFF) ^ *p++] ^ (h >> 8) ;

  return h ;
} ;

/*------------------------------------------------------------------------------
 * Simple symbol byte vector hash function.
 *
 * Starts with an arbitrary non-zero "seed", so that strings of zeros do
 * not all hash to zero.
 */
extern  vhash_hash_t
vhash_hash_bytes(const void* bytes, size_t len)
{
  return vhash_hash_bytes_cont(bytes, len, 0xA2056064) ;
} ;

/*------------------------------------------------------------------------------
 * Simple symbol byte vector hash function.
 *
 * Continue from the given hash value.
 *
 * NB: hashing two or more strings of bytes is the same as concatenating the
 *     strings together and hashing that -- provided (of course) the output
 *     of each hash is passed in to the next.
 *
 * NB: it is a *good*idea* to start with a non-zero initial hash value, for
 *     otherwise, long strings of zero will hash to 0, no matter how long the
 *     string is.
 *
 * Testing does not suggest that jhash() does a significantly better job than
 * this.
 */
extern vhash_hash_t
vhash_hash_bytes_cont(const void* bytes, size_t len, vhash_hash_t h)
{
  const uint8_t* p ;
  const uint8_t* e ;

  confirm(sizeof(vhash_hash_t) == 4) ;         /* it's a uint32_t !    */

  p = bytes ;
  e = p + len ;

  switch (len & 3)
    {
      case 3: h = crc_table[(h & 0xFF) ^ *p++] ^ (h >> 8) ;
      case 2: h = crc_table[(h & 0xFF) ^ *p++] ^ (h >> 8) ;
      case 1: h = crc_table[(h & 0xFF) ^ *p++] ^ (h >> 8) ;
      case 0:
        break ;
    } ;

  while (p < e)
    {
      h = crc_table[(h & 0xFF) ^ *(p + 0)] ^ (h >> 8) ;
      h = crc_table[(h & 0xFF) ^ *(p + 1)] ^ (h >> 8) ;
      h = crc_table[(h & 0xFF) ^ *(p + 2)] ^ (h >> 8) ;
      h = crc_table[(h & 0xFF) ^ *(p + 3)] ^ (h >> 8) ;
      p += 4 ;
    } ;

  return h ;
} ;

/*------------------------------------------------------------------------------
 * Table for generating CRC-32 -- Standard (0x1_04C1_1DB7 0xEDB8_8320)
 */
static u_int32_t crc_table[] =
{
  0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
  0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
  0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
  0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
  0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
  0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
  0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
  0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
  0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
  0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
  0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
  0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
  0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
  0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
  0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
  0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
  0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
  0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
  0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
  0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
  0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
  0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
  0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
  0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
  0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
  0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
  0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
  0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
  0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
  0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
  0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
  0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
  0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
  0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
  0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
  0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
  0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
  0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
  0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
  0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
  0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
  0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
  0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
} ;
