/* Index Hash Table structure -- functions
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, see:
 * <http://www.gnu.org/licenses/>.
 */
#include "misc.h"

#include "ihash.h"
#include "memory.h"

/*==============================================================================
 * An Index Hash Table maps an ihash_index_t to a pointer to some value.
 *
 * An Index Hash Table is, essentially, a sparse vector.
 *
 * There are no reference counts or other stuff.
 *
 *------------------------------------------------------------------------------
 * An Index Hash Table comprises the ihash_table structure and an array of
 * ihash_node.
 *
 * Each ihash_node contains a pointer to the ihash_item -- ie the "users" data.
 *
 * The first 'base_count' nodes in the array are the "chain bases".  The
 * remaining nodes are used when there are "clashes".  So, looking up a
 * given index hashes it to one of the chain base items, and then searches
 * forward from there along the list of nodes, as required.
 *
 * To save a little space, the list of nodes is implemented using indexes
 * into the ihash_node array.  Obviously, the smallest valid index value for
 * this will be the current 'base_count'.  The use of an index also allows for
 * the body of the ihash_node array to be extended and for realloc() to move
 * the body while doing so.
 *
 * The 'base_count' is always odd.  The list of nodes is singly linked.  See
 * vhash.h for further discussion of all that, but note that do not do
 * "move to front" in the ihash_table.
 *
 * For reaming and reorganising an ihash_table 'bases_used' keeps track of
 * the highest numbered base node occupied -- where 'bases_used' is the index
 * of the last base node occupied + 1.
 */

/*------------------------------------------------------------------------------
 * Index Hash Node.
 *
 * When a node is unused, its 'next' pointer == IHASH_NODE_EMPTY (== 0).
 *
 * When a node is in use, its 'next' pointer is one of:
 *
 *   * == IHASH_NODE_EOL    -- indicating that there are no further nodes on
 *                             the list.
 *
 *   * >= table->base_count -- pointing at the next node on the list of nodes
 *                             with the same hash value.
 *
 * An unused node which is not a "base node" is a "free node".  All free nodes
 * have the 'next' pointer == IHASH_NODE_EMPTY, and live on a list of free
 * nodes based at table->free_nodes, whose next pointers live in the 'item'
 * field, but are node *indexes* (they are NOT node *addresses*).
 */
struct ihash_node
{
  ihash_item    item ;          /* points to actual value       */

  ihash_index_t self ;          /* value of the index           */

  uint          next ;          /* "pointer" to next entry      */
} ;

enum { IHASH_NODE_INIT_ALL_ZEROS = true } ;

/*------------------------------------------------------------------------------
 * Empty ihash_node array.
 */
static ihash_node_t  ihash_empty_node[1] ;

/*==============================================================================
 * Index Hash Table Operations
 */
static void ihash_free_body(ihash_table table) ;
static uint ihash_extend_body(ihash_table table) ;
static uint ihash_new_body(ihash_table table, uint new_node_count) ;

inline static uint ihash_index(ihash_index_t i, uint base_count) ;

/*------------------------------------------------------------------------------
 * Allocate and initialise a new ihash table.
 *
 * Requires:
 *
 *   node_count -- number of nodes to start the ihash table at.
 *
 *                 The ihash table grows as required, but can set initial size
 *                 if have some expectations and wish to avoid growth steps.
 *
 *                 A minimum of IHASH_TABLE_NODES_MIN will be allocated when
 *                 the time comes.
 *
 *                 A limit of UINT16_MAX is imposed on this (!).
 *
 *   base_pc    -- %-age of bases.   0 => use default.
 *                                  20 => use 20% of nodes as bases
 *                                  90 => use 90% of nodes as bases
 *
 *                 See below for discussion.
 *
 *                 When the time comes, the bases will be clamped to
 *                 IHASH_TABLE_BASE_PC_MIN..IHASH_TABLE_BASE_PC_MAX
 *
 * Note that does not allocate any nodes, and leaves the processing of the
 * given node_count and the base_pc settings until they are needed -- see
 * ihash_new_body().
 *
 * Does, however set a dummy body and base_count, so that lookups in an empty
 * table do not have to check for emptiness.
 *
 * In the ihash (unlike the vhash) each base is also a node.  When an entry is
 * added, if the base is empty, that's where the entry goes.  Otherwise, the
 * entry is placed in the next available free node -- extending ihash table
 * body as necessary.
 *
 * Assuming the hash generates reasonably random values, simulation suggests
 * that on average, if 20% of the nodes are bases, when the table fills
 * (ie runs out of free nodes) it we be:
 *
 * 99.9% full at 20% bases
 *   0: =                                                    0.0% :  0.0%
 *   1: =====                                                0.7% :  0.7%
 *   2: ===========                                          3.5% :  4.3%
 *   3: =================                                    8.5% : 12.8%
 *   4: ======================                              14.2% : 26.9%
 *   5: =======================                             18.4% : 45.3%
 *   6: ===================                                 18.5% : 63.8%
 *   7: ============                                        13.7% : 77.5%
 *   8: ========                                            10.4% : 87.9%
 *   9: ====                                                 6.3% : 94.2%
 *  10: ==                                                   3.4% : 97.5%
 *  11: =                                                    1.4% : 98.9%
 *  12:                                                      0.8% : 99.7%
 *  13:                                                      0.3% :100.0%
 *  14:                                                      0.0% :100.0%
 *
 * where this is a histogram of chain lengths, showing that if lookups are
 * evenly distributed, 87.9% are achieved in at most 8 steps -- so you pay
 * for this level of utilisation.
 *
 * Using 50% of nodes as bases (the default) gives:
 *
 * 91.9% full at 50% bases
 *   0: ====================                                 0.0% :  0.0%
 *   1: ====================================                15.8% : 15.8%
 *   2: ==================================                  30.2% : 45.9%
 *   3: ====================                                26.6% : 72.5%
 *   4: =========                                           15.9% : 88.4%
 *   5: ====                                                 7.8% : 96.2%
 *   6: =                                                    2.7% : 98.9%
 *   7:                                                      0.7% : 99.6%
 *   8:                                                      0.3% : 99.9%
 *   9:                                                      0.1% :100.0%
 *
 * which is pretty dense and does the vast majority of lookups in 4/5 steps.
 *
 * Using 60% of nodes as bases gives:
 *
 * 85.6% full at 60% bases
 *   0: ==============================                       0.0% :  0.0%
 *   1: ===========================================         24.4% : 24.4%
 *   2: ==============================                      34.2% : 58.5%
 *   3: ===============                                     24.6% : 83.1%
 *   4: =====                                               11.8% : 94.8%
 *   5: =                                                    3.7% : 98.6%
 *   6:                                                      1.1% : 99.6%
 *   7:                                                      0.3% : 99.9%
 *   8:                                                      0.1% :100.0%
 *   9:                                                      0.0% :100.0%
 *
 * Using 90% of nodes as bases gives:
 *
 * 45.1% full at 90% bases
 *   0: =========================================......===   0.0% :  0.0%
 *   1: ======================================              60.1% : 60.1%
 *   2: ==========                                          30.5% : 90.6%
 *   3: ==                                                   8.1% : 98.7%
 *   4:                                                      1.2% : 99.9%
 *   5:                                                      0.1% :100.0%
 *
 * Which is a bit extreme, and the maximum supported.
 *
 * Returns:  address of new ihash table
 */
extern ihash_table
ihash_table_new(uint node_count, uint base_pc)
{
  return ihash_table_init(XMALLOC(MTYPE_IHASH_TABLE, sizeof (ihash_table_t)),
                                                          node_count, base_pc) ;
} ;

/*------------------------------------------------------------------------------
 * Initialise a new ihash table.
 *
 * See ihash_table_new() for the arguments etc.
 */
extern ihash_table
ihash_table_init(ihash_table table, uint node_count, uint base_pc)
{
  assert(node_count <= IHASH_TABLE_NODES_MAX) ;

  memset(table, 0, sizeof(ihash_table_t)) ;

  /* The memset(0) sets:
   *
   *   nodes           -- X     -- set to point at ihash_empty_node, below
   *
   *   node_count      -- 0     -- does not allocate nodes until required
   *   free_nodes      -- 0     -- none, yet
   *
   *   base_count      -- X     -- set to 1, for empty table, below
   *   bases_used      -- 0     -- the table is empty
   *
   *   entry_count     -- 0     -- ditto
   *
   *   base_pc         -- X     -- set below (clamped to uint16_t)
   *   init_base_count -- X     -- set below (clamped to unit16_t)
   */
  if (node_count > UINT16_MAX)
    node_count = UINT16_MAX ;

  if (base_pc > UINT16_MAX)
    base_pc = UINT16_MAX ;

  memset(ihash_empty_node, 0, sizeof(ihash_node_t)) ;
  confirm(IHASH_NODE_EMPTY == 0) ;

  table->nodes      = ihash_empty_node ;
  table->base_count = 1 ;

  table->init_node_count = node_count ;
  table->base_pc         = base_pc ;

  return table ;
} ;

/*------------------------------------------------------------------------------
 * Ream out given ihash_table
 *
 * Returns the next non-NULL item in the table (in no particular order), if
 * any.  The node is removed from the table *before* the item is returned.
 *
 * If the table is empty, reset it -- which frees the body (unconditionally)
 * and frees the table (if required).
 *
 * So use is:
 *
 *    while ((item = ihash_table_ream(table, <keep_it/free_it>)) != NULL)
 *      ... deal with the item ... ;
 *
 * Returns:  NULL     => ihash_table was empty and has been reset.
 *           not-NULL == address of next item in the table
 *
 * NB: any items which are set while the table is being reamed will be picked
 *     up and reamed out at some point before the process completes.
 *
 * NB: up to the point that this function returns NULL the ihash_table remains
 *     a valid table.
 *
 *     Can break off reaming and continue to use the table.
 *
 * NB: reaming does NOT return items which have been set NULL
 */
extern ihash_item
ihash_table_ream(ihash_table table, free_keep_b free_table)
{
  ihash_node nodes ;
  uint b ;

  if (table == NULL)
    return NULL ;

  /* Run backwards from current last known used base, looking for a base node
   * which is not empty.
   */
  nodes = table->nodes ;
  b = table->bases_used ;
  while (b > 0)
    {
      ihash_node  node ;
      ihash_item  item ;
      uint        n ;

      b -= 1 ;                          /* step back to last used base  */

      node = &nodes[b] ;
      n = node->next ;

      if (n == IHASH_NODE_EMPTY)
        continue ;                      /* keep walking                 */

      /* We have a non-empty base node.
       *
       * Remove that node -- replacing it with the first node on its list, if
       * any.
       */
      item = node->item ;

      if (n == IHASH_NODE_EOL)
        {
          /* The base node is the last of its kind -- so empty it.
           */
          memset(node, 0, sizeof(ihash_node_t)) ;
          confirm(IHASH_NODE_EMPTY == 0) ;
        }
      else
        {
          /* Replace the base node by the first node on the list, and free
           * that node.
           */
          ihash_node base ;

          qassert((n >= table->base_count) && (n < table->node_count)) ;

          base = node ;
          node = &nodes[n] ;

          *base = *node ;

          memset(node, 0, sizeof(ihash_node_t)) ;
          confirm(IHASH_NODE_EMPTY == 0) ;

          qassert((n >= table->base_count) && (n < table->node_count)) ;

          node->item = (void*)(uintptr_t)table->free_nodes ;
          table->free_nodes = n ;

          b += 1 ;                      /* step back to bases_used      */
        } ;

      if (item != NULL)
        {
          table->bases_used = b ;       /* for next time                */
          return item ;
        } ;
    } ;

  /* All the base nodes are believed to be empty
   */
  qassert(table->entry_count == 0) ;

  ihash_table_reset(table, free_table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Reset the given table (if any) and free it (if required).
 *
 * All items in the table are discarded and the body of the table is freed.
 *
 * If the table is not freed, then can continue to use it (!) and if a new
 * item is added to the table, will create a new body.
 *
 * Returns:  table if not 'free_table' (may be NULL)
 *           NULL if 'free_table'
 *
 * NB: it is the caller's responsibility to free any memory that the ihash
 *     table items may refer to, if that is required.
 */
extern ihash_table
ihash_table_reset(ihash_table table, free_keep_b free_table)
{
  if (table != NULL)
    {
      ihash_free_body(table) ;

      if (free_table)
        XFREE(MTYPE_VHASH_TABLE, table) ;       /* sets table = NULL    */
    } ;

  return table ;
} ;

/*------------------------------------------------------------------------------
 * Reset number of nodes given ihash table (if any) should allow for, if any.
 *
 * This is for use when a table has grown and then shrunk, and it is felt to
 * be essential to recover space by reducing the size of the ihash body.
 *
 * Sets the new number of nodes to the number given, or such that there is room
 * for about 1.25 * number of items currently have, whichever is the greater.
 *
 * If the table is empty, and the number of bases requested is zero, then will
 * free any existing body.  [A new body will be constructed automatically if
 * an item is then set.]
 *
 * Does nothing if given table is NULL.
 */
extern void
ihash_table_reset_body(ihash_table table, uint node_count)
{
  if (table != NULL)
    {
      if ((table->entry_count != 0) || (node_count != 0))
        ihash_new_body(table, node_count) ;
      else
        ihash_free_body(table) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Free the ihash table body, if any -- sets the given table to empty.
 *
 * NB: it is the caller's responsibility to free any memory that the ihash
 *     table items may refer to, if that is required.
 */
static void
ihash_free_body(ihash_table table)
{
  qassert(table != NULL) ;
  qassert(table->entry_count == 0) ;

  if (table->nodes != ihash_empty_node)
    XFREE(MTYPE_IHASH_BODY, table->nodes) ;     /* sets NULL    */

  ihash_table_init(table, table->init_node_count, table->base_pc) ;
} ;

/*------------------------------------------------------------------------------
 * Extend the body of the given ihash_table (or create a new one).
 *
 * To be called when runs out of free ihash_nodes.
 *
 * Creates a new body as required, and transfers any existing nodes to that.
 *
 * Returns:  index of the first free node (ie: contents of table->free_nodes)
 *
 * NB: there will always be at least one free node available.
 */
static uint
ihash_extend_body(ihash_table table)
{
  uint new_node_count ;

  /* Should be here because there are no more free nodes in the table.
   *
   * Depending on how big the table is, we either double it or add 50% as
   * much, or leave it to ihash_table_new_nodes() to set the number of nodes
   * (to allow for 25% more entries before needing to do this again.)
   */
  new_node_count = table->node_count ;

  if      (new_node_count <= IHASH_TABLE_NODES_DOUBLE_MAX)
    {
      confirm((IHASH_TABLE_NODES_DOUBLE_MAX * 2) <= IHASH_TABLE_NODES_MAX) ;
      new_node_count *= 2 ;
    }
  else if (new_node_count <= IHASH_TABLE_NODES_ADD_HALF_MAX)
    {
      confirm( ( IHASH_TABLE_NODES_ADD_HALF_MAX
              + (IHASH_TABLE_NODES_ADD_HALF_MAX / 2)) <= IHASH_TABLE_NODES_MAX);
      new_node_count += (new_node_count / 2) ;
    } ;

  /* Do the hard work of rearranging the bases -- ensures at least one free
   * node and aims to create room for at least 25% more nodes than currently.
   */
  return ihash_new_body(table, new_node_count) ;
} ;

/*------------------------------------------------------------------------------
 * Create and set new array of ihash_node.
 *
 * Ensures that the base count used is at least the minimum and is odd.
 *
 * The minimum is the larger of the absolute IHASH_TABLE_NODES_MIN, or enough
 * for the number of entries to grow by 25% before the table fills again.
 *
 * The number of nodes in the table which are required for a given number of
 * entries depends on the proportion of nodes which are chain bases.  The
 * following table gives some values for the range of proportion of bases
 * supported.
 *
 *    Bases    Full    Mult
 *     20%     99.9%   1.00
 *     30%     98.8%   1.01
 *     40%     96.3%   1.04
 *     50%     92.0%   1.09
 *     60%     85.4%   1.17
 *     70%     75.8%   1.32
 *     80%     63.8%   1.57
 *     90%     45.4%   2.20
 *
 * So, at 50% of nodes being bases, the table will (on average, for random
 * hash values) fill to 92% of the total nodes.  Which means that to
 * accommodate 'e' entries requires ~1.09 * e nodes.  That multiplier is
 * calculated by linear interpolation between these values, plus 5% rounded
 * up.
 *
 * The resulting new node count may be less than the current.  (Passing in
 * a new_node_count == 0 is a request for the, current, minimum number of
 * nodes -- which is at least IHASH_TABLE_NODES_MIN.)
 *
 * Transfers any existing nodes to the new body.
 *
 * Returns:  index of the first free node (ie: contents of table->free_nodes)
 *
 * NB: there will always be at least one free node available.
 */
static uint
ihash_new_body(ihash_table table, uint new_node_count)
{
  ihash_node old_nodes, new_nodes ;
  uint   new_base_count, old_bases_used, new_bases_used, new_entry_count ;
  uint   next_free, b, m, base_pc, i ;
  urlong temp ;

  confirm(sizeof(urlong) > sizeof(uint)) ;

  static const uint node_mult[] =
  {
    [0] = 105,                  /* 1.00 * 100 * 1.05, rounded up        */
    [1] = 105,
    [2] = 105,
    [3] = ((101 * 105) + 99) / 100,
    [4] = ((104 * 105) + 99) / 100,
    [5] = ((109 * 105) + 99) / 100,
    [6] = ((117 * 105) + 99) / 100,
    [7] = ((132 * 105) + 99) / 100,
    [8] = ((157 * 105) + 99) / 100,
    [9] = ((220 * 105) + 99) / 100,
  } ;

  CONFIRM((IHASH_TABLE_BASE_PC_MAX / 10) < (sizeof(node_mult) / sizeof(uint))) ;

  /* We fret about the table->base_pc here... so that could be changed, and
   * because this is where we *really* need the right value.
   */
  base_pc = table->base_pc ;

  if      (base_pc < IHASH_TABLE_BASE_PC_MIN)
    {
      if (base_pc == 0)
        base_pc = IHASH_TABLE_BASE_PC_DEFAULT ;
      else
        base_pc = IHASH_TABLE_BASE_PC_MIN ;

      table->base_pc = base_pc ;
    }
  else if (base_pc > IHASH_TABLE_BASE_PC_MAX)
    {
      base_pc = IHASH_TABLE_BASE_PC_MAX ;
      table->base_pc = base_pc ;
    } ;

  /* Decide how many nodes we want.
   *
   * At a minimum we'd like to be able to accommodate 25% more nodes that there
   * are at present, at the number of nodes required given the base_pc.
   *
   * We calculate temp = number of nodes by multiplying the current entry count
   * by the multiplier depending on the base_pc and by 5, and divide down.
   *
   * Use of urlong intermediate values avoid overflowing uint.
   */
  m = base_pc / 10 ;
  temp = node_mult[m] ;

  if (((base_pc % 10) != 0) && ((m + 1) < (sizeof(node_mult) / sizeof(uint))))
    {
      /* Linear interpolation, as required.
       */
      urlong delta ;

      delta = (urlong)node_mult[m + 1] - temp ;

      temp += ((delta * (base_pc % 10)) + 9) / 10 ;
    } ;

  temp = ((urlong)table->entry_count * (urlong)5 * temp) / (urlong)(4 * 100) ;

  if (temp >= IHASH_TABLE_NODES_MAX)
    new_node_count = IHASH_TABLE_NODES_MAX ;
  else
    {
      if (temp < IHASH_TABLE_NODES_MIN)
        temp = IHASH_TABLE_NODES_MIN ;

      if (new_node_count < temp)
        new_node_count = temp ;
    } ;

  new_base_count = (((urlong)new_node_count * base_pc) / (urlong)100) | 1 ;

  confirm(((IHASH_TABLE_NODES_MIN * IHASH_TABLE_BASE_PC_MIN) / 100)
                                                     >= IHASH_TABLE_BASES_MIN) ;
  qassert(new_base_count >= IHASH_TABLE_BASES_MIN) ;

  if (new_base_count < IHASH_TABLE_BASES_MIN)
    {
      /* This is impossible -- but to be absolutely certain !
       */
      new_base_count = IHASH_TABLE_BASES_MIN ;
      new_node_count = ((new_base_count * 100) + base_pc - 1) / base_pc ;
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
  new_nodes = XMALLOC(MTYPE_IHASH_BODY,
                                  (size_t)new_node_count * sizeof(ihash_node)) ;

  qassert(new_base_count & 1) ;         /* odd and greater than zero    */
  qassert(new_base_count < new_node_count) ;

  next_free = new_base_count ;          /* at least one free            */

  qassert(next_free < new_node_count) ; /* for the avoidance of doubt   */
  qassert(2 <= new_node_count) ;        /* ditto                        */

  /* Zeroize all the bases, so they are all marked IHASH_NODE_EMPTY
   */
  memset(new_nodes, 0, (size_t)new_base_count * sizeof(ihash_node)) ;
  confirm(IHASH_NODE_EMPTY == 0) ;

  /* Rehome everything on the new chain bases.
   */
  old_nodes      = table->nodes ;
  old_bases_used = table->bases_used ;

  if (old_nodes == ihash_empty_node)
    qassert((old_bases_used == 0) && (table->base_count == 1)
                                  && (table->node_count == 0)) ;
  else
    qassert((old_nodes != NULL)
                              && (table->base_count >= IHASH_TABLE_BASES_MIN)
                              && (table->node_count >= IHASH_TABLE_NODES_MIN)) ;

  new_entry_count = 0 ;
  new_bases_used  = 0 ;
  for (b = 0 ; b < old_bases_used ; ++b)
    {
      ihash_node  old_node ;

      old_node = &old_nodes[b] ;

      if (old_node->next == IHASH_NODE_EMPTY)
        continue ;

      while (1)
        {
          ihash_node new_node ;
          uint n ;

          i = ihash_index(old_node->self, new_base_count) ;
          qassert(i < new_base_count) ;
          new_node = &new_nodes[i] ;

          n = new_node->next ;
          if (n == IHASH_NODE_EMPTY)
            {
              /* The base node is empty, so use that and keep table->bases_used
               * up to date.
               */
              n = IHASH_NODE_EOL ;

              if (i >= new_bases_used)
                new_bases_used = i + 1 ;
            }
          else
            {
              /* The base node in the new body is not empty, so need to use
               * the next free node and link that onto the base node's list.
               *
               * Note that we arrange to have at least one free node left
               * *after* using the next free one -- so that we exit this
               * function with at least one free node.
               */
              ihash_node base_node ;

              base_node = new_node ;

              if (next_free >= (new_node_count - 1))
                {
                  /* This is peculiar... we seem to have run out of free nodes
                   * while rebuilding the table.  Which suggests that the
                   * multiplication to construct the total number of nodes
                   * has underestimated -- which is a sad surprise :-(
                   *
                   * We have to extend the nodes !
                   */
                  qassert(next_free == (new_node_count - 1)) ;

                  temp = ((urlong)new_node_count * (urlong)5) / (urlong)4 ;

                  if (temp <= IHASH_TABLE_NODES_MAX)
                    new_node_count = temp ;
                  else
                    new_node_count = IHASH_TABLE_NODES_MAX ;

                  assert(next_free < (new_node_count - 1)) ;

                  new_nodes = XREALLOC(MTYPE_IHASH_BODY, new_nodes,
                                  (size_t)new_node_count * sizeof(ihash_node)) ;

                  base_node = &new_nodes[i] ;
                } ;

              /* Use the next free node, and point the base node at it.
               *
               * So, we insert the new node after the relevant base node, but
               * before any other nodes on the base node's list.  The order of
               * nodes is arbitrary and this is the least work.
               */
              new_node = &new_nodes[next_free] ;

              base_node->next = next_free ;

              next_free += 1 ;
            } ;

          /* Copy the old_node across and set the new node's 'next'.
           *
           * At this point we have one of:
           *
           *   * new_node points at an empty base node, and n = IHASH_NODE_EOL
           *
           *   * new_node points at what was a free node:
           *
           *       - the base node 'next' points at this node
           *
           *       - n = the previous base node 'next'.
           */
          *new_node = *old_node ;
          new_node->next = n ;

          new_entry_count += 1 ;

          /* Worry about the next node on the list
           */
          i = old_node->next ;

          if (i == IHASH_NODE_EOL)
            break ;

          qassert(i >= table->base_count) ;     /* old value    */

          old_node = &old_nodes[i] ;
        } ;
    } ;

  /* Now update the table to the new values
   */
  assert(next_free < new_node_count) ;

  qassert(new_entry_count == table->entry_count) ;
  qassert(new_bases_used  <= new_base_count) ;

  table->nodes       = new_nodes ;
  table->base_count  = new_base_count ;
  table->node_count  = new_node_count ;
  table->entry_count = new_entry_count ;
  table->bases_used  = new_bases_used ;

  /* Release the old nodes
   */
  if (old_nodes != ihash_empty_node)
    XFREE(MTYPE_IHASH_BODY, old_nodes) ;

  /* Zeroize all the free nodes, so they are all marked IHASH_NODE_EMPTY
   *
   * And so that the last free node has its 'item' value == 0 == end.
   *
   * Then set the 'item' entry of all but the last free node to be the index
   * of the next free node.
   */
  memset(&new_nodes[next_free], 0, (size_t)(new_base_count - next_free)
                                                        * sizeof(ihash_node)) ;
  confirm(IHASH_NODE_EMPTY == 0) ;

  for (i = next_free ; i < (new_node_count - 1) ; ++i)
    {
      confirm(sizeof(uintptr_t) >= sizeof(uint)) ;

      table->nodes[i].item = (void*)(uintptr_t)(i + 1) ;
    } ;

  qassert(table->nodes[new_node_count - 1].item == (void*)0) ;

  /* Set and return the next free node index
   */
  qassert((1 <= new_base_count) && (new_base_count < new_node_count)) ;
  qassert( (table->base_count == new_base_count) &&
           (table->node_count == new_node_count) ) ;

  qassert((next_free >= new_base_count) && (next_free < new_node_count)) ;

  return table->free_nodes = next_free ;
} ;

/*==============================================================================
 * Item operations
 *
 * Note that elsewhere it is arranged for an empty table to point at a single
 * dummy empty base node, so that ihash_get_item() and ihash_del_item() do not
 * need to worry about an empty table.
 */

/*------------------------------------------------------------------------------
 * Get value (if any) of 'index' item from table.
 *
 * Returns:  address for item, or 'absent' if not present.
 *
 * NB: may be present and NULL -- this function can distinguish that from
 *                                not present using the 'absent' argument.
 */
extern ihash_item
ihash_get_item(ihash_table table, ihash_index_t index, void* absent)
{
  ihash_node  nodes, node ;
  uint        n ;

  qassert(table != NULL) ;

  nodes = table->nodes ;
  node  = &nodes[ihash_index(index, table->base_count)] ;

  n = node->next ;

  if (node->self == index)
    {
      /* Looks like the node we want is the base node -- but not if the
       * base node is, in fact, empty !
       */
      if (n == IHASH_NODE_EMPTY)
        return absent ;
    }
  else
    {
      /* The node we want is not the base node.
       *
       * If the base node is empty or the list is empty, then we are done,
       * otherwise we search along the list.
       *
       * NB: we don't expect to find non-base nodes which are empty and will
       *     exit the loop if attempt to step forwards from one.
       *
       *     If we find an empty node with the required index, will return
       *     its value... it really does not seem worth checking for this
       *     invalid case.
       */
      while (1)
        {
          confirm(IHASH_NODE_EMPTY < IHASH_NODE_EOL) ;
          qassert(IHASH_NODE_EOL < table->base_count) ;

          if (n <= IHASH_NODE_EOL)
            return absent ;

          qassert((n >= table->base_count) && (n < table->node_count)) ;

          node = &nodes[n] ;

          if (node->self == index)
            break ;

          n = node->next ;
        } ;
    } ;

  return node->item ;
} ;

/*------------------------------------------------------------------------------
 * Set value of 'index' item in table -- insert if required.
 *
 * The ihash_table is, essentially, a sparse vector, so setting the value of
 * an 'index' which is already in the table will overwrite the existing value.
 *
 * It is possible to set a NULL value.  There is little difference setting an
 * ihash_node to NULL and deleting it, except that (a) the ihash_node continues
 * to occupy space in the table and (b) setting a non-NULL value later does not
 * then need to re-create the node.
 */
extern void
ihash_set_item(ihash_table table, ihash_index_t index, ihash_item item)
{
  ihash_node  nodes, node ;
  uint        b, n ;

  qassert(table != NULL) ;

  if (table->node_count == 0)
    {
      /* The table is empty -- time to create the initial size body.
       */
      qassert(table->nodes       == ihash_empty_node) ;
      qassert(table->free_nodes  == 0) ;
      qassert(table->base_count  == 1) ;
      qassert(table->bases_used  == 0) ;
      qassert(table->entry_count == 0) ;

      ihash_new_body(table, table->init_node_count) ;
    } ;

  b     = ihash_index(index, table->base_count) ;
  nodes = table->nodes ;

  node = &nodes[b] ;
  n    = node->next ;

  if      (n == IHASH_NODE_EMPTY)
    {
      /* Set a currently empty base node, and keep table->bases_used up to
       * date.
       */
      node->self = index ;
      node->next = IHASH_NODE_EOL ;

      if (n >= table->bases_used)
        table->bases_used = n + 1 ;
    }
  else if (node->self != index)
    {
      /* Base node is not empty and is not the node we want to set.
       *
       * Find node to set, or create one and insert after the base.
       *
       * Note that the order of nodes on a base node's list is arbitrary.  As
       * elsewhere, we here insert just after the base node, for minimum work.
       */
      while (1)
        {
          ihash_node base_node ;

          node = &nodes[n] ;

          if (node->self == index)
            break ;

          n = node->next ;

          qassert((n == IHASH_NODE_EOL) || (n >= table->base_count)) ;

          if (n != IHASH_NODE_EOL)
            continue ;

          /* Time to create a new node.
           */
          n = table->free_nodes ;

          if (n == 0)
            {
              n = ihash_extend_body(table) ;
              nodes = table->nodes ;            /* *new* address        */
            } ;

          node = &nodes[n] ;
          table->free_nodes = (uintptr_t)node->item ;

          base_node = &nodes[b] ;

          node->self = index ;
          node->next = base_node->next ;

          base_node->next = n ;

          break ;
        } ;
    } ;

  node->item = item ;
} ;

/*------------------------------------------------------------------------------
 * Delete value of 'index' item (if any) in table.
 *
 * Does nothing if nothing is found for the given 'index'.
 *
 * Returns:  value of node->item, if item existed in table (may be NULL)
 *       or: the given value if item did not exist,
 */
extern ihash_item
ihash_del_item(ihash_table table, ihash_index_t index, ihash_item value)
{
  ihash_node  nodes, node ;
  uint        n ;

  qassert(table != NULL) ;

  nodes = table->nodes ;
  node  = &nodes[ihash_index(index, table->base_count)] ;

  n = node->next ;

  if (node->self == index)
    {
      /* Looks like the node we want is the base node -- but not if the
       * base node is, in fact, empty !
       */
      ihash_node base ;

      if (n <= IHASH_NODE_EOL)
        {
          /* The base node is empty or there is nothing following it.
           */
          confirm(IHASH_NODE_EMPTY < IHASH_NODE_EOL) ;

          if (n != IHASH_NODE_EMPTY)
            memset(node, 0, sizeof(ihash_node_t)) ;

          confirm(IHASH_NODE_EMPTY == 0) ;

          return value ;                /* not found    */
        } ;

      /* We need to remove the base node.  We do this by copying the following
       * node to the base node, and then freeing that following node.
       */
      qassert((n >= table->base_count) && (n < table->node_count)) ;

      base = node ;
      node = &nodes[n] ;

      *base = *node ;
    }
  else
    {
      /* The node we want is not the base node.
       *
       * If the base node is empty or the list is empty, then we are done,
       * otherwise we search along the list.
       *
       * NB: we don't expect to find non-base nodes which are empty and will
       *     exit the loop if attempt to step forwards from one.
       */
      ihash_node  prev ;

      while (1)
        {
          confirm(IHASH_NODE_EMPTY < IHASH_NODE_EOL) ;
          qassert(IHASH_NODE_EOL < table->base_count) ;

          if (n <= IHASH_NODE_EOL)
            return value ;              /* not found    */

          qassert((n >= table->base_count) && (n < table->node_count)) ;

          prev = node ;
          node = &nodes[n] ;

          if (node->self == index)
            break ;

          n = node->next ;
        } ;

      /* We want to drop 'node', which follows 'prev'
       */
      prev->next = node->next ;
    } ;

  /* We need to free the node 'node' whose index is 'n'.
   *
   * NB: by the time we arrive here, the node to be returned to the free pool
   *     has been removed from the list it was on.
   */
  value = node->item ;

  memset(node, 0, sizeof(ihash_node_t)) ;
  confirm(IHASH_NODE_EMPTY == 0) ;

  qassert((n >= table->base_count) && (n < table->node_count)) ;

  node->item = (void*)(uintptr_t)table->free_nodes ;
  table->free_nodes = n ;

  return value ;
} ;

/*------------------------------------------------------------------------------
 * Hash given index to base node index.
 */
inline static uint
ihash_index(ihash_index_t index, uint base_count)
{
  return (((index ^ 3141592653) * 2650845021u) + 5) /* See Knuth 3.3.4      */
                                           % base_count ;
} ;

/*==============================================================================
 * Walking an ihash table
 *
 * Simple walk: visits all entries in the table, in the order they are hashed
 *              to.  Simple iterator.
 *
 * Extract:     makes vector of pointers to selected entries, and sorts that
 *              vector as required.
 */

/*------------------------------------------------------------------------------
 * Walk the given ihash_table.
 *
 * Usage:
 *
 *   ihash_walker_t walker ;
 *   ihash_item     item ;
 *   ....
 *   ihash_walk_start(table, walker) ;
 *   while ((item = ihash_walk_next(walker, NULL)) != NULL)
 *     ....             // walker->self == index of item
 *
 * where table == NULL is treated as an empty table.
 *
 * NB: during a walk it is possible to:
 *
 *      * delete the current item -- by ihash_del_item()
 *
 *      * change the current item -- by ihash_set_item()
 *
 *     Any other changes to the table must NOT be attempted.
 */
extern void
ihash_walk_start(ihash_table table, ihash_walker walk)
{
  assert(walk != NULL) ;

  walk->table      = table ;
  walk->next       = IHASH_NODE_EOL ;
  walk->base_count = (table != NULL) ? table->bases_used : 0 ;
  walk->self       = 0 ;
} ;

/*------------------------------------------------------------------------------
 * Walk to next item to consider
 *
 * If 'inull' is NULL will simply skip NULL items.  Otherwise, for NULL items,
 * copies the 'self' value to the ihash_null_item value, and returns that.
 *
 * NB: if walk->table is NULL and walk->base_count == 0, does not use the
 *     walk->table -- so can set up an ihash_walker for a NULL table, and this
 *     will return NULL.
 */
extern ihash_item
ihash_walk_next(ihash_walker walk, void* inull)
{
  ihash_table table ;
  ihash_item  item ;
  uint n ;

  table = walk->table ;
  n     = walk->next ;

  if (table == NULL)
    qassert((n == IHASH_NODE_EOL) && (walk->base_count == 0)) ;
  else
    qassert((n == IHASH_NODE_EOL) || (n >= table->base_count)) ;

  while (1)
    {
      ihash_node node ;

      if (n != IHASH_NODE_EOL)
        {
          node = &table->nodes[n] ;
          n = node->next ;
        }
      else
        {
          uint b ;

          b = walk->base_count ;
          do
            {
              if (b == 0)
                {
                  walk->base_count = 0 ;
                  return NULL ;
                } ;

              b -= 1 ;

              node = &table->nodes[b] ;
              n = node->next ;
            }
          while (n == IHASH_NODE_EMPTY) ;

          walk->base_count = b ;
        } ;

      qassert((n == IHASH_NODE_EOL) || (n >= table->base_count)) ;

      item = node->item ;

      if (item == NULL)
        {
          if (inull == NULL)
            continue ;

          item = (ihash_item)inull ;
        } ;

      walk->next = n ;

      walk->self = node->self ;
      return item ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Extract items from ihash_table (if any).
 *
 * Walk ihash table and select items to add to a new vector.  Then sort the
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
ihash_table_extract(ihash_table table,
                     ihash_select_test* selector, ihash_data_c p_val, bool most,
                                                          ihash_sort_cmp* sort)
{
  vector      extract ;
  ihash_node  nodes ;
  uint        b, n ;

  if ((table == NULL) || ((n = table->entry_count) == 0))
    return vector_new(0) ;

  if ((selector != NULL) && !most && (n > 64))
    n = n / 8 ;

  extract = vector_init_new(NULL, n) ;
  nodes = table->nodes ;

  for (b = 0 ; b < table->bases_used ; ++b)
    {
      ihash_node  node ;
      uint n ;

      node = &nodes[b] ;

      n = node->next ;
      if (n == IHASH_NODE_EMPTY)
        continue ;

      while (1)
        {
          if (node->item != NULL)
            {
              if ((selector == NULL)
                         || selector((const ihash_item_c*)&node->item, p_val))
                vector_push_item(extract, node->item) ;
            } ;

          if (n == IHASH_NODE_EOL)
            break ;

          qassert(n >= table->base_count) ;

          node = &nodes[n] ;
          n = node->next ;
        } ;
    } ;

  /* Sort the vhash_items as required.
   */
  if (sort != NULL)
    vector_sort(extract, (vector_sort_cmp*)sort) ;

  return extract ;
} ;

