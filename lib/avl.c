/* Generic AVL tree structure -- functions.
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
#include "avl.h"
#include "memory.h"

/*==============================================================================
 * This implementation of AVL trees ...
 *
 * Note: lg N is log base 2 of N.
 *
 * Perfectly balanced binary tree will give a maximum height of ceiling(lg N),
 * and an average path length of ~ lg N - 1.  So 500,000 nodes give a tree of
 * maximum height 19, and an average path length of ~18.  (The path length
 * being the number of comparisons required to find a given value, and the
 * average being the sum of comparisons to find all all nodes, divided by the
 * number of nodes.)
 *
 * The AVL tree will give a maximum height of 1.4405 lg N+2.  Building a tree
 * from a sorted list (forwards or backwards) seems to produce a *perfectly*
 * balanced tree !
 *
 * Experiments with AVL tree, using random keys, give results similar to
 * this:
 *
 */

/*==============================================================================
 * Initialisation, allocation, reset etc.
 */

/*------------------------------------------------------------------------------
 * Initialize AVL tree -- allocating if required.
 *
 * Returns the AVL tree which has been initialised.
 */
extern avl_tree
avl_tree_init_new(avl_tree tree, avl_tree_params_c params, void* parent)
{
  if (tree == NULL)
    tree = XCALLOC(MTYPE_RB_TREE, sizeof(avl_tree_t)) ;
  else
    memset(tree, 0, sizeof(avl_tree_t)) ;

  /* Zeroising the structure has set:
   *
   *   parent      -- X, set below
   *
   *   root        -- NULL, empty tree
   *
   *   node_count  -- 0, no nodes, yet
   *
   *   link_is     -- 0 => avl_parent
   *   height      -- 0
   *
   *   base        -- NULL, no nodes linked
   *
   *   params      -- X, set below
   */
  confirm(avl_parent == 0) ;

  tree->params = *params ;

  return tree ;
} ;

/*------------------------------------------------------------------------------
 * Ream out given AVL tree -- freeing structure if required.
 *
 * Removes each entry in the tree and returns same, in some order, for the
 * caller to deal with.
 *
 * Returns:  next value to deal with -- NULL if tree is empty.
 *
 * If does not free the structure, it retains the parameters set when the tree
 * was initialised -- so tree can be reused without reinitialising it.
 *
 * NB: once started, this process MUST be completed.
 *
 *     The first step of the process is to empty the tree, and link all the
 *     nodes in in_order.
 *
 *     If the process does not run to completion, the unprocessed nodes will
 *     remain unprocessed, but the tree is valid and empty.
 */
extern avl_value
avl_tree_ream(avl_tree tree, free_keep_b free_structure)
{
  avl_node  next ;
  avl_value value ;

  if (tree == NULL)
    return NULL ;               /* easy if no tree !    */

  if (tree->link_is != avl_reaming)
    {
      /* Start the reaming process by creating the in_order list, and then
       * mark the tree as empty.
       *
       * Each node is reset to have no children and nothing else other than
       * the link -- which is cleared when the node is reamed.
       */
      avl_tree_link(tree, avl_reaming) ;

      tree->root       = NULL ;
      tree->node_count = 0 ;
    } ;

  next = dsl_pop(&next, tree->base, link) ;

  if (next != NULL)
    {
      next->link = NULL ;
      value = avl_value_for(tree, next) ;
    }
  else
    {
      avl_tree_reset(tree, free_structure) ;
      value = NULL ;
    } ;

  return value ;
} ;

/*------------------------------------------------------------------------------
 * Reset given AVL tree -- freeing structure if required.
 *
 * Returns:  NULL if frees structure, otherwise returns reset structure.
 *
 * If does not free the structure, it retains the parameters set when the tree
 * was initialised -- so tree can be reused without reinitialising it.
 *
 * This is pretty trivial because takes no responsibility for the data in which
 * the 'avl_node's are embedded -- so can discard the tree structure, or simply
 * set the root NULL, and the count to zero.
 *
 * NB: it is the caller's responsibility to release any tree item values
 *     *before* doing this.
 */
extern avl_tree
avl_tree_reset(avl_tree tree, free_keep_b free_structure)
{
  confirm(free_it) ;    /* free_it == true      */

  if (tree == NULL)
    return NULL ;               /* easy if no tree !    */

  if (free_structure)
    XFREE(MTYPE_RB_TREE, tree) ; /* sets tree = NULL      */
  else
    {
      tree->root       = NULL ;
      tree->node_count = 0 ;
      tree->link_is    = avl_parent ;
      dsl_init(tree->base) ;
    } ;

  return tree ;
} ;

/*==============================================================================
 * AVL lookup, lookup-add and delete.
 */
static inline void avl_set_parent(avl_tree tree, avl_node node) ;
static avl_node avl_rebalance_left(avl_node b) ;
static avl_node avl_rebalance_right(avl_node d) ;
static avl_node avl_rebalance_centre(avl_node b, avl_node c, avl_node d) ;

static uint avl_tree_check(avl_tree tree) ;

/*------------------------------------------------------------------------------
 * Lookup item in the AVL tree -- does NOT add if not found.
 *
 * Returns:  address of item found
 *       or: NULL if not found
 *
 * NB: does not affect how the tree is linked.
 */
extern avl_value
avl_lookup(avl_tree tree, avl_key_c key)
{
  avl_node  node ;

  node = tree->root ;
  while (node != NULL)
    {
      avl_value  value ;
      int cmp ;

      value = avl_value_for(tree, node) ;
      cmp   = tree->params.cmp(key, value) ;

      if (cmp == 0)
        return value ;          /* FOUND                        */

      if (cmp < 0)              /* key < node's key             */
        node = node->child[avl_left] ;
      else
        node = node->child[avl_right] ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Lookup item in the AVL tree, and add if not there.
 *
 * Returns:  address of item found or added
 *
 * Sets:     *add false/true <=> found/added
 *
 * Uses the avl_create_func() to create the entry to insert from the given key.
 *
 * NB: if has to add an item to the tree, will relink as avl_parent if
 *     required.
 */
extern avl_value
avl_lookup_add(avl_tree tree, avl_key_c key, bool* added)
{
  avl_value value ;
  avl_node  node ;
  avl_node  parent_node ;
  avl_dir_t which_child ;

  /* Go down tree looking for node or its putative parent.
   */
  parent_node = tree->root ;
  which_child = avl_left ;

  node = parent_node ;
  while (node != NULL)
    {
      int cmp ;

      value = avl_value_for(tree, node) ;
      cmp   = tree->params.cmp(key, value) ;

      if (cmp == 0)
        {
          *added = false ;
          return value ;        /* FOUND -- easy !!             */
        } ;

      parent_node = node ;      /* proceed down from here       */

      if (cmp < 0)              /* key < node's key             */
        which_child = avl_left ;
      else
        which_child = avl_right ;

      node = parent_node->child[which_child] ;
    } ;

  /* Create value and insert.
   *
   * When we emerge from the down tree loop we have:
   *
   *   parent_node -> node which will be parent -- NULL <=> tree is empty
   *   parent_dir  -> which child this will be.
   *
   * We now need the tree to be linked avl_parent-wise.
   *
   * Create a new value and initialise the node.  Zeroising sets:
   *
   *   * child[]        -- both NULL  -- no children
   *
   *   * link           -- X          -- set below
   *   * which          -- X          -- set below
   *
   *   * bal            -- 0          -- is balanced
   *   * level          -- 0          -- not known ATM
   */
  if (tree->link_is != avl_parent)
    avl_tree_link(tree, avl_parent) ;

  value = tree->params.new(tree, key) ;        /* make (minimal) value */
  node  = avl_node_for(tree, value) ;

  memset(node, 0, sizeof(avl_node_t)) ;

  node->link  = parent_node ;
  node->which = which_child ;

  if (parent_node == NULL)
    {
      /* Add first node in tree.
       */
      tree->root = node ;
    }
  else
    {
      /* Add node to parent, then rebalance as required.
       */
      qassert(parent_node->child[which_child] == NULL) ;

      parent_node->child[which_child] = node ;

      while (1)
        {
          int delta ;
          int bal ;

          delta = (which_child == avl_left) ? -1 : +1 ;

          bal = parent_node->bal ;

          /* If the old balance == 0:
           *
           *   new balance = delta.
           *
           *   the change has tipped the node, increasing the height, which
           *   must be propagated up the tree.
           *
           * If the new balance == 0:
           *
           *   the change has rebalanced the node, so height has not changed,
           *   so can stop now.
           *
           * Otherwise:
           *
           *   the change has unbalanced the node, in the delta direction, must
           *   now rebalance and if that succeeds, propagate up the tree,
           *   otherwise stop.
           */
          if (bal == 0)
            {
              parent_node->bal = delta ;        /* 0 -> -1 or +1        */

              which_child = parent_node->which ;
              parent_node = parent_node->link ;

              if (parent_node == NULL)
                break ;         /* Hit root                             */
            }
          else
            {
              qassert((bal == -1) || (bal == +1)) ;

              bal += delta ;

              if (bal == 0)
                {
                  parent_node->bal = bal ;
                  break ;       /* rebalanced => height unchanged       */
                } ;

              /* Must now rebalance and then update parent down pointer.
               */
              if (parent_node->bal < 0)
                parent_node = avl_rebalance_right(parent_node) ;
              else
                parent_node = avl_rebalance_left(parent_node) ;

              avl_set_parent(tree, parent_node) ;

              qassert(parent_node->bal == 0) ;
              break ;           /* rebalanced => height unchanged       */
            } ;
        } ;
    } ;

  if (avl_debug)
    avl_tree_check(tree) ;      /* check the balance            */

  /* Count in the new node and return its value.
   */
  ++tree->node_count ;

  *added = true ;
  return value ;
} ;

/*------------------------------------------------------------------------------
 * Delete item from the AVL tree, if finds it.
 *
 * Returns:  address of item deleted
 *       or: NULL if not found.
 *
 * NB: unless the item is not found, will relink as avl_parent if required.
 */
extern avl_value
avl_delete(avl_tree tree, avl_key_c key)
{
  avl_value value ;
  avl_node  node, parent_node, child_node, del_parent ;
  avl_dir_t del_which ;

  /* Go down tree, looking for the node to be deleted.
   */
  node = tree->root ;
  while (1)
    {
      int cmp ;

      if (node == NULL)
        return NULL ;

      value = avl_value_for(tree, node) ;
      cmp   = tree->params.cmp(key, value) ;

      if (cmp == 0)
        break ;                         /* found node to delete */

      if (cmp < 0)                      /* key < node's key     */
        node = node->child[avl_left] ;
      else
        node = node->child[avl_right] ;
    } ;

  /* When we emerge from the down tree loop we have found the node to be
   * deleted:
   *
   *   node  == address of node
   *
   *   value == address of node value -- to be returned
   *
   * We now need the tree to be linked avl_parent-wise.
   *
   * If the node has no left child, or no right child, or no children at all,
   * then the node can be deleted directly.
   *
   * If the node has both left and right children, the we need to go down to
   * find the successor of this node -- collecting stuff on the stack as we go.
   * We then "delete" the successor -- moving it to replace the node to be
   * really deleted.
   */
  if (tree->link_is != avl_parent)
    avl_tree_link(tree, avl_parent) ;

  child_node  = node->child[avl_right] ;
  parent_node = node->link ;

  if ((child_node == NULL) || (node->child[avl_left] == NULL))
    {
      /* Node to be deleted has no right child or no left child, or no
       * children at all.
       *
       * Deletion is straightforward -- point parent at the child, if any,
       * copying the deleted node's link and which settings to the child.
       *
       *   down == right child.
       *   cp   == pointer to parent's pointer to the node
       */
      del_parent = parent_node ;
      del_which  = node->which ;

      if (child_node == NULL)
        {
          /* No right child, go left.
           */
          child_node = node->child[avl_left] ;

          if (child_node == NULL)
            {
              /* No left child -- we are deleting a leaf.
               */
              qassert(node->bal == 0) ;
            }
          else
            {
              /* Left child must be a leaf.                     */
              qassert(node->bal == -1) ;
              qassert(child_node->bal ==  0) ;
              qassert( (child_node->child[avl_left]  == NULL) &&
                       (child_node->child[avl_right] == NULL) ) ;
              qassert(child_node->link  == node) ;
              qassert(child_node->which == avl_left) ;

              child_node->link  = node->link ;
              child_node->which = node->which ;
            } ;
        }
      else
        {
          /* Have right child, but no left.
           *
           * The right child must be a leaf.
           */
          qassert(node->bal == +1) ;
          qassert(child_node->bal ==  0) ;
          qassert( (child_node->child[avl_left]  == NULL) &&
                   (child_node->child[avl_right] == NULL) ) ;
          qassert(child_node->link  == node) ;
          qassert(child_node->which == avl_right) ;

          child_node->link  = node->link ;
          child_node->which = node->which ;
        } ;
    }
  else
    {
      /* Node to be deleted has both left and right children (and may be root).
       *
       * Go find the successor and move it into the place occupied by the
       * node to be deleted.
       *
       *   child_node == right child.
       *
       * Will then balance on the basis of the removal of the successor.
       */
      avl_node down ;

      qassert(child_node == node->child[avl_right]) ;

      /* Proceed down to find the successor
       */
      while (1)
        {
          down = child_node->child[avl_left] ;

          if (down == NULL)
            break ;                     /* child_node is the successor  */

          child_node = down ;
        } ;

      /* Remove the successor, which has no left children, by replacing it
       * with its right child, if any.
       *
       * The right child must be a leaf.
       *
       * If the successor is the right child of the node being deleted, the
       * node being deleted is updated here.
       */
      down = child_node->child[avl_right] ;

      if (down != NULL)
        {
          qassert(child_node->bal == +1) ;
          qassert(down->bal ==  0) ;
          qassert( (down->child[avl_left]  == NULL) &&
                   (down->child[avl_right] == NULL) ) ;
          qassert(down->link  == node) ;
          qassert(down->which == avl_right) ;

          down->link  = child_node->link ;
          down->which = child_node->which ;
        } ;

      del_parent = child_node->link ;
      del_which  = child_node->which ;

      qassert(del_parent != NULL) ;

      del_parent->child[del_which] = down ;

      /* Transfer the successor, so that it occupies the place of the
       * node to actually be deleted.  Updating the children so they now
       * point at the replacement node.  The parent is updated, below.
       */
      *child_node = *node ;     /* copy the node being removed to the
                                 * successor node which replaces it.    */

      down = child_node->child[avl_left] ;
      if (down != NULL)
        down->link = child_node ;

      down = child_node->child[avl_right] ;
      if (down != NULL)
        down->link = child_node ;

      /* The del_parent and del_which now reflect the parentage of the
       * successor.  If that is the node we are actually deleting, we need
       * to point at the node that has just replaced the deleted node, and
       * note that the tree has changed to the right of that.
       */
      if (del_parent == node)
        {
          del_parent = child_node ;
          del_which  = avl_right ;
        } ;
    } ;

  /* Update the parent node of the node we are deleting, to point the child
   * which has been promoted to take its place.
   */
  if (parent_node == NULL)
    tree->root = child_node ;
  else
    parent_node->child[node->which] = child_node ;

  /* Have deleted the node.  Now need to rebalance, as required.
   *
   * We have:
   *
   *   del_parent   -- the node whose balance has been affected
   *   del_which    -- which side of the node has been affected
   *
   * But if tree is now empty, del_parent == NULL
   */
  while (del_parent != NULL)
    {
      int delta ;
      int bal ;

      delta = (del_which == avl_left) ? +1 : -1 ;

      bal = del_parent->bal ;

      /* If the old balance == 0:
       *
       *   new balance = delta.
       *
       *   the change has tipped the node, so height has not changed,
       *   so can stop now.
       *
       * If the new balance == 0:
       *
       *   the change has rebalanced the node, reducing the height, which
       *   must be propagated up the tree (unless is now root).
       *
       * Otherwise:
       *
       *   the change has unbalanced the node, in the delta direction, must
       *   now rebalance and if that balances this node, propagate up the tree, otherwise
       *   stop.
       */
      if (bal == 0)
        {
          del_parent->bal = delta ;
          break ;
        }
      else
        {
          qassert((bal >= -1) && (bal <= +1)) ;

          bal += delta ;

          if (bal == 0)
            del_parent->bal = bal ;
          else
            {
              /* Must now rebalance and then update parent down pointer.
               */
              if (delta < 0)
                del_parent = avl_rebalance_right(del_parent) ;
              else
                del_parent = avl_rebalance_left(del_parent) ;

              avl_set_parent(tree, del_parent) ;

              if (del_parent->bal != 0)
                break ;
            } ;

          del_which  = del_parent->which ;
          del_parent = del_parent->link ;
        } ;
    } ;

  if (avl_debug)
    avl_tree_check(tree) ;      /* check the balance            */

  /* Count off the deleted node and return its value.
   */
  --tree->node_count ;

  return value ;
} ;

/*==============================================================================
 * AVL Tree Mechanics
 */

/*------------------------------------------------------------------------------
 * Set the parent of the given node to point at it.
 */
static inline void
avl_set_parent(avl_tree tree, avl_node node)
{
  avl_node parent ;

  parent = node->link ;

  if (parent == NULL)
    tree->root = node ;
  else
    parent->child[node->which] = node ;
} ;

/*------------------------------------------------------------------------------
 * Rebalance AVL tree, by rotating LEFTWARDS -- RL/RRL
 *
 * RL -- Rotate LEFT -- two cases:
 *
 *   Case B:    +2                RL:           -1 <--
 *          ____b____                       ____d____
 *         /         \0 <<--         --> +1/         \
 *        a          _d_                 _b_          e
 *                  /   \               /   \
 *                 c     e             a     c
 *
 *   Case X:    +2                RL:           -1 <--
 *          ____b____                       ____d____
 *         /         \+1 <<--        --> +1/         \
 *        a          _d_                  _b_         e
 *                  /   \                /   \
 *                 c     e              a     c
 *
 * RRL -- Rotate Right and then LEFT -- three cases:
 *
 *   Case L:    +2                RRL:          0 <--
 *          ____b____                       ____c____
 *         /         \-1 <<--         --> 0/         \+1 <--
 *        a          _d_                 _b_        _d_
 *           -->> -1/   \               /   \      /   \
 *                 c     e             a     x    y     e
 *                / \
 *               x   y
 *
 *   Case 0:    +2                RRL:          0 <--
 *          ____b____                       ____c____
 *         /         \-1 <<--         --> 0/         \0 <--
 *        a          _d_                 _b_         _d_
 *            -->> 0/   \               /   \       /   \
 *                 c     e             a     x     y     e
 *                / \
 *               x   y
 *
 *   Case R:    +2                RRL:          0 <--
 *          ____b____                       ____c____
 *         /         \-1 <<--        --> -1/         \0 <--
 *        a          _d_                 _b_         _d_
 *           -->> +1/   \               /   \       /   \
 *                 c     e             a     x     y     e
 *                / \
 *               x   y
 *
 * Note that case 'B' does not occur in insertion.
 *
 * Note that we don't really care that 'b' is nominally '+2', and we don't
 * actually set that, so don't need to be able to represent it.
 */
static avl_node
avl_rebalance_left(avl_node b)
{
  avl_node  c, d ;
  int bal ;

  qassert(b->bal > 0) ;
  qassert(b->child[avl_right] != NULL) ;

  d = b->child[avl_right] ;     /* RIGHT child                  */
  c = d->child[avl_left] ;      /* RIGHT child's LEFT child     */

  bal = d->bal ;

  if (bal >= 0)
    {
      /* RL: single rotate LEFT
       */
      qassert(bal <= +1) ;

      d->link  = b->link ;
      d->which = b->which ;

      d->child[avl_left]  = b ;
      b->link  = d ;
      b->which = avl_left ;

      b->child[avl_right] = c ;
      if (c != NULL)
        {
          c->link  = b ;
          c->which = avl_right ;
        } ;

      bal -= 1 ;                /* case: 'B'  0 -> -1   */
                                /* case: 'X' +1 ->  0   */

      b->bal = - bal ;          /* case: 'B' -> +1      */
                                /* case: 'X' ->  0      */
      d->bal =   bal ;          /* case: 'B' -> -1      */
                                /* case: 'X' ->  0      */

      return d ;            /* return the rotated up node   */
    }
  else
    {
      /* RRL: double rotate RIGHT then LEFT.
       */
      qassert(bal == -1) ;

      c->link  = b->link ;
      c->which = b->which ;

      return avl_rebalance_centre(b, c, d) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Rebalance AVL tree, by rotating RIGHTWARDS -- RR/RLR
 *
 * RR -- Rotate RIGHT -- two cases:
 *
 *   Case B:       -2                RR:           +1 <--
 *             ____d____                       ____b____
 *      -->> 0/         \                     /         \-1 <--
 *          _b_          e                   a          _d_
 *         /   \                                       /   \
 *        a     c                                     c     e
 *
 *   Case X:       -2                RR:           0 <--
 *             ____d____                       ____b____
 *     -->> -1/         \                     /         \0 <--
 *          _b_          e                   a          _d_
 *         /   \                                       /   \
 *        a     c                                     c     e
 *
 *
 * RLR -- Rotate Left and then RIGHT -- three cases:
 *
 *   Case L:       -2                RLR:          0 <--
 *             ____d____                       ____c____
 *     -->> +1/         \                --> 0/         \+1 <--
 *          _b_          e                  _b_        _d_
 *         /   \-1 <<--                    /   \      /   \
 *        a     c                         a     x    y     e
 *             / \
 *            x   y
 *
 *   Case 0:       -2                RLR:          0 <--
 *             ____d____                       ____c____
 *     -->> +1/         \                --> 0/         \0 <--
 *          _b_          e                  _b_        _d_
 *         /   \0 <<--                     /   \      /   \
 *        a     c                         a     x    y     e
 *             / \
 *            x   y
 *
 *   Case R:       -2                RLR:          0 <--
 *             ____d____                       ____c____
 *     -->> +1/         \               --> -1/         \0 <--
 *          _b_          e                  _b_        _d_
 *         /   \+1 <<--                    /   \      /   \
 *        a     c                         a     x    y     e
 *             / \
 *            x   y
 *
 * Note that case 'B' does not occur in insertion.
 *
 * Note that we don't really care that 'd' is nominally '-2', and we don't
 * actually set that, so don't need to be able to represent it.
 */
static avl_node
avl_rebalance_right(avl_node d)
{
  avl_node  b, c ;
  int bal ;

  qassert(d->bal < 0) ;
  qassert(d->child[avl_left] != NULL) ;

  b = d->child[avl_left] ;      /* LEFT child                   */
  c = b->child[avl_right] ;     /* LEFT child's RIGHT child     */

  bal = b->bal ;

  if (bal <= 0)
    {
      /* RR: single rotate RIGHT
       */
      qassert(bal >= -1) ;

      b->link  = d->link ;
      b->which = d->which ;

      b->child[avl_right] = d ;
      d->link  = b ;
      d->which = avl_right ;

      d->child[avl_left]  = c ;
      if (c != NULL)
        {
          c->link  = d ;
          c->which = avl_left ;
        } ;

      bal += 1 ;                /* case: 'B'  0 -> +1   */
                                /* case: 'X' -1 ->  0   */

      b->bal =   bal ;          /* case: 'B' -> +1      */
                                /* case: 'X' ->  0      */
      d->bal = - bal ;          /* case: 'B' -> -1      */
                                /* case: 'X' ->  0      */

      return b ;            /* return the rotated up node   */
    }
  else
    {
      /* RLR: double rotate LEFT then RIGHT.
       */
     qassert(bal == +1) ;

     c->link  = d->link ;
     c->which = d->which ;

     return avl_rebalance_centre(b, c, d) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Rebalance AVL tree -- double rotation.
 */
static avl_node
avl_rebalance_centre(avl_node b, avl_node c, avl_node d)
{
  avl_node x, y ;
  int bal ;

  qassert(c != NULL) ;

  bal = c->bal ;                /* -1 => case: 'L'      */
                                /*  0 => case: '0'      */
                                /* +1 => case: 'R'      */
  qassert((bal >= -1) && (bal <= +1)) ;

  x = c->child[avl_left] ;
  b->child[avl_right] = x ;
  if (x != NULL)
    {
      x->link  = b ;
      x->which = avl_right ;
    } ;

  y = c->child[avl_right] ;
  d->child[avl_left]  = y ;
  if (y != NULL)
    {
      y->link  = d ;
      y->which = avl_left ;
    } ;

  c->child[avl_left]  = b ;
  b->link  = c ;
  b->which = avl_left ;

  c->child[avl_right] = d ;
  d->link  = c ;
  d->which = avl_right ;

  b->bal = (bal > 0) ? -1 : 0 ;
  c->bal = 0 ;
  d->bal = (bal < 0) ? +1 : 0 ;

  return c ;
} ;

/*==============================================================================
 * Tree running
 *
 * Can "link" the tree to do traversal in almost any order.
 *
 * Can also find the first and last, and the first value after a given key.
 *
 * Can step to the next or the previous (in key order) value from a given
 * value.
 */

/*------------------------------------------------------------------------------
 * Get the first value -- in key order -- in the tree, if any.
 *
 * NB: does not affect the tree linkage.
 */
extern avl_value
avl_get_first(avl_tree tree)
{
  avl_node node ;

  if ((tree == NULL) || ((node = tree->root) == NULL))
    return NULL ;

  while (1)
    {
      avl_node down ;

      down = node->child[avl_left] ;

      if (down == NULL)
        return avl_value_for(tree, node) ;

      node = down ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the value immediately before (or equal to) the given key, if any.
 *
 * Returns: avl_value as required
 *          NULL if no value with a key <= the given key.
 *
 * NB: if the tree is linked avl_in_reverse, then may use that linkage.
 *
 *     Otherwise, may set avl_parent (the standard) linkage.
 */
extern avl_value
avl_get_before(avl_tree tree, avl_key_c key, bool* equal)
{
  avl_value value ;
  avl_node  node ;
  avl_dir_t which_child ;

  if ((tree == NULL) || ((node = tree->root) == NULL))
    return NULL ;

  /* Go down tree looking for node or its putative parent.
   *
   * The putative parent will be either the value immediately before or
   * immediately after the key in question.
   */
  do
    {
      int cmp ;

      value = avl_value_for(tree, node) ;
      cmp   = tree->params.cmp(key, value) ;

      if (cmp == 0)
        {
          *equal = true ;
          return value ;        /* FOUND -- easy !!             */
        } ;

      if (cmp < 0)              /* key < node's key             */
        which_child = avl_left ;
      else
        which_child = avl_right ;

      node = node->child[which_child] ;
    }
  while (node != NULL) ;

  *equal = false ;

  return (which_child == avl_left) ? avl_get_prev(tree, value)
                                   : value ;
} ;

/*------------------------------------------------------------------------------
 * Get the value immediately after (or equal to) the given key, if any.
 *
 * Returns: avl_value as required
 *          NULL if no value with a key >= the given key.
 *
 * NB: if the tree is linked avl_in_order, then may use that linkage.
 *
 *     Otherwise, may set avl_parent (the standard) linkage.
 */
extern avl_value
avl_get_after(avl_tree tree, avl_key_c key, bool* equal)
{
  avl_value value ;
  avl_node  node ;
  avl_dir_t which_child ;

  if ((tree == NULL) || ((node = tree->root) == NULL))
    return NULL ;

  /* Go down tree looking for node or its putative parent.
   *
   * The putative parent will be either the value immediately before or
   * immediately after the key in question.
   */
  do
    {
      int cmp ;

      value = avl_value_for(tree, node) ;
      cmp   = tree->params.cmp(key, value) ;

      if (cmp == 0)
        {
          *equal = true ;
          return value ;        /* FOUND -- easy !!             */
        } ;

      if (cmp < 0)              /* key < node's key             */
        which_child = avl_left ;
      else
        which_child = avl_right ;

      node = node->child[which_child] ;
    }
  while (node != NULL) ;

  *equal = false ;

  return (which_child == avl_right) ? avl_get_next(tree, value)
                                    : value ;
} ;

/*------------------------------------------------------------------------------
 * Get the last value -- in key order -- in the tree, if any.
 *
 * NB: does not affect the tree linkage.
 */
extern avl_value
avl_get_last(avl_tree tree)
{
  avl_node node ;

  if ((tree == NULL) || ((node = tree->root) == NULL))
    return NULL ;

  while (1)
    {
      avl_node down ;

      down = node->child[avl_right] ;

      if (down == NULL)
        return avl_value_for(tree, node) ;

      node = down ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the next value, if any -- in key order -- after the given value.
 *
 * NB: if the tree is linked avl_in_order, then uses that linkage.
 *
 *     Otherwise, sets avl_parent (the standard) linkage if that is not
 *     already set.
 */
extern avl_value
avl_get_next(avl_tree tree, avl_value value)
{
  avl_node node, down ;

  node = avl_node_for(tree, value) ;

  if (tree->link_is != avl_parent)
    {
      if (tree->link_is == avl_in_order)
        return avl_value_for(tree, node->link) ;

      avl_tree_link(tree, avl_parent) ;
    } ;

  down = node->child[avl_right] ;

  if (down != NULL)
    {
      /* Have a right child.  Next value is it, or its left-most child.
       */
      do
        {
          node = down ;
          down = node->child[avl_left] ;
        }
      while (down != NULL) ;
    }
  else
    {
      /* Do not have a right child, so back-track up the tree.
       *
       * While the node is the right-child of its parent, keep moving up
       * the tree.  Note that the root node is, by convention, the left child.
       */
      avl_dir_t which_child ;

      do
        {
          which_child = node->which ;
          node = node->link ;

          qassert(  (which_child == avl_left) ||
                  ( (which_child == avl_right) && (node != NULL) )) ;
        }
      while (which_child == avl_right) ;

      if (node == NULL)
        return NULL ;
    } ;

  return avl_value_for(tree, node) ;
} ;

/*------------------------------------------------------------------------------
 * Get the previous value, if any -- in key order -- before the given value.
 *
 * NB: if the tree is linked avl_in_reverse, then uses that linkage.
 *
 *     Otherwise, sets avl_parent (the standard) linkage if that is not
 *     already set.
 */
extern avl_value
avl_get_prev(avl_tree tree, avl_value value)
{
  avl_node node, down ;

  node = avl_node_for(tree, value) ;

  if (tree->link_is != avl_parent)
    {
      if (tree->link_is == avl_in_reverse)
        return avl_value_for(tree, node->link) ;

      avl_tree_link(tree, avl_parent) ;
    } ;

  down = node->child[avl_left] ;

  if (down != NULL)
    {
      /* Have a left child.  Next value is it, or its right-most child.
       */
      do
        {
          node = down ;
          down = node->child[avl_right] ;
        }
      while (down != NULL) ;
    }
  else
    {
      /* Do not have a left child, so back-track up the tree.
       *
       * While the node is the left-child of its parent, keep moving up
       * the tree.  Note that the root node is, by convention, the left child.
       */
      avl_dir_t which_child ;

      while (1)
        {
          which_child = node->which ;
          node = node->link ;

          qassert(  (which_child == avl_left) ||
                  ( (which_child == avl_right) && (node != NULL) )) ;

          if (which_child == avl_right)
            break ;

          if (node == NULL)
            return NULL ;
        } ;
    } ;

  return avl_value_for(tree, node) ;
} ;

/*==============================================================================
 * Tree linking
 */
static void avl_link_parents(avl_node node, avl_node parent, avl_dir_t which) ;
static void avl_link_in_order(avl_tree tree, avl_node node, uint level) ;
static void avl_link_in_reverse(avl_tree tree, avl_node node, uint level) ;
static void avl_link_pre_order(avl_tree tree, avl_node node, uint level) ;
static void avl_link_post_order(avl_tree tree, avl_node node, uint level) ;
static void avl_link_level_order(avl_tree tree, avl_node node, uint level) ;
static void avl_link_level_reverse(avl_tree tree, avl_node node, uint level) ;
static void avl_link_ream_order(avl_tree tree, avl_node node) ;

/*------------------------------------------------------------------------------
 * Link list in the required order, and return first value in that order.
 *
 * This is debounced if is already in the required order.
 *
 * Inserting or deleting nodes clears the trees link state, so a subsequent
 * link call will remake the required list.
 *
 * NB: linking in anything except avl_parent or avl_reaming sets the level on
 *     each node and the height of the tree.  (Height is maximum level + 1.)
 */
extern avl_value
avl_tree_link(avl_tree tree, avl_link_t how)
{
  avl_node node ;

  if (how != tree->link_is)
    {
      dsl_init(tree->base) ;
      tree->link_is = how ;
      tree->height = 0 ;

      switch (how)
        {
          default:
            qassert(false) ;
            fall_through ;

          case avl_parent:
            avl_link_parents(tree->root, NULL, avl_left) ;
            break ;

          case avl_in_order:
            avl_link_in_order(tree, tree->root, 0) ;
            break ;

          case avl_in_reverse:
            avl_link_in_reverse(tree, tree->root, 0) ;
            break ;

          case avl_pre_order:
            avl_link_pre_order(tree, tree->root, 0) ;
            break ;

          case avl_post_order:
            avl_link_post_order(tree, tree->root, 0) ;
            break ;

          case avl_level_order:
            avl_link_level_order(tree, tree->root, 0) ;
            break ;

          case avl_level_reverse:
            avl_link_level_reverse(tree, tree->root, 0) ;
            break ;

          case avl_reaming:
            avl_link_ream_order(tree, tree->root) ;
            break ;
        } ;
    } ;

  node = dsl_head(tree->base) ;

  return (node != NULL) ? avl_value_for(tree, node) : NULL ;
} ;

/*------------------------------------------------------------------------------
 * Set the node->link in every node to point at its parent.
 *
 * For qdebug, check the node->which value.
 */
static void
avl_link_parents(avl_node node, avl_node parent, avl_dir_t which)
{
  if (node != NULL)
    {
      qassert(node->which == which) ;

      node->link  = parent ;
      node->which = which ;
      node->level = 0 ;

      avl_link_parents(node->child[avl_left],  node, avl_left) ;
      avl_link_parents(node->child[avl_right], node, avl_right) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: in-order.
 *
 * In in-order each node follows its left but precedes its right children.
 */
static void
avl_link_in_order(avl_tree tree, avl_node node, uint level)
{
  if (node != NULL)
    {
      avl_link_in_order(tree, node->child[avl_left],  level + 1) ;

      node->level = level ;
      dsl_append(tree->base, node, link) ;

      avl_link_in_order(tree, node->child[avl_right], level + 1) ;
    }
  else
    {
      if (level > tree->height) /* If this is leaf, then level is its   */
        tree->height = level ;  /* height                               */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: in-order, reversed.
 *
 * In in-order each node follows its right but precedes its left children.
 */
static void
avl_link_in_reverse(avl_tree tree, avl_node node, uint level)
{
  if (node != NULL)
    {
      avl_link_in_reverse(tree, node->child[avl_right],  level + 1) ;

      node->level = level ;
      dsl_append(tree->base, node, link) ;

      avl_link_in_reverse(tree, node->child[avl_left], level + 1) ;
    }
  else
    {
      if (level > tree->height)
        tree->height = level ;  /* height is the maximum level + 1      */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: pre-order.
 *
 * In pre-order each node precedes its left and then its right children.
 */
static void
avl_link_pre_order(avl_tree tree, avl_node node, uint level)
{
  if (node != NULL)
    {
      node->level = level ;
      dsl_append(tree->base, node, link) ;

      avl_link_pre_order(tree, node->child[avl_left],  level + 1) ;
      avl_link_pre_order(tree, node->child[avl_right], level + 1) ;
    }
  else
    {
      if (level > tree->height)
        tree->height = level ;  /* height is the maximum level + 1      */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, depth first: post-order.
 *
 * In post-order each node follows its left and then its right children.
 */
static void
avl_link_post_order(avl_tree tree, avl_node node, uint level)
{
  if (node != NULL)
    {
      node->level = level ;

      avl_link_post_order(tree, node->child[avl_left],  level + 1) ;
      avl_link_post_order(tree, node->child[avl_right], level + 1) ;

      dsl_append(tree->base, node, link) ;
    }
  else
    {
      if (level > tree->height)
        tree->height = level ;  /* height is the maximum level + 1      */
    } ;
} ;

/*------------------------------------------------------------------------------
 * Add tree to list, starting with level 0 (root), then level 1 and so on.
 *
 * In each level, the nodes are left to right across the tree.
 */
static void
avl_link_level_order(avl_tree tree, avl_node node, uint level)
{
  struct dl_base_pair(avl_node) queue ;
  uint height ;

  dsl_init(queue) ;
  height = 0 ;

  if (node != NULL)
    node->level = 0 ;           /* root is level 0                      */

  while (node != NULL)
    {
      avl_node child ;

      level = node->level + 1 ; /* next level                           */

      if (level > height)
        height = level ;        /* height is the maximum level + 1      */

      dsl_append(tree->base, node, link) ;

      if ((child = node->child[avl_left]) != NULL)
        {
          dsl_append(queue, child, link) ;
          child->level = level ;
        } ;

      if ((child = node->child[avl_right]) != NULL)
        {
          dsl_append(queue, child, link) ;
          child->level = level ;
        } ;

      node = dsl_pop(&node, queue, link) ;
    } ;

  tree->height = height ;
} ;

/*------------------------------------------------------------------------------
 * Add tree to list, starting with deepest level, then up to level 0 (root).
 *
 * In each level, the nodes are left to right across the tree.
 */
static void
avl_link_level_reverse(avl_tree tree, avl_node node, uint level)
{
  struct dl_base_pair(avl_node) queue ;
  uint height ;

  dsl_init(queue) ;
  height = 0 ;

  if (node != NULL)
    node->level = 0 ;           /* root is level 0                      */

  while (node != NULL)
    {
      avl_node child ;

      level = node->level + 1 ; /* next level                           */

      if (level > height)
        height = level ;        /* height is the maximum level + 1      */

      dsl_push(tree->base, node, link) ;

      if ((child = node->child[avl_right]) != NULL)
        {
          dsl_append(queue, child, link) ;
          child->level = level ;
        } ;

      if ((child = node->child[avl_left]) != NULL)
        {
          dsl_append(queue, child, link) ;
          child->level = level ;
        } ;

      node = dsl_pop(&node, queue, link) ;
    } ;

  tree->height = height ;
} ;

/*------------------------------------------------------------------------------
 * Add given subtree to tree list, in-order.
 *
 * Clear the contents of each node, other than the node-link entry
 */
static void
avl_link_ream_order(avl_tree tree, avl_node node)
{
  if (node != NULL)
    {
      avl_node right ;

      avl_link_ream_order(tree, node->child[avl_left]) ;

      right = node->child[avl_right] ;

      memset(node, 0, sizeof(avl_node_t)) ;

      dsl_append(tree->base, node, link) ;

      avl_link_ream_order(tree, right) ;
    } ;
} ;


/*==============================================================================
 * Diagnostics
 */
static uint avl_get_node_height(avl_node node, avl_node parent,
                                                  avl_dir_t which, bool check) ;

/*------------------------------------------------------------------------------
 * Get the height of the given tree.
 *
 * Returns the height of the longest branch.
 *
 * Returns zero if tree is empty.
 *
 * NB: if avl_debug, checks the balance of every node, and if is avl_parent,
 *     checks the validity of the node->link and done->which.
 */
static uint
avl_tree_check(avl_tree tree)
{
  return avl_get_node_height(tree->root, NULL, avl_left,
                                                (tree->link_is == avl_parent)) ;
} ;

/*------------------------------------------------------------------------------
 * Get the height of the given node.
 *
 * Gets the heights of the left and right sub-trees, and returns the max of
 * those + 1.
 *
 * If avl_debug, checks the balance on every node against the left and right
 * tree heights.
 *
 * Returns zero if node is NULL.
 */
static uint
avl_get_node_height(avl_node node, avl_node parent, avl_dir_t which, bool check)
{
  uint hl, hr ;

  if (node == NULL)
    return 0 ;

  if (avl_debug && check)
    {
      assert(node->link  == parent) ;
      assert(node->which == which) ;
    } ;

  hl = avl_get_node_height(node->child[avl_left],  node, avl_left, check) ;
  hr = avl_get_node_height(node->child[avl_right], node, avl_right, check) ;

  if (avl_debug)
    assert(node->bal == ((int)hr - (int)hl)) ;

  return ((hl >= hr) ? hl : hr) + 1 ;
} ;

#if 0
/*==============================================================================
 * Tree walking -- replaced by tree linking.
 */

/*------------------------------------------------------------------------------
 * Start a tree walk.
 *
 * Returns:  number of nodes in the tree
 *
 * Note that if the tree is NULL, will set up a walk that will stop immediately.
 */
extern uint
avl_tree_walk_start(avl_tree tree, avl_walker walk)
{
  memset(walk, 0, sizeof(avl_walker_t)) ;

  /* Zeroising sets:
   *
   *   tree        -- NULL, set below
   *
   *   count       -- 0   => walk just started
   *
   *   level       -- 0      ) see avl_tree_walk_level_next
   *   more        -- false  )
   *
   *   stack       -- all zero.  Set by "next" when count == 0 and root != NULL
   */
  walk->tree   = tree ;

  return (tree != NULL) ? tree->node_count : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Step to next in-order node in given walk
 */
extern avl_value
avl_tree_walk_next(avl_walker walk)
{
  avl_node node, down ;

  if (walk->count == 0)
    {
      /* We are at the start of the process, which is the end if the tree
       * is empty.
       *
       * Need to head down to the left-most child.
       */
      if (walk->tree == NULL)
        return NULL ;

      node = walk->tree->root ;

      if (node == NULL)
        return NULL ;

      walk->stack.sp = walk->stack.empty ;
    }
  else
    {
      /* We are somewhere in the tree, top of the stack contains the node
       * whose value we just returned.  So:
       *
       *   a. if there is a right child:
       *
       *      step right and then head leftwards and return the left-most
       *      available (or self if none).
       *
       *   b. if no right child:
       *
       *      if this is the root, we are finished.
       *
       *      if this is the left child of the parent, return to parent and
       *      return its value.
       *
       *      if this is the right child of the parent, return to the parent,
       *      repeat....
       */
      node = walk->stack.sp->node ;
      down = node->child[avl_right] ;

      if (down != NULL)
        {
          ++walk->stack.sp ;            /* push current                 */
          node = down ;
        }
      else
        {
          while (1)
            {
              if (node == walk->tree->root)
                {
                  /* We have returned to the root -- we are done.       */
                  qassert(walk->stack.sp == walk->stack.empty) ;
                  return NULL ;
                } ;

              qassert(walk->stack.sp > walk->stack.empty) ;

              if (walk->stack.sp->dir == avl_left)
                {
                  /* We can step up the left-hand path, and return the
                   * parent's value.
                   */
                  --walk->stack.sp ;

                  ++walk->count ;
                  return avl_value_for(walk->tree, walk->stack.sp->node) ;
                } ;

              /* We step up the right-hand path, and keep going, depending
               * on how we arrived at the parent node.
               */
              --walk->stack.sp ;
              node = walk->stack.sp->node ;
            } ;
        } ;
    } ;

  /* If we get here we have just stepped rightwards to the current
   * node.
   *
   * Now head as far to the left as we can go.
   *
   * Note that the root is depth == 0.
   */
  walk->stack.sp->node = node ;
  walk->stack.sp->dir  = avl_right ;

  while ((down = node->child[avl_left]) != NULL)
    {
      ++walk->stack.sp ;    /* push current         */
      node = down ;

      walk->stack.sp->node = node ;
      walk->stack.sp->dir  = avl_left ;
    } ;

  qassert( (walk->stack.sp >= walk->stack.empty)
        && (walk->stack.sp <= walk->stack.full) ) ;

  ++walk->count ;
  return avl_value_for(walk->tree, node) ;
} ;

/*------------------------------------------------------------------------------
 * Step to next depth-first node in given walk
 */
extern avl_value
avl_tree_walk_depth_next(avl_walker walk)
{
  avl_node node, down ;

  if (walk->count == 0)
    {
      /* We are at the start of the process, which is the end if the tree
       * is empty.
       *
       * Need to head down to the left-most child.
       */

      down = walk->tree->root ;

      if (down == NULL)
        return NULL ;

      walk->stack.sp = walk->stack.empty ;
    }
  else
    {
      /* We are somewhere in the tree, top of the stack contains the node
       * whose value we just returned.  So:
       *
       *   a. if this is the root, we are finished.
       *
       *   b. if this is a left child, return to the parent, and then head
       *      right and down.
       *
       *   c. if this is a right child, return the parent value.
       */
      node = walk->stack.sp->node ;

      if (node == walk->tree->root)
        {
          /* We have returned to the root -- we are done.       */
          qassert(walk->stack.sp == walk->stack.empty) ;
          return NULL ;
        } ;

      node = (walk->stack.sp - 1)->node ;
      down = NULL ;

      if ( (walk->stack.sp->dir == avl_left)
                                  && ((down = node->child[avl_right]) != NULL) )
        ;                       /* Go to the right, and then down       */
      else
        --walk->stack.sp ;      /* pop                                  */
    } ;

  /* If down != NULL, we have just stepped rightwards to that node (or have
   * just started with the root node).  In which case head as far down as
   * we can go.
   *
   * If down == NULL, return the current node.
   *
   * Note that the root is depth == 0.
   */
  if (down != NULL)
    {
      node = down ;

      walk->stack.sp->node = node ;
      walk->stack.sp->dir  = avl_right ;

      while (1)
        {
          avl_dir_t dir ;

          if      ((down = node->child[avl_left]) != NULL)
            dir = avl_left ;
          else if ((down = node->child[avl_right]) != NULL)
            dir = avl_right ;
          else
            break ;

          ++walk->stack.sp ;    /* push current         */
          node = down ;

          walk->stack.sp->node = node ;
          walk->stack.sp->dir  = dir ;
        }
    } ;

  qassert( (walk->stack.sp >= walk->stack.empty)
        && (walk->stack.sp <= walk->stack.full) ) ;

  ++walk->count ;
  return avl_value_for(walk->tree, node) ;
} ;

/*------------------------------------------------------------------------------
 * Step to next level order node in given walk
 */
extern avl_value
avl_tree_walk_level_next(avl_walker walk)
{
  avl_node  node ;

  /* First: if we are at the beginning, place self on root, at proceed
   *        from there.
   *
   * Otherwise, we need to backtrack to find next branch to run down, or
   * restart the process with a new target level.
   */
  if (walk->count == 0)
    {
      /* We are at the start of the process, which is the end if the tree
       * is empty.
       *
       * Need to head down to the left-most child.
       */

      node = walk->tree->root ;

      if (node == NULL)
        return NULL ;

      walk->stack.sp = walk->stack.empty ;

      walk->stack.sp->node = node ;
      walk->stack.sp->dir  = avl_right ;
    }
  else
    {
      uint     level ;

      level = walk->level ;     /* current level == target level !      */
      qassert(avl_tree_walk_depth(walk) == level) ;

      node = walk->stack.sp->node ;

      /* The outer do loop manages the backtracking required when cannot reach
       * the current level along the current branch.
       */
      do
        {
          /* We are somewhere in the tree, top of the stack contains the node
           * whose value we just returned, or where we stopped last time,
           * because failed to reach depth.  So:
           *
           *   a. if we are at the root, and there is more to come, set the
           *      new target level and set off to find it.
           *
           *   b. backtrack.
           *
           *      if was left child of parent, try the right child, otherwise,
           *      go back to (a).
           *
           * The while loop backtracks until:
           *
           *   * hit root and either increases the level, or stops.
           *
           *     Note that we cope with the case of having just returned the
           *     root node.
           *
           *   * are able to step rightwards, from a node that we backtrack to.
           */
          while (1)
            {
              if (node == walk->tree->root)
                {
                  /* We have returned to the root -- we are done.       */
                  qassert(walk->stack.sp == walk->stack.empty) ;
                  qassert(level == 0) ;

                  if (!walk->more)
                    return NULL ;

                  walk->more = false ;
                  ++walk->level ;
                  break ;               /* proceed to find level        */
                }
              else
                {
                  avl_dir_t dir ;
                  avl_node  down ;

                  dir = walk->stack.sp->dir ;

                  --walk->stack.sp ;            /* pop          */
                  --level ;                     /* up a level   */

                  node = walk->stack.sp->node ;

                  if ( (dir == avl_left) &&
                       ((down = node->child[avl_right]) != NULL) )
                    {
                      /* We can step right and down             */
                      node = down ;

                      ++walk->stack.sp ;            /* push         */
                      ++level ;                     /* down a level */

                      break ;           /* proceed to find level        */
                    } ;
                } ;
            } ;

          /* If we get here we have just stepped rightwards to the current
           * node -- or have just started at the root.
           *
           * Now head as far to the down we can go, subject to stopping at the
           * current required level.
           *
           * Note that the root is depth == 0.
           */
          walk->stack.sp->node = node ;
          walk->stack.sp->dir  = avl_right ;

          while (level < walk->level)
            {
              avl_node  down ;
              avl_dir_t dir ;

              if      ((down = node->child[avl_left]) != NULL)
                dir = avl_left ;
              else if ((down = node->child[avl_right]) != NULL)
                dir = avl_right ;
              else
                break ;

              ++level ;
              ++walk->stack.sp ;    /* push current         */
              node = down ;

              walk->stack.sp->node = node ;
              walk->stack.sp->dir  = dir ;
            } ;

        /* This is the end of the outer do loop.
         *
         * If we have reached the required depth, then can exit the loop to
         * return the current node.
         *
         * Otherwise, there is nothing deep enough on the current branch, so
         * loops back to backtrack.
         */
        } while (level < walk->level) ;
    } ;

  /* When we get here we are ready to return the current node.          */
  if ((node->child[avl_left] != NULL) || (node->child[avl_right] != NULL))
    walk->more = true ;

  qassert( (walk->stack.sp >= walk->stack.empty)
        && (walk->stack.sp <= walk->stack.full) ) ;

  ++walk->count ;
  return avl_value_for(walk->tree, node) ;
} ;

/*------------------------------------------------------------------------------
 * How deep in the tree was the last value returned by the walk ?
 *
 * Note that the root is at depth == 0.
 */
extern uint
avl_tree_walk_depth(avl_walker walk)
{
  return (walk->stack.sp - walk->stack.empty) ;
} ;

/*------------------------------------------------------------------------------
 * For avl_tree_walk_level_next walk, what level are we at ?
 *
 * Note that the root is at level == 0.
 */
extern uint
avl_tree_walk_level(avl_walker walk)
{
  return walk->level ;
} ;
#endif
