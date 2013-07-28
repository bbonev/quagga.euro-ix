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
 * being the number of comparisons required to find a given item, and the
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
avl_tree_init_new(avl_tree tree, avl_tree_params_c params)
{
  if (tree == NULL)
    tree = XCALLOC(MTYPE_AVL_TREE, sizeof(avl_tree_t)) ;
  else
    memset(tree, 0, sizeof(avl_tree_t)) ;

  /* Zeroising the structure has set:
   *
   *   root        -- NULL, empty tree
   *   params      -- X, set below
   */
  tree->params = params ;

  return tree ;
} ;

/*------------------------------------------------------------------------------
 * Ream out given AVL tree.
 *
 * The recommendation is that before reaming a tree, the root of the tree is
 * copied to a temporary "root", and the real root set NULL -- so that the tree
 * is immediately emptied -- see avl_tree_fell().
 *
 * Removes each item in the partial tree and returns same, for the caller
 * to deal with.
 *
 * Items are returned "in-order".
 *
 * Returns:  next item to deal with -- NULL if there are none left
 *
 * NB: once reaming has started, the partial tree is *invalid* -- at least, it
 *     is no longer balanced.
 */
extern avl_item
avl_tree_ream(avl_item* p_next)
{
  avl_node next, node ;

  node = *(avl_node*)p_next ;
  confirm(avl_node_offset == 0) ;

  if (node == NULL)
    return NULL ;

  /* Move as far left as possible
   */
  while ((next = node->child[avl_left]) != NULL)
    node = next ;

  next = node->child[avl_right] ;
  if (next != NULL)
    {
      /* We have a right-child but no left child.  So we can detach the
       * current node, and replace it by the right-child.
       *
       * The right-child becomes the next item to consider.
       */
      avl_node parent ;

      parent = node->parent ;

      next->parent = parent ;
      next->which  = node->which ;

      if (parent != NULL)
        parent->child[next->which] = next ;
    }
  else
    {
      /* We have neither left nor right child.  So can detach the current
       * leaf node from the parent.
       *
       * The parent becomes the next node to consider.
       */
      next = node->parent ;

      if (next != NULL)
        next->child[node->which] = NULL ;
    } ;

  *p_next = next ;

  node->child[avl_left]  = NULL ;
  node->child[avl_right] = NULL ;
  node->parent           = NULL ;

  return (avl_item)node ;
} ;


/*------------------------------------------------------------------------------
 * Empty out given AVL tree -- setting given p_next, ready to be reamed.
 *
 * Returns:  current root
 */
extern avl_item
avl_tree_fell(avl_tree tree)
{
  avl_item root ;

  root       = tree->root ;
  tree->root = NULL ;

  return root ;
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
 * NB: it is the caller's responsibility to release any tree items *before*
 *     doing this.
 */
extern avl_tree
avl_tree_reset(avl_tree tree, free_keep_b free_structure)
{
  confirm(free_it) ;    /* free_it == true      */

  if (tree != NULL)
    {
      if (free_structure)
        XFREE(MTYPE_AVL_TREE, tree) ;   /* sets tree = NULL     */
      else
        avl_tree_init_new(tree, tree->params) ;
    } ;

  return tree ;
} ;

/*==============================================================================
 * AVL lookup, lookup-add and delete.
 */
static inline void avl_set_parent(avl_item* p_root, avl_node node) ;
static avl_node avl_rebalance_left(avl_node b) ;
static avl_node avl_rebalance_right(avl_node d) ;
static avl_node avl_rebalance_centre(avl_node b, avl_node c, avl_node d) ;

static uint avl_tree_check(avl_node node) ;

/*------------------------------------------------------------------------------
 * Lookup item in the AVL tree -- does NOT add if not found.
 *
 * Takes the address of the root ('p_root') and the item to start searching
 * from ('item').
 *
 * In the straightforward case, the item given will be the root (or NULL).
 *
 * However, the item can be any item in the tree, so that a lookup can
 * continue from some (more) advantageous part of the tree.  If the key is not
 * found at or below the given item, then runs the lookup from the root -- so
 * the given item may only be a guess.  The circumstances under which this is
 * advantageous are a matter for the application.
 *
 * Returns:  address of item found
 *       or: NULL if not found
 */
extern avl_item
avl_lookup(avl_item* p_root, avl_item item, avl_key_c key,
                                                       avl_tree_params_c params)
{
  avl_node  node ;
  int cmp ;

  /* If the item is NULL, then search from the root -- which may also be NULL !
   */
  if (item == NULL)
    {
      item = *p_root ;
      if (item == NULL)
        return NULL ;
    } ;

  /* Search from the item
   */
  node = (avl_node)item ;
  confirm(avl_node_offset == 0) ;

  do
    {
      cmp = params->cmp(key, (avl_item)node) ;

      if (cmp == 0)
        return (avl_item)node ; /* FOUND                    */

      if (cmp < 0)              /* key < node's key         */
        node = node->child[avl_left] ;
      else
        node = node->child[avl_right] ;
    }
  while (node != NULL) ;

  /* Note found at or below item.  If item was not root, search from the
   * root.
   *
   * Note that we arrange to stop searching if we arrive at the original item,
   * again.
   *
   * There is no reason for the root to be NULL when the item was not !
   */
  node = (avl_node)(*p_root) ;

  qassert(node != NULL) ;

  while ((node != (avl_node)item) && (node != NULL)) ;
    {
      cmp = params->cmp(key, (avl_item)node) ;

      if (cmp == 0)
        return (avl_item)node ; /* FOUND                    */

      if (cmp < 0)              /* key < node's key         */
        node = node->child[avl_left] ;
      else
        node = node->child[avl_right] ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Lookup item in the AVL tree, and add if not there.
 *
 * Takes the address of the root ('p_root') and the item to start searching
 * from ('item') -- see avl_lookup(), above.
 *
 * Returns:  address of item found or added
 *
 * If required, uses the avl_new_func() to create the entry to insert, passing
 * it the 'key' and the 'new_arg'.
 *
 * NB: if the caller needs to distinguish the found/added cases, must do so
 *     using something in the item, or something done by the avl_new_func()
 *     (possibly using the 'new_arg').
 */
extern avl_item
avl_lookup_add(avl_item* p_root, avl_item item, avl_key_c key,
                                        avl_tree_params_c params, void* new_arg)
{
  avl_node  node, parent_node ;
  avl_dir_t which_child ;
  int cmp ;

  /* Go down tree looking for node or its putative parent.
   */
  node = avl_lookup_inexact(p_root, item, key, params, &cmp) ;

  if (cmp == 0)
    return (avl_item)node ;

  /* Create item and insert.  We have:
   *
   *   node == node which will be parent -- NULL <=> tree is empty
   *   cmp  == -1 => new node must be left child
   *        == +1 => new node must be right child
   *
   * Create a new item and initialise the node.  Zeroising sets:
   *
   *   * child[]        -- both NULL  -- no children
   *   * parent         -- X          -- set below
   *   * which          -- X          -- set below
   *
   *   * bal            -- 0          -- is balanced
   *   * level          -- 0          -- not known ATM
   *   * height         -- 0          -- not known ATM
   */
  parent_node = node ;
  which_child = (cmp < 0) ? avl_left : avl_right ;

  node = (avl_node)params->new(key, new_arg) ;  /* make (minimal) item */

  memset(node, 0, sizeof(avl_node_t)) ;

  node->parent = parent_node ;
  node->which  = which_child ;

  if (parent_node == NULL)
    {
      /* Add first node in tree.
       */
      *p_root = (avl_item)node ;
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
              parent_node = parent_node->parent ;

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

              avl_set_parent(p_root, parent_node) ;

              qassert(parent_node->bal == 0) ;
              break ;           /* rebalanced => height unchanged       */
            } ;
        } ;
    } ;

  if (avl_debug)
    avl_tree_check(*p_root) ;   /* check the balance            */

  /* Return the new item.
   */
  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Lookup item in the AVL tree -- does NOT add if not found.
 *
 * Takes the address of the root ('p_root') and the item to start searching
 * from ('item') -- see avl_lookup(), above.
 *
 * Returns:  address of item found  -- *p_cmp: -1 <=> key <  item found
 *                                              0 <=> key == item found
 *                                             +1 <=> key >  item found
 *       or: NULL if tree is empty  -- *p_cmp = -1
 *
 * Where -1 is returned: the item returned will have no left children, and if
 *                       the key is inserted, it must be the left child.
 *
 *       +1 is returned: the item returned will have no right children, and if
 *                       the key is inserted, it must be the right child.
 */
extern avl_item
avl_lookup_inexact(avl_item* p_root, avl_item item, avl_key_c key,
                                           avl_tree_params_c params, int* p_cmp)
{
  avl_node  down, node ;
  int cmp ;

  /* The start item is NULL, if the root is also NULL, give up.
   */
  if (item == NULL)
    {
      item = *p_root ;

      if (item == NULL)
        {
          *p_cmp = -1 ;
          return NULL ;
        } ;
    } ;

  /* Search down from the given item
   */
  down = (avl_node)item ;
  confirm(avl_node_offset == 0) ;

  do
    {
      node = down ;                     /* result so far        */

      cmp = params->cmp(key, (avl_item)node) ;

      if (cmp == 0)
        {
          *p_cmp = 0 ;                  /* FOUND                */
          return (avl_item)node ;
        } ;

      if (cmp < 0)                      /* key < node's key     */
        down = node->child[avl_left] ;
      else
        down = node->child[avl_right] ;
    }
  while (down != NULL) ;

  /* Not found at or below item.  Search down from root, if that is different.
   *
   * Note that we arrange to stop searching if we arrive at the original item,
   * again.
   *
   * There is no reason for the root to be NULL when the item was not !
   */
  down = (avl_node)(*p_root) ;
  if ((down != (avl_node)item) && (down != NULL))
    {
      avl_node node_i ;
      int      cmp_i ;

      node_i = node ;                   /* result starting from item    */
      cmp_i  = cmp ;

      do
        {
          node = down ;                 /* result so far, from root     */

          cmp = params->cmp(key, (avl_item)node) ;

          if (cmp == 0)
            break ;                     /* FOUND                */

          if (cmp < 0)                  /* key < node's key     */
            down = node->child[avl_left] ;
          else
            down = node->child[avl_right] ;

          if (down == (avl_node)item)
            {
              /* We are back at the original item, so we can now stop and
               * return the original result.
               */
              node = node_i ;
              cmp  = cmp_i ;
              break ;
            } ;
        }
      while (down != NULL) ;
    } ;

  /* Return what we found
   */
  *p_cmp = cmp ;
  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Delete item from the AVL tree, if finds it.
 *
 * Takes the address of the root ('p_root') and the item to start searching
 * from ('item') -- see avl_lookup(), above.
 *
 * Returns:  address of item deleted
 *       or: NULL if not found.
 */
extern avl_item
avl_delete(avl_item* p_root, avl_item item, avl_key_c key,
                                                       avl_tree_params_c params)
{
  return avl_remove(p_root, avl_lookup(p_root, item, key, params)) ;
} ;

/*------------------------------------------------------------------------------
 * Remove item (if any) from the AVL tree.
 *
 * NB: it is a VERY SAD MISTAKE to remove an item which is not in the tree.
 *
 *     But will cope with a NULL item.
 *
 * Returns:  address of item removed
 */
extern avl_item
avl_remove(avl_item* p_root, avl_item item)
{
  avl_node  node, parent_node, child_node, del_parent ;
  avl_dir_t del_which ;

  if (item == NULL)
    return item ;

  node = (avl_node)item ;
  confirm(avl_node_offset == 0) ;

  /* If the node has no left child, or no right child, or no children at all,
   * then the node can be deleted directly.
   *
   * If the node has both left and right children, then we need to go down to
   * find the successor of this node.  We then "delete" the successor -- moving
   * it to replace the node to be really deleted.
   */
  child_node  = node->child[avl_right] ;
  parent_node = node->parent ;

  if ((child_node == NULL) || (node->child[avl_left] == NULL))
    {
      /* Node to be deleted has no right child or no left child, or no
       * children at all.
       *
       * Deletion is straightforward -- point parent at the child, if any,
       * copying the deleted node's 'parent' and 'which' settings to the child.
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
              qassert(child_node->parent == node) ;
              qassert(child_node->which  == avl_left) ;

              child_node->parent = node->parent ;
              child_node->which  = node->which ;
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
          qassert(child_node->parent == node) ;
          qassert(child_node->which  == avl_right) ;

          child_node->parent = node->parent ;
          child_node->which  = node->which ;
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
          qassert(down->parent == child_node) ;
          qassert(down->which  == avl_right) ;

          down->parent = child_node->parent ;
          down->which  = child_node->which ;
        } ;

      del_parent = child_node->parent ;
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
        down->parent = child_node ;

      down = child_node->child[avl_right] ;
      if (down != NULL)
        down->parent = child_node ;

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
    *p_root = (avl_item)child_node ;
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

              avl_set_parent(p_root, del_parent) ;

              if (del_parent->bal != 0)
                break ;
            } ;

          del_which  = del_parent->which ;
          del_parent = del_parent->parent ;
        } ;
    } ;

  if (avl_debug)
    avl_tree_check(*p_root) ;   /* check the balance            */

  /* Count off the deleted node and return its item.
   */
  return (avl_item)node ;
} ;

/*==============================================================================
 * AVL Tree Mechanics
 */

/*------------------------------------------------------------------------------
 * Set the parent of the given node to point at it.
 */
static inline void
avl_set_parent(avl_item* p_root, avl_node node)
{
  avl_node parent ;

  parent = node->parent ;

  if (parent == NULL)
    *p_root = (avl_item)node ;
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

      d->parent = b->parent ;
      d->which  = b->which ;

      d->child[avl_left]  = b ;
      b->parent = d ;
      b->which  = avl_left ;

      b->child[avl_right] = c ;
      if (c != NULL)
        {
          c->parent = b ;
          c->which  = avl_right ;
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

      c->parent = b->parent ;
      c->which  = b->which ;

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

      b->parent = d->parent ;
      b->which  = d->which ;

      b->child[avl_right] = d ;
      d->parent = b ;
      d->which  = avl_right ;

      d->child[avl_left]  = c ;
      if (c != NULL)
        {
          c->parent = d ;
          c->which  = avl_left ;
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

     c->parent = d->parent ;
     c->which  = d->which ;

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
      x->parent = b ;
      x->which  = avl_right ;
    } ;

  y = c->child[avl_right] ;
  d->child[avl_left]  = y ;
  if (y != NULL)
    {
      y->parent = d ;
      y->which  = avl_left ;
    } ;

  c->child[avl_left]  = b ;
  b->parent = c ;
  b->which  = avl_left ;

  c->child[avl_right] = d ;
  d->parent = c ;
  d->which  = avl_right ;

  b->bal = (bal > 0) ? -1 : 0 ;
  c->bal = 0 ;
  d->bal = (bal < 0) ? +1 : 0 ;

  return c ;
} ;

/*==============================================================================
 * Tree running
 *                          __F__
 *                         /     \
 *                        B       G
 *                       / \       \
 *                      A   D       I
 *                         / \     /
 *                        C   E   H
 *
 * Can do:
 *
 *   * avl_get_first() and then avl_get_next()
 *
 *     traverses in key order: A B C D E F G H I
 *
 *     ie: left child (recurse), node, right child (recurse)
 *
 *   * avl_get_last() and then avl_get_prev()
 *
 *     traverses in reverse key order: I H G F E D C B A
 *
 *     ie: right child (recurse), node, left child (recurse)
 *
 *   * avl_get_pre_next()
 *
 *     traverses (starting from the root) in "pre-order": F B A D C E G I H
 *
 *     ie: node, left child (recurse), right child (recurse)
 *
 *   * avl_get_post_first() and then avl_get_post_next()
 *
 *     traverses in "post-order": A C E D B H I G F
 *
 *     ie: left child (recurse), right child (recurse), node
 *
 *   * avl_get_level_next()
 *
 *     traverses (starting from the root) in level order -- starting at level 1
 *     (the root level): A B G A D I C E H
 *
 *   * avl_get_depth_first() and then avl_get_depth_next()
 *
 *     traverses (starting from the root) in level order -- starting at the
 *     *deepest* level: C E H A D I B G A
 */

/*------------------------------------------------------------------------------
 * Get the first item -- in key order -- in the tree, if any.
 */
extern avl_item
avl_get_first(avl_item root)
{
  avl_node node, down ;

  confirm(avl_node_offset == 0) ;

  if (root == NULL)
    return NULL ;

  down = root ;
  do
    {
      node = down ;
      down = node->child[avl_left] ;
    }
  while (down != NULL) ;

  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Get the next item, if any -- in key order -- after the given item.
 */
extern avl_item
avl_get_next(avl_item item)
{
  avl_node node, down ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  down = node->child[avl_right] ;

  if (down != NULL)
    {
      /* Have a right child.  Next item is it, or its left-most child.
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
          node        = node->parent ;

          qassert(  (which_child == avl_left) ||
                  ( (which_child == avl_right) && (node != NULL) )) ;
        }
      while (which_child == avl_right) ;

      if (node == NULL)
        return NULL ;
    } ;

  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Get the last item -- in key order -- in the tree, if any.
 */
extern avl_item
avl_get_last(avl_item root)
{
  avl_node node, down ;

  confirm(avl_node_offset == 0) ;

  if (root == NULL)
    return NULL ;

  down = root ;
  do
    {
      node = down ;
      down = node->child[avl_right] ;
    }
  while (down != NULL) ;

  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Get the previous item, if any -- in key order -- before the given item.
 */
extern avl_item
avl_get_prev(avl_item item)
{
  avl_node node, down ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  down = node->child[avl_left] ;

  if (down != NULL)
    {
      /* Have a left child.  Next item is it, or its right-most child.
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
          node        = node->parent ;

          qassert(  (which_child == avl_left) ||
                  ( (which_child == avl_right) && (node != NULL) )) ;

          if (which_child == avl_right)
            break ;

          if (node == NULL)
            return NULL ;
        } ;
    } ;

  return (avl_item)node ;
} ;

/*------------------------------------------------------------------------------
 * Get the next item, if any -- in pre-order -- after the given item.
 *
 * The first item in pre-order is the root.
 */
extern avl_item
avl_get_pre_next(avl_item item)
{
  avl_node node, down ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  /* If we have a left child, that is the next one to consider.
   */
  down = node->child[avl_left] ;
  if (down != NULL)
    return (avl_item)down ;

  /* If we have a right child, that is the next one to consider.
   *
   * If no right child, back-up the tree until arrive at a parent node from a
   * left child.  Note that the root node is, by convention, the left child.
   *
   * If at the root, return NULL, otherwise, loop back to return the right
   * child (if any) or continue to back-up the tree.
   */
  while (1)
    {
      avl_dir_t which_child ;

      down = node->child[avl_right] ;
      if (down != NULL)
        return (avl_item)down ;

      do
        {
          which_child = node->which ;
          node        = node->parent ;

          qassert(  (which_child == avl_left) ||
                  ( (which_child == avl_right) && (node != NULL) )) ;
        }
      while (which_child == avl_right) ;

      if (node == NULL)
        return NULL ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the first item, if any, in post-order
 */
extern avl_item
avl_get_post_first(avl_item root)
{
  avl_node down ;

  if (root == NULL)
    return root ;

  confirm(avl_node_offset == 0) ;

  /* If we have a left child go down.
   *
   * If we have a right child go down.
   *
   * If hit leaf, stop.
   */
  down = (avl_node)root ;
  while (1)
    {
      avl_node node ;

      node = down ;

      down = node->child[avl_left] ;
      if (down != NULL)
        continue ;

      down = node->child[avl_right] ;
      if (down != NULL)
        continue ;

      return node ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the next item, if any -- in post-order -- after the given item.
 *
 * The first item in post-order is given by: avl_get_post_first().
 */
extern avl_item
avl_get_post_next(avl_item item)
{
  avl_node  node ;
  avl_dir_t which_child ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  /* If at the root, return NULL, otherwise go up to parent.
   *
   * If was right child, return this node (the parent).
   *
   * If was left child, if cannot go to the right, return this node.
   *
   * Otherwise, go to the right, then recurse down to the deepest on that side,
   * going left if possible, otherwise right.
   */
  which_child = node->which ;
  node        = node->parent ;

  qassert(  (which_child == avl_left) ||
          ( (which_child == avl_right) && (node != NULL) )) ;

  if ((node == NULL) || (which_child == avl_right))
    return (avl_item)node ;

  while (1)
    {
      /* At the top of the loop, cannot go left because:
       *
       *   1) we have arrived at the current node from its left child, which
       *      is the case when the loop is entered.
       *
       *   2) there is no left child, which is the case for all subsequent
       *      times around the loop.
       *
       * If there is no right child, we can return the current node -- for the
       * reasons above, there is no left child to return.
       *
       * If there is a right child, step to it and then step left as far as
       * possible.
       */
      avl_node  down ;

      down = node->child[avl_right] ;
      if (down == NULL)
        return (avl_item)node ;

      do
        {
          node = down ;
          down = node->child[avl_left] ;
        }
      while (down != NULL) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the first item, if any, in level first order.
 *
 * Note that the first item is the given 'root', which is marked as level 0.
 */
extern avl_item
avl_get_level_first(avl_item root)
{
  if (root != NULL)
    {
      ((avl_node)root)->level  = 0 ;
      ((avl_node)root)->height = avl_get_height(root) ;
    } ;

  return root ;
} ;

/*------------------------------------------------------------------------------
 * Get the next item, if any, in highest level first order.
 *
 * The first item is given by: avl_get_level_first().
 */
extern avl_item
avl_get_level_next(avl_item item)
{
  avl_node  node, next ;
  avl_dir_t which_child ;
  uint      level ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  /* If not at the root, and is left child, if can go to the right, return that
   * node straight away.
   */
  which_child = node->which ;
  level       = node->level ;

  if (level != 0)
    {
      /* Special case of stepping from left-child, through parent, straight to
       * sibling right-child.
       */
      node = node->parent ;

      if ((which_child == avl_left) &&
                                      ((next = node->child[avl_right]) != NULL))
        {
          next->level = level ;
          return (avl_item)next ;
        } ;

      qassert(level == ((uint)node->level + 1)) ;
    } ;

  /* We have 'node' and no more items of interest below that.
   *
   * We need to work our way up the tree and then down again to the required
   * level.  If run out of the current level, need to move down a level and
   * start with the leftmost at that level.
   */
  while (1)
    {
      if (node->level == 0)
        {
          /* We are at the root -- so there are no more items of interest at
           * the current level.
           *
           * If the current level is the last level (equal to height of tree)
           * we can stop !
           *
           * Otherwise, we increase the level and then move down.
           *
           * NB: if the tree height is 2, it is possible for the tree to be:
           *
           *            R
           *             \
           *              S
           *
           * But for all other cases there must be a left child -- otherwise
           * the tree is unbalanced.
           */
          if (level == node->height)
            return NULL ;

          level += 1 ;

          next = node->child[avl_left] ;

          if (next == NULL)
            {
              next = node->child[avl_right] ;

              qassert((level == 2) && (next != NULL)) ;

              if (next == NULL)
                return NULL ;           /* stop if no children of root  */
            } ;
        }
      else
        {
          /* Move up and, if possible, down again to the right.
           *
           * If cannot go to the right, loop back to continue going up, if
           * possible.
           */
          which_child = node->which ;
          node        = node->parent ;

          if (which_child == avl_right)
            continue ;          /* Keep going up if was right-child     */

          next = node->child[avl_right] ;
        } ;

      /* Move down to the required level, where:
       *
       *   'next' is left or right child of 'node' (if any)
       *
       * While we are processing the final level it is possible that will
       * either have to do a final step to the right, or may not reach the
       * final level and have to step back up the tree.
       */
      while (next != NULL)
        {
          if (node->level == (level - 1))
            {
              next->level = level ;
              return (avl_item)next ;
            } ;

          node = next ;
          next = node->child[avl_left] ;

          if (next == NULL)
            next = node->child[avl_right] ;
        } ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the first item, if any, in deepest level first order.
 */
extern avl_item
avl_get_depth_first(avl_item root)
{
  avl_node down ;
  uint     level ;

  if (root == NULL)
    return root ;

  confirm(avl_node_offset == 0) ;

  /* If is heavier to the left or equal weight, go left if possible.
   *
   * Otherwise, go right
   *
   * If hit leaf, stop.
   */
  level = 0 ;
  down = (avl_node)root ;
  while (1)
    {
      avl_node node ;

      node   = down ;
      level += 1 ;

      node->level = level ;

      if (node->bal == 0)
        {
          down = node->child[avl_left] ;
          if (down == NULL)
            return (avl_item)node ;
        }
      else if (node->bal < 0)
        {
          qassert(node->bal == -1) ;
          down = node->child[avl_left] ;
        }
      else if (node->bal > 0)
        {
          qassert(node->bal == +1) ;
          down = node->child[avl_right] ;
        }

      qassert(down != NULL) ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * Get the next item, if any, in deepest level first order.
 *
 * The first item is given by: avl_get_depth_first().
 */
extern avl_item
avl_get_depth_next(avl_item item)
{
  avl_node  node, next ;
  avl_dir_t which_child ;
  uint      level, current ;

  if (item == NULL)
    return item ;

  node = item ;
  confirm(avl_node_offset == 0) ;

  /* If at the root, return NULL, otherwise go up to parent.
   *
   * If was left child, if can go to the right, return that node.
   */
  which_child = node->which ;
  level       = node->level ;

  node        = node->parent ;
  current     = level - 1 ;

  qassert(  (which_child == avl_left) ||
          ( (which_child == avl_right) && (node != NULL) )) ;

  if (node == NULL)
    {
      qassert(current == 0) ;
      return NULL ;
    } ;

  if ((which_child == avl_left) && ((next = node->child[avl_right]) != NULL))
    {
      next->level = level ;
      return next ;
    } ;

  /* We need to work our way up the tree and then down again to the required
   * level.  If run out of the current level, need to move up a level and start
   * with the leftmost at that level.
   *
   * NB: if we move up a level we expect to find ourselves at a full level.
   *
   *     But for the first (deepest) level in the tree, we may or may not
   *     find items as we move back down the tree.
   *
   * NB: we are processing level > current >= 1.
   */
  qassert((level > current) && (current >= 1)) ;

  while (1)
    {
      /* At the top of the loop need to move up the tree.
       *
       * If we arrive at the root, then need to reduce the level and then
       * recurse back down again.
       *
       * If go up from the right child, loop back to keep backing up the tree.
       *
       * If go up from the left child, and there is no right child, loop
       * back to keep backing up the tree.
       *
       * If go up from the left child, and there is a right child, step right
       * and then go down to the required level.  If cannot reach the required
       * level, loop back to try again.
       */
      avl_node  down ;

      if (current == 1)
        {
          qassert(node->parent == NULL) ;
          qassert(node->level  == 1) ;
          qassert(level > 1) ;

          level -= 1 ;
          if (level <= current)
            return node ;

          down = node->child[avl_left] ;
          qassert(down != NULL) ;

          if (down == NULL)
            {
              down = node->child[avl_right] ;
              if (down == NULL)
                return NULL ;
            } ;
        }
      else
        {
          which_child = node->which ;
          node        = node->parent ;
          current     = level - 1 ;

          qassert((node != NULL) && (node->level == current)) ;
          qassert((which_child == avl_left) || (which_child == avl_right)) ;

          if (which_child == avl_right)
            continue ;                  /* keep going up        */

          down = node->child[avl_right] ;
          if (down == NULL)
            continue ;
        } ;

      /* We have made our way up to a level from which we need to make our
       * way back down to the current level.
       *
       *   'down' is the first step back down to the level we want, and its
       *   parent is 'node' which is at 'current' level.
       */
      while (1)
        {
          qassert(down->parent == node) ;
          qassert(node->level  == current) ;

          node = down ;
          current += 1 ;

          node->level = current ;

          if (current == level)
            return (avl_item)node ;

          down = node->child[avl_left] ;
          if (down != NULL)
            continue ;

          down = node->child[avl_right] ;
          if (down != NULL)
            continue ;

          break ;               /* Failed to get down to the required level
                                 * so need to work back up from 'node'  */
        } ;
    } ;
} ;

/*==============================================================================
 * Diagnostics
 */
static uint avl_get_node_height(avl_node node, avl_node parent,
                                                              avl_dir_t which) ;

/*------------------------------------------------------------------------------
 * Get the height of the given tree by walking the entire tree.
 *
 * Returns the height of the longest branch -- sets node->height on the given
 * node.
 *
 * Returns zero if tree is empty.
 *
 * NB: if avl_debug, checks the balance of every node, and the validity of the
 *     node->parent and node->which.
 *
 *     Also,
 */
static uint
avl_tree_check(avl_node root)
{
  uint height ;

  if (root == NULL)
    return 0 ;

  height = avl_get_node_height(root, NULL, avl_left) ;

  if (avl_debug)
    assert(height == avl_get_height(root)) ;

  return ((avl_node)root)->height = height ;
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
avl_get_node_height(avl_node node, avl_node parent, avl_dir_t which)
{
  avl_node down ;
  uint hl, hr ;

  if (avl_debug)
    {
      assert(node->parent == parent) ;
      assert(node->which  == which) ;
    } ;

  down = node->child[avl_left] ;
  if (down != NULL)
    hl = avl_get_node_height(down, node, avl_left) ;
  else
    hl = 0 ;

  down = node->child[avl_right] ;
  if (down != NULL)
    hr = avl_get_node_height(down, node, avl_right) ;
  else
    hr = 0 ;

  if (avl_debug)
    assert(node->bal == ((int)hr - (int)hl)) ;

  return ((hl >= hr) ? hl : hr) + 1 ;
} ;

/*==============================================================================
 * Walk a tree to establish number of entries or height.
 */
static uint avl_get_node_count(avl_node node, uint depth) ;

/*------------------------------------------------------------------------------
 * How many items are there in the given tree ?
 *
 * Since has to walk the tree to do the count, sets node level on every node.
 *
 * The root node is at level 0.
 *
 * Does a complete walk of the tree in order to establish the facts.
 */
extern uint
avl_get_count(avl_item root)
{
  if (root == NULL)
    return 0 ;

  return avl_get_node_count((avl_node)root, 0) ;
} ;

/*------------------------------------------------------------------------------
 * Get height of the given tree.
 *
 * An empty tree has height == 0.
 *
 * Note that this uses the node balance to find the height by stepping down one
 * branch of the tree to one of the deepest nodes.
 */
extern uint
avl_get_height(avl_item root)
{
  avl_node node ;
  uint     height ;

  if (root == NULL)
    return 0 ;

  confirm(avl_node_offset == 0) ;

  /* If is heavier to the left or equal weight, go left if possible.
   *
   * Otherwise, go right
   *
   * When hit leaf, stop.
   */
  height = 0 ;
  node   = (avl_node)root ;
  while (1)
    {
      avl_node down ;

      height += 1 ;

      if (node->bal == 0)
        {
          down = node->child[avl_left] ;
          if (down == NULL)
            {
              qassert(node->child[avl_right] == NULL) ;
              return ((avl_node)root)->height = height ;
            } ;
        }
      else if (node->bal < 0)
        {
          qassert(node->bal == -1) ;
          down = node->child[avl_left] ;
        }
      else if (node->bal > 0)
        {
          qassert(node->bal == +1) ;
          down = node->child[avl_right] ;
        }

      qassert(down != NULL) ;
      node = down ;
    } ;
} ;

/*------------------------------------------------------------------------------
 * How many items are there in the given sub-tree ?
 *
 * Set node level on every node.
 *
 * Requires:  node  != NULL
 *            level == level for this node (so will be 0 for root node)
 */
extern uint
avl_get_node_count(avl_node node, uint level)
{
  avl_node down ;
  uint count ;

  qassert(node != NULL) ;

  node->level = level ;
  count  = 1 ;
  level += 1 ;

  if ((down = node->child[avl_left]) != NULL)
    count += avl_get_node_count(down, level) ;

  if ((down = node->child[avl_right]) != NULL)
    count += avl_get_node_count(down, level) ;

  return count ;
} ;

