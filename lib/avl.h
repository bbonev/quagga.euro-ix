/* Generic AVL tree structure -- header.
 * Copyright (C) 2009 Chris Hall (GMCH), Highwayman
 *.
 * This file is part of GNU Zebra.
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

#ifndef _ZEBRA_AVL_H
#define _ZEBRA_AVL_H

#include "misc.h"
#include "list_util.h"

/*==============================================================================
 * Data structures etc.
 *
 * The AVL tree provided here is designed so that the nodes may be embedded in
 * some other data structure.  So, this handles:
 *
 *   * avl_node:  which contains the pointers etc for the AVL tree
 *
 *   * avl_value: some data structure, in which an avl_node is embedded.
 *
 *     Each avl_tree is expected to contain avl_values of the same type,
 *     or at least values which contain an avl_node at a fixed offset.
 *     (Different trees can have different offsets for their avl_nodes.)
 *
 * All the external interfaces work in terms of the avl_value.
 *
 * The structure is designed to provide an ordered list of values with
 * *unique* keys.  In addition to finding values by key, can find the first
 * and last entry, and can step backwards and forwards along the list from
 * a given entry.
 *
 * A tree may be (temporarily) linked to provide depth first and breadth
 * first walking of the values.
 *
 * The location and from of the key is a matter for each tree's comparison
 * function -- which takes an avl_value and a pointer to a key.
 *
 * When a new avl_value is created, the tree's creator function is used.
 */

/*------------------------------------------------------------------------------
 * Sort out AVL_DEBUG.
 *
 *   Set to 1 if defined, but blank.
 *   Set to QDEBUG if not defined.
 *
 *   Force to 0 if AVL_NO_DEBUG is defined and not zero.
 *
 * So: defaults to same as QDEBUG, but no matter what QDEBUG is set to:
 *
 *       * can set AVL_DEBUG    == 0 to turn off debug
 *       *  or set AVL_DEBUG    != 0 to turn on debug
 *       *  or set AVL_NO_DEBUG != 0 to force debug off
 */

#ifdef AVL_DEBUG                /* If defined, make it 1 or 0           */
# if IS_BLANK_OPTION(AVL_DEBUG)
#  undef  AVL_DEBUG
#  define AVL_DEBUG 1
# endif
#else                           /* If not defined, follow QDEBUG        */
# define AVL_DEBUG QDEBUG
#endif

#ifdef AVL_NO_DEBUG             /* Override, if defined                 */
# if IS_NOT_ZERO_OPTION(AVL_NO_DEBUG)
#  undef  AVL_DEBUG
#  define AVL_DEBUG 0
# endif
#endif

enum { avl_debug = AVL_DEBUG | 1 } ;

/*------------------------------------------------------------------------------
 * Structures and other definitions
 */

/* The avl_value and avl_key are abstract as far as the avl tree is concerned.
 */
typedef void* avl_value ;
typedef const void* avl_key_c ;

/* The pointer to an avl_tree and the avl_tree parameters.
 *
 * The avl_tree parameters include two functions:
 *
 *   * new:  is passed the avl_tree in which the new avl_value lives, and its
 *           avl_key.
 *
 *           Returns: a new avl_value
 *
 *           The contents of the new avl_value are immaterial.  When the a
 *           new value is created the enclosed avl_node is initialised and
 *           then used to insert the avl_value in the tree.
 *
 *           The new() may choose to set the avl_value's key, but that is not
 *           strictly necessary.  But is is, of course, *essential* that the
 *           key is set before any further tree operations !
 *
 *           The avl_tree contains a "parent" pointer, which may be useful.
 *
 *   * cmp:  is passed the avl_key being sought and an avl_value whose key
 *           is to be compared.
 *
 *           Returns: -1, 0, +1 as usual, for avl_key cmp avl_value.
 *
 *           Note that what the avl_key void* pointer points to and how the
 *           key is stored for the avl_value are both entirely up to the
 *           cmp function.
 */
typedef struct avl_tree* avl_tree ;

typedef int avl_cmp_func(avl_key_c key, avl_value value) ;
typedef avl_value avl_new_func(avl_tree tree, avl_key_c key) ;

typedef struct avl_tree_params* avl_tree_params ;
typedef struct avl_tree_params  avl_tree_params_t ;

typedef const avl_tree_params_t* avl_tree_params_c ;

struct avl_tree_params
{
  uint      offset ;            /* offset of node in value      */

  avl_new_func* new ;           /* create new value             */
  avl_cmp_func* cmp ;           /* compare key and value        */
} ;

/* The avl_node_t is to be embedded in each tree's particular avl_value.
 */
typedef struct avl_node  avl_node_t ;
typedef struct avl_node* avl_node ;

typedef enum
{
  avl_left   = 0,
  avl_right  = 1,
} avl_dir_t ;

struct avl_node
{
  avl_node  child[2] ;  /* two children, avl_left and avl_right         */
  avl_node  link ;      /* parent, or next when tree has been linked in
                         * some order                                   */
  uint8_t   which ;     /* when link = parent, which child this is      */
  int8_t    bal ;
  uint8_t   level ;     /* set by some linkages                         */
} ;

/* The various ways in which the avl_node.link value is used at any
 * moment.
 */
typedef enum
{
  avl_parent    = 0,            /* node link = parent                   */

  avl_in_order,                 /* node link = next, in-order           */
  avl_in_reverse,               /* node link = next, in-order, reverse  */

  avl_pre_order,                /* node link = next, pre-order          */
  avl_post_order,               /* node link = next, post-order         */

  avl_level_order,              /* node link = next, root level first   */
  avl_level_reverse,            /* node link = next, root level last    */

  avl_reaming,                  /* node link = next, in-order           */
} avl_link_t ;

/* The actual tree structure.
 */
typedef struct avl_tree  avl_tree_t ;

struct avl_tree
{
  avl_node  root ;              /* address of root node                 */

  uint      node_count ;        /* number of nodes in the tree          */

  avl_link_t link_is ;          /* what node->link contains             */
  uint      height ;            /* invalid if avl_parent                */

  struct dl_base_pair(avl_node) base ;
                                /* of linked nodes                      */

  avl_tree_params_t params ;    /* see above                            */

  void*     parent ;            /* not used by the avl_tree             */
} ;

#if 0                           /* dropped the tree walker      */

/* Stack structure for "recursing" around tree.
 *
 * Absolute worst case for AVL tree is 1.44 lg N + 2, so we arrange here to
 * cope with N = 2^32 in a *worst case* -- which is clearly bonkers.
 */
typedef struct
{
  struct entry
  {
    avl_node  node ;
    avl_dir_t dir ;
  }
    empty[49],                  /* impossibly huge !            */
    full[1] ;                   /* sentinel                     */

  struct entry* sp ;

} avl_stack_t ;

#endif

/*==============================================================================
 * Prototypes.
 */
extern avl_tree avl_tree_init_new(avl_tree tree, avl_tree_params_c params,
                                                                 void* parent) ;
extern avl_value avl_tree_ream(avl_tree tree, free_keep_b free_structure) ;
extern avl_tree avl_tree_reset(avl_tree tree, free_keep_b free_structure) ;

Inline uint avl_tree_node_count(avl_tree tree) ;

extern avl_value avl_lookup(avl_tree tree, avl_key_c key) ;
extern avl_value avl_lookup_add(avl_tree tree, avl_key_c key, bool* added) ;
extern avl_value avl_delete(avl_tree tree, avl_key_c key) ;

extern avl_value avl_get_first(avl_tree tree) ;
extern avl_value avl_get_before(avl_tree tree, avl_key_c key, bool* equal) ;
extern avl_value avl_get_after(avl_tree tree, avl_key_c key, bool* equal) ;
extern avl_value avl_get_last(avl_tree tree) ;
extern avl_value avl_get_next(avl_tree tree, avl_value value) ;
extern avl_value avl_get_prev(avl_tree tree, avl_value value) ;

extern avl_value avl_tree_link(avl_tree tree, avl_link_t how) ;

Inline avl_value avl_get_child(avl_tree tree, avl_value value, avl_dir_t dir) ;
Inline avl_value avl_get_next_linked(avl_tree tree, avl_value value) ;
Inline uint avl_get_level(avl_tree tree, avl_value value) ;
Inline uint avl_get_height(avl_tree tree) ;
Inline int avl_get_balance(avl_tree tree, avl_value value) ;

Inline avl_node avl_node_for(avl_tree tree, avl_value value) ;
Inline avl_value avl_value_for(avl_tree tree, avl_node node) ;

/*==============================================================================
 * The Inlines
 */

/*------------------------------------------------------------------------------
 * Get the node count for the tree
 */
Inline uint
avl_tree_node_count(avl_tree tree)
{
  return (tree != NULL) ? tree->node_count : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Get height of tree -- after avl_tree_link
 *
 * Empty tree has height == 0, just root has height == 1, etc.
 */
Inline uint
avl_get_height(avl_tree tree)
{
  return (tree != NULL) ? tree->height : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Step to next avl_value as currently linked.
 */
Inline avl_value
avl_get_next_linked(avl_tree tree, avl_value value)
{
  if (value != NULL)
    {
      avl_node next ;

      qassert(tree->link_is != avl_parent) ;

      next = avl_node_for(tree, value)->link ;

      if (next != NULL)
        return avl_value_for(tree, next) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Return value for left/right child of given value (if any).
 */
Inline avl_value
avl_get_child(avl_tree tree, avl_value value, avl_dir_t dir)
{
  if (value != NULL)
    {
      avl_node child ;

      child = avl_node_for(tree, value)->child[dir] ;

      if (child != NULL)
        return avl_value_for(tree, child) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Get level for given value -- after avl_tree_link
 *
 * Root has level == 0.
 */
Inline uint
avl_get_level(avl_tree tree, avl_value value)
{
  return (value != NULL) ? avl_node_for(tree, value)->level : 0 ;
} ;

/*------------------------------------------------------------------------------
 * Return "balance" state of given value (if any).
 */
Inline int
avl_get_balance(avl_tree tree, avl_value value)
{
  return (value != NULL) ? avl_node_for(tree, value)->bal : 0 ;
} ;

/*==============================================================================
 * Switching between node and value -- for *internal* consumption.
 */

/*------------------------------------------------------------------------------
 * Return the avl_node for the given avl_value.
 */
Inline avl_node
avl_node_for(avl_tree tree, avl_value value)
{
  return (avl_node)((char*)value + tree->params.offset) ;
} ;

/*------------------------------------------------------------------------------
 * Return the avl_value for the given avl_node.
 */
Inline avl_value
avl_value_for(avl_tree tree, avl_node node)
{
  return (avl_value)((char*)node - tree->params.offset) ;
} ;

#endif /* _ZEBRA_AVL_H */
