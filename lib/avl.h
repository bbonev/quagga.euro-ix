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
 *   * avl_item: some data structure, in which an avl_node is embedded.
 *
 *     Each avl_tree is expected to contain avl_values of the same type,
 *     or at least values which contain an avl_node at a fixed offset.
 *     (Different trees can have different offsets for their avl_nodes.)
 *
 * All the external interfaces work in terms of the avl_item.
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
 * function -- which takes an avl_item and a pointer to a key.
 *
 * When a new avl_item is created, the tree's creator function is used.
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

enum { avl_debug = AVL_DEBUG } ;

/*------------------------------------------------------------------------------
 * Structures and other definitions
 */

/* The avl_item and avl_key are abstract as far as the avl tree is concerned.
 *
 * There is, however the constraint that an avl_node MUST be at offset zero in
 * an avl_item.
 */
typedef void* avl_item ;
typedef const void* avl_key_c ;

enum
{
  avl_node_offset = 0           /* offset of avl_node in avl_item       */
} ;

/* The pointer to an avl_tree and the avl_tree parameters.
 *
 * The avl_tree parameters include two functions:
 *
 *   * new:  the avl_key key for a new item, and the 'new_arg' passed in to
 *           avl_lookup_add().
 *
 *           Returns: a new avl_item
 *
 *           The contents of the new avl_item are immaterial.  When the a
 *           new value is created the enclosed avl_node is initialised and
 *           then used to insert the avl_item in the tree.
 *
 *           The new() may choose to set the avl_item's key, but that is not
 *           strictly necessary.  But is is, of course, *essential* that the
 *           key is set before any further tree operations !
 *
 *   * cmp:  is passed the avl_key being sought and an avl_item whose key
 *           is to be compared.
 *
 *           Returns: -1, 0, +1 as usual, for avl_key cmp avl_item.
 *
 *           Note that what the avl_key void* pointer points to and how the
 *           key is stored for the avl_item are both entirely up to the
 *           cmp function.
 */
typedef struct avl_tree  avl_tree_t ;
typedef struct avl_tree* avl_tree ;

typedef int avl_cmp_func(avl_key_c key, avl_item item) ;
typedef avl_item avl_new_func(avl_key_c key, void* arg) ;

typedef struct avl_tree_params* avl_tree_params ;
typedef struct avl_tree_params  avl_tree_params_t ;

typedef const avl_tree_params_t* avl_tree_params_c ;

struct avl_tree_params
{
  avl_new_func* new ;           /* create new item                      */
  avl_cmp_func* cmp ;           /* compare key and item                 */
} ;

/* The avl_node_t is to be embedded in each tree's particular avl_item.
 *
 * The avl_node_t MUST be at offset zero in the avl_item.
 *
 * On a 64-bit machine, this runs to 28 bytes (3 * pointer + 4)
 */
typedef struct avl_node  avl_node_t ;
typedef struct avl_node* avl_node ;

CONFIRM(avl_node_offset == 0) ;

typedef enum
{
  avl_left   = 0,
  avl_right  = 1,
} avl_dir_t ;

struct avl_node
{
  avl_node  child[2] ;  /* two children, avl_left and avl_right         */
  avl_node  parent ;    /* NULL for root node                           */

  uint8_t   which ;     /* which child this is -- avl_left for root     */
  int8_t    bal ;

  uint8_t   level ;     /* used by avl_get_level_first()/_next()
                         *  and by avl_get_depth_first()/_next()
                         *
                         * also set by avl_get_count()
                         */
  uint8_t   height ;    /* Set in the root node only
                         *
                         * used by avl_get_level_first()/_next()
                         * and by avl_get_depth_first()/_next()
                         *
                         * also set by avl_get_height()
                         */
} ;

/*------------------------------------------------------------------------------
 * The actual tree structure.
 *
 * This is not, in fact, required by any of the AVL tree operations, but may
 * be a convenient way of representing a tree and its parameters !
 */
struct avl_tree
{
  avl_item  root ;              /* address of root item                 */
  avl_tree_params_c params ;    /* see above                            */
} ;

/*==============================================================================
 * Prototypes.
 */
extern avl_tree avl_tree_init_new(avl_tree tree, avl_tree_params_c params) ;
extern avl_item avl_tree_ream(avl_item* p_next) ;
extern avl_item avl_tree_fell(avl_tree tree) ;
extern avl_tree avl_tree_reset(avl_tree tree, free_keep_b free_structure) ;

extern avl_item avl_lookup(avl_item* p_root, avl_item item, avl_key_c key,
                                                     avl_tree_params_c params) ;
extern avl_item avl_lookup_add(avl_item* p_root, avl_item item, avl_key_c key,
                                      avl_tree_params_c params, void* new_arg) ;
extern avl_item avl_lookup_inexact(avl_item* p_root, avl_item item,
                          avl_key_c key, avl_tree_params_c params, int* p_cmp) ;
extern avl_item avl_delete(avl_item* p_root, avl_item item, avl_key_c key,
                                                     avl_tree_params_c params) ;
extern avl_item avl_remove(avl_item* p_root, avl_item item) ;

extern avl_item avl_get_first(avl_item root) ;
extern avl_item avl_get_next(avl_item item) ;
extern avl_item avl_get_last(avl_item root) ;
extern avl_item avl_get_prev(avl_item item) ;
extern avl_item avl_get_pre_next(avl_item item) ;
extern avl_item avl_get_post_first(avl_item root) ;
extern avl_item avl_get_post_next(avl_item item) ;
extern avl_item avl_get_level_first(avl_item root) ;
extern avl_item avl_get_level_next(avl_item item) ;
extern avl_item avl_get_depth_first(avl_item root) ;
extern avl_item avl_get_depth_next(avl_item item) ;

extern uint avl_get_count(avl_item root) ;
extern uint avl_get_height(avl_item root) ;

#endif /* _ZEBRA_AVL_H */
