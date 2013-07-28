/* Index Hash Table structure -- header
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

#ifndef _ZEBRA_IHASH_H
#define _ZEBRA_IHASH_H

#include "misc.h"
#include "vector.h"

/*==============================================================================
 * Index Hash Table definitions
 *
 * Note that count things in uint -- which is known to be at least 32 bits.
 *
 * Expect to run out of memory before really challenge that assumption !  (At
 * 8 bytes to a pointer, 4G of pointers is already 32G.)
 */
CONFIRM(sizeof(uint) >= 4) ;

enum
{
  /* When extending the number of nodes, the number will:
   *
   *   * double if is      <= IHASH_TABLE_BASES_DOUBLE_MAX
   *
   *   * grow by 50% if is <= IHASH_TABLE_BASES_ADD_HALF_MAX
   *
   *   * grow by 25% otherwise -- when changing the number of nodes, will
   *     allocate enough to increase the number of entries by 25%, before
   *     filling up again (assuming roughly the same distribution of indexes).
   */
  IHASH_TABLE_NODES_DOUBLE_MAX   =  5000,
  IHASH_TABLE_NODES_ADD_HALF_MAX = 20000,

  /* Minimum and maximum number of ihash table nodes.
   *
   * Something has gone tragically wrong if we hit the maximum !
   */
  IHASH_TABLE_NODES_MIN       = 40,
  IHASH_TABLE_NODES_MAX       = UINT_MAX,

  /* We enforce at least 3 bases, so the 'next' node pointer must be >= 3,
   * and we can use the impossible values to encode an "empty" base and
   * an "end of list" 'next' value.
   */
  IHASH_NODE_EMPTY            = 0,
  IHASH_NODE_EOL              = 1,

  IHASH_TABLE_BASES_MIN       = 3,

  /* Min/Default/Max percentage of nodes which are base nodes
   */
  IHASH_TABLE_BASE_PC_MIN     = 20,     /* 20% bases    */
  IHASH_TABLE_BASE_PC_DEFAULT = 50,     /* 50% bases    */
  IHASH_TABLE_BASE_PC_MAX     = 90,     /* 90% bases    */
} ;

CONFIRM(IHASH_NODE_EMPTY < IHASH_TABLE_BASES_MIN) ;
CONFIRM(IHASH_NODE_EOL   < IHASH_TABLE_BASES_MIN) ;

CONFIRM(((IHASH_TABLE_NODES_MIN * IHASH_TABLE_BASE_PC_MIN) / 100)
                                                     >= IHASH_TABLE_BASES_MIN) ;

/*------------------------------------------------------------------------------
 * Structures defined below or elsewhere.
 */
typedef uint32_t ihash_index_t ;
CONFIRM(sizeof(uint) >= sizeof(ihash_index_t)) ;

typedef struct ihash_table*  ihash_table ;
typedef struct ihash_table   ihash_table_t ;

typedef struct ihash_walker* ihash_walker ;
typedef struct ihash_walker  ihash_walker_t ;

typedef struct ihash_node*   ihash_node ;
typedef struct ihash_node    ihash_node_t ;

/*------------------------------------------------------------------------------
 * An ihash_item is some arbitrary data, pointed at by an ihash_node.
 *
 * ihash_data is a pointer some arbitrary value, used in ihash_select_test().
 */
typedef void* ihash_item ;
typedef const void* ihash_item_c ;

typedef void* ihash_data ;
typedef const void* ihash_data_c ;

/*------------------------------------------------------------------------------
 * Index Hash Table.
 *
 * NB: the node_count, free_count, entry_count and bases_used will be zero if
 *     the ihash_table has no body.  However, base_count will be 1 and nodes
 *     will be set to the dummy ihash_empty_node -- this allows lookups to
 *     proceed without checking for empty table.
 *
 *     At all other times: node_count  >  base_count
 *                         bases_used  <= base_count
 *
 *                         entry_count <= node_count
 *
 *     At no time is base_count == 0 (or even) and at no time are nodes == NULL.
 */
struct ihash_table
{
  ihash_node nodes ;            /* ref:array of ihash_node              */

  uint     node_count ;         /* total nodes in the table             */
  uint     free_nodes ;         /* index of first free node (if any)    */

  uint     base_count ;         /* number of chain bases                */
  uint     bases_used ;         /* last base used + 1                   */

  uint     entry_count ;        /* number of entries in the table       */

  uint16_t base_pc ;            /* %age of nodes which are bases        */
  uint16_t init_node_count ;    /* initial number of nodes              */
} ;

/*------------------------------------------------------------------------------
 * Index Hash Walk Iterator and mechanism for returning NULL value
 */
struct ihash_walker
{
  ihash_table table ;           /* table we are working in              */
  uint        next ;            /* next node to return (if any)         */
  uint        base_count ;      /* count of chain bases left to process */

  ihash_index_t self ;          /* for last item returned               */
} ;

/*==============================================================================
 * Value Hash Table Operations.
 */
extern ihash_table ihash_table_new(uint node_count, uint base_pc) ;
extern ihash_table ihash_table_init(ihash_table table, uint node_count,
                                                                 uint base_pc) ;

extern ihash_item ihash_table_ream(ihash_table table, free_keep_b free_table) ;
extern ihash_table ihash_table_reset(ihash_table table,
                                                       free_keep_b free_table) ;
extern void ihash_table_reset_body(ihash_table table, uint node_count) ;

extern ihash_item ihash_get_item(ihash_table table, ihash_index_t index,
                                                                void* absent) ;
extern void ihash_set_item(ihash_table table, ihash_index_t index,
                                                              ihash_item item) ;
extern ihash_item ihash_del_item(ihash_table table, ihash_index_t index,
                                                             ihash_item value) ;

extern void ihash_walk_start(ihash_table table, ihash_walker walk) ;
extern ihash_item ihash_walk_next(ihash_walker walk, void* inull) ;

typedef bool ihash_select_test(const ihash_item_c*, ihash_data_c data) ;
typedef int ihash_sort_cmp(const ihash_item_c* a, const ihash_item_c* b) ;

extern vector ihash_table_extract(ihash_table table,
                                   ihash_select_test* select,
                                   ihash_data_c data,
                                   bool most,
                                   ihash_sort_cmp* sort) ;
Inline uint ihash_entry_count(ihash_table table) ;

/*==============================================================================
 */

/*------------------------------------------------------------------------------
 * Return number of entries in the given table (if any).
 */
Inline uint
ihash_entry_count(ihash_table table)
{
  return (table != NULL) ? table->entry_count : 0 ;
} ;


#endif /* _ZEBRA_IHASH_H */
