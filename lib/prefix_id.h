/* Prefix ID Table and Index -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_PREFIX_ID_H
#define _QUAGGA_BGP_PREFIX_ID_H

#include "vhash.h"
#include "prefix.h"

/*==============================================================================
 * Prefix ID Table and Index.
 *
 * Users may refer directly to a prefix_id_entry or use the prefix_id
 * indirection -- the latter being 32 bits and suitable for use with an
 * ihash.
 */
typedef uint32_t prefix_id_t ;

enum { prefix_id_null = 0 } ;

typedef struct prefix_id_entry  prefix_id_entry_t ;
typedef struct prefix_id_entry* prefix_id_entry ;
typedef const struct prefix_id_entry* prefix_id_entry_c ;

struct prefix_id_entry
{
  union
  {
    vhash_node_t     vhash ;
    prefix_id_entry  next ;
  } rt ;

  prefix_t      pfx[1] ;

  prefix_id_t   id ;
} ;

CONFIRM(offsetof(prefix_id_entry_t, rt.vhash) == 0) ; /* see vhash.h  */

/*------------------------------------------------------------------------------
 * Route Distinguisher and Index
 */
typedef struct prefix_rd  prefix_rd_t ;
typedef struct prefix_rd* prefix_rd ;
typedef const struct prefix_rd* prefix_rd_c ;

enum { prefix_rd_len  = 8 } ;           /* well-known fact: RFC4364     */

struct prefix_rd
{
  byte val[prefix_rd_len] ;
} ;

typedef struct prefix_rd_id_entry  prefix_rd_id_entry_t ;
typedef struct prefix_rd_id_entry* prefix_rd_id_entry ;
typedef const struct prefix_rd_id_entry* prefix_rd_id_entry_c ;

struct prefix_rd_id_entry
{
  union
  {
    vhash_node_t       vhash ;
    prefix_rd_id_entry next ;
  } rt ;

  prefix_rd_t        rd ;

  prefix_rd_id_t     id ;
} ;

CONFIRM(offsetof(prefix_rd_id_entry_t, rt.vhash) == 0) ; /* see vhash.h  */

/*==============================================================================
 * Functions
 */
extern void prefix_id_init(void) ;
extern void prefix_id_init_r(void) ;
extern void prefix_id_finish(void) ;

extern prefix_id_entry prefix_id_find_entry(prefix pfx, const byte* rd_val) ;

extern prefix_id_entry prefix_id_seek_entry(prefix pfx) ;
extern prefix_rd_id_entry prefix_rd_id_seek_entry(const byte* rd_val) ;

extern int prefix_id_cmp(prefix_id_t a_id, prefix_id_t b_id) ;
extern int prefix_id_p_entry_cmp(prefix_id_entry_c* p_a,
                                 prefix_id_entry_c* p_b) ;
extern int prefix_id_entry_cmp(prefix_id_entry_c a, prefix_id_entry_c b) ;

extern int prefix_rd_id_cmp(prefix_rd_id_t a_id, prefix_rd_id_t b_id) ;
extern int prefix_rd_id_p_entry_cmp(prefix_rd_id_entry_c* p_a,
                                    prefix_rd_id_entry_c* p_b) ;
extern int prefix_rd_id_entry_cmp(prefix_rd_id_entry_c a,
                                  prefix_rd_id_entry_c b) ;

Inline prefix prefix_id_get_prefix(prefix_id_t pid) ;
Inline prefix_id_entry prefix_id_get_entry(prefix_id_t pid) ;

Inline prefix_rd prefix_rd_id_get_val(prefix_rd_id_t rdid) ;
Inline prefix_rd_id_entry prefix_rd_id_get_entry(prefix_rd_id_t pid) ;

Inline prefix_id_t prefix_id_get_id(prefix_id_entry pie) ;
Inline prefix_id_t prefix_id_get_id_inc_ref(prefix_id_entry pie) ;
Inline prefix_id_t prefix_id_inc_ref(prefix_id_t pid) ;
Inline prefix_id_t prefix_id_dec_ref(prefix_id_t pid) ;

Inline prefix_id_entry prefix_id_entry_inc_ref(prefix_id_entry pie) ;
Inline prefix_id_entry prefix_id_entry_dec_ref(prefix_id_entry pie) ;

/*==============================================================================
 * The Inline stuff.
 */
Private vhash_table prefix_id_table ;           /* for dec_ref          */
Private vector      prefix_id_index ;           /* to map pid to pie    */

Private vector      prefix_rd_id_index ;        /* to map rdid to rd    */

/*------------------------------------------------------------------------------
 * Increment prefix_id_entry reference count.
 *
 * When storing a pointer to a prefix_id_entry, the reference count must be
 * incremented.
 *
 * Returns:  the prefix_id_entry
 */
Inline prefix_id_entry
prefix_id_entry_inc_ref(prefix_id_entry pie)
{
  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ; /* see vhash.h  */
  return vhash_inc_ref(pie) ;
} ;

/*------------------------------------------------------------------------------
 * Decrement prefix_id_entry reference count.
 *
 * When discarding a pointer to a prefix_id_entry, the reference count must be
 * decremented.
 *
 * Returns:  NULL
 */
Inline prefix_id_entry
prefix_id_entry_dec_ref(prefix_id_entry pie)
{
  confirm(offsetof(prefix_id_entry_t, rt.vhash) == 0) ; /* see vhash.h  */

  qassert(vhash_is_set(pie) && vhash_has_references(pie)) ;

  vhash_dec_ref_simple(pie) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_id to prefix
 *
 * NB: this does NOT change the reference count.
 *
 * Returns:  the prefix
 */
Inline prefix
prefix_id_get_prefix(prefix_id_t pid)
{
  prefix_id_entry pie ;

  pie = vector_get_item(prefix_id_index, pid) ;

  qassert((pie != NULL) && (pie->id == pid)) ;

  return pie->pfx ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_id to prefix_id_entry
 *
 * NB: this does NOT change the reference count.
 *
 * Returns:  the prefix_id_entry
 */
Inline prefix_id_entry
prefix_id_get_entry(prefix_id_t pid)
{
  prefix_id_entry pie ;

  pie = vector_get_item(prefix_id_index, pid) ;

  qassert((pie != NULL) && (pie->id == pid)) ;

  return pie ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_rd_id to prefix_rd_id_entry
 *
 * NB: this does NOT change the reference count.
 *
 * Returns:  the prefix_rd_id_entry -- NULL if prefix_rd_id_null
 */
Inline prefix_rd_id_entry
prefix_rd_id_get_entry(prefix_rd_id_t rdid)
{
  prefix_rd_id_entry rdie ;

  if (rdid == prefix_rd_id_null)
    return NULL ;

  rdie = vector_get_item(prefix_rd_id_index, rdid) ;

  qassert((rdie != NULL) && (rdie->id == rdid)) ;

  return rdie ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_rd_id to prefix_rd
 *
 * NB: this does NOT change the reference count.
 *
 * Returns:  the prefix_rd value -- NULL if prefix_rd_id_null
 */
Inline prefix_rd
prefix_rd_id_get_val(prefix_rd_id_t rdid)
{
  prefix_rd_id_entry rdie ;

  if (rdid == prefix_rd_id_null)
    return NULL ;

  rdie = vector_get_item(prefix_rd_id_index, rdid) ;

  qassert((rdie != NULL) && (rdie->id == rdid)) ;

  return &rdie->rd ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_id_entry to prefix_id
 *
 * NB: this does NOT change the reference count.
 *
 * Returns:  the prefix_id_t
 */
Inline prefix_id_t
prefix_id_get_id(prefix_id_entry pie)
{
  qassert(vector_get_item(prefix_id_index, pie->id) == pie) ;
  return pie->id ;
} ;

/*------------------------------------------------------------------------------
 * Map prefix_id_entry to prefix_id AND increment reference count
 *
 * Returns:  the prefix_id_entry
 */
Inline prefix_id_t
prefix_id_get_id_inc_ref(prefix_id_entry pie)
{
  prefix_id_entry_inc_ref(pie) ;
  return prefix_id_get_id(pie) ;
} ;

/*------------------------------------------------------------------------------
 * Increment prefix_id reference count.
 *
 * When storing a prefix_id, the reference count must be incremented.
 *
 * Returns:  the prefix_id
 */
Inline prefix_id_t
prefix_id_inc_ref(prefix_id_t pid)
{
  prefix_id_entry_inc_ref(prefix_id_get_entry(pid)) ;

  return pid ;
} ;

/*------------------------------------------------------------------------------
 * Decrement prefix_id reference count.
 *
 * When discarding a prefix_id, the reference count must be decremented.
 *
 * Returns:  prefix_id_null
 */
Inline prefix_id_t
prefix_id_dec_ref(prefix_id_t pid)
{
  prefix_id_entry_dec_ref(prefix_id_get_entry(pid)) ;

  return prefix_id_null ;
} ;

#endif /* _QUAGGA_BGP_PREFIX_ID_H */
