/* Name Index System
 * Copyright (C) 2013 Chris Hall (GMCH), Highwayman
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

#include "name_index.h"
#include "elstring.h"
#include "memory.h"

/*==============================================================================

 */

/* The name index comprises a vector for 'id' -> index entry map, and a
 * vhash for the name to index entry map.
 */
typedef struct name_index  name_index_t ;

struct name_index
{
  vector_t      id_vec[1] ;             /* *embedded* vector            */

  vhash_table_t table[1] ;              /* *embedded* table             */

  niid_t        free_id ;               /* next niid to use, if any     */
};

CONFIRM(offsetof(name_index_t, id_vec) == name_index_offset_of_vector) ;

/* The vhash table magic
 */
static vhash_hash_func          ni_name_hash ;
static vhash_equal_func         ni_name_equal ;
static vhash_new_func           ni_name_new ;
static vhash_free_func          ni_name_free ;
static vhash_table_free_func    ni_name_table_free ;

static const vhash_params_t name_index_vhash_params =
{
  .hash         = ni_name_hash,
  .equal        = ni_name_equal,
  .new          = ni_name_new,
  .free         = ni_name_free,
  .orphan       = vhash_orphan_null,
  .table_free   = ni_name_table_free,
} ;

/*------------------------------------------------------------------------------
 * Create and initialise a new name-index.
 */
extern name_index
name_index_new(void)
{
  name_index ni ;

  ni = XCALLOC(MTYPE_NAME_INDEX, sizeof(name_index_t)) ;

  /* Zeroizing sets:
   *
   *   * id_vec                 -- X    -- set below
   *
   *   * table                  -- X    -- set below
   *
   *   * free_id                -- niid_null
   */
  confirm(VECTOR_INIT_ALL_ZEROS) ;
  confirm(niid_null == 0) ;

  vhash_table_init(
          ni->table,
          ni,
          50,                     /* start ready for a few name */
          200,                    /* allow to be quite dense    */
          &name_index_vhash_params) ;

  /* Make sure that niid_null maps to NULL, and that the first 'id' to
   * be allocated will be niid_first.
   */
  vector_push_item(ni->id_vec, NULL) ;

  qassert(vector_end(ni->id_vec) == niid_first) ;

  return ni ;
} ;

/*------------------------------------------------------------------------------
 * Free the given name-index.
 */
extern name_index
name_index_free(name_index ni)
{
  if (ni != NULL)
    {
      /* Delete everything from the table, and discard chain bases.
       *
       * This will discard the vector and free the entire name_index if there
       * are no orphans.  Otherwise, holds on to those until the orphans drop
       * to zero.
       */
      vhash_table_reset(ni->table) ;
    } ;

  return NULL ;
} ;

/*==============================================================================
 * The get/set/clear functions.
 */

/*------------------------------------------------------------------------------
 * Get nref_c for the given string -- incrementing its ref-count.
 *
 * Creates entry if required.
 *
 * For NULL name returns NULL.
 */
extern nref_c
ni_nref_get_c(name_index ni, chs_c name)
{
  return ni_nref_get_b(ni, (const void*)name, strlen(name)) ;
}

/*------------------------------------------------------------------------------
 * Get nref_c for the given bytes -- incrementing its ref-count.
 *
 * Creates entry if required.
 *
 * For NULL name returns NULL.
 */
extern nref_c
ni_nref_get_b(name_index ni, ptr_c name, uint name_len)
{
  elstring_t    els ;
  bool          add ;
  nref_c        nref ;

  if (name == NULL)
    return NULL ;

  els->body.cv  = name ;
  els->len      = name_len ;

  nref = vhash_lookup(ni->table, els, &add) ;

  return ni_nref_inc(nref) ;
} ;

/*------------------------------------------------------------------------------
 * Get niid for the given string -- incrementing its ref-count.
 *
 * Creates entry if required.
 *
 * For NULL name return niid_null.
 */
extern niid_t
ni_niid_get_c(name_index ni, chs_c name)
{
  if (name == NULL)
    return niid_null ;
  else
    return ni_nref_get_c(ni, name)->niid ;
}

/*------------------------------------------------------------------------------
 * Get niid for the given bytes -- incrementing its ref-count.
 *
 * Creates entry if required.
 *
 * For NULL name return niid_null.
 */
extern niid_t
ni_niid_get_b(name_index ni, ptr_c name, uint name_len)
{
  if (name == NULL)
    return niid_null ;
  else
    return ni_nref_get_b(ni, name, name_len)->niid ;
} ;

/*------------------------------------------------------------------------------
 * Get nref_c for the given string -- incrementing its ref-count.
 *
 * If the given reference is not NULL, decrement its ref-count and replace it
 * by the nref we just got.
 *
 * Creates entry if required.
 *
 * NULL name clears the given reference.
 */
extern void
ni_nref_set_c(nref_c* p_ref, name_index ni, chs_c name)
{
  nref_c  got ;

  got = ni_nref_get_c(ni, name) ;

  if (*p_ref != NULL)
    ni_nref_dec(*p_ref) ;

  *p_ref = got ;
} ;

/*------------------------------------------------------------------------------
 * Get nref_c for the given bytes -- incrementing its ref-count.
 *
 * If the given reference is not NULL, decrement its ref-count and replace it
 * by the nref we just got.
 *
 * Creates entry if required.
 *
 * NULL name clears the given reference.
 */
extern void
ni_nref_set_b(nref_c* p_ref, name_index ni, ptr_c name, uint name_len)
{
  nref_c  got ;

  got = ni_nref_get_b(ni, name, name_len) ;

  if (*p_ref != NULL)
    ni_nref_dec(*p_ref) ;

  *p_ref = got ;
} ;

/*------------------------------------------------------------------------------
 * Get niid for the given string -- incrementing its ref-count.
 *
 * If the given reference is not NULL, decrement its ref-count and replace it
 * by the niid we just got.
 *
 * Creates entry if required.
 *
 * NULL name clears the given reference.
 */
extern void
ni_niid_set_c(niid_t* p_id, name_index ni, chs_c name)
{
  niid_t  got ;

  got = ni_niid_get_c(ni, name) ;

  if (*p_id != niid_null)
    ni_niid_dec(*p_id, ni) ;

  *p_id = got ;
} ;

/*------------------------------------------------------------------------------
 * Get niid for the given bytes -- incrementing its ref-count.
 *
 * If the given reference is not NULL, decrement its ref-count and replace it
 * by the niid we just got.
 *
 * Creates entry if required.
 *
 * NULL name clears the given reference.
 */
extern void
ni_niid_set_b(niid_t* p_id, name_index ni, ptr_c name, uint name_len)
{
  niid_t  got ;

  got = ni_niid_get_b(ni, name, name_len) ;

  if (*p_id != niid_null)
    ni_niid_dec(*p_id, ni) ;

  *p_id = got ;
}

/*------------------------------------------------------------------------------
 * If the given reference is not NULL, decrement its ref-count and set it NULL.
 */
extern void
ni_nref_clear(nref_c* p_ref)
{
  if (*p_ref != NULL)
    *p_ref = ni_nref_dec(*p_ref) ;
} ;

/*------------------------------------------------------------------------------
 * If the given reference is not niid_null, decrement its ref-count and set it
 * niid_null.
 */
extern void
ni_niid_clear(niid_t* p_id, name_index ni)
{
  if (*p_id != niid_null)
    *p_id = ni_niid_dec(*p_id, ni) ;
}

/*==============================================================================
 * To set/clear 'held' state for name-index
 */

/*------------------------------------------------------------------------------
 * Set 'held' on the given nref.
 */
extern void
ni_nref_set_held(nref_c nref)
{
  if (nref != NULL)
    vhash_set_held(miyagi(nref)) ;
} ;

/*------------------------------------------------------------------------------
 * Set 'held' on the given niid.
 */
extern void
ni_niid_set_held(niid_t niid, name_index ni)
{
  if (niid != niid_null)
    vhash_set_held(miyagi(ni_get_nref(niid, ni))) ;
}

/*------------------------------------------------------------------------------
 * Clear 'held' (if set) on given nref -- and discard if ref-count == 0
 *
 * Returns:  NULL
 */
extern nref_c
ni_nref_drop(nref_c nref)
{
  if (nref != NULL)
    {
      name_index_entry entry ;

      entry = miyagi(nref) ;

      vhash_drop(entry, entry->table) ;
    } ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Clear 'held' (if set) on given niid -- and discard if ref-count == 0
 *
 * Returns:  niid_null
 */
extern niid_t
ni_niid_drop(niid_t niid, name_index ni)
{
  if (niid != niid_null)
    {
      name_index_entry entry ;

      entry = miyagi(ni_get_nref(niid, ni)) ;

      vhash_drop(entry, entry->table) ;
    } ;

  return niid_null ;
}

/*==============================================================================
 * The vhash functions.
 */

/*------------------------------------------------------------------------------
 * Construct hash for the given name -- vhash_hash_func()
 */
static vhash_hash_t
ni_name_hash(vhash_data_c data)
{
  elstring_c    name ;

  name = data ;

  return vhash_hash_bytes(name->body.v, name->len) ;
} ;

/*------------------------------------------------------------------------------
 * Comparison function -- vhash_equal_func()
 */
static int
ni_name_equal(vhash_item_c item, vhash_data_c data)
{
  nref_c        nref ;
  elstring_c    name ;

  nref = item ;
  name = data ;

  if (nref->name_len != name->len)
    return -1 ;

  if (name->len == 0)
    return 0 ;
  else
    return memcmp(nref->name.b, name->body.v, name->len) ;
} ;

/*------------------------------------------------------------------------------
 * Create a new entry in the name-index for the given name -- vhash_new_func()
 *
 * Allocates and sets the next id
 */
static vhash_item
ni_name_new(vhash_table table, vhash_data_c data)
{
  elstring_c       name ;
  name_index_entry nref ;
  name_index       ni ;
  niid_t           niid ;

  name = data ;
  ni   = table->parent ;
  qassert(ni->table == table) ;

  /* Make a new item and copy in the name.
   *
   * Note that at this point we do not know if the name is '\0' terminated or
   * not, and the length we have excludes any '\0'.  So, we always allocate at
   * least one extra byte, and by zeroizing the new item, we ensure we have
   * a trailing '\0' in any case.
   */
  nref = XCALLOC(MTYPE_NAME, offsetof(name_index_entry_t,
                                          name.b[uround_up_up(name->len, 4)])) ;
  nref->name_len = name->len ;
  if (name->len != 0)
    memcpy(&nref->name, name->body.v, name->len) ;

  /* So we now have:
   *
   *   * vhash                  -- all zeros    -- set on exit
   *
   *   * table                  -- X            -- set below
   *
   *   * niid                   -- X            -- set below
   *
   *   * name_len               -- set above
   *   * name                   -- set above
   *
   * So we now need to allocate an 'id' and add point the id_vec entry at the
   * new name-index-entry.
   */
  niid = ni->free_id ;
  if (niid != niid_null)
    {
      void**    p_vec ;

      p_vec = vector_get_p_item(ni->id_vec, niid) ;
      ni->free_id = (uintptr_t)(void*)(*p_vec) ;

      *p_vec = nref ;
    }
  else
    {
      qassert(!vector_is_empty(ni->id_vec)) ;

      vector_push_item(ni->id_vec, nref) ;
      niid = vector_last(ni->id_vec) ;
    } ;

  nref->niid  = niid ;
  nref->table = table ;

  /* Done... returns to the vhash code, which completes the addition of the
   * new item to the table.
   */
  return nref ;
} ;

/*------------------------------------------------------------------------------
 * Give back the given name-index entry, and its 'id' -- vhash_free_func()
 */
static vhash_item
ni_name_free(vhash_item item, vhash_table table)
{
  name_index_entry nref ;
  name_index       ni ;
  void**           p_vec ;

  ni   = table->parent ;
  nref = item ;

  qassert(nref->table == table) ;
  qassert(nref->niid  != niid_null) ;

  p_vec = vector_get_p_item(ni->id_vec, nref->niid) ;
  qassert((p_vec != NULL) && (*p_vec == nref)) ;

  *p_vec = (void*)(uintptr_t)(ni->free_id) ;

  ni->free_id  = nref->niid ;

  XFREE(MTYPE_NAME, nref) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Orphan the given name-index-entry -- vhash_orphan_func()
 *
 * The table is
 */
static vhash_table
ni_name_table_free(vhash_table table, bool on_reset)
{
  name_index    ni ;

  ni   = table->parent ;

  vector_reset(ni->id_vec, keep_it) ;   /* embedded     */

  XFREE(MTYPE_NAME_INDEX, ni) ;

  return NULL ;
} ;

