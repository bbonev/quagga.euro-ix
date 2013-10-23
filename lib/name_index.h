/* Name Index System -- header
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
#ifndef _ZEBRA_NAME_INDEX_H_
#define _ZEBRA_NAME_INDEX_H_

#include "misc.h"

#include "vhash.h"
#include "vector.h"
#include "miyagi.h"

/*==============================================================================
 * A name-index maps a "name" (an arbitrary string of bytes) to (short)
 * 'reference'.
 *
 * This may be used to store names in form that the equality of two names may
 * be established by comparing their 'reference's.
 *
 * Each name in a name-index has a name-index-entry, and that may be used as
 * the 'reference'.  The name itself is embedded in the name-index-entry.
 *
 * Each name-index-entry is given a unique, non-zero 'id'.  That too may be
 * used as the 'reference'.
 *
 * Names are placed in the index automatically when a 'reference' is requested.
 * The reference count on the name-index-entry is increased each time a
 * 'reference' is requested.
 *
 * The reference count for a name-index-entry can be incremented to allow
 * (another) copy to be store.
 *
 * When a name 'reference' is no longer required, its reference count must be
 * decremented.  Names are automatically dropped from the name-index when the
 * reference count drops to zero.
 *
 * The reference count mechanism is the same as for a 'vhash'.  It is also
 * possible, therefore, to set a name-index-entry 'held'.
 *
 * The 'id's are handed out in no particular order.  But will start at 1, and
 * any 'id' which has been released will be used before the range of 'id's
 * is increased.
 *
 * It is possible to have any number of name indexes, each one with its own
 * name and id space.
 *
 * NB: the length of a name is "limited" to a uint.
 *
 * NB: the 'id's are also "limited" to a uint.
 */
typedef enum niid niid_t ;
enum niid
{
  niid_null       = 0,

  niid_first      = 1,
  niid_last       = UINT_MAX,
} ;

/* A name index is an opaque structure -- but at offset 0 we have the vector
 * to map 'id' to its name-index-entry.
 */
typedef struct name_index* name_index ;

enum { name_index_offset_of_vector  = 0 } ;

/* When a name reference is returned, it is an nref_c.
 *
 * It is permissible to access:  nref->name.c   -- char string
 *                               nref->name.b   -- byte string
 *                               nref->name_len -- length (excluding '\0')
 *                               nref->niid     -- the id (!)
 */
typedef struct name_index_entry  name_index_entry_t ;
typedef struct name_index_entry* name_index_entry ;
typedef struct name_index_entry const* nref_c ;

struct name_index_entry
{
  vhash_node_t  vhash ;
  vhash_table   table ;

  niid_t        niid ;

  uint          name_len ;
  union
    {
      char  c[0] ;
      byte  b[0] ;
    }           name ;
} ;

CONFIRM(offsetof(name_index_entry_t, vhash) == 0) ; /* see vhash.h  */

/*==============================================================================
 * Prototypes
 */
extern name_index name_index_new(void) ;
extern name_index name_index_free(name_index ni) ;

extern nref_c ni_nref_get_c(name_index ni, chs_c name) ;
extern nref_c ni_nref_get_b(name_index ni, ptr_c name, uint name_len) ;
extern niid_t ni_niid_get_c(name_index ni, chs_c name) ;
extern niid_t ni_niid_get_b(name_index ni, ptr_c name, uint name_len) ;

extern void ni_nref_set_c(nref_c* p_ref, name_index ni, chs_c name) ;
extern void ni_nref_set_b(nref_c* p_ref, name_index ni, ptr_c name,
                                                                uint name_len) ;
extern void ni_nref_set_copy(nref_c* p_ref, nref_c nref) ;

extern void ni_niid_set_c(niid_t* p_id, name_index ni, chs_c name) ;
extern void ni_niid_set_b(niid_t* p_id, name_index ni, ptr_c name,
                                                                uint name_len) ;
extern void ni_niid_set_copy(niid_t* p_id, name_index ni, niid_t niid) ;

extern void ni_nref_clear(nref_c* p_ref) ;
extern void ni_niid_clear(niid_t* p_id, name_index ni) ;

extern void ni_nref_set_held(nref_c nref) ;
extern void ni_niid_set_held(niid_t niid, name_index ni) ;
extern nref_c ni_nref_drop(nref_c nref) ;
extern niid_t ni_niid_drop(niid_t niid, name_index ni) ;

Inline chs_c ni_nref_name(nref_c nref) ;
Inline chs_c ni_niid_name(niid_t niid, name_index ni) ;

Inline nref_c ni_get_nref(niid_t niid, name_index ni) ;

Inline nref_c ni_nref_inc(nref_c nref) ;
Inline nref_c ni_nref_dec(nref_c nref) ;
Inline niid_t ni_niid_inc(niid_t niid, name_index ni) ;
Inline niid_t ni_niid_dec(niid_t niid, name_index ni) ;

/*==============================================================================
 * The Inlines
 */

/*------------------------------------------------------------------------------
 * Map nref to name -- if any
 */
Inline chs_c
ni_nref_name(nref_c nref)
{
  if (nref == NULL)
    return NULL ;
  else
    return nref->name.c ;
} ;

/*------------------------------------------------------------------------------
 * Map niid to name -- if any
 */
Inline chs_c
ni_niid_name(niid_t niid, name_index ni)
{
  return ni_nref_name(ni_get_nref(niid, ni)) ;
} ;

/*------------------------------------------------------------------------------
 * Map name 'id' to nref.
 *
 * NB: niid_null -> NULL
 *
 * NB: unused 'id' may may to NULL or some other nonsense.
 */
Inline nref_c
ni_get_nref(niid_t niid, name_index ni)
{
  vector  id_vec ;

  id_vec = (vector)&ni ;
  confirm(name_index_offset_of_vector == 0) ;

  return vector_get_item(id_vec, niid) ;
} ;

/*------------------------------------------------------------------------------
 * Increment the reference count in the given nref.
 *
 * NB: nref must NOT be NULL
 *
 * Returns:  the nref as given (with reference count increased
 */
Inline nref_c
ni_nref_inc(nref_c nref)
{
  return vhash_inc_ref(miyagi(nref)) ;
} ;

/*------------------------------------------------------------------------------
 * Decrement the reference count in the given nref, and discard if required.
 *
 * NB: nref must NOT be NULL
 *
 * Returns:  NULL
 */
Inline nref_c
ni_nref_dec(nref_c nref)
{
  name_index_entry entry ;

  entry = miyagi(nref) ;

  vhash_dec_ref(entry, entry->table) ;

  return NULL ;
} ;

/*------------------------------------------------------------------------------
 * Increment the reference count in the given niid.
 *
 * Does nothing for niid_null.
 *
 * Returns:  the niid as given (with reference count increased
 */
Inline niid_t
ni_niid_inc(niid_t niid, name_index ni)
{
  if (niid != niid_null)
    vhash_inc_ref(miyagi(ni_get_nref(niid, ni))) ;

  return niid ;
} ;

/*------------------------------------------------------------------------------
 * Decrement the reference count in the given nref, and discard if required.
 *
 * Does nothing for niid_null.
 *
 * Returns:  niid_null
 */
Inline niid_t
ni_niid_dec(niid_t niid, name_index ni)
{
  if (niid != niid_null)
    {
      name_index_entry entry ;

      entry = miyagi(miyagi(ni_get_nref(niid, ni))) ;

      vhash_dec_ref(entry, entry->table) ;
    } ;

  return niid_null ;
} ;

#endif /* _ZEBRA_NAME_INDEX_H_ */
