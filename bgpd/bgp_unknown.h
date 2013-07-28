/* BGP Unknown Attribute handling -- Header
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_UNKNOWN_H
#define _QUAGGA_BGP_UNKNOWN_H

#include "misc.h"

/*==============================================================================
 * Unknown attributes are held in attr_unknown objects.
 *
 * As attributes are read, pointers to the unknown attributes are added to
 * an attr_unknown -- at this stage, the actual attributes are not stored in
 * the attr_unknown.  The attr_unknown may be sorted, and that will establish
 * whether there are any attributes which are:
 *
 *   * repeated
 *
 *   * optional transitive
 *
 *   * optional non-transitive
 *
 *   * well-known (ie, not optional)
 *
 * A set of unknown attributes may be copied, in which case the attributes are
 * copied to a local stash in the new attr_unk.  Note that this preserves all
 * duplicates. transitive, non-transitive and well-known.  The attributes are
 * copied in canonical form, but further attributes may be added, which are
 * not.  A copy must be made if all the attributes received in a given message
 * must be available after the message itself is discarded.
 *
 * A set of unknown attributes may be stored.  This discards all but the
 * unique optional transitive attributes -- so if an optional-transitive is
 * repeated, *all* copies of it are discarded; also if (say) an optional-non-
 * transitive and an optional-transitive attribute of the same type appear, the
 * optional-transitive will be discarded.  The attributes which are stored
 * are copied to a local stash, in canonical form:
 *
 *   * in ascending order of type
 *
 *   * with the LS 4 bits of the attribute flags zeroized.
 *
 *   * the length rendered as 1 byte if possible, even if arrived as 2 bytes.
 *
 * also: the Partial bit is set.  The result is ready for sending as part of
 * an outgoing UPDATE.
 *
 * NB: until an attr_unknown is copied or stored, it is the caller's
 *     responsibility to ensure that the pointers to each attribute are
 *     stable.
 */
enum attr_unknown_state
{
  unks_null  = 0,               /* no state                             */

  /* The following are established when an uknown attribute set is sorted
   */
  unks_opt_trans     = BIT(0),  /* one or more optional-transitive      */
  unks_opt_non_trans = BIT(1),  /* one or more optional-non-transitive  */
  unks_well_known    = BIT(2),  /* one or more well_known               */

  unks_duplicate     = BIT(3),  /* one or more duplicates
                                 * NB: duplicate are counted as one of
                                 * the above as well.                   */

  unks_any           = unks_opt_trans | unks_opt_non_trans | unks_well_known,

  /* 'unks_sorted' means that the attributes have been sorted into type order
   * (and then arrival order, if have duplicated type).
   *
   * Must be unks_sorted for the unks_opt_trans etc to be valid.
   *
   * If there is an aux vector, then it is sorted.
   *
   * If there is no aux vector, then the attributes must be stashed, and are
   * in order.
   */
  unks_sorted        = BIT(4),

  /* 'unks_stashed' means that the attribute has been stashed, and nothing has
   * beed added since then.
   *
   * The attributes are sorted before being stashed, so 'unks_stashed' =>
   * 'unks_sorted' must also be set.
   *
   * If a set of attributes is stashed, and then added to, then the aux
   * vector contains a mixture of pointers into the current stash, and pointers
   * to newly added attribute(s).  In this state 'unks_stashed' is not set.
   */
  unks_stashed       = BIT(5),
} ;

typedef enum attr_unknown_state attr_unknown_state_t ;

typedef       struct attr_unknown  attr_unknown_t ;
typedef       struct attr_unknown* attr_unknown ;
typedef const struct attr_unknown* attr_unknown_c ;

struct attr_unknown
{
  /* Red tape for storing unknown, transitive attributes
   */
  vhash_node_t vhash ;

  bool      stored ;

  /* This contains attr_unknown_state_t
   */
  byte      state ;

  /* The mechanics for the body of the unk stuff
   */
  uint      count ;             /* if 'stashed'                 */

  ulen      len ;               /* bytes in the stash           */
  byte*     body ;              /* address of same              */

  /* aux vector
   *
   * When collecting attributes, this contains (stable) pointers to the
   * attributes, somewhere (eg in an input buffer).
   *
   * When attributes have been copied to the 'unk' stash, this may contain
   * pointers to the attributes, or may be empty -- but can be recreated.
   */
  vector    aux ;
} ;

CONFIRM(offsetof(attr_unknown_t, vhash) == 0) ; /* see vhash.h  */

/* When walking a set of unknown attributes, the following structure is
 * filled for each one.
 */
typedef struct attr_unknown_item  attr_unknown_item_t ;
typedef struct attr_unknown_item* attr_unknown_item ;

struct attr_unknown_item
{
  byte  type ;
  byte  flags ;

  uint  len ;
  byte* val ;
} ;

/*==============================================================================
 */
extern void attr_unknown_start(void) ;
extern void attr_unknown_finish(void) ;

extern attr_unknown attr_unknown_new(void) ;
extern attr_unknown attr_unknown_store(attr_unknown unk) ;
extern attr_unknown attr_unknown_free(attr_unknown unk) ;

Inline void attr_unknown_lock(attr_unknown unk) ;
Inline attr_unknown attr_unknown_release(attr_unknown unk) ;

extern attr_unknown attr_unknown_copy(attr_unknown unk) ;
extern bool attr_unknown_transitive(attr_unknown unk) ;

extern attr_unknown attr_unknown_add(attr_unknown unk, const byte* unknown) ;
extern byte* attr_unknown_out_prepare(attr_unknown unk, ulen* p_len) ;

extern attr_unknown_state_t attr_unknown_sort(attr_unknown unk) ;
extern attr_unknown_item attr_unknown_get_item(attr_unknown_item item,
                                                     attr_unknown unk, uint i) ;

/*------------------------------------------------------------------------------
 * Functions to increase the reference count and to release an attr_unknown.
 */
Private vhash_table attr_unknown_vhash ;

/*------------------------------------------------------------------------------
 * Increase the reference count on the given attr_unknown
 *
 * NB: unk may NOT be NULL and MUST be stored
 */
Inline void
attr_unknown_lock(attr_unknown unk)
{
  qassert((unk != NULL) && (unk->stored)) ;

  vhash_inc_ref(unk) ;
} ;

/*------------------------------------------------------------------------------
 * Release the given attr_unknown (if any):
 *
 *   * do nothing if NULL
 *
 *   * if is stored, reduce the reference count.
 *
 *   * if is not stored, free it.
 *
 * Returns:  NULL
 */
Inline attr_unknown
attr_unknown_release(attr_unknown unk)
{
  if (unk != NULL)
    {
      if (unk->stored)
        vhash_dec_ref(unk, attr_unknown_vhash) ;
      else
        attr_unknown_free(unk) ;
    } ;

  return NULL ;
} ;

#endif /* _QUAGGA_BGP_UNKNOWN_H */
