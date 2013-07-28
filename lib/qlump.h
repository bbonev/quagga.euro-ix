/* Lumps of Memory -- header
 * Copyright (C) 2012 Chris Hall (GMCH), Highwayman
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

#ifndef _ZEBRA_QLUMP_H
#define _ZEBRA_QLUMP_H

#include "misc.h"
#include "memory.h"

/*==============================================================================
 * The qlump is a lump of memory with a size and a length.
 *
 * All qlump operations take a qlump and a qlump_type (at least).  The
 * qlump_type tells the qlump handler everything it needs to know to
 * allocate/reallocate/free etc. the qlump.
 */

/*------------------------------------------------------------------------------
 * A qlump is expected to be an *embedded* structure in some other structure.
 *
 * The qlump.body is an array of qlump items.  Each item is "unit" bytes, as
 * specified in the qlump_type.
 *
 * The qlump.size is a count of *items* -- NOT bytes.
 *
 * The qlump handler does not store any 'len' (number of items used) but
 * where a qlump operation uses a given 'len', that too is a count of
 * *items* -- NOT bytes.
 *
 * If qlump.size == 0, there is no body and qlump.body is ignored (by the
 * qlump code) but will usually be NULL.
 *
 * Currently, expect the qlump.body to be a 64-bit address and the qlump.size
 * to be a 32-bit unsigned integer.  So with the red tape, the qlump_t is a
 * 16 byte object.
 *
 * In order to allow for negative offsets and for offsets beyond the end of
 * a qlump, we limit the number of items to (INT_MAX / 2) + 1.  So, for
 * 32-bit integer thats:
 *
 *    0x00000000..0x40000000  -- valid size (1G items !)
 *
 *    0x40000001..0x80000000  -- +ve offset beyond size up to 1G items
 *
 *    0x80000001..0x9FFFFFFF  -- no man's land -- deemed +ve
 *    0xA0000001..0xBFFFFFFF  -- no man's land -- deemed -ve
 *
 *    0xC0000000..0xFFFFFFFF  -- -ve offset up to 1G items
 *
 * Where -ve values are represented as 2's complement in a uint -- so that
 * testing for an invalid size does not have to test for -ve values.
 */
enum {
  QLUMP_SIZE_MAX       = ((uint)INT_MAX / 2) + 1,

  /* Anything >= QLUMP_SIZE_NEGATIVE is deemed -ve
   */
  QLUMP_SIZE_NEGATIVE  = ((uint)0 - QLUMP_SIZE_MAX - (QLUMP_SIZE_MAX / 2)),

  /* QLUMP_SIZE_OVERFLOW <= x <  QLUMP_SIZE_NEGATIVE  is overflow.
   *
   * QLUMP_SIZE_NEGATIVE <= x <= QLUMP_SIZE_UNDERFLOW is underflow.
   */
  QLUMP_SIZE_OVERFLOW  = ((uint)QLUMP_SIZE_MAX * 2) + 1,
  QLUMP_SIZE_UNDERFLOW = ((uint)0 - QLUMP_SIZE_MAX) - 1,
} ;

/* The state of a qlump -- fits in a ushort.
 */
typedef enum qlump_state qlump_state_t ;

enum qlump_state
{
  /* If the qlump is unset it is a FATAL ERROR to perform any qlump operation
   * on it, other than:
   *
   *   qlump_init()      -- sets state and mtype
   *
   *   qlump_re_init()   -- same as qlump_init() if unset
   *
   *   qlump_free_body() -- does nothing if unset
   *
   *   qlump_extend()    -- same as qlump_init() if unset
   */
  qls_unset      = 0,

  /* The first "set" value
   */
  qls_set_first,

  /* The two alias states
   */
  qls_alias      = qls_set_first,
  qls_alias_term,

  /* The two non-alias states
   */
  qls_embedded,
  qls_normal,

  /* Not much here, really.
   */
  qls_count_of_values,
  qls_max_value  = qls_count_of_values - 1,

  /* The last "set" value
   */
  qls_set_last   = qls_max_value,
} ;

/*------------------------------------------------------------------------------
 * The body is a "blob" -- but can fetch its address in a number of ways.
 *
 * Can set the "blob" to point to a "const" -- it is up to the caller to
 * ensure this is safe.  Setting the qlump size to zero *guarantees* that
 * the qlump handler will not attempt to free such a body, and any test for
 * sufficient room to write to it will fail !
 */
typedef void* qlump_body ;

union qlump_body
{
  void* v ;

  byte* b ;
  char* c ;

  const void* cv ;
} ;

typedef union qlump_body qlump_body_u ;

/*------------------------------------------------------------------------------
 * The qlump itself.
 *
 * Note that the body, len and cp map to an elstring.
 */
typedef struct qlump  qlump_t ;
typedef struct qlump* qlump ;

struct qlump
{
  qlump_body_u body ;   /* pointer to body                      */

  ulen         len ;    /* "items" -- NOT bytes                 */
  ulen         cp ;     /* ditto                                */
  usize        size ;   /* ditto                                */

  ushort       mtype ;  /* should be MTYPE_NULL if unset        */

  ushort       state ;  /* state as above                       */
} ;

CONFIRM(MTYPE_MAX     <= USHRT_MAX) ;
CONFIRM(qls_max_value <= USHRT_MAX) ;

CONFIRM((sizeof(qlump_t) % sizeof(void*)) == 0) ;

/* Initialising a qlump to all zeros produces an empty, unset qlump.
 */
enum
{
  QLUMP_UNSET           = qls_unset + MTYPE_NULL,

  QLUMP_INIT_ALL_ZEROS  = false,
  QLUMP_UNSET_ALL_ZEROS = (QLUMP_UNSET == 0),
};

CONFIRM(QLUMP_UNSET_ALL_ZEROS) ;

/*------------------------------------------------------------------------------
 * The qlump_type structure specifies how to handle the body of a qlump.
 *
 * This is expected to be allocated as a const, and all qlump functions take
 * a pointer to a constant structure.
 */
typedef struct qlump_type  qlump_type_t ;
typedef struct qlump_type* qlump_type ;

typedef const struct qlump_type* qlump_type_c ;

/* Allocation function -- allocate or reallocate *body* of qlump.
 *
 * Is passed the qlump -- which may be part of some other structure, for
 * some allocators.
 *
 * Is called only when allocating or reallocating memory.  Is not called when
 * allocates the embedded body.
 *
 * The 'store' flag is set if this is an allocation for qlump_store(), and
 * implies that is allocating about the smallest amount required for the
 * current contents of the lump, and may be about to keep it for a while.
 *
 * The qlump contains its current state etc.  The allocation must:
 *
 *   * if the current state is not qls_normal, or if is 'store', or if
 *     the current size == 0, the allocator must malloc() a brand new piece
 *     of memory.
 *
 *   * otherwise, the allocator must extend the current body -- realloc().
 *
 * Must return having set:  ql->size  = new size -- in ITEMS
 *                          ql->body  = new body
 *                          ql->state = qls_normal
 *
 * The ql->mtype gives the type of memory.
 *
 * The allocator may allocate more items than requested -- but never fewer.
 *
 * See: qlump_alloc() -- default.
 */
typedef usize qlump_alloc_func(qlump ql, usize new_size, bool store,
                                                              qlump_type_c qt) ;

/* Free function -- free *body* of given qlump.
 *
 * Is passed the qlump -- which may be part of some other structure, for
 * some allocators.
 *
 * The contents of the qlump MUST be ignored, other than ql->mtype
 *
 * Is passed: body = last body allocated
 *            size = *item* size  -- won't be zero
 *
 * See: qlump_free() -- default.
 */
typedef void qlump_free_func(qlump ql, void* body, usize size, qlump_type_c qt);

/* The qlump_type structure.
 */
struct qlump_type
{
  /* Functions to allocate/free memory.
   *
   * NB: not called if embedded body is sufficient, or when "freeing" the
   *     embedded body.
   */
  qlump_alloc_func*      alloc ;
  qlump_free_func*       free ;

  /* The len and size in the qlump refer to some count of "items".
   *
   * unit = size of each item, in bytes -- MUST NOT be 0 !
   */
  usize   unit ;                /* maximum = 64K-1 (!)          */

  /* When allocating a body for a qlump, rounds the size to a multiple of 'U',
   * ensuring that there are at least 'F' free items beyond the required
   * new_size.
   *
   * Note that if there is an embedded body, will use that *without* applying
   * these, if possible.
   *
   * 'U' MUST be 2^n.
   *
   * So, to allocate in multiples of 8 items while arranging for there to be
   * at least 3 free items beyond the required new size:
   *
   *   .size_add     = 3,          // 'F'
   *   .size_unit_m1 = 8 - 1,      // 'U' - 1
   */
  usize   size_add ;            /* in "items" (not bytes)       */
  usize   size_unit_m1 ;        /* in "items" (not bytes)       */

  /* When allocating a body for a qlump, adds size_terminator to the
   * requirement -- unlike size_add, this applies to the embedded body and
   * when allocating for a "reduced" body.
   */
  usize   size_term ;

  /* Can specify a minimum allocation size -- so, for example, can on the
   * first allocation get some generally expected minimum.
   *
   * Rounds up to multiple of 'U'.
   *
   * NB: either size_add or size_min MUST be > 0
   */
  usize   size_min ;            /* in "items" (not bytes)       */

  /* May use a generous size_add, size_unit or size_min when creating and
   * working with a qlump.  When work on the qlump is complete (in some way),
   * may reduce it to a multiple of 'MU' -- and release any excess.
   *
   * 'MU' MUST be 2^n
   */
  usize   size_min_unit_m1 ;    /* in "items" (not bytes)       */

  /* In some cases, a qlump may be associated with an amount of memory which
   * is reasonably predictable, so that it makes sense to have a structure
   * which contains a qlump and an embedded body, eg:
   *
   *    struct foo
   *    {
   *      .....
   *
   *      qlump_t   bar ;
   *
   *      .....
   *      uint      bar_body[99] ;  // item is a uint -- .unit = 4
   *
   *      ....
   *    } ;
   *
   * In which case:
   *
   *   .embedded_size   = 99,
   *   .embedded_offset = offsetof(struct foo, bar_body)
   *                                               - offsetof(struct foo, bar),
   *
   * NB: the offset is the offset BETWEEN the qlump and the embedded body,
   *     (both embedded in the same structure).
   *
   *     See the qlump_embedded_offset() macro, below.
   *
   * If the *effective* embedded_size is not zero then:
   *
   *   * when allocating, will use the embedded body if possible:
   *
   *      - ignoring size_add, size_unit_m1 and size_min,
   *
   *      - but taking into account size_terminator
   *
   *   * when reducing a qlump, will use the embedded body if possible:
   *
   *      - ignoring and size_min_unit_m1,
   *
   *      - but taking into account size_terminator
   *
   *   * will not free the body when it is set to the embedded body (!).
   */
  usize   embedded_size ;       /* in "items" (not bytes)       */
  int     embedded_offset ;     /* in bytes                     */
} ;

/* Macro to calculate embedded_offset.
 */
#define qlump_embedded_offset(_struct, _qlump, _body) \
  ((int)offsetof(_struct, _body) - (int)offsetof(_struct, _qlump))

/* Types of issue detected by qlump_register_type()
 */
enum qlump_register_ret
{
  qlrr_ok   = 0,

  qlrr_invalid_mtype,
  qlrr_reregister,
  qlrr_functions,
  qlrr_zero_unit,
  qlrr_size_unit_m1,
  qlrr_size_min_unit_m1
} ;

typedef enum qlump_register_ret qlump_register_ret_t ;

/*------------------------------------------------------------------------------
 * For sort and bchop etc., need comparison function
 */
typedef int qlump_cmp_func(const void* a, const void* b) ;

/*==============================================================================
 * Functions
 */
extern void qlump_start_up(void) ;
extern void qlump_finish(void) ;

extern qlump_register_ret_t qlump_register_type(mtype_t mtype, qlump_type_c qt,
                                                                    bool test) ;
extern usize qlump_alloc(qlump ql, usize new_size, bool store, qlump_type_c qt);
extern void qlump_free(qlump ql, void* body, usize size, qlump_type_c qt) ;

extern qlump_body qlump_init(qlump ql, usize req, mtype_t mtype) ;
extern void qlump_set_alias(qlump ql, qlump_state_t atype,
                                   const void* alias, ulen len, mtype_t mtype) ;
extern void qlump_clear(qlump ql) ;
Inline void qlump_alias_clear(qlump ql) ;
extern qlump_body qlump_re_init(qlump ql, usize req, mtype_t mtype) ;
extern qlump_body qlump_extend(qlump ql, usize req, mtype_t mtype) ;
extern qlump_body qlump_store(qlump ql) ;
extern void qlump_copy(qlump dst, qlump src) ;
extern void qlump_copy_store(qlump dst, qlump src) ;
extern void qlump_post_clone(qlump ql) ;
extern void qlump_post_clone_store(qlump ql) ;
extern void  qlump_free_body(qlump ql) ;
extern void qlump_sort(qlump ql, qlump_cmp_func* cmp) ;
extern void qlump_sort_dedup(qlump ql, qlump_cmp_func* cmp) ;
extern uint qlump_bsearch(qlump ql, qlump_cmp_func* cmp, const void* val,
                                                                  int* result) ;
extern qlump_body qlump_bubble(qlump ql, uint at, ulen r, ulen n) ;
Inline qlump_body qlump_add_space(qlump ql, uint at, ulen n) ;
Inline qlump_body qlump_drop_items(qlump ql, uint at, ulen n) ;
extern void qlump_swap_items(qlump ql, uint a, ulen na, uint b, ulen nb) ;

/*==============================================================================
 * Inline stuff
 */

/*------------------------------------------------------------------------------
 * Clear contents of qlump, if is alias -- otherwise, do nothing.
 *
 * When discarding an alias, sets 'cp' == 'len' == 0.
 */
Inline void
qlump_alias_clear(qlump ql)
{
  if ((ql->state == qls_alias) || (ql->state == qls_alias_term))
    qlump_clear(ql) ;
} ;

/*------------------------------------------------------------------------------
 * Make space for 'n' additional items at the given 'at' position.
 *
 * Uses ql->len to determine how much need to move out of the way.
 *
 * See qlump_bubble for the full SP.
 *
 * Returns:  the (new) address of the body
 *
 *           updates: ql->len, ql->size and ql->body, as required.
 *
 *           will have room for at least 'n' items from the 'at' position
 *           forwards, plus size_term.
 *
 * NB: *FATAL* error if the qlump is unset.
 */
Inline qlump_body
qlump_add_space(qlump ql, uint at, ulen n)
{
  return qlump_bubble(ql, at, 0, n) ;
} ;

/*------------------------------------------------------------------------------
 * Drop 'n' items at the given 'at' position.
 *
 * Uses ql->len to determine how much need to move out of the way.
 *
 * See qlump_bubble for the full SP.
 *
 * Returns:  the address of the body
 *
 *           updates: ql->len, ql->size and ql->body, as required.
 *
 *           this will be the same as the old body, unless was an alias, or
 *           unless ql->len or the 'at' position exceed the old body (taking
 *           into account any size_term).
 *
 * NB: *FATAL* error if the qlump is unset.
 */
Inline qlump_body
qlump_drop_items(qlump ql, uint at, ulen n)
{
  return qlump_bubble(ql, at, n, 0) ;
}

#endif /* _ZEBRA_QLUMP_H */
